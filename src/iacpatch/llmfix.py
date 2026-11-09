"""AI 수정 (D-27, 2026-10-31): Claude Code(구독)에게 수정안을 받아 8개 관문에 통과시키고, 막히면 이유를 붙여 다시 요청한다.

흐름 (시도마다)
  1. 요청문 만들기 — Trivy 가 지목한 문제 + 원본 파일 (+ 고객 설계도, context="design" 일 때). 2번째부터는 앞 시도가 막힌 이유
     (결과 화면과 같은 '무엇 · 왜 · 어떻게', web/problems.py)와 앞 시도의 파일을 붙인다.
  2. Claude Code 를 print 모드로 부른다: `claude -p --output-format json --tools "" ...`
       - 도구 전부 끔(파일 읽기 · 명령 실행 · 검색 없음, MCP 도구도 금지) → 글(수정한 파일 전체)만 돌려받는다
       - 빈 임시 폴더에서 실행 → 저장소 파일(정답이 적힌 manifest 등)을 볼 수 없다
       - 자식 프로세스 환경에서 ANTHROPIC_API_KEY · AWS 자격증명을 지운다 → 구독으로만 돌고, AWS 에 닿을 수 없다
  3. 응답에서 코드 블록 하나를 꺼내 후보 파일로 저장 (llm:<폴더> — review/candidates.py)
  4. 다른 후보와 똑같이 검사 (실행 전 안전 점검 → 정책 → V1~V6, review/flow.py) — AI 출력은 신뢰하지 않는다
  5. 배포 전 검사를 통과하면 멈춘다. 아니면 결과를 세 갈래로 나눈다 (D-36, 2026-11-02 — 검토 문서 "모든 실패를 AI 에게 보내지 말 것"):
       - 수정안 부적합 (BLOCKED: 요구사항 위반 · 위험 유지 · 코드 오류 · 형식 위반 · 위험도 HIGH) → 이유를 붙여 다음 시도 (최대 max_attempts, 기본 3)
       - 실행 오류     (TOOL_ERROR: 도구 · 환경 · 입력 문제로 검사 자체가 돌지 않음)                → 중단. AI 에게 다시 묻지 않는다 (코드로 못 고치는 문제)
       - 검증 불가     (UNDECIDABLE: 미확정 값 · 미지원 구성으로 판정할 수 없음, 또는 검사는 통과했지만 설계도가 초안(확정 전, D-38)) → 중단. 사람 검토로 넘긴다
     AI 가 바로 앞 시도와 똑같은 파일을 또 내면(REPEATED) 검사하지 않고 중단한다 (같은 수정안 반복).
기록: data/llm_runs/<run_id>/run.json (요청 조건 · 시도별 프롬프트 지문 · 응답 원문 파일 · 검사 기록 id · 결과).
결과 상태와 종료 코드 (STATUS_KO · EXIT_CODES): PASSED 만 0. 나머지(GAVE_UP · REPEATED=1, AI_ERROR=2, TOOL_ERROR=3, UNDECIDABLE=4)는 모두 실패 —
GitHub Actions 가 'AI 가 끝내 통과하지 못함' 을 성공으로 표시하지 않게 (검토 문서 지적, 2026-11-02: 전에는 GAVE_UP 도 0 이었다).
어떤 상태에서도 원본은 바꾸지 않는다. 실패하면 사람이 고친 파일을 같은 검사(⑤ '고친 파일 올리기' · review/candidates.py)에 넣는다.
apply · 승인 · 병합은 하지 않는다 (사람). 이 모듈은 AWS 를 부르지 않는다.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

PROMPT_VERSION = "llmfix-v1"
MAX_ATTEMPTS = 3

# 실행 결과 상태 (run.json 의 status) — 한 가지 뜻만 갖는다. 화면(m_two.js AI_ST) · PR 요약 · CI 판정이 같은 표를 쓴다
STATUS_KO = {
    "PASSED": "배포 전 검사 통과 — 사람 검토 후 PR · (시험 환경이 있으면) 실제 AWS 검사",
    "GAVE_UP": "수정안 부적합 — 최대 시도까지 미통과. 자동 패치 안 함, 사람이 직접 수정",
    "REPEATED": "수정안 부적합 — AI 가 바로 앞 시도와 같은 수정안을 되풀이해 중단. 사람이 직접 수정",
    "AI_ERROR": "AI 오류 — 응답을 받지 못함(설치 · 로그인 · 시간 초과 · 형식). 자동 패치 안 함",
    "TOOL_ERROR": "실행 오류 — 검사 도구 · 환경 · 입력 문제로 검사가 돌지 않음. 환경을 고친 뒤 다시 실행 (AI 에게 다시 묻지 않음)",
    "UNDECIDABLE": "검증 불가 — 미확정 값 · 미지원 구성으로 판정할 수 없음. 사람 검토 (AI 에게 다시 묻지 않음)",
    "RUNNING": "진행 중",
}
# 명령줄 · GitHub Actions 종료 코드: 0 = 검증 통과뿐. 실패는 종류별로 다른 값 (프로세스가 정상 종료된 것과 패치 검증 성공은 다르다)
EXIT_CODES = {"PASSED": 0, "GAVE_UP": 1, "REPEATED": 1, "AI_ERROR": 2, "TOOL_ERROR": 3, "UNDECIDABLE": 4}
NEXT_KO = {
    "PASSED": "사람이 변경 내용 · 검증 표를 검토하고 PR 을 만든다 (프로그램 ⑧, 확인 문구 입력)",
    "GAVE_UP": "원본은 그대로다. 마지막 시도의 '무엇 · 왜 · 어떻게' 를 보고 사람이 고친 파일을 ⑤ '고친 파일 올리기' 로 제출 — AI 수정안과 같은 검사를 받는다",
    "REPEATED": "원본은 그대로다. 사람이 고친 파일을 ⑤ '고친 파일 올리기' 로 제출 — AI 수정안과 같은 검사를 받는다",
    "AI_ERROR": "Claude Code 설치 · 로그인(claude auth status) · 시간 초과를 확인하고 다시 실행. 급하면 사람이 고친 파일을 ⑤ 로 제출",
    "TOOL_ERROR": "검사 도구(Trivy · Terraform) · provider 내려받기 · 입력 파일을 확인하고 같은 수정안을 다시 검사한다. 코드 문제가 아니다",
    "UNDECIDABLE": "판정할 수 없는 값(기본값 없는 변수 · 미지원 리소스 · 외부 참조)을 사람이 확인한다. 값을 확정하거나 지원 범위 안으로 고친 뒤 다시 검사",
}
# 검증 불가의 한 갈래 (D-38): 8개 관문은 다 통과했지만 비교 기준인 설계도가 초안(확정 전) — 코드 문제가 아니라 기준 문제라 AI 에게 다시 묻지 않는다
DRAFT_STATUS_KO = "검증 불가 — 배포 전 검사는 통과했지만 설계도가 초안(확정 전)이라 '고객 요구 충족' 판정을 보류. 담당자 확정 뒤 다시 검사 (AI 에게 다시 묻지 않음)"
DRAFT_NEXT_KO = "③ 원하는 구조에서 담당자가 설계도를 확정한 뒤 AI 수정을 다시 실행한다 — 코드 문제가 아니라 비교 기준이 확정 전이다"


def exit_code(status: Any) -> int:
    """run.json status → 종료 코드. 모르는 상태(예: RUNNING 으로 끊김)는 5."""
    return EXIT_CODES.get(str(status), 5)


def classify_attempt(brief: Dict[str, Any]) -> str:
    """검사 기록 요약(_record_brief) → 시도 결과 한 가지: PASSED · BLOCKED(수정안 부적합 → 재요청) · TOOL_ERROR(실행 오류 → 중단) ·
    UNDECIDABLE(검증 불가 → 사람). 판정은 기록에 있는 값(상태 · 계층 결과 · 검토 수준)만 읽는다 — 여기서 새로 판정하지 않는다."""
    if brief.get("passed"):
        return "PASSED"
    st = str(brief.get("state") or "")
    layers = brief.get("layers") or {}
    if st == "INPUT_ERROR" or any(str(v) == "ERROR" for v in layers.values()):
        return "TOOL_ERROR"            # 도구가 돌지 않음(provider 못 받음 · Trivy 실행 실패) · 입력 손상 — 코드를 다시 써도 달라지지 않는다
    if st in ("CANDIDATE_INVALID", "INFO_INSUFFICIENT") or brief.get("tone") == "bad":
        return "BLOCKED"               # 형식 위반 · 검증 실패 · 정책 밖 변경 — 수정안의 문제, 이유를 붙여 다시 요청
    if brief.get("tone") == "warn" and str(brief.get("level") or "") == "REPORT_ONLY" and str(brief.get("validity") or "") == "COMPLETE":
        return "BLOCKED"               # 검사는 다 돌았는데 위험도 HIGH(너무 넓은 변경) — 더 좁은 수정안을 다시 요청
    return "UNDECIDABLE"               # 결과가 없는 계층(UNKNOWN · NOT_RUN · SKIPPED) · 판정 불가 요구사항 — 사람이 봐야 한다
# AI 호출 프로세스 환경에서 지우는 변수: API 키(과금 경로) · AWS 자격증명
UNSET_ENV = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
             "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
             "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"]
NO_TOOLS = ["--tools", "", "--disallowedTools", "mcp__*", "--permission-mode", "dontAsk", "--max-turns", "1"]


# ----------------------------------------------------------------------------- Claude Code 찾기 · 상태
def claude_bin() -> Optional[str]:
    """IACPATCH_CLAUDE_BIN → PATH 의 claude → 설치 기본 위치(~/.local/bin). 설치 직후 PATH 가 안 잡힌 PC 에서도 찾게."""
    env = os.environ.get("IACPATCH_CLAUDE_BIN")
    if env and Path(env).exists():
        return env
    hit = shutil.which("claude")
    if hit:
        return hit
    for p in (Path.home() / ".local" / "bin" / ("claude.exe" if os.name == "nt" else "claude"),):
        if p.exists():
            return str(p)
    return None


_STATUS: Dict[str, Any] = {"at": 0.0, "value": None}


def claude_status(refresh: bool = False) -> Dict[str, Any]:
    """설치 · 로그인 상태 (claude --version, claude auth status). 60초 동안 다시 묻지 않는다."""
    from .tools.runner import run
    if not refresh and _STATUS["value"] is not None and time.time() - _STATUS["at"] < 60:
        return _STATUS["value"]
    b = claude_bin()
    out: Dict[str, Any] = {"found": bool(b), "path": b, "version": None, "logged_in": None, "auth_method": None, "note": ""}
    if not b:
        out["note"] = "Claude Code 가 설치되어 있지 않음 — PowerShell: irm https://claude.ai/install.ps1 | iex 후 claude 로 로그인"
    else:
        try:
            r = run([b, "--version"], timeout=30, unset=UNSET_ENV)
            out["version"] = (r.stdout or r.stderr).strip().splitlines()[0][:80] if (r.stdout or r.stderr).strip() else None
            a = run([b, "auth", "status"], timeout=30, unset=UNSET_ENV)
            out["logged_in"] = a.returncode == 0
            try:
                out["auth_method"] = (json.loads(a.stdout or "{}") or {}).get("authMethod")
            except ValueError:
                out["auth_method"] = None
            if not out["logged_in"]:
                out["note"] = "로그인 필요 — PowerShell 에서 claude 실행 후 Claude 계정으로 로그인"
        except Exception as e:  # noqa: BLE001 — 상태 확인 실패는 화면에 그대로
            out["note"] = f"상태 확인 실패: {type(e).__name__}: {e}"
    _STATUS.update(at=time.time(), value=out)
    return out


# ----------------------------------------------------------------------------- 요청 대상
@dataclass
class FixTask:
    set_id: str
    case_id: str
    tf_dir: str
    trivy_json: str
    rule: str
    resource: str
    filename: str
    line: int
    title: str
    original: str                          # 지목 파일의 원본 전체
    design: Optional[Dict[str, Any]]       # 고객 설계도 (토폴로지 형식) — 지금 기준 버전 (D-30)
    intent_path: Optional[str]
    manifest: Dict[str, Any] = field(default_factory=dict)
    set_dir: Optional[Path] = None
    design_version: int = 1


def load_task(root: Path, set_id: str, intent_path: Optional[str] = None) -> FixTask:
    """intent_path 를 주지 않으면 '지금 기준' 설계도 (화면에서 고친 버전 포함 — web/designs.py)."""
    from .review.inputs import list_findings, load_trivy_report
    from .rubric_demo import _resolve
    from .web import cases as cs
    from .web import designs
    case = cs.case_of_set(set_id)
    if case is None:
        raise ValueError(f"세트 없음: {set_id}")
    man, set_dir = cs._manifest(set_id)
    tf_dir = str(man.get("tf_dir") or case["tf_dir"])
    trivy_json = _resolve(man.get("trivy_json"), set_dir)
    rule, resource = str(man.get("rule") or ""), str(man.get("resource") or "")
    rep = load_trivy_report(root / trivy_json if not Path(str(trivy_json)).is_absolute() else Path(str(trivy_json)))
    hits = [f for f in list_findings(rep) if f.rule_id == rule and f.resource == resource]
    if not hits:
        raise ValueError(f"Trivy 결과에 대상 문제가 없음: {rule} @ {resource}")
    f = hits[0]
    fname = Path(f.filename).name
    original = (root / tf_dir / fname).read_text(encoding="utf-8")
    ip = intent_path or designs.active_path(set_id) or _resolve(man.get("intent"), set_dir)
    ipp = (root / ip if not Path(str(ip)).is_absolute() else Path(str(ip))) if ip else None
    design = json.loads(ipp.read_text(encoding="utf-8")) if ipp and ipp.exists() else None
    dv = 1
    try:
        dv = int((design or {}).get("intent_version") or 1) if ipp and ipp != _resolve(man.get("intent"), set_dir) else 1
    except ValueError:
        dv = 1
    return FixTask(set_id, case["id"], tf_dir, str(trivy_json), rule, resource, fname, int(f.start_line), f.title, original, design,
                   str(ipp) if ipp else None, man, set_dir, dv)


def _labels(design: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {str(x.get("id")): x for x in (design.get("tiers") or []) + (design.get("external") or [])}


def _src_text(node: Dict[str, Any]) -> str:
    if node.get("cidrs_v4") or node.get("cidrs_v6"):
        return f"{node.get('label') or node.get('id')} ({', '.join(list(node.get('cidrs_v4') or []) + list(node.get('cidrs_v6') or []))})"
    return f"{node.get('label') or node.get('id')} (보안 그룹 {node.get('security_group')})"


def approved_sources(task: FixTask) -> str:
    """지목 리소스(보안 그룹)로 들어오도록 설계도가 허용한 통신 — 원래 요청문(cc_prompt TEMPLATE)의 '허용돼야 하는 출처' 줄."""
    if not task.design:
        return "정해진 목록 없음 (고객 설계도가 아직 없음) — 꼭 필요한 출처만"
    d = task.design or {}
    nodes = _labels(d)
    tier = next((t for t in d.get("tiers") or [] if t.get("security_group") == task.resource), None)
    if not tier:
        return "설계도에 이 리소스가 없음"
    rows = [f"{_src_text(nodes.get(str(fl.get('from')), {'id': fl.get('from')}))} → 포트 {fl.get('port') or str(fl.get('from_port')) + '-' + str(fl.get('to_port'))}"
            for fl in d.get("flows") or [] if str(fl.get("to")) == str(tier.get("id"))]
    return "; ".join(rows) or "없음"


def design_text(task: FixTask) -> str:
    d = task.design or {}
    nodes = _labels(d)
    tiers = [f"- {t.get('label')}: 보안 그룹 {t.get('security_group')}" for t in d.get("tiers") or []]
    flows = [f"- {_src_text(nodes.get(str(f.get('from')), {'id': f.get('from')}))} → {nodes.get(str(f.get('to')), {}).get('label', f.get('to'))} "
             f"({nodes.get(str(f.get('to')), {}).get('security_group', '')}) {f.get('protocol', 'tcp')} {f.get('port') or str(f.get('from_port')) + '-' + str(f.get('to_port'))}"
             for f in d.get("flows") or []]
    return "계층과 보안 그룹:\n" + "\n".join(tiers) + "\n허용 통신 (이 목록 밖의 인바운드 허용은 없어야 한다):\n" + "\n".join(flows)


HEAD = "도구(파일 읽기·명령 실행·검색)를 쓰지 말고, 아래 요청 문장에만 답해. 답은 요청대로 코드 블록 하나만 출력해.\n\n"


def build_prompt(task: FixTask, context: str = "trivy", prev: Optional[Dict[str, Any]] = None) -> str:
    """1번째: 기존 Claude Code 요청문(scripts/cc_prompt.py TEMPLATE)과 같은 문장 (+ 설계도). 2번째부터: 앞 시도가 막힌 이유 + 앞 시도 파일."""
    base = (f"다음 Terraform 파일에서 Trivy 가 아래 설정 오류를 보고했다. 파일을 고쳐서 전체 내용을 돌려줘.\n\n"
            f"- 파일: {task.filename}  (내용은 아래)\n- 룰: {task.rule} — {task.title}\n- 지목 리소스: {task.resource}  ({task.line} 번째 줄)\n"
            f"- 이 리소스에 허용돼야 하는 출처: {approved_sources(task)}  (그 외 출처는 허용하면 안 된다)\n"
            f"- 다른 리소스나 파일은 만들지 말고, 이 파일의 수정본 전체만 코드 블록 하나로 출력해줘.\n")
    if context == "design" and task.design:
        base += f"\n고객 설계도 (이 구조를 지켜야 한다):\n{design_text(task)}\n"
    if not prev:
        return HEAD + base + f"\n```hcl\n{task.original.rstrip()}\n```\n"
    reasons = "\n".join(f"{i + 1}. 무엇: {p.get('what')}\n   왜: {p.get('why')}\n   어떻게: {p.get('how')}" for i, p in enumerate(prev.get("problems") or [])) \
        or f"- {prev.get('title') or '검사 실패'}: {prev.get('reason') or ''}"
    return (HEAD + base + f"\n앞에서 낸 수정안을 검사했더니 통과하지 못했다. 결과: {prev.get('title') or ''}\n발견된 문제:\n{reasons}\n"
            f"이 문제를 고치되, 원래 지적({task.rule} · {task.resource})도 계속 해결된 상태여야 한다.\n"
            f"\n원래 파일:\n```hcl\n{task.original.rstrip()}\n```\n\n앞에서 낸 수정안:\n```hcl\n{str(prev.get('content') or '').rstrip()}\n```\n")


_BLOCK = re.compile(r"```[ \t]*(?:hcl|terraform|tf)?[ \t]*\r?\n(.*?)```", re.S | re.I)


def extract_file(text: str) -> tuple:
    """응답에서 코드 블록 하나 → (내용, 오류). 블록이 없거나 여러 개면 오류 (요청 형식 위반 — 다음 시도에서 알려 준다)."""
    blocks = _BLOCK.findall(text or "")
    if len(blocks) != 1:
        return None, f"코드 블록이 {len(blocks)}개 — 요청은 파일 전체를 코드 블록 하나로"
    body = blocks[0]
    if not body.strip():
        return None, "코드 블록이 비어 있음"
    return body if body.endswith("\n") else body + "\n", None


def call_claude(prompt: str, timeout: int = 300, model: Optional[str] = None) -> Dict[str, Any]:
    """Claude Code print 모드 1회. 반환: ok · text · session_id · cost · stdout(원문) · error."""
    from .tools.runner import run
    b = claude_bin()
    if not b:
        return {"ok": False, "error": "Claude Code 없음 — 설치 후 로그인 필요 (irm https://claude.ai/install.ps1 | iex → claude)", "stdout": "", "stderr": ""}
    argv = [b, "-p", "--output-format", "json", *NO_TOOLS] + (["--model", model] if model else []) + ["표준 입력으로 받은 요청에 답해."]
    with tempfile.TemporaryDirectory(prefix="iacpatch-ai-") as cwd:          # 빈 폴더: 저장소 파일 · CLAUDE.md 를 읽지 않게
        r = run(argv, cwd=cwd, timeout=timeout, input_text=prompt, unset=UNSET_ENV)
    out = {"ok": False, "text": "", "session_id": None, "cost": None, "stdout": r.stdout, "stderr": r.stderr[-4000:], "returncode": r.returncode,
           "timed_out": r.timed_out, "argv": [os.path.basename(argv[0])] + argv[1:-1] + ["<요청문은 표준 입력>"]}
    if r.timed_out:
        out["error"] = f"Claude 응답 시간 초과 ({timeout}초)"
        return out
    try:
        j = json.loads(r.stdout or "")
    except ValueError:
        out["error"] = "Claude 응답이 JSON 이 아님: " + (r.stdout or r.stderr or "")[:300]
        return out
    if isinstance(j, list):                                   # 일부 판: 메시지 목록 — 마지막 result 메시지
        j = next((x for x in reversed(j) if isinstance(x, dict) and x.get("type") == "result"), {})
    out.update(text=str(j.get("result") or ""), session_id=j.get("session_id"), cost=j.get("total_cost_usd"),
               model=",".join(sorted((j.get("modelUsage") or {}).keys())) or None)
    if r.returncode != 0 or j.get("is_error"):
        out["error"] = "Claude 오류: " + (out["text"] or r.stderr or f"종료 코드 {r.returncode}")[:300]
        return out
    out["ok"] = True
    return out


# ----------------------------------------------------------------------------- 시도 반복
def runs_root(root: Path) -> Path:
    """data/llm_runs (시험은 IACPATCH_LLM_RUNS_DIR 로 바꾼다)."""
    env = os.environ.get("IACPATCH_LLM_RUNS_DIR")
    return Path(env) if env else root / "data" / "llm_runs"


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def run_fix(root: Path, set_id: str, context: str = "trivy", max_attempts: int = MAX_ATTEMPTS, log: Callable[[str], None] = print,
            reviews_dir: Optional[Path] = None, model: Optional[str] = None, timeout: int = 300, intent_path: Optional[str] = None,
            prog: Optional[Callable[[int, int], None]] = None) -> Dict[str, Any]:
    from .config import load_settings
    from .review.flow import ReviewOptions, run_review
    from .rubric_demo import _resolve
    max_attempts = max(1, min(int(max_attempts or MAX_ATTEMPTS), MAX_ATTEMPTS))
    if reviews_dir is None and os.environ.get("IACPATCH_REVIEWS_DIR"):     # 명령줄 경로도 화면과 같은 기록 폴더 규칙 (시험은 임시 폴더)
        reviews_dir = Path(os.environ["IACPATCH_REVIEWS_DIR"])
    task = load_task(root, set_id, intent_path)
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    rdir = runs_root(root) / run_id
    rdir.mkdir(parents=True, exist_ok=True)
    rec: Dict[str, Any] = {"run_id": run_id, "set_id": set_id, "case_id": task.case_id, "context": context, "max_attempts": max_attempts,
                           "prompt_version": PROMPT_VERSION, "target": {"rule": task.rule, "resource": task.resource, "file": task.filename, "line": task.line},
                           "design": {"intent_id": (task.design or {}).get("intent_id"), "intent_version": (task.design or {}).get("intent_version"),
                                      "version": task.design_version},
                           "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "status": "RUNNING", "attempts": [], "final_record_id": None,
                           "safety": {"tools": "전부 끔 (--tools \"\" · MCP 금지)", "cwd": "빈 임시 폴더", "env_removed": UNSET_ENV, "apply": "하지 않음 (사람)"}}
    try:                                   # 어느 프로그램 · 정책 판이 이 실행을 했나 (D-37)
        from .version import provenance
        rec["provenance"] = provenance(root)
    except Exception as e:
        rec["provenance"] = {"error": str(e)}

    def save() -> None:
        (rdir / "run.json").write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
    save()
    s = load_settings(str(root))
    man, set_dir = task.manifest, (task.set_dir or (root / "experiments" / "candidate-sets" / set_id))
    prev: Optional[Dict[str, Any]] = None
    for n in range(1, max_attempts + 1):
        adir = rdir / f"attempt-{n}"
        (adir / "candidate").mkdir(parents=True, exist_ok=True)
        prompt = build_prompt(task, context, prev)
        (adir / "prompt.txt").write_text(prompt, encoding="utf-8")
        att: Dict[str, Any] = {"n": n, "prompt_sha256": _sha(prompt), "prompt_file": f"attempt-{n}/prompt.txt", "status": "ASKING", "record_id": None}
        rec["attempts"].append(att)
        save()
        if prog:
            prog(2 * n - 1, 2 * max_attempts)
        log(f"AI 수정 시도 {n}/{max_attempts}: Claude 에게 요청 (도구 끔 · 빈 폴더 · API 키 · AWS 자격증명 제거)")
        t0 = time.time()
        res = call_claude(prompt, timeout=timeout, model=model)
        (adir / "response.json").write_text(res.get("stdout") or "", encoding="utf-8")
        att.update(response_file=f"attempt-{n}/response.json", seconds=round(time.time() - t0, 1), session_id=res.get("session_id"),
                   cost_usd=res.get("cost"), model=res.get("model"))
        if not res.get("ok"):
            att.update(status="AI_ERROR", error=res.get("error"))
            rec.update(status="AI_ERROR", error=res.get("error"))
            save()
            log(f"  → {res.get('error')} — 반복 중단 (AI 가 답하지 못함)")
            break
        content, err = extract_file(res.get("text") or "")
        meta = {"origin": "llm", "generator": "claude-code:cli", "model": res.get("model") or "", "prompt_version": PROMPT_VERSION,
                "prompt_sha256": att["prompt_sha256"], "raw_response_path": (adir / "response.json").relative_to(root).as_posix() if str(adir).startswith(str(root)) else str(adir / "response.json"), "attempt": n,
                "provenance": f"AI(Claude Code, 구독) 수정안 — AI 수정 {run_id} 시도 {n} · 요청 정보: {'Trivy 결과 + 고객 설계도' if context == 'design' else 'Trivy 결과'}"}
        if content is not None:
            (adir / "candidate" / task.filename).write_text(content, encoding="utf-8")
        else:
            meta["error"] = err
        (adir / "candidate" / "candidate.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
        att["response_sha256"] = _sha(res.get("text") or "")
        att["content_sha256"] = _sha(content) if content is not None else None
        # 같은 수정안 반복: 바로 앞 시도와 파일이 똑같으면 검사해도 결과가 같다 — 검사하지 않고 중단 (시도 횟수만 태우지 않게)
        if content is not None and prev is not None and prev.get("content_sha256") == att["content_sha256"]:
            att.update(status="REPEATED", title="앞 시도와 같은 수정안", error="AI 가 바로 앞 시도와 같은 파일을 다시 냄")
            rec.update(status="REPEATED", error=att["error"])
            save()
            log(f"  → 시도 {n}: 앞 시도와 같은 파일 — 같은 수정안 반복, 중단 (사람이 직접 수정)")
            break
        log(f"  → 응답 받음 ({att['seconds']}초){'' if content is not None else ' — ' + str(err)} · 8개 관문 검사 시작")
        opt = ReviewOptions(tf_dir=task.tf_dir, trivy_json=task.trivy_json, candidate=f"llm:{adir / 'candidate'}",
                            scenario=f"ui/{set_id}/ai-{run_id}-a{n}", rule=task.rule, filename=man.get("file"), resource=task.resource,
                            line=man.get("line"), candidate_note=meta["provenance"], baseline_plan=_resolve(man.get("baseline_plan"), set_dir),
                            intent=task.intent_path, out_dir=str(reviews_dir) if reviews_dir else None, local_tools=True,
                            display_name=f"AI 수정 · 시도 {n}", design_meta=_design_meta(set_id))
        rr = run_review(s, opt)
        att["record_id"] = rr.run_id
        if prog:
            prog(2 * n, 2 * max_attempts)
        view = _record_brief(rr.run_id, reviews_dir)
        cls = classify_attempt(view)
        att.update(status=cls, title=view.get("title"), layers=view.get("layers"), record_state=view.get("state"),
                   problems=[{k: p.get(k) for k in ("layer", "tag", "what")} for p in view.get("problems") or []])
        rec["final_record_id"] = rr.run_id
        save()
        log(f"  → 시도 {n}: {view.get('title') or rr.state.value}")
        if cls == "PASSED":
            rec["status"] = "PASSED"
            break
        if cls in ("TOOL_ERROR", "UNDECIDABLE"):
            # 코드를 다시 써서 풀 문제가 아니다 — AI 에게 다시 묻지 않고 사람에게 넘긴다 (남은 시도는 쓰지 않음)
            rec.update(status=cls, error=view.get("reason") or view.get("title"))
            if cls == "UNDECIDABLE" and view.get("draft_design"):
                rec["undecidable_kind"] = "DRAFT_DESIGN"   # 검사는 다 통과했지만 비교 기준(설계도)이 확정 전 — 담당자 확정 뒤 다시 검사 (D-38)
            save()
            log(f"  → {STATUS_KO[cls]}")
            break
        prev = {"title": view.get("title"), "reason": view.get("reason"), "problems": view.get("problems") or [], "content": content or "",
                "content_sha256": att.get("content_sha256")}
    else:
        rec["status"] = "GAVE_UP"
    if rec["status"] == "RUNNING":
        rec["status"] = "GAVE_UP"
    if rec["status"] == "GAVE_UP":
        log(f"AI 수정 {max_attempts}번 모두 배포 전 검사 미통과 — 사람에게 넘김 (자동 패치 안 함)")
    rec["status_ko"] = STATUS_KO.get(rec["status"], rec["status"])
    rec["next"] = NEXT_KO.get(rec["status"], "")
    if rec.get("undecidable_kind") == "DRAFT_DESIGN":
        rec["status_ko"] = DRAFT_STATUS_KO
        rec["next"] = DRAFT_NEXT_KO
    rec["exit_code"] = exit_code(rec["status"])
    rec["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    save()
    return rec


def _design_meta(set_id: str) -> Optional[Dict[str, Any]]:
    """지금 기준 설계도의 확정 상태 (web/designs.confirmation) — 기록에 같이 남긴다. 못 읽으면 None (판정은 그대로)."""
    try:
        from .web import designs
        return designs.confirmation(set_id)
    except Exception:
        return None


def _record_brief(rid: str, reviews_dir: Optional[Path]) -> Dict[str, Any]:
    """검사 기록 → 다음 요청에 붙일 이유 (결과 화면과 같은 문장: web/server.record_view)."""
    from .web import server as ws
    old = os.environ.get("IACPATCH_REVIEWS_DIR")
    if reviews_dir:
        os.environ["IACPATCH_REVIEWS_DIR"] = str(reviews_dir)
    try:
        v = ws.record_view(rid)
    finally:
        if reviews_dir:
            if old is None:
                os.environ.pop("IACPATCH_REVIEWS_DIR", None)
            else:
                os.environ["IACPATCH_REVIEWS_DIR"] = old
    c = v.get("conclusion") or {}
    stt = v.get("state") or {}
    return {"passed": c.get("tone") == "good", "tone": c.get("tone"), "title": c.get("title") or c.get("headline"), "reason": c.get("reason"),
            "draft_design": bool(c.get("draft_design")),
            "state": stt.get("code"), "level": stt.get("level"), "validity": stt.get("verification_status"),
            "problems": v.get("problems") or [], "layers": {l.get("layer"): l.get("verdict") for l in v.get("layers") or []}}


def summary_markdown(rec: Dict[str, Any]) -> str:
    """PR 댓글 · 기록용 요약 (GitHub Actions 가 그대로 올린다)."""
    status = str(rec.get("status"))
    st = STATUS_KO.get(status, status)
    lines = [f"## IaCPatch AI 수정 결과: {status} — {st}", "",
             f"- 대상: `{rec['target']['rule']}` · `{rec['target']['resource']}` ({rec['target']['file']} {rec['target']['line']}행)",
             f"- AI 에게 준 정보: {'Trivy 결과 + 고객 설계도' if rec.get('context') == 'design' else 'Trivy 결과'} · 최대 {rec.get('max_attempts')}번",
             "- AI 는 도구 없이 글만 생성 · AWS 자격증명 없음 · apply 안 함 · 원본은 바꾸지 않음",
             f"- 종료 코드 {exit_code(status)} (0 = 검증 통과뿐 · 1 수정안 부적합 · 2 AI 오류 · 3 실행 오류 · 4 검증 불가)",
             f"- 다음: {NEXT_KO.get(status, '')}"]
    pv = rec.get("provenance") or {}
    if pv.get("program_version"):
        try:
            from .version import short
            lines.append(f"- 판: {short(pv)} · 정책 {pv.get('policy_version')} · 요청문 {pv.get('prompt_version')}")
        except Exception:
            pass
    lines += ["", "| 시도 | 상태 | 결과 | V1 | V2 | V3 | V4 | V5 | V6 |", "|---|---|---|---|---|---|---|---|---|"]
    for a in rec.get("attempts") or []:
        lay = a.get("layers") or {}
        lines.append(f"| {a['n']} | {a.get('status')} | {a.get('title') or a.get('error') or ''} | " + " | ".join(str(lay.get(k, '-')) for k in ("V1", "V2", "V3", "V4", "V5", "V6")) + " |")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    """GitHub Actions · 명령줄: python -m iacpatch.llmfix --set arch-3tier-sg [--context design] [--summary out.md]"""
    import argparse
    ap = argparse.ArgumentParser(description="AI 수정 (Claude Code 구독) → 8개 관문 → 실패 시 이유를 붙여 재요청 (최대 3번)")
    ap.add_argument("--set", required=True)
    ap.add_argument("--context", choices=["trivy", "design"], default="trivy")
    ap.add_argument("--max-attempts", type=int, default=MAX_ATTEMPTS)
    ap.add_argument("--summary", help="요약 Markdown 을 쓸 파일 (PR 댓글용)")
    ap.add_argument("--status-file", help="결과 상태 한 단어(PASSED · GAVE_UP · …)를 쓸 파일 — CI 가 종료 코드와 함께 판정에 쓴다")
    ap.add_argument("--root", default=None)
    a = ap.parse_args(argv)
    from . import app as _app
    root = Path(a.root) if a.root else _app.ROOT
    rec = run_fix(root, a.set, a.context, a.max_attempts)
    md = summary_markdown(rec)
    if a.summary:
        Path(a.summary).write_text(md, encoding="utf-8")
    if a.status_file:
        Path(a.status_file).write_text(str(rec.get("status")) + "\n", encoding="utf-8")
    print(md)
    return exit_code(rec.get("status"))     # PASSED 만 0 — GAVE_UP 을 0 으로 돌려주던 것을 고침 (2026-11-02)


if __name__ == "__main__":
    raise SystemExit(main())
