"""아키텍처 Terraform → Trivy 점검 → 결과물 (지도교수 9/29 지시: "테라폼 → 트리비 점검 → 결과가 나오는 플로우").

입력: Terraform 폴더 하나 (기본 infrastructure/webapp-2tier).
출력: data/arch/<실행 ID>/ 에
    trivy.json            Trivy 원문 (바꾸지 않는다)
    plan.json             자격증명 없는 오프라인 plan (terraform 이 있을 때) — "이 코드가 무엇을 만드는가" 의 근거
    summary.json          파일·리소스·도구·finding 목록 (CIS 대응·파이프라인 지원 여부 포함)
    findings.md           사람용 표
    interpret_prompt.md   AI 해석 단계에 붙여 넣는 프롬프트 (모델 호출은 하지 않는다 — D-5)

이 모듈은 모델을 호출하지 않고, AWS 에 접속하지 않고, 원본 폴더를 바꾸지 않는다. 도구가 없으면 그 단계는 NOT_RUN 으로 적는다.
"""
from __future__ import annotations

import json
import os
import platform
import re
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import load_json, package_root
from .tools.terraform import TerraformAdapter
from .tools.trivy import TrivyAdapter, TrivyScan

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
_RES_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
_DATA_RE = re.compile(r'^\s*data\s+"([^"]+)"\s+"([^"]+)"\s*\{')


def tool_env(root: Path) -> Dict[str, str]:
    """tools/ 의 trivy·terraform 을 우선 쓴다 (app._env 와 같은 규칙). exe 의 --exec 는 환경을 안 넘기므로 여기서 잡는다."""
    win = platform.system() == "Windows"
    root = Path(root).resolve()          # 도구 경로는 절대 경로로 (작업 복사본 안에서 cwd 를 바꿔 실행하므로)
    env: Dict[str, str] = {}
    for name, key in (("trivy", "TRIVY_BIN"), ("terraform", "TERRAFORM_BIN")):
        exe = root / "tools" / (name + (".exe" if win else ""))
        if exe.exists():
            env[key] = str(exe)
        elif os.environ.get(key):
            env[key] = os.environ[key]
    env.setdefault("TRIVY_SKIP_CHECK_UPDATE", os.environ.get("TRIVY_SKIP_CHECK_UPDATE", "1"))
    env.setdefault("TRIVY_SKIP_VERSION_CHECK", "true")
    cache = root / "tools" / "plugin-cache"
    try:
        cache.mkdir(parents=True, exist_ok=True)
        env.setdefault("TF_PLUGIN_CACHE_DIR", os.environ.get("TF_PLUGIN_CACHE_DIR", str(cache)))
    except OSError:
        pass
    return env


@dataclass
class TfFile:
    name: str
    lines: int
    resources: List[str] = field(default_factory=list)   # "type.name"
    data_sources: List[str] = field(default_factory=list)


def inventory(tf_dir: Path) -> List[TfFile]:
    """폴더의 *.tf 를 읽어 파일별 줄 수와 resource 블록 목록을 만든다 (정규식 — plan 이 없어도 동작)."""
    out: List[TfFile] = []
    for p in sorted(tf_dir.glob("*.tf")):
        if p.name.startswith("zz_iacpatch_"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        f = TfFile(p.name, text.count("\n") + (0 if text.endswith("\n") or not text else 1))
        for line in text.splitlines():
            m = _RES_RE.match(line)
            if m:
                f.resources.append(f"{m.group(1)}.{m.group(2)}")
            m2 = _DATA_RE.match(line)
            if m2:
                f.data_sources.append(f"data.{m2.group(1)}.{m2.group(2)}")
        out.append(f)
    return out


def cis_lookup(rule_id: str, mapping: Dict[str, Any]) -> Dict[str, Any]:
    """policy/cis_mapping.json 의 항목. 표에 없는 룰은 '매핑표에 없음' 으로 — 지어내지 않는다."""
    r = (mapping.get("rules") or {}).get(rule_id)
    if not r:
        return {"in_table": False, "level": "매핑표에 없음", "items": [], "status": ""}
    items = []
    for c in r.get("cis_candidates") or []:
        items.append({"benchmark": c.get("benchmark", ""), "section": c.get("section", ""), "title": c.get("title", ""),
                      "source": c.get("source", ""), "verified": bool(c.get("verified"))})
    return {"in_table": True, "level": r.get("mapping_level", ""), "items": items, "status": r.get("mapping_status", "")}


def classify_scope(rule_id: str, policy: Dict[str, Any]) -> str:
    """이 finding 을 파이프라인(패치 생성→V1~V6)이 끝까지 다룰 수 있는가. supported_target_rules 기준 — 다른 룰은 '탐지·해석만'."""
    return "패치 파이프라인 대상" if rule_id in (policy.get("supported_target_rules") or []) else "탐지·해석만 (파이프라인 밖)"


def findings_rows(scan: TrivyScan, mapping: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for f in scan.findings:
        rows.append({
            "severity": f.severity, "rule_id": f.rule_id, "title": f.title, "resource": f.resource, "file": f.filename,
            "line": f.start_line, "end_line": f.end_line, "message": f.message, "resolution": f.resolution,
            "references": f.references[:3], "cis": cis_lookup(f.rule_id, mapping), "scope": classify_scope(f.rule_id, policy),
        })
    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9), r["file"], r["line"], r["rule_id"]))
    return rows


def plan_summary(plan: Dict[str, Any]) -> Dict[str, Any]:
    rc = plan.get("resource_changes") or []
    by_type = Counter(r.get("type", "?") for r in rc)
    actions = Counter("/".join(r.get("change", {}).get("actions") or []) for r in rc)
    return {"resource_count": len(rc), "by_type": dict(sorted(by_type.items())), "actions": dict(actions),
            "terraform_version": plan.get("terraform_version", "")}


def run_scan(tf_dir: Path, out_dir: Path, root: Optional[Path] = None, do_plan: bool = True,
             log: Callable[[str], None] = print, region: str = "ap-northeast-2", provider_version: str = "5.100.0") -> Dict[str, Any]:
    """전체 흐름. 결과 dict 를 돌려주고 out_dir 에 파일들을 쓴다."""
    root = Path(root or package_root()).resolve()
    tf_dir = Path(tf_dir).resolve()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    env = tool_env(root)
    os.environ.update({k: v for k, v in env.items() if k not in os.environ or k.endswith("_BIN")})
    mapping = load_json(root / "policy" / "cis_mapping.json")
    policy = load_json(root / "policy" / "patch_policy.json")

    inv = inventory(tf_dir)
    rel = _rel(tf_dir, root)
    log(f"대상: {rel}  ({len(inv)} 파일, 리소스 블록 {sum(len(f.resources) for f in inv)}개)")
    for f in inv:
        log(f"  {f.name:<28} {f.lines:>4} 줄  {', '.join(f.resources) if f.resources else '(리소스 없음)'}")

    result: Dict[str, Any] = {
        "schema": "iacpatch-arch-scan-v1", "scan_id": out_dir.name, "tf_dir": rel, "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "files": [asdict(f) for f in inv], "tools": {}, "plan": {"status": "NOT_RUN"}, "scan": {"status": "NOT_RUN"}, "findings": [],
    }

    # ---- terraform: fmt / validate / offline plan (자격증명 없음 — 만들지 않는다)
    tf = TerraformAdapter(env.get("TERRAFORM_BIN"), region, template_dir=_template_dir(root), provider_version=provider_version)
    info = tf.info()
    result["tools"]["terraform"] = {"available": info.available, "kind": info.kind, "version": info.version, "bin": tf.binary}
    if do_plan and info.available:
        wd = TerraformAdapter.make_workdir(tf_dir, out_dir / "work")
        steps = tf.plan_pipeline(wd, True, write_plan_json_to=out_dir / "plan.json")
        st = {k: {"ok": v.ok, "error": ("" if v.ok else _step_error(v))} for k, v in steps.items()}
        ok = all(v.ok for v in steps.values()) and "show" in steps
        result["plan"] = {"status": "PASS" if ok else "FAIL", "steps": st}
        if ok:
            result["plan"].update(plan_summary(steps["show"].data))
            log(f"terraform ({info.kind} {info.version}): init/fmt/validate/plan 통과 — 리소스 {result['plan']['resource_count']}개 "
                f"{result['plan']['actions']}")
        else:
            bad = [k for k, v in steps.items() if not v.ok]
            log(f"terraform: 실패 단계 {bad} — {st[bad[0]]['error'][:300] if bad else ''}")
    elif do_plan:
        log("terraform 없음 → plan NOT_RUN (화면의 '도구 설치/확인' 또는 tools/ 에 두기)")

    # ---- trivy
    trivy = TrivyAdapter(env.get("TRIVY_BIN"))
    result["tools"]["trivy"] = {"available": trivy.available(), "version": trivy.version() if trivy.available() else "", "bin": trivy.binary}
    if trivy.available():
        scan = trivy.scan_dir(tf_dir, out_dir / "trivy.json")
        if scan.ok:
            rows = findings_rows(scan, mapping, policy)
            result["findings"] = rows
            result["scan"] = {"status": "PASS", "trivy_version": scan.version, "successes": scan.summary.get("successes", 0),
                              "failures": scan.summary.get("failures", 0), "checks_executed": scan.summary.get("checks_executed", 0),
                              "parse_errors": scan.parse_errors, "by_severity": dict(Counter(r["severity"] for r in rows)),
                              "argv": scan.argv}
            log(f"trivy {scan.version}: 검사 {result['scan']['checks_executed']}개 중 실패(finding) {result['scan']['failures']}개 "
                f"{result['scan']['by_severity']}" + (f"  파싱 실패 {len(scan.parse_errors)}건!" if scan.parse_errors else ""))
        else:
            result["scan"] = {"status": "ERROR", "error": scan.error, "argv": scan.argv}
            log(f"trivy 실패: {scan.error[:300]}")
    else:
        log("trivy 없음 → 스캔 NOT_RUN")

    result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    (out_dir / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "findings.md").write_text(render_findings_md(result), encoding="utf-8")
    (out_dir / "interpret_prompt.md").write_text(render_prompt(result, tf_dir), encoding="utf-8")
    log(f"결과: {out_dir}  (findings.md · summary.json · interpret_prompt.md{' · plan.json' if (out_dir / 'plan.json').exists() else ''})")
    return result


def _step_error(v: Any) -> str:
    """StepOutput 의 오류 문장: error 가 있으면 그것, 아니면 명령의 stderr/stdout."""
    r = getattr(v, "result", None)
    text = getattr(v, "error", "") or (getattr(r, "stderr", "") if r else "") or (getattr(r, "stdout", "") if r else "")
    return (text or "")[:1500]


def _template_dir(root: Path) -> Optional[Path]:
    if os.environ.get("IACPATCH_NO_CACHE", "") in ("1", "true", "True"):
        return None
    return root / "data" / "cache" / "tf-template"


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(p)


def render_findings_md(res: Dict[str, Any]) -> str:
    L: List[str] = []
    L.append(f"# 아키텍처 점검 결과 — `{res['tf_dir']}` ({res['scan_id']})")
    L.append("")
    t_tf = res["tools"].get("terraform", {})
    t_tv = res["tools"].get("trivy", {})
    L.append(f"- 도구: terraform = {t_tf.get('kind') or '없음'} {t_tf.get('version') or ''} · trivy = {t_tv.get('version') or '없음'}")
    L.append(f"- 파일 {len(res['files'])}개, 리소스 블록 {sum(len(f['resources']) for f in res['files'])}개")
    pl = res.get("plan", {})
    if pl.get("status") == "PASS":
        L.append(f"- 오프라인 plan: 통과 — 리소스 {pl['resource_count']}개 (actions {pl['actions']})")
    elif pl.get("status") == "FAIL":
        bad = [k for k, v in pl.get("steps", {}).items() if not v.get("ok")]
        L.append(f"- 오프라인 plan: **실패** 단계 {bad}")
    else:
        L.append("- 오프라인 plan: NOT_RUN (terraform 없음)")
    sc = res.get("scan", {})
    if sc.get("status") == "PASS":
        L.append(f"- Trivy {sc.get('trivy_version')}: 검사 {sc['checks_executed']}개 실행, finding {sc['failures']}개 — {sc['by_severity']}"
                 + (f" · **파싱 실패 {len(sc['parse_errors'])}건 (그 파일은 검사 안 됨)**" if sc.get("parse_errors") else ""))
    elif sc.get("status") == "ERROR":
        L.append(f"- Trivy: **오류** {sc.get('error', '')[:200]}")
    else:
        L.append("- Trivy: NOT_RUN")
    L.append("")
    L.append("## 파일별 리소스")
    L.append("")
    L.append("| 파일 | 줄 | 리소스 |")
    L.append("|---|---:|---|")
    for f in res["files"]:
        L.append(f"| `{f['name']}` | {f['lines']} | {', '.join('`' + r + '`' for r in f['resources']) or '—'} |")
    L.append("")
    rows = res.get("findings") or []
    L.append(f"## Finding {len(rows)}개 (심각도순)")
    L.append("")
    if not rows and sc.get("status") == "PASS":
        L.append("finding 없음 (검사는 실행됨).")
    elif rows:
        L.append("| # | 심각도 | 룰 | 리소스 | 위치 | 제목 | CIS 대응(매핑표) | 파이프라인 |")
        L.append("|---:|---|---|---|---|---|---|---|")
        for i, r in enumerate(rows, 1):
            cis = r["cis"]
            if cis["in_table"] and cis["items"]:
                cis_s = "; ".join(f"{it['benchmark'].replace('CIS AWS Foundations Benchmark ', '')} {it['section']}" for it in cis["items"][:3])
                cis_s = f"{cis['level']}: {cis_s}"
            elif cis["in_table"]:
                cis_s = cis["level"]
            else:
                cis_s = "매핑표에 없음"
            L.append(f"| {i} | {r['severity']} | `{r['rule_id']}` | `{r['resource']}` | `{r['file']}:{r['line']}` | {r['title']} | {cis_s} | {r['scope']} |")
        L.append("")
        L.append("## Finding 상세")
        L.append("")
        for i, r in enumerate(rows, 1):
            L.append(f"### {i}. `{r['rule_id']}` {r['severity']} — `{r['resource']}` (`{r['file']}:{r['line']}`)")
            L.append("")
            L.append(f"- Trivy 메시지: {r['message']}")
            if r.get("resolution"):
                L.append(f"- Trivy 권고: {r['resolution']}")
            cis = r["cis"]
            if cis["in_table"]:
                L.append(f"- CIS 대응(매핑표 `policy/cis_mapping.json`): {cis['level']}" + (f" — {cis['status']}" if cis.get("status") else ""))
                for it in cis["items"]:
                    L.append(f"  - {it['benchmark']} {it['section']} {it['title']} (출처 {it['source']}, 검증 {'됨' if it['verified'] else '안 됨'})")
            else:
                L.append("- CIS 대응: 매핑표에 없는 룰 — 사람이 확인해 표에 넣기 전까지 '대응 미상'")
            L.append(f"- 파이프라인: {r['scope']}")
            for ref in r.get("references") or []:
                L.append(f"- 참고: {ref}")
            L.append("")
    if sc.get("parse_errors"):
        L.append("## 파싱 실패 (검사되지 않은 파일)")
        L.append("")
        for e in sc["parse_errors"]:
            L.append(f"- {e}")
        L.append("")
    L.append("## AI 해석")
    L.append("")
    L.append("아직 없음. `interpret_prompt.md` 를 Claude Code 새 세션에 붙여 넣고, 응답 JSON 을 `scripts/arch_interpret_add.py <이 폴더> <응답.json>` 으로 등록하면 여기에 채워진다.")
    L.append("")
    return "\n".join(L)


# 예시는 **이 아키텍처와 무관한 가상의 finding** 으로 적는다 — 예시가 답(어느 finding 이 의도적인지, Trivy 가 못 잡는 것이 무엇인지)을 흘리면 해석 실험이 아니다.
INTERPRETATION_SCHEMA = {
    "schema": "iacpatch-arch-interpretation-v1",
    "scan_id": "20261002-120000",
    "model": "Claude (화면에 보이는 모델 이름)",
    "findings": [
        {
            "rule_id": "AVD-AWS-0124",
            "resource": "aws_security_group.example",
            "file": "main.tf",
            "line": 12,
            "what": "ingress 규칙에 description 이 없어 어떤 용도의 허용인지 코드만 보고 알 수 없다.",
            "why_risky": "검토자가 규칙의 목적을 확인할 수 없어 불필요한 허용이 남아도 알아채기 어렵다.",
            "attack_path": None,
            "intended_or_incidental": "incidental",
            "fix": "main.tf 의 해당 ingress 블록에 description = \"<용도>\" 를 추가한다.",
            "fix_risk": "LOW",
            "cis_section": None,
            "confidence_note": "위생 규칙이라 직접적인 공격 경로는 없다.",
        }
    ],
    "not_flagged_but_risky": [
        {"resource": "aws_db_instance.example", "file": "main.tf", "line": 40,
         "what": "(예시) publicly_accessible = true 인데 스캐너 목록에 없다면 여기에 적는다. 없으면 빈 리스트."}
    ],
    "summary": {"fix_order": ["AVD-AWS-0124@aws_security_group.example"], "overall": "세 문장 이내 총평."},
}

FIELD_DOCS = [
    ("schema", "고정 문자열 `iacpatch-arch-interpretation-v1`"),
    ("scan_id", "위 '스캔 정보' 의 scan_id 그대로"),
    ("model", "응답을 만든 모델 이름(화면 표시 그대로)"),
    ("findings[].rule_id / resource / file / line", "Trivy 표의 값을 **그대로 복사** (표에 없는 finding 금지, 표의 finding 누락 금지)"),
    ("findings[].what", "무엇이 잘못됐는지 한두 문장. 설정값(속성 이름·값)을 인용"),
    ("findings[].why_risky", "이 설정이 그대로 배포되면 생기는 일"),
    ("findings[].attack_path", "공격자가 이용하는 경로. 모르면 null"),
    ("findings[].intended_or_incidental", "`intended`(이 코드의 설계상 들어간 설정) / `incidental`(기본값을 스캐너가 잡은 것) / `unknown` 중 **하나만**"),
    ("findings[].fix", "Terraform 에서 어떻게 고치는지 — 파일·속성 이름까지"),
    ("findings[].fix_risk", "`LOW` / `MEDIUM` / `HIGH` 중 **하나만** — 고치면 정상 기능이 깨질 가능성"),
    ("findings[].cis_section", "CIS AWS Foundations Benchmark 항목 번호(예: \"5.2\"). 확실하지 않으면 null"),
    ("findings[].confidence_note", "근거가 약한 부분. 없으면 null"),
    ("not_flagged_but_risky[]", "Trivy 가 잡지 않았지만 위험하다고 보는 설정 (없으면 빈 리스트)"),
    ("summary.fix_order", "`rule_id@resource` 를 고칠 순서대로"),
    ("summary.overall", "세 문장 이내 총평"),
]


def render_prompt(res: Dict[str, Any], tf_dir: Path) -> str:
    rows = res.get("findings") or []
    L: List[str] = []
    L.append("다음은 AWS 인프라를 정의한 Terraform 코드와, 그 코드를 Trivy(`trivy config`)로 점검한 결과다.")
    L.append("너는 보안 검토자다. 각 finding 이 **무슨 뜻인지, 왜 위험한지, 어떻게 고치는지** 를 해석해서 아래 JSON 스키마 그대로 **JSON 하나만** 출력해라.")
    L.append("")
    L.append("규칙:")
    L.append("- 파일을 수정하지 말고, 새 리소스를 제안할 때도 코드 파일을 만들지 마라. 출력은 JSON 하나다.")
    L.append("- finding 목록은 아래 표가 전부다. 표에 없는 finding 을 지어내지 말고, 표의 finding 을 빼지 마라 (rule_id·resource·file·line 을 그대로 복사).")
    L.append("- 근거는 반드시 파일 이름과 줄 번호로 적어라. 확실하지 않은 것은 null 로 두거나 confidence_note 에 적어라.")
    L.append("- CIS 항목 번호는 아는 경우에만 적어라. 모르면 null. (등록 스크립트가 팀 매핑표와 대조한다.)")
    L.append("- 'vulnerability(CVE)' 가 아니라 'misconfiguration(설정 오류)' 다. 용어를 섞지 마라.")
    L.append("")
    L.append("## 스캔 정보")
    L.append("")
    L.append(f"- scan_id: `{res['scan_id']}`")
    L.append(f"- 대상 폴더: `{res['tf_dir']}`")
    sc = res.get("scan", {})
    if sc.get("status") == "PASS":
        L.append(f"- Trivy {sc.get('trivy_version')}: 검사 {sc['checks_executed']}개, finding {sc['failures']}개")
    pl = res.get("plan", {})
    if pl.get("status") == "PASS":
        L.append(f"- 오프라인 plan: 리소스 {pl['resource_count']}개 — {json.dumps(pl['by_type'], ensure_ascii=False)}")
    L.append("")
    L.append("## Trivy finding 목록")
    L.append("")
    L.append("| rule_id | severity | resource | file | line | title | Trivy message |")
    L.append("|---|---|---|---|---:|---|---|")
    for r in rows:
        L.append(f"| {r['rule_id']} | {r['severity']} | {r['resource']} | {r['file']} | {r['line']} | {r['title']} | {r['message']} |")
    L.append("")
    L.append("## Terraform 파일 전체")
    L.append("")
    for f in res["files"]:
        p = Path(tf_dir) / f["name"]
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        L.append(f"### {f['name']}")
        L.append("")
        L.append("```hcl")
        L.append(text.rstrip("\n"))
        L.append("```")
        L.append("")
    L.append("## 출력 형식 — 아래 예시와 같은 구조의 JSON 하나 (예시 값은 형식을 보여 주는 것이고, 내용은 네가 분석한 것으로 채운다)")
    L.append("")
    L.append("```json")
    L.append(json.dumps(INTERPRETATION_SCHEMA, ensure_ascii=False, indent=2))
    L.append("```")
    L.append("")
    L.append("필드 설명:")
    L.append("")
    for k, v in FIELD_DOCS:
        L.append(f"- `{k}`: {v}")
    L.append("")
    L.append(f"Claude Code 안에서 돌고 있다면 결과를 `data/arch/{res['scan_id']}/response.json` 파일로 저장해도 된다 (다른 파일은 만들거나 고치지 마라). "
             "그러면 등록은 `python scripts/arch_interpret_add.py data/arch/" + str(res['scan_id']) + " data/arch/" + str(res['scan_id']) + "/response.json` 이다.")
    L.append("")
    return "\n".join(L)
