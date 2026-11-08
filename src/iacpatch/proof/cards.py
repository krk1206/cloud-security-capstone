"""기록 폴더 → 검사 단계별 증거 카드.

카드 한 장 = 한 단계(V1~V6, 배포 후 V7·V8).
  method   탐지 방식: 실제로 실행한 명령(commands.json 그대로)과 비교·계산 순서
  evidence 증거: 도구 원본 출력에서 꺼낸 값, 코드 줄
  basis    근거: 외부 기준 항목(확인 상태 포함) / 팀 요구사항 / 도구 정보 / 교차 확인
  reason   판정 이유 (기록의 판정 값 + 증거에서 만든 한 줄)
  limits   이 단계가 못 보는 것
  leaves   근거 파일: 이 단계가 남긴 파일과 해시
  key      증거 블록마다 '처음부터 펼쳐 보일 것' 표시 (proof/primary.py — 값은 바꾸지 않음)

판정은 기록(verification.json)에 있는 값만 쓴다. 이 모듈은 판정을 새로 내리지 않는다 (교차 확인 값은 따로 표시).
기록이 아직 덜 만들어졌으면(검사 중) 그 단계는 status='pending'.
"""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..evidence_log import load_commands, sha256_file
from ..tools.trivy import parse_findings, scan_summary
from . import hcl_lines, plain, primary, recheck, standards

VKO = {"PASS": "통과", "FAIL": "실패", "WARN": "통과(경고)", "UNKNOWN": "판정 불가", "NOT_RUN": "미실행", "SKIPPED": "건너뜀", "ERROR": "오류"}
LAYER_NAMES = {
    # 첫 칸: 화면 이름 = 사용자가 묻는 질문 (교수 피드백 2026-10-31). 둘째 칸: 무엇으로 어떻게 확인하나
    "V1": ("기존 보안 문제가 해결됐나요?", "원본에서 Trivy 가 찾은 보안 설정 오류가 수정 후 코드에서 없어졌는가 (Trivy 재검사)"),
    "V2": ("수정하면서 새로운 문제가 생겼나요?", "수정 후 코드에서 Trivy 가 새로 찾은 보안 문제가 있는가 (HIGH 이상이면 실패)"),
    "V3": ("Terraform 코드가 올바르게 작성됐나요?", "구문 · 속성 이름 · 리소스 참조가 유효한가 (terraform validate)"),
    "V4": ("이 코드를 실행하면 무엇이 변경되나요?", "terraform plan 으로 변경 예정 사항을 계산할 수 있는가 (AWS 에 적용하지 않음)"),
    "V5": ("허용하지 않은 부분까지 수정했나요?", "팀 정책이 허용한 리소스 · 속성만 바꿨는가 · 교체 · 삭제가 없는가"),
    "V6": ("고객이 원하는 통신 구조를 유지하나요?", "보안 그룹 인바운드 규칙이 허용하는 통신이 고객 설계도와 같은가 (규칙 기준 — 실제 연결은 V8)"),
    "V7": ("실제 AWS에도 예상대로 적용됐나요?", "AWS 에 실제 적용된 보안 그룹 규칙이 고객 설계도와 같은가 (AWS 조회)"),
    "V8": ("실제 연결과 차단이 정상적으로 동작하나요?", "시험 환경에서 허용 경로는 접속 성공, 막아야 할 경로는 차단되는가 (통신 시험)"),
}
# 확인 방법 한 줄 — 화면에서 판정 바로 아래에 보인다 (자세한 순서·명령은 '자세히' 안)
HOW = {
    "V1": "원본·수정 후 코드를 각각 trivy config 로 검사하고, 동일 탐지 키(규칙·파일·리소스)의 잔존 여부 비교",
    "V2": "V1 의 수정 전·후 Trivy 결과 비교 — 수정 후에만 있는 탐지를 신규 탐지로 분류 (HIGH 이상이면 실패, 그 미만은 경고)",
    "V3": "terraform validate 로 후보 코드의 구문·속성 이름·참조 검사 (AWS 접속 없음)",
    "V4": "terraform plan 으로 실행 계획 생성 (가짜 자격 증명 — AWS 접속 없음, 실제 적용 결과 아님)",
    "V5": "수정 전·후 실행 계획을 비교해 변경 리소스·속성을 추출하고, 팀 정책의 변경 허용 목록과 대조",
    "V6": "실행 계획의 보안 그룹 규칙으로 허용 통신을 모두 계산하고, 설계 기준 통신 9개와 비교",
    "V7": "AWS 에서 보안 그룹 규칙을 직접 조회(읽기 전용)해 V6 와 같은 방법으로 설계 기준과 비교",
    "V8": "시험 환경 내부 측정 지점 5곳에서 실제 접속을 시도하고, 결과를 EC2 콘솔 출력으로 수집",
}
# Trivy 규칙 → 화면용 이름 (판정에는 쓰지 않음)
RULE_PLAIN = {"AVD-AWS-0107": "SSH·RDP 전체 IP 허용", "AVD-AWS-0104": "아웃바운드 전체 IP 허용",
              "AVD-AWS-0124": "보안 그룹 규칙 설명 누락", "AVD-AWS-0099": "보안 그룹 설명 누락"}


# ----------------------------------------------------------------------------- 읽기 도우미
def _j(p: Path) -> Optional[Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _t(p: Path, limit: int = 400_000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


class Ctx:
    def __init__(self, record_dir: Path, repo_root: Optional[Path] = None):
        self.d = Path(record_dir).resolve()
        self.root = Path(repo_root).resolve() if repo_root else None
        self.lv = self.d / "local_verify"
        self.state = _j(self.d / "state.json") or {}
        self.ver = _j(self.d / "verification.json")
        self.layers = {l.get("layer"): l for l in (((self.ver or {}).get("report") or {}).get("layers") or [])}
        lvv: Dict[str, Any] = {}
        if not self.layers:
            lvv = _j(self.lv / "verification.json") or _j(self.lv / "layers_progress.json") or {}
            self.layers = {l.get("layer"): l for l in (lvv.get("layers") or [])}
            self.partial = True
        else:
            self.partial = False
        self.cmds = load_commands(self.lv / "commands.json")
        self.tools = _j(self.lv / "tools.json") or lvv.get("tools") or {}
        self.finding = _j(self.d / "input" / "selected_finding.json") or {}
        self.manifest = {f["path"]: f for f in ((_j(self.d / "evidence" / "manifest.json") or {}).get("files") or [])}
        self.original = {p.name: _t(p) for p in sorted((self.d / "original").glob("*.tf"))}
        self.candidate = {p.name: _t(p) for p in sorted((self.d / "candidate").glob("*.tf"))}
        self.sources = dict(self.original)
        self.sources.update(self.candidate)

    def rel(self, s: Optional[str]) -> str:
        if not s:
            return ""
        out = str(s)
        for base, label in ((self.d, "<기록>"), (self.root, "<저장소>")):
            if base is None or len(str(base)) < 4:
                continue
            forms = {str(base), str(base).replace("\\", "/"), str(base).replace("/", "\\")}
            for form in sorted(forms, key=len, reverse=True):
                out = out.replace(form, label)
        return out

    def leaf(self, rel: str) -> Optional[Dict[str, Any]]:
        p = self.d / rel
        if not p.exists():
            return None
        m = self.manifest.get(rel)
        return {"path": rel, "bytes": p.stat().st_size, "sha256": (m or {}).get("sha256") or sha256_file(p)}

    def leaves(self, rels: List[str]) -> List[Dict[str, Any]]:
        return [x for x in (self.leaf(r) for r in rels) if x]


def _cmd_view(ctx: Ctx, c: Dict[str, Any]) -> Dict[str, Any]:
    argv = c.get("argv") or []
    shown = []
    for i, a in enumerate(argv):
        a = ctx.rel(a)
        if i == 0:
            a = re.split(r"[\\/]", a)[-1]
        shown.append(a)
    return {"step": c.get("step"), "cmd": " ".join(shown) if shown else None, "cwd": ctx.rel(c.get("cwd")), "started_at": c.get("started_at"),
            "elapsed_s": c.get("elapsed_s"), "returncode": c.get("returncode"), "ok": c.get("ok"), "cached": c.get("cached"),
            "cache_created_at": c.get("cache_created_at"), "output": c.get("output"), "output_sha256": c.get("output_sha256"),
            "note": plain.legacy(c.get("note") or ""), "stdout_tail": ctx.rel(c.get("stdout_tail") or "")[-700:], "stderr_tail": ctx.rel(c.get("stderr_tail") or "")[-500:]}


def _cmds(ctx: Ctx, prefixes: Tuple[str, ...]) -> List[Dict[str, Any]]:
    return [_cmd_view(ctx, c) for c in ctx.cmds if str(c.get("step", "")).startswith(prefixes)]


def _base(layer: str, ctx: Ctx) -> Dict[str, Any]:
    name, q = LAYER_NAMES[layer]
    l = ctx.layers.get(layer) or {}
    v = l.get("verdict")
    return {"layer": layer, "name": name, "question": q, "how": HOW.get(layer, ""), "verdict": v, "verdict_ko": VKO.get(str(v), v) if v else None,
            "summary": "", "record_summary": l.get("summary") or "", "status": "done" if v else "pending",
            "method": {"steps": [], "commands": []}, "evidence": [], "basis": {"standard": [], "team": [], "tool": [], "cross": []},
            "reason": "", "limits": [], "leaves": []}


def _code_block(title: str, fname: str, text: str, start: int, end: int, marks: Tuple[int, ...] = (), tone: str = "") -> Dict[str, Any]:
    return {"t": "code", "title": title, "file": fname, "tone": tone, "lines": hcl_lines.excerpt(text, start, end, 0, marks)}


def _changed_lines(a: str, b: str) -> Tuple[List[int], List[int]]:
    """원본 a 와 후보 b 의 바뀐 줄 번호 (a 쪽, b 쪽)."""
    A, B = a.replace("\r", "").split("\n"), b.replace("\r", "").split("\n")
    ra: List[int] = []
    rb: List[int] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=A, b=B, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        ra.extend(range(i1 + 1, i2 + 1))
        rb.extend(range(j1 + 1, j2 + 1))
    return ra, rb


# ----------------------------------------------------------------------------- V1
def card_v1(ctx: Ctx) -> Dict[str, Any]:
    c = _base("V1", ctx)
    f = ctx.finding
    rule, fname, res = f.get("rule_id", ""), f.get("filename", ""), f.get("resource", "")
    key = f"{rule} | {fname} | {res}"
    c["method"]["steps"] = ["원본 폴더와 후보 폴더를 각각 trivy config 로 검사", "비교 키 = 규칙 ID | 파일 | 리소스 (행 번호는 수정으로 바뀌므로 제외)",
                            "후보 결과에 같은 키가 없으면 통과, 있으면 실패"]
    c["method"]["commands"] = _cmds(ctx, ("trivy:",))
    before_p, after_p = ctx.lv / "trivy_before.json", ctx.lv / "trivy_after.json"
    before, after = _j(before_p), _j(after_p)
    c["evidence"].append({"t": "kv", "title": "비교 키", "rows": [["대상", key], ["심각도", f.get("severity", "")], ["제목", f.get("title", "")]]})
    old_lines: List[Dict[str, Any]] = []
    new_lines: List[Dict[str, Any]] = []
    if before:
        bf = [x for x in parse_findings(before) if x.key == f"{rule}|{fname}|{res}"]
        if bf:
            b = bf[0]
            c["evidence"].append({"t": "kv", "title": "수정 전 결과 (trivy_before.json)", "tone": "bad",
                                  "rows": [["결과", "FAIL — 탐지됨"], ["위치", f"{b.filename} {b.start_line}행"], ["메시지", b.message]]})
            src = ctx.original.get(fname, "")
            if src:
                blk = hcl_lines.resource_blocks(src).get(res)
                s0, e0 = (blk if blk else (max(1, b.start_line - 4), b.end_line + 2))
                s0, e0 = max(s0, b.start_line - 6), min(e0, b.end_line + 2)
                c["evidence"].append(_code_block("수정 전 코드 — Trivy 탐지 행", fname, src, s0, e0, tuple(range(b.start_line, b.end_line + 1)), "before"))
                sl = src.replace("\r", "").split("\n")
                old_lines = [{"n": n, "text": sl[n - 1]} for n in range(b.start_line, min(b.end_line, b.start_line + 7) + 1) if 0 < n <= len(sl)]
    if after:
        af = [x for x in parse_findings(after) if x.key == f"{rule}|{fname}|{res}"]
        recs = _rule_records(after, rule)
        summ = scan_summary(after)
        c["evidence"].append({"t": "kv", "title": "수정 후 결과 (trivy_after.json)", "tone": "bad" if af else "good",
                              "rows": [["결과", "FAIL — 동일 키 잔존" if af else "동일 키 없음 (해소)"],
                                       [f"{rule} 실행 기록", f"실패 {recs.get('FAIL', 0)}건 · 통과 {recs.get('PASS', 0)}건 (규칙 실행 확인)"],
                                       ["실행된 규칙 수", str(summ.get("checks_executed"))]]})
        csrc, osrc = ctx.candidate.get(fname, ""), ctx.original.get(fname, "")
        if csrc and osrc:
            _, rb = _changed_lines(osrc, csrc)
            blk = hcl_lines.resource_blocks(csrc).get(res)
            if blk:
                marks = tuple(n for n in rb if blk[0] <= n <= blk[1])
                if marks:
                    s0, e0 = max(blk[0], min(marks) - 5), min(blk[1], max(marks) + 1)
                    c["evidence"].append(_code_block("수정 후 코드 — 변경 행", fname, csrc, s0, e0, marks, "after"))
                    cl = csrc.replace("\r", "").split("\n")
                    new_lines = [{"n": n, "text": cl[n - 1]} for n in marks[:8] if 0 < n <= len(cl)]
    if old_lines or new_lines:
        # 화면 핵심: 탐지 행(수정 전)과 변경 행(수정 후)만 두세 줄로
        c["evidence"].insert(0, {"t": "diffline", "title": "변경 행", "file": fname, "old": old_lines, "new": new_lines})
    meta = standards.for_rule(rule)
    c["basis"]["standard"] = meta.get("external", [])
    tr = meta.get("trivy") or {}
    if tr:
        fw = "; ".join(f"{k}: {', '.join(v)}" for k, v in (tr.get("frameworks") or {}).items()) or "없음"
        c["basis"]["tool"].append({"k": "Trivy 규칙 정의", "v": f"{rule} · {tr.get('severity')} · {tr.get('title')}"})
        c["basis"]["tool"].append({"k": "Trivy 규칙의 기준 태그", "v": fw + " (Trivy 표기 — 최신 CIS 번호와 동일하다고 가정하지 않음)"})
    t = ctx.tools.get("trivy") or {}
    if t:
        c["basis"]["tool"].append({"k": "도구", "v": f"trivy {t.get('version', '')} · 규칙 묶음 {'내장 (갱신 안 함)' if t.get('skip_check_update') else '최신 다운로드'}"})
    c["basis"]["tool"].append({"k": "Trivy 로그의 'Falling back to embedded checks'",
                               "v": "규칙 묶음을 내려받지 않고 바이너리 내장 규칙을 사용한다는 의미 (--skip-check-update 고정 설정). 로그 등급은 ERROR 로 표시되나 검사는 정상 실행"})
    l = ctx.layers.get("V1") or {}
    what = f"{plain.server(res, ctx.root)}: {RULE_PLAIN.get(rule, f.get('title') or rule)} ({rule})"
    if l.get("verdict") == "PASS":
        c["summary"] = f"해소 — 수정 후 코드에서 '{what}' 미탐지"
    elif l.get("verdict") == "FAIL":
        c["summary"] = f"미해소 — 수정 후 코드에서도 '{what}' 탐지"
    if l.get("verdict") == "PASS":
        c["reason"] = f"후보 결과에 '{key}' 없음. 해당 규칙은 이번 재검사에서 실행됨."
    elif l.get("verdict") == "FAIL":
        c["reason"] = f"후보 결과에 '{key}' 잔존."
    else:
        c["reason"] = plain.legacy(l.get("summary") or "")
    c["limits"] = ["같은 의미를 다르게 표기한 설정은 탐지하지 못함 (예: 0.0.0.0/0 을 0.0.0.0/1 + 128.0.0.0/1 로 분할 — 사전 실험 01-cidr-split)",
                   "Trivy 규칙에 없는 문제는 검사 대상 아님 (예: 웹 서버 → MySQL 직접 연결)"]
    c["leaves"] = ctx.leaves(["local_verify/trivy_before.json", "local_verify/trivy_after.json", "local_verify/commands.json", "input/selected_finding.json"])
    return c


def _res_label(addr: Any, root: Optional[Path]) -> str:
    """리소스 주소 → 화면 이름. 보안 그룹이면 'Bastion 보안 그룹', 아니면 주소 그대로."""
    a = str(addr or "")
    return plain.sg(a, root) if a.startswith("aws_security_group.") else a


def _rule_records(report: Dict[str, Any], rule_id: str) -> Dict[str, int]:
    out = {"FAIL": 0, "PASS": 0}
    short = rule_id.replace("AVD-", "")
    for r in report.get("Results") or []:
        for m in r.get("Misconfigurations") or []:
            if str(m.get("AVDID") or m.get("ID") or "") in (rule_id, short):
                st = str(m.get("Status") or "FAIL")
                out[st] = out.get(st, 0) + 1
    return out


# ----------------------------------------------------------------------------- V2
def card_v2(ctx: Ctx) -> Dict[str, Any]:
    c = _base("V2", ctx)
    d = (ctx.layers.get("V2") or {}).get("details") or {}
    pol = _j(ctx.root / "policy" / "patch_policy.json") if ctx.root else None
    block = d.get("block_severities") or (pol or {}).get("v2_block_severities") or ["CRITICAL", "HIGH"]
    c["method"]["steps"] = ["V1 결과 파일 2개(trivy_before.json · trivy_after.json) 재비교 — 추가 실행 없음",
                            "비교 키 집합: 후보에만 있는 키 = 신규 탐지, 원본에만 있는 키 = 해소",
                            f"신규 탐지 심각도가 {' · '.join(block)} 이면 실패, 그 미만이면 경고"]
    c["method"]["commands"] = [{"step": "compare", "cmd": None, "note": "명령 실행 없음 — 결과 파일 2개 비교"}]
    if d:
        c["evidence"].append({"t": "kv", "title": "키 집합 비교", "rows": [["수정 전 탐지", f"{d.get('before_count')}건"], ["수정 후 탐지", f"{d.get('after_count')}건"],
                                                                     ["신규 탐지", f"{len(d.get('new') or [])}건"], ["해소", f"{len(d.get('resolved') or [])}건"]]})
        def frow(x: Dict[str, Any]) -> List[Any]:
            rid = str(x.get("rule_id") or "")
            return [rid + (f" ({RULE_PLAIN[rid]})" if rid in RULE_PLAIN else ""), x.get("severity"), _res_label(x.get("resource"), ctx.root),
                    f"{x.get('filename')} {x.get('start_line')}행"]
        c["evidence"].append({"t": "table", "title": "신규 탐지", "head": ["규칙", "심각도", "대상", "위치"], "rows": [frow(x) for x in (d.get("new") or [])],
                              "empty": "없음 — 수정 후에만 나타난 탐지 없음"})
        c["evidence"].append({"t": "table", "title": "해소된 탐지", "head": ["규칙", "심각도", "대상", "위치 (수정 전)"], "rows": [frow(x) for x in (d.get("resolved") or [])],
                              "empty": "없음"})
        left = d.get("after_count")
        if left:
            c["evidence"].append({"t": "note", "text": f"수정 후 남은 탐지 {left}건은 원본에도 있던 항목 (이번 수정 대상 외) — 신규 탐지 아님."})
        if d.get("possibly_moved"):
            c["evidence"].append({"t": "note", "text": "같은 규칙이 다른 리소스 키로 이동한 것으로 보이는 탐지: " +
                                  ", ".join(f"{m['rule']} {m['from']} → {m['to']}" for m in d["possibly_moved"])})
    c["basis"]["team"].append({"k": "차단 심각도", "v": f"{', '.join(block)} — 팀 정책 policy/patch_policy.json (v2_block_severities)"})
    c["basis"]["tool"].append({"k": "심각도 출처", "v": "Trivy 규칙 정의의 severity 값"})
    l = ctx.layers.get("V2") or {}
    n_new = len(d.get("new") or [])
    if d and l.get("verdict") in ("PASS", "WARN", "FAIL"):
        n_res = len(d.get("resolved") or [])
        c["summary"] = (f"신규 탐지 0건 · 해소 {n_res}건" if l.get("verdict") == "PASS" else
                        f"신규 탐지 {n_new}건 — 모두 HIGH 미만 (경고) · 해소 {n_res}건" if l.get("verdict") == "WARN" else
                        f"신규 탐지 {n_new}건 — HIGH 이상 포함 (실패) · 해소 {n_res}건")
    c["reason"] = ("신규 탐지 없음." if l.get("verdict") == "PASS" else
                   f"신규 탐지 {n_new}건 중 차단 심각도 포함." if l.get("verdict") == "FAIL" else
                   f"신규 탐지 {n_new}건 — 모두 차단 심각도 미만 (경고)." if l.get("verdict") == "WARN" else plain.legacy(l.get("summary") or ""))
    c["limits"] = ["Trivy 규칙에 없는 신규 문제는 탐지하지 못함", "MEDIUM·LOW 신규 탐지는 차단하지 않음 (경고)"]
    c["leaves"] = ctx.leaves(["local_verify/trivy_before.json", "local_verify/trivy_after.json"])
    return c


# ----------------------------------------------------------------------------- V3
def card_v3(ctx: Ctx) -> Dict[str, Any]:
    c = _base("V3", ctx)
    tf = ctx.tools.get("terraform") or {}
    c["method"]["steps"] = ["후보 폴더 복사본에서 terraform init (공급자 플러그인 준비, 백엔드 미사용)",
                            "terraform validate -json — 속성 이름·값 형식·리소스 참조를 aws 공급자 스키마로 확인"]
    c["method"]["commands"] = _cmds(ctx, ("candidate:init", "candidate:fmt", "candidate:validate"))
    vj = _j(ctx.lv / "validate_candidate.json")
    if vj is not None:
        ok = bool(vj.get("valid"))
        diags = vj.get("diagnostics") or []
        first = next((f"{x.get('summary') or ''} {x.get('detail') or ''}" for x in diags if x.get("severity") == "error"), "")
        rows = [["결과", "유효 (valid = true)" if ok else "유효하지 않음 (valid = false)"], ["오류", f"{vj.get('error_count')}개"], ["경고", f"{vj.get('warning_count')}개"]]
        c["summary"] = (f"유효 — 오류 {vj.get('error_count')}개 · 경고 {vj.get('warning_count')}개 (valid = true)" if ok else
                        f"유효하지 않음 — 오류 {vj.get('error_count')}개" + (f": {plain.tf_error_ko(first)}" if first.strip() else ""))
        c["evidence"].append({"t": "kv", "title": "validate 결과 (validate_candidate.json)", "tone": "good" if ok else "bad", "rows": rows})
        if diags:
            sev = {"error": "오류", "warning": "경고"}
            c["evidence"].append({"t": "table", "title": "오류 내용 (terraform 출력 원문)", "head": ["종류", "내용", "위치"],
                                  "rows": [[sev.get(str(x.get("severity")), x.get("severity")), (x.get("summary") or "") + " — " + (x.get("detail") or "")[:160],
                                            f"{((x.get('range') or {}).get('filename') or '')} {(((x.get('range') or {}).get('start') or {}).get('line') or '')}행"] for x in diags[:8]]})
    lv3 = ctx.layers.get("V3") or {}
    if not c["summary"] and lv3.get("verdict") == "PASS":
        c["summary"] = "유효 — terraform validate 오류 없음"
    elif not c["summary"] and lv3.get("verdict") == "FAIL":
        c["summary"] = "유효하지 않음 — " + (plain.tf_error_ko(lv3.get("summary")) or "구문 오류")
    ov = ctx.lv / "work" / "candidate" / "zz_iacpatch_offline_override.tf"
    if ov.exists():
        txt = _t(ov)
        c["evidence"].append({"t": "code", "title": "오프라인 설정 (작업 복사본에만 추가 — 원본·후보 파일 변경 없음)", "file": ov.name, "tone": "",
                              "lines": hcl_lines.excerpt(txt, 1, len(txt.split("\n")))})
    if tf:
        c["basis"]["tool"].append({"k": "도구", "v": f"{tf.get('kind') or 'terraform'} {tf.get('version', '')}"})
        c["basis"]["tool"].append({"k": "aws 공급자", "v": f"{tf.get('aws_provider') or '?'} (고정값 {tf.get('aws_provider_pin') or '없음'})"})
        if tf.get("kind") == "opentofu":
            c["basis"]["tool"].append({"k": "주의", "v": "OpenTofu 로 실행 — 팀 PC 기준 도구는 Terraform 1.16.1"})
    c["basis"]["standard"].append({"org": "HashiCorp", "doc": "Terraform CLI", "item": "terraform validate",
                                   "text": "구성 파일의 문법·스키마·참조가 유효한지 확인 (원격 상태·AWS 접속 없음)", "status": "공식 도구"})
    l = ctx.layers.get("V3") or {}
    raw3 = " ".join(str(l.get("summary") or "").split())
    c["reason"] = ("validate 결과 valid=true." if l.get("verdict") == "PASS" else
                   (f"{plain.tf_error_ko(raw3)} (기록 원문: {raw3})" if l.get("verdict") == "FAIL" and raw3 else raw3))
    c["limits"] = ["값의 보안 적합성은 검사하지 않음 (0.0.0.0/0 도 형식상 유효)"]
    c["leaves"] = ctx.leaves(["local_verify/validate_candidate.json", "local_verify/commands.json"])
    return c


# ----------------------------------------------------------------------------- V4
def _plan_line(txt: str) -> str:
    for line in txt.splitlines():
        if line.strip().startswith(("Plan:", "No changes")):
            return line.strip()
    return ""


def card_v4(ctx: Ctx) -> Dict[str, Any]:
    c = _base("V4", ctx)
    c["method"]["steps"] = ["terraform plan -out=plan.bin (가짜 자격 증명 · AWS 접속 없음)", "terraform show -json plan.bin → plan_candidate.json"]
    c["method"]["commands"] = _cmds(ctx, ("candidate:plan", "candidate:show", "terraform:baseline", "baseline:"))
    line = _plan_line(_t(ctx.lv / "plan_candidate.txt"))
    pj = _j(ctx.lv / "plan_candidate.json")
    rows = []
    if line:
        rows.append(["terraform 출력", line])
    if pj:
        acts: Dict[str, int] = {}
        types: Dict[str, int] = {}
        for rc in pj.get("resource_changes") or []:
            a = "/".join((rc.get("change") or {}).get("actions") or [])
            acts[a] = acts.get(a, 0) + 1
            types[rc.get("type", "")] = types.get(rc.get("type", ""), 0) + 1
        if set(acts) == {"create"}:
            rows.append(["전부 생성(add)으로 표시되는 이유", "AWS 상태를 조회하지 않고 계산하므로 기존 리소스도 '생성'으로 표시됨. 실제 변경 내용은 V5 에서 원본 계획과 비교"])
        else:
            rows.append(["동작별 리소스 수", ", ".join(f"{k} {v}개" for k, v in sorted(acts.items()))])
        rows.append(["보안 그룹", f"{types.get('aws_security_group', 0)}개"])
    if rows:
        c["evidence"].append({"t": "kv", "title": "실행 계획 (plan_candidate.json)", "rows": rows})
    lv4 = ctx.layers.get("V4") or {}
    if pj and lv4.get("verdict") == "PASS":
        c["summary"] = f"실행 계획 생성 성공 — 리소스 {len(pj.get('resource_changes') or [])}개 (AWS 적용 결과 아님)"
    elif lv4.get("verdict") == "FAIL":
        raw = str(lv4.get("summary") or "")
        c["summary"] = "실행 계획 생성 실패 — " + (plain.tf_error_ko(raw) or "plan 오류")
        # terraform 오류 원문 (기록 그대로) — 요약 한 줄의 근거
        lines = [ln for ln in raw.replace("\r", "").split("\n")]
        while lines and not lines[-1].strip():
            lines.pop()
        if any(ln.strip() for ln in lines):
            c["evidence"].append({"t": "code", "title": "terraform 오류 출력 (원문)", "file": "plan_candidate.txt", "tone": "bad",
                                  "lines": [{"n": i + 1, "text": ln, "mark": False} for i, ln in enumerate(lines[:40])]})
    tf = ctx.tools.get("terraform") or {}
    if tf:
        c["basis"]["tool"].append({"k": "도구", "v": f"{tf.get('kind') or 'terraform'} {tf.get('version', '')} · aws 공급자 {tf.get('aws_provider') or '?'}"})
    c["basis"]["standard"].append({"org": "HashiCorp", "doc": "Terraform CLI", "item": "terraform plan / show -json",
                                   "text": "적용 전 예정 변경을 계산하고 JSON 으로 내보냄", "status": "공식 도구"})
    l = ctx.layers.get("V4") or {}
    raw4 = " ".join(str(l.get("summary") or "").split())
    c["reason"] = (("실행 계획 생성 성공. " + (line or "")) if l.get("verdict") == "PASS" else
                   (f"{plain.tf_error_ko(raw4)} (기록 원문: {raw4[:300]})" if l.get("verdict") == "FAIL" and raw4 else raw4))
    c["limits"] = ["plan 성공은 AWS 적용 성공을 의미하지 않음",
                   "실제 AWS 상태 기준 교체·삭제 여부는 확인 불가 → 실제 AWS 검사(시험 환경)에서 실제 상태 기준 plan 확인"]
    c["leaves"] = ctx.leaves(["local_verify/plan_candidate.json", "local_verify/plan_candidate.txt", "local_verify/plan_baseline.json"])
    return c


# ----------------------------------------------------------------------------- V5
def _sg_rule_strings(world: Any, sg: str, root: Optional[Path] = None) -> List[str]:
    """보안 그룹 규칙 → 한 줄씩. 예: '인바운드 · SSH 22 ← 0.0.0.0/0 (인터넷 전체)'."""
    m = world.security_groups.get(sg)
    if m is None:
        return []
    out = []
    for r in m.rules:
        srcs = [str(s.value) if s.kind != "self" else "자기 자신" for s in r.sources]
        way = "인바운드" if r.direction == "ingress" else "아웃바운드" if r.direction == "egress" else str(r.direction)
        arrow = "←" if r.direction == "ingress" else "→"
        out.append(f"{way} · {plain.port(r.protocol, r.from_port, r.to_port)} {arrow} {plain.sources(srcs, root)}")
    return out


ATTR_KO = {"ingress": "인바운드 규칙", "egress": "아웃바운드 규칙", "description": "설명", "tags": "태그", "tags_all": "태그(전체)", "name": "이름",
           "name_prefix": "이름 접두사", "vpc_id": "VPC", "revoke_rules_on_delete": "삭제 시 규칙 회수"}


def _attr_ko(a: Any) -> str:
    return ATTR_KO.get(str(a), str(a))


V5_SCOPE, V5_REPLACE = "허용 범위 밖 변경", "교체·삭제 위험"


def violation_kind(v: Any) -> str:
    """V5 위반 문장(영어) → 구분: 허용 범위 밖 변경(리소스 종류·속성·개수·공급자) / 교체·삭제 위험(계획의 삭제·교체·제거)."""
    t = str(v)
    return V5_REPLACE if t.startswith(("plan deletes ", "plan replaces ", "resource removed from configuration")) else V5_SCOPE


def violation_ko(v: Any, root: Optional[Path]) -> str:
    """V5 위반 문장(영어) → 화면 문장 (구분 · 내용). 모르는 형식이면 원문 그대로."""
    t = str(v)
    k = violation_kind(t)
    m = re.match(r"^(\d+) resources touched > max_changed_resources=(\d+)$", t)
    if m:
        return f"{k} · 한 번에 리소스 {m.group(1)}개 변경 — 팀 정책 한도 {m.group(2)}개"
    m = re.match(r"^(\S+): attributes changed outside allowlist: (.+)$", t)
    if m:
        attrs = [x.strip() for x in m.group(2).split(",")]
        extra = " (보안 그룹 이름 변경 시 AWS 에서 삭제 후 재생성 — 교체)" if "name" in attrs and m.group(1).startswith("aws_security_group.") else ""
        return f"{k} · {_res_label(m.group(1), root)}: 허용되지 않은 속성 변경 — {', '.join(_attr_ko(x) for x in attrs)}{extra}"
    m = re.match(r"^plan replaces \(destroy\+create\) (\S+)$", t)
    if m:
        return f"{k} · {_res_label(m.group(1), root)}: 교체 (삭제 후 재생성)"
    m = re.match(r"^plan deletes (\S+)$", t)
    if m:
        return f"{k} · {_res_label(m.group(1), root)}: 삭제"
    m = re.match(r"^resource removed from configuration: (\S+) \((.+)\)$", t)
    if m:
        return f"{k} · {_res_label(m.group(1), root)}: 구성에서 리소스 제거 ({m.group(2)})"
    m = re.match(r"^resource type changed for (\S+): (.+)$", t)
    if m:
        return f"{k} · {_res_label(m.group(1), root)}: 리소스 종류 변경 ({m.group(2)})"
    m = re.match(r"^new resource (\S+) of type (\S+) is not in allowed_create_resource_types$", t)
    if m:
        return f"{k} · {m.group(1)}: 생성 허용 목록에 없는 리소스 종류 ({m.group(2)})"
    m = re.match(r"^changed resource (\S+) of type (\S+) is not in allowed_change_resource_types$", t)
    if m:
        return f"{k} · {_res_label(m.group(1), root)}: 변경 허용 목록에 없는 리소스 종류 ({m.group(2)})"
    m = re.match(r"^provider configuration changed: (.+)$", t)
    if m:
        return f"{k} · 공급자(provider) 설정 변경 — {m.group(1)}"
    return t


def card_v5(ctx: Ctx) -> Dict[str, Any]:
    c = _base("V5", ctx)
    d = (ctx.layers.get("V5") or {}).get("details") or {}
    pol = (_j(ctx.root / "policy" / "patch_policy.json") if ctx.root else None) or {}
    c["method"]["steps"] = ["원본 계획(plan_baseline.json)과 후보 계획(plan_candidate.json)의 planned_values 를 리소스·속성 단위로 비교",
                            "팀 정책 policy/patch_policy.json 과 대조: 삭제·교체 금지, 변경 가능한 리소스 종류·속성, 한 번에 변경 가능한 리소스 수"]
    c["method"]["commands"] = [{"step": "compare", "cmd": None, "note": "명령 실행 없음 — 계획 파일 2개 비교"}]
    changed = d.get("changed") or {}
    allowed = pol.get("allowed_attribute_changes") or {}
    rows, tones, pol_rows = [], [], []
    for addr, attrs in changed.items():
        t = addr.split(".")[0]
        al = allowed.get(t)
        bad = [x for x in attrs if al is not None and x not in al]
        rows.append([_res_label(addr, ctx.root), ", ".join(_attr_ko(x) for x in attrs), "허용" if not bad else "허용 범위 밖 — " + ", ".join(_attr_ko(x) for x in bad)])
        tones.append("bad" if bad else "good")
        if al is not None and t not in [r[0] for r in pol_rows]:
            pol_rows.append([t, ", ".join(_attr_ko(x) for x in al)])
    c["evidence"].append({"t": "table", "title": "변경 위치", "head": ["리소스", "변경 속성", "판정"], "rows": rows, "tones": tones, "empty": "변경된 리소스 없음"})
    if pol_rows:
        c["evidence"].append({"t": "kv", "title": "팀 정책 — 리소스 종류별 변경 허용 속성 (policy/patch_policy.json)", "rows": pol_rows})
    try:
        from ..verify.plan_model import build_world, load_plan
        bp, cp = ctx.lv / "plan_baseline.json", ctx.lv / "plan_candidate.json"
        if bp.exists() and cp.exists() and changed:
            wb = build_world(load_plan(str(bp)), ctx.original)
            wc = build_world(load_plan(str(cp)), ctx.sources)
            diff_rows = []
            for addr in changed:
                if not addr.startswith("aws_security_group."):
                    continue
                a, b = _sg_rule_strings(wb, addr, ctx.root), _sg_rule_strings(wc, addr, ctx.root)
                for x in a:
                    if x not in b:
                        diff_rows.append([plain.server(addr, ctx.root), "삭제", x])
                for x in b:
                    if x not in a:
                        diff_rows.append([plain.server(addr, ctx.root), "추가", x])
            if diff_rows:
                c["evidence"].append({"t": "table", "title": "규칙 변경 내용 (실행 계획 기준 계산)", "head": ["보안 그룹", "변경", "규칙 (← 허용 출발지)"], "rows": diff_rows,
                                      "tones": ["bad" if r[1] == "삭제" else "good" for r in diff_rows]})
    except Exception:  # 계획 해석 실패는 카드에서 생략 (판정은 기록 값)
        pass
    kv = [["변경 리소스 수", f"{d.get('touched_resources', '?')}개 (정책 한도 {pol.get('max_changed_resources', '?')}개)"],
          ["교체·삭제 (계획 동작)", "없음" if not (d.get("removed") or d.get("plan_actions_delete") or d.get("plan_actions_replace")) else "있음"],
          ["공급자 설정 변경", "없음" if not d.get("provider_config_diff") else ", ".join(d["provider_config_diff"])]]
    c["evidence"].append({"t": "kv", "title": "변경 범위", "rows": kv})
    lv5 = ctx.layers.get("V5") or {}
    vio = [violation_ko(v, ctx.root) for v in d.get("violations") or []]
    if d and lv5.get("verdict") == "PASS":
        where = " · ".join(f"{plain.server(a, ctx.root) if a.startswith('aws_security_group.') else a} {', '.join(_attr_ko(x) for x in v)}" for a, v in changed.items())
        c["summary"] = f"변경 {d.get('touched_resources', len(changed))}개 모두 허용 범위 내 · 교체·삭제 없음 ({where or '없음'})"
    elif lv5.get("verdict") == "FAIL":
        kinds = [violation_kind(v) for v in d.get("violations") or []]
        cnt = " · ".join(f"{k} {kinds.count(k)}건" for k in (V5_SCOPE, V5_REPLACE) if k in kinds)
        c["summary"] = f"정책 위반 {len(vio) or 1}건{f' ({cnt})' if cnt else ''} — " + (vio[0] if vio else plain.legacy(lv5.get("summary") or ""))
    if vio:
        c["evidence"].append({"t": "table", "title": "정책 위반", "head": ["내용"], "rows": [[v] for v in vio], "tone": "bad"})
    psha = sha256_file(ctx.root / "policy" / "patch_policy.json") if ctx.root else None
    c["basis"]["team"].append({"k": "정책 파일", "v": f"policy/patch_policy.json · {pol.get('policy_version', '')} · sha256 {psha[:12] + '…' if psha else '?'}"})
    c["basis"]["team"].append({"k": "구분", "v": "팀이 정한 수정 허용 범위 (외부 기준 아님)"})
    l = ctx.layers.get("V5") or {}
    c["reason"] = ("변경 리소스·속성 모두 정책 범위 내." if l.get("verdict") == "PASS" else
                   ("정책 위반: " + "; ".join(vio)[:300]) if l.get("verdict") == "FAIL" else plain.legacy(l.get("summary") or ""))
    c["limits"] = ["허용 속성 안의 값 변경은 통과 처리 (CIDR 분할도 '인바운드 규칙 값 변경'으로 통과) → 값의 의미는 V6 에서 계산",
                   "교체·삭제 여부는 오프라인 계획 기준 — 실제 AWS 상태 기준 교체 여부는 실제 AWS 검사의 plan 확인"]
    c["leaves"] = ctx.leaves(["local_verify/plan_baseline.json", "local_verify/plan_candidate.json", "verification.json"])
    return c


# ----------------------------------------------------------------------------- V6
_SVC = re.compile(r"^(ingress|egress)/(\w+|-1)/(\d+)-(\d+)$")
_SCOPE_KO = {"aws_instance.web": "웹 서버", "aws_instance.app": "앱 서버", "aws_security_group.web": "웹 서버 보안 그룹", "aws_security_group.app": "앱 서버 보안 그룹"}


def _svc_port(service_id: Any) -> str:
    m = _SVC.match(str(service_id or ""))
    return plain.port(m.group(2), int(m.group(3)), int(m.group(4))) if m else str(service_id or "")


def _sg_oracle_view(d: Dict[str, Any]) -> Dict[str, Any]:
    """요구사항 목록 방식(서비스별 허용 출처 · 꼭 필요한 접속)의 V6 결과 → 화면 표·답 한 줄 재료. 판정은 기록 값 그대로."""
    lim, lim_t, keep, keep_t, bad, unk = [], [], [], [], [], []
    for t in d.get("targets") or []:
        if t.get("reason") and not t.get("scopes"):
            bad.append(f"{t.get('target')} 보안 그룹 제거됨")
            continue
        for sc in t.get("scopes") or []:
            where = _SCOPE_KO.get(str(sc.get("scope_id")), str(sc.get("scope_id") or ""))
            for sv in sc.get("services") or []:
                v = sv.get("verdict")
                eff = list(sv.get("effective_v4") or []) + list(sv.get("effective_v6") or []) + [_SCOPE_KO.get(str(x), f"보안 그룹 {x}") for x in sv.get("effective_sg_refs") or []]
                exc = list(sv.get("excess_v4") or []) + list(sv.get("excess_v6") or [])
                if not eff and v == "PASS":
                    continue                      # 허용 출발지가 없는 서비스는 표에 넣지 않음 (차단 상태)
                port = _svc_port(sv.get("service_id"))
                whole = sv.get("covers_entire_internet_v4") or sv.get("covers_entire_internet_v6")
                res = ("허용 출발지 내에서만 허용" if v == "PASS" else
                       ("허용 출발지 밖까지 허용 — 인터넷 전체" if whole else "허용 출발지 밖까지 허용") if v == "FAIL" else "판정 불가")
                lim.append([where, port, res, ", ".join(eff) or "-"])
                lim_t.append("good" if v == "PASS" else "bad" if v == "FAIL" else "warn")
                if v == "FAIL":
                    bad.append(f"허용 출발지 밖 허용 — {where} {port} ({'인터넷 전체' if whole else ', '.join(exc[:2]) or '?'})")
                elif v not in ("PASS", None):
                    unk.append(f"{where} {port}")
            for r in sc.get("required") or []:
                v = r.get("verdict")
                port = _svc_port(r.get("service_id"))
                keep.append([where, port, str(r.get("source_cidr") or ""), "허용 유지" if v == "PASS" else "허용 규칙 없음 (필수 통신)" if v == "FAIL" else "판정 불가"])
                keep_t.append("good" if v == "PASS" else "bad" if v == "FAIL" else "warn")
                if v == "FAIL":
                    bad.append(f"필수 통신 허용 규칙 없음 — {where} {port} ← {r.get('source_cidr')}")
                elif v not in ("PASS", None):
                    unk.append(f"{where} {port} (필수 통신)")
    return {"lim": lim, "lim_t": lim_t, "keep": keep, "keep_t": keep_t, "bad": bad, "unk": unk}


def card_v6(ctx: Ctx) -> Dict[str, Any]:
    c = _base("V6", ctx)
    d = (ctx.layers.get("V6") or {}).get("details") or {}
    c["method"]["steps"] = ["후보 계획에서 보안 그룹 규칙과 서버별 연결 보안 그룹 추출 (한 서버에 여러 개면 합산)",
                            "IP 대역 출발지는 포트별 합집합 계산 (분할 표기 대역도 합산)",
                            "설계 기준 통신 9개와 비교: 설계 외 허용 경로 / 허용 규칙 없는 필수 통신을 구분 (보안 그룹 인바운드 규칙 기준 — 실제 연결은 실제 AWS 검사 V8)",
                            "계획에서 값이 확정되지 않으면 통과로 처리하지 않고 '판정 불가'"]
    c["method"]["commands"] = [{"step": "compute", "cmd": None, "note": "명령 실행 없음 — 계획 파일·설계도 파일로 계산"}]
    flows = d.get("flows") or []
    if not flows and d.get("targets"):
        return _card_v6_requirements(ctx, c, d)
    st_ko = {"ok": "허용", "broken": "허용 규칙 없음", "unknown": "판정 불가"}
    if flows:
        c["evidence"].append({"t": "table", "title": f"설계 기준 경로 {len(flows)}개", "head": ["경로", "포트", "결과"],
                              "rows": [[f"{f.get('src_label')} → {f.get('dst_label')}", f.get("ports"), st_ko.get(f.get("status"), f.get("status"))] for f in flows],
                              "tones": ["good" if f.get("status") == "ok" else "bad" if f.get("status") == "broken" else "warn" for f in flows]})
    ex = d.get("excess") or []
    pj = _j(ctx.lv / "plan_candidate.json")

    def where(e: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        origin = e.get("rule", "").split(",")[0].strip()
        return hcl_lines.locate_rule(ctx.sources, origin, _plan_rule(pj, origin))
    rows = []
    for e in ex:
        loc = where(e)
        rows.append([f"{plain.legacy(e.get('src_label'))} → {e.get('dst_label')}", plain.port_text(e.get("ports")), plain.legacy(e.get("detail", "")),
                     f"{loc['file']} {loc['start']}~{loc['end']}행" if loc else e.get("rule", "")])
    c["evidence"].append({"t": "table", "title": "설계 외 허용 경로", "head": ["경로", "포트", "불일치 내용", "코드 위치"], "rows": rows,
                          "empty": "없음 — 설계 외 허용 경로 0개", "tone": "bad" if rows else "good"})
    for e in ex[:2]:
        loc = where(e)
        if loc:
            src = ctx.sources.get(str(loc["file"]), "")
            c["evidence"].append(_code_block(f"불일치 원인 코드 · {plain.legacy(e.get('src_label'))} → {e.get('dst_label')} ({plain.port_text(e.get('ports'))})", str(loc["file"]), src,
                                             int(loc["start"]), int(loc["end"]), tuple(range(int(loc["start"]), int(loc["end"]) + 1)), "bad"))
    # 교차 확인: 인터넷 쪽 대역 합집합을 다른 방식으로 다시 계산 (표시만)
    cross = []
    try:
        from ..verify.plan_model import build_world, load_plan
        from ..topology_intent import try_load_topology_intent
        cp = ctx.lv / "plan_candidate.json"
        spec = None
        if ctx.root:
            spec, _ = try_load_topology_intent(ctx.root / "experiments" / "candidate-sets" / "arch-3tier-sg" / "intents" / "arch-3tier-flows.json")
        if cp.exists() and spec is not None:
            w = build_world(load_plan(str(cp)), ctx.sources)
            ext = {e.id: e for e in spec.external}
            for t in spec.tiers:
                m = w.security_groups.get(t.security_group)
                if m is None:
                    continue
                groups: Dict[Tuple[str, Any, Any], List[str]] = {}
                for r in m.rules:
                    if r.direction != "ingress":
                        continue
                    for s in r.sources:
                        if s.kind == "cidr4":
                            groups.setdefault((r.protocol, r.from_port, r.to_port), []).append(s.value)
                for (proto, lo, hi), cidrs in groups.items():
                    covering = [f for f in spec.flows if f.dst == t.id and f.src in ext and f.from_port <= (lo or 0) and f.to_port >= (hi or 65535)]
                    allowed = [cc for f in covering for cc in ext[f.src].cidrs_v4]
                    cmp = recheck.compare_with_netset(cidrs, allowed)
                    if cmp.get("mine", {}).get("ok"):
                        mine = cmp["mine"]
                        cross.append({"k": f"{t.label} {lo if lo == hi else f'{lo}-{hi}'} 허용 출발지 대역",
                                      "v": f"{', '.join(cidrs)} → 합집합 {'인터넷 전체' if mine['covers_internet'] else ', '.join(mine['union'][:2])}"
                                           f" · 허용 범위 밖 주소 {mine['outside_addresses']:,}개 · 두 계산 방식 {'일치' if cmp['same'] else '불일치'}",
                                      "same": cmp["same"]})
    except Exception as e:  # 교차 확인 실패는 표시만
        cross.append({"k": "교차 확인", "v": f"계산 실패: {type(e).__name__}", "same": None})
    c["basis"]["cross"] = cross
    ipath = (ctx.root / "experiments" / "candidate-sets" / "arch-3tier-sg" / "intents" / "arch-3tier-flows.json") if ctx.root else None
    isha = sha256_file(ipath) if ipath and ipath.exists() else None
    c["basis"]["team"].append({"k": "설계도 파일", "v": f"{standards.TEAM_REQUIREMENTS['design']['file']} · sha256 {isha[:12] + '…' if isha else '?'} · 2026-10-20 실행 전 고정"})
    c["basis"]["team"].append({"k": "관리자 허용 목록", "v": ", ".join(standards.TEAM_REQUIREMENTS["admin_allowlist"]["value"]) + " — 문서용 예시 대역(TEST-NET), 실제 값은 팀이 지정"})
    if any(e.get("src") == "internet" and str(e.get("ports")) in ("22", "3389") for e in ex):
        c["basis"]["standard"] = [x for x in standards.for_rule("AVD-AWS-0107").get("external", []) if x["org"] in ("AWS", "CIS")]
    if any(e.get("src") not in ("internet",) for e in ex):
        c["basis"]["team"].append({"k": "계층 간 통신", "v": "외부 기준에 '웹 서버의 DB 직접 접속 금지' 같은 항목 없음 — 팀 설계 요구사항으로 판정"})
    l = ctx.layers.get("V6") or {}
    broken = [f for f in flows if f.get("status") == "broken"]
    if flows:
        n_ok = sum(1 for f in flows if f.get("status") == "ok")
        if l.get("verdict") == "PASS":
            c["summary"] = f"설계 기준과 일치 — 정상 통신 경로 {len(flows)}개 모두 허용 · 설계 외 허용 경로 0개"
        else:
            parts = []
            if ex:
                parts.append(f"설계 외 허용 경로 {len(ex)}개 ({plain.legacy(ex[0].get('src_label'))} → {ex[0].get('dst_label')}, {plain.port_text(ex[0].get('ports'))}"
                             + (f" 외 {len(ex) - 1}개" if len(ex) > 1 else "") + ")")
            if broken:
                parts.append(f"허용 규칙 없는 필수 통신 {len(broken)}개 ({broken[0].get('src_label')} → {broken[0].get('dst_label')})")
            if not parts:
                parts.append(f"설계 기준 경로 {len(flows)}개 중 허용 확인 {n_ok}개 — 판정 불가 경로 있음")
            c["summary"] = ("설계 기준과 불일치 — " if l.get("verdict") == "FAIL" else "") + " · ".join(parts)
    if l.get("verdict") == "PASS":
        c["reason"] = f"설계 기준 경로 {len(flows)}개 모두 허용, 설계 외 허용 경로 0개."
    elif l.get("verdict") == "FAIL":
        parts = [f"설계 외 허용 경로 {len(ex)}개"] if ex else []
        if broken:
            parts.append(f"허용 규칙 없는 필수 통신 {len(broken)}개")
        c["reason"] = " · ".join(parts) + " — " + "; ".join(f"{plain.legacy(e.get('src_label'))} → {e.get('dst_label')} {e.get('ports')}" for e in ex[:3])
    else:
        c["reason"] = plain.legacy(l.get("summary") or "")
    if flows:
        c["diagram"] = {"flows": {f.get("id"): f.get("status") for f in flows if f.get("id")},
                        "excess": [{k: e.get(k) for k in ("src", "dst", "ports", "src_label", "dst_label", "kind", "detail")} for e in ex]}
    c["limits"] = ["보안 그룹 규칙만 계산 — 네트워크 ACL·라우팅·서버 프로세스의 실제 수신 여부는 V8 에서 확인",
                   "인바운드(ingress) 규칙만 검사"]
    c["leaves"] = ctx.leaves(["local_verify/plan_candidate.json", "verification.json"])
    return c



def _card_v6_requirements(ctx: Ctx, c: Dict[str, Any], d: Dict[str, Any]) -> Dict[str, Any]:
    """2계층 사례처럼 설계도 대신 요구사항 목록(서비스별 허용 출발지 · 필수 통신)으로 판정한 기록."""
    c["method"]["steps"] = ["후보 계획에서 서버별 연결 보안 그룹 규칙 추출 (한 서버에 여러 개면 합산)",
                            "서비스(포트)별 허용 출발지 합집합 계산 (분할 표기 대역도 합산)",
                            "요구사항과 비교: 허용 출발지 밖 허용 / 허용 규칙 없는 필수 통신을 구분 (보안 그룹 인바운드 규칙 기준)",
                            "계획에서 값이 확정되지 않으면 통과로 처리하지 않고 '판정 불가'"]
    vw = _sg_oracle_view(d)
    c["evidence"].append({"t": "table", "title": "서비스별 허용 출발지 (요구사항: 허용 목록 내만)", "head": ["서버", "포트", "결과", "허용 출발지"],
                          "rows": vw["lim"], "tones": vw["lim_t"], "empty": "허용된 서비스 없음"})
    c["evidence"].append({"t": "table", "title": "필수 통신", "head": ["서버", "포트", "출발지", "결과"], "rows": vw["keep"], "tones": vw["keep_t"], "empty": "요구사항에 없음"})
    l = ctx.layers.get("V6") or {}
    v = l.get("verdict")
    if v == "PASS":
        c["summary"] = "요구사항과 일치 — 허용 출발지만 허용 · 필수 통신 허용 규칙 유지"
    elif v == "FAIL":
        c["summary"] = "요구사항과 불일치 — " + (" · ".join(vw["bad"][:2]) or "요구사항 위반") + (f" 외 {len(vw['bad']) - 2}건" if len(vw["bad"]) > 2 else "")
    elif v:
        c["summary"] = "판정 불가 — " + (", ".join(vw["unk"][:3]) or "계획에서 값 미확정")
    raw = " ".join(str(l.get("summary") or "").split())
    c["reason"] = c["summary"] + (f" (기록 원문: {raw[:300]})" if raw and v != "PASS" else "")
    c["basis"]["team"].append({"k": "요구사항", "v": "이 사례의 요구사항 — 서비스별 허용 출발지, 필수 통신 (외부 기준 아님)"})
    disc = d.get("disclaimer")
    if disc:
        try:
            from ..web.explain import disclaimer_ko
            disc = disclaimer_ko(str(disc))
        except Exception:  # 번역 실패면 원문 그대로
            pass
    c["limits"] = ["보안 그룹 규칙만 계산 — 네트워크 ACL·라우팅·서버 프로세스의 실제 수신 여부는 확인 불가",
                   "인바운드(ingress) 규칙만 검사"] + ([f"기록된 한계: {disc}"] if disc else [])
    c["leaves"] = ctx.leaves(["local_verify/plan_candidate.json", "verification.json"])
    return c

def _plan_rule(pj: Optional[Dict[str, Any]], origin: str) -> Optional[Dict[str, Any]]:
    """'aws_security_group.api#ingress[0]' → 실행 계획(planned_values)에 있는 그 규칙의 값 (description·포트·프로토콜). 없으면 None."""
    m = re.match(r"^([^#]+)#(ingress|egress)\[(\d+)\]$", origin or "")
    if not pj or not m:
        return None
    addr, kind, k = m.group(1).strip(), m.group(2), int(m.group(3))

    def walk(mod: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for res in mod.get("resources") or []:
            if res.get("address") == addr:
                vals = (res.get("values") or {}).get(kind) or []
                return vals[k] if k < len(vals) and isinstance(vals[k], dict) else None
        for ch in mod.get("child_modules") or []:
            hit = walk(ch)
            if hit is not None:
                return hit
        return None
    return walk((pj.get("planned_values") or {}).get("root_module") or {})


def policy_ko(v: Any) -> str:
    """정책 확인(policy/validator.py) 위반 문장 → 화면 문장. 모르는 형식이면 원문 그대로."""
    t = str(v)
    m = re.match(r"^exec_guard:(\S+?): (.*)$", t, re.S)
    if m:
        return f"{m.group(1)}: 실행 전 안전 점검 차단 — {m.group(2)}"
    m = re.match(r"^forbidden_tokens:(\S+): introduced \[(.*)\]$", t)
    if m:
        toks = re.findall(r"'([^']+)'", m.group(2)) or [m.group(2)]
        return f"{m.group(1)}: 금지 코드 추가 — {', '.join(toks)} (terraform 실행 PC 에서 임의 명령 실행 가능)"
    m = re.match(r"^file_count: (\d+) files \(max (\d+)\)$", t)
    if m:
        return f"파일 {m.group(1)}개 변경 — 팀 정책 한도 {m.group(2)}개"
    for key, text in (("file_protected", "변경 금지 파일 (공급자·백엔드·버전 설정)"), ("path_protected", "변경 금지 폴더의 파일"),
                      ("path_editable", "수정 허용 파일 목록에 없음"), ("file_exists", "새 파일 생성 불가"),
                      ("protected_blocks", "terraform·provider 설정 블록 변경"), ("diff_nonempty", "원본과 내용 동일 (변경 없음)"),
                      ("file_size", "파일 크기 한도 초과"), ("path_safe", "허용되지 않은 경로")):
        m = re.match(rf"^{key}:(\S+?):", t)
        if m:
            return f"{m.group(1)}: {text}"
    return t


BUILDERS = {"V1": card_v1, "V2": card_v2, "V3": card_v3, "V4": card_v4, "V5": card_v5, "V6": card_v6}


def _skip_summaries(cards: List[Dict[str, Any]]) -> None:
    """앞 단계(V3 구문 · V4 실행 계획)에서 막혀 결과가 없는 단계 → 요약 한 줄 (판정 값은 기록 그대로).
    예: V5 '검증 대기 — 원본/후보 plan JSON 없음' → '미실행 — 앞 단계 V4(실행 계획 생성) 실패로 검사 진행 안 함'."""
    order = ["V1", "V2", "V3", "V4", "V5", "V6"]
    by = {str(c.get("layer")): c for c in cards}
    for cd in cards:
        lay = str(cd.get("layer"))
        if lay not in order or cd.get("summary") or cd.get("verdict") not in ("NOT_RUN", "ERROR", "SKIPPED"):
            continue
        prev = [by[k] for k in order[:order.index(lay)] if k in ("V3", "V4") and k in by]
        blk = next((p for p in prev if p.get("verdict") == "FAIL"), None) or next((p for p in prev if p.get("verdict") == "ERROR"), None)
        if blk is None:
            continue
        how = "실패" if blk.get("verdict") == "FAIL" else "오류"
        cd["summary"] = f"미실행 — 앞 단계 {blk.get('layer')}({blk.get('name')}) {how}로 검사 진행 안 함"
        raw = str(cd.get("reason") or "")
        cd["reason"] = cd["summary"] + (f" (기록 원문: {raw})" if raw else "")


def build_cards(record_dir: Path, repo_root: Optional[Path] = None) -> Dict[str, Any]:
    ctx = Ctx(record_dir, repo_root)
    cards = []
    for k, fn in BUILDERS.items():
        try:
            cd = fn(ctx)
        except Exception as e:  # 카드 하나가 깨져도 나머지는 보여 준다
            cd = _base(k, ctx)
            cd["reason"] = f"카드 생성 실패: {type(e).__name__}: {e}"
        if ctx.partial and k in ("V5", "V6"):
            cd["status"] = "pending" if not (ctx.layers.get(k) or {}).get("verdict") else cd["status"]
        cards.append(primary.mark(cd))
    _skip_summaries(cards)
    st = ctx.state
    blocked_before = None
    if st.get("state") == "POLICY_BLOCKED":
        pol = _j(record_dir / "policy.json") or {}
        vio = [str(v) for v in (pol.get("violations") or [])][:6]
        blocked_before = {"stage": "정책 확인 (검사 전)", "violations": vio, "violations_ko": [policy_ko(v) for v in vio], "file": "policy.json"}
        for cd in cards:
            if cd.get("status") != "done":
                # 걸린 항목은 '정책' 단계 카드에 있다 — 여기서는 왜 안 했는지만 한 줄로
                cd["reason"] = "미실행 — 검사(V1~V6) 시작 전 정책 확인에서 차단 (위반 항목은 '정책' 단계 참고)"
                cd["skipped"] = "policy"
    from ..web.cases import record_label
    return {"record": record_dir.name, "candidate_label": record_label(st), "candidate_sha256": st.get("candidate_sha256"),
            "design": st.get("design"),
            "state": st.get("state"), "blocked_before": blocked_before,
            "started_at": st.get("started_at"), "finished_at": st.get("finished_at"), "level": st.get("review_level"),
            "partial": ctx.partial or not st.get("finished_at"), "cards": cards,
            "manifest": {"files": len(ctx.manifest), "path": "evidence/manifest.json" if ctx.manifest else None}}
