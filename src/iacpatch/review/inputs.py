"""B 3주차 — Trivy 결과 입력과 대상 finding 선택.

A 가 만든 Trivy JSON(`trivy config --format json`) 을 **파일로** 받는다. 이 모듈은 trivy 를 실행하지 않는다.

기능
  - load_trivy_report(path)      : JSON 로딩 + 구조 검증 (손상/형식 불일치 → TrivyInputError)
  - list_findings(report)        : FAIL finding 목록 (Finding)
  - select_findings(findings, sel): 파일·룰 ID·리소스·시작 줄로 필터. **여러 개면 임의로 첫 항목을 고르지 않는다** (호출자가 AMBIGUOUS 처리)
  - check_source_consistency()   : 스캔 결과와 원본 코드가 같은 시점인지 — Trivy 가 기록한 원인 줄(Code.Lines[IsCause])의
                                   내용과 실제 파일의 그 줄을 비교한다. 파일 mtime 은 git checkout 으로 바뀌므로 보조 정보로만 기록.

한계 (정직하게): Trivy JSON 에는 소스 해시가 없다. 줄 내용 비교는 "지목된 줄이 아직 그 자리에 그대로 있다" 까지만 보장하며,
다른 줄이 바뀐 경우는 잡지 못한다. 완전한 확인은 A 가 스캔 시점의 커밋 해시를 함께 넘길 때 가능하다 (IO 명세의 `source_commit`).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Finding
from ..tools.trivy import parse_findings, scan_summary


class TrivyInputError(ValueError):
    pass


@dataclass
class FindingSelector:
    rule_id: Optional[str] = None      # 예: AVD-AWS-0107 (AWS-0107 도 허용)
    filename: Optional[str] = None     # Trivy Target 기준 (예: main.tf)
    resource: Optional[str] = None     # 예: aws_security_group.vulnerable_ssh
    start_line: Optional[int] = None   # 같은 리소스에 같은 룰이 여러 줄이면 이걸로 구분

    def describe(self) -> str:
        parts = [f"{k}={v}" for k, v in (("rule", self.rule_id), ("file", self.filename), ("resource", self.resource), ("line", self.start_line)) if v]
        return ", ".join(parts) if parts else "(조건 없음)"


def _norm_rule(r: str) -> str:
    r = r.strip()
    return r if r.startswith("AVD-") else "AVD-" + r


def load_trivy_report(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise TrivyInputError(f"Trivy JSON 파일이 없다: {p}")
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise TrivyInputError(f"Trivy JSON 을 읽을 수 없다: {p}: {e}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise TrivyInputError(f"Trivy JSON 이 올바른 JSON 이 아니다 ({p}): {e}")
    if not isinstance(data, dict) or "Results" not in data:
        raise TrivyInputError(f"Trivy JSON 형식이 아니다 (Results 키 없음): {p}")
    if not isinstance(data.get("Results"), list):
        raise TrivyInputError(f"Trivy JSON 의 Results 가 리스트가 아니다: {p}")
    return data


def list_findings(report: Dict[str, Any], include_pass: bool = False) -> List[Finding]:
    """parse_findings + 완전 중복 제거. Trivy 는 같은 IAM 정책을 policies 와 role.policies 두 경로로 평가해
    (룰, 파일, 리소스, 줄, 상태) 가 똑같은 finding 을 두 번 낸다 (AVD-AWS-0345). 하나만 남긴다 — 다른 리소스/줄이면 남긴다."""
    out: List[Finding] = []
    seen = set()
    for f in parse_findings(report, include_pass=include_pass):
        key = (f.rule_id, f.filename, f.resource, f.start_line, f.end_line, f.status)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def select_findings(findings: List[Finding], sel: FindingSelector) -> List[Finding]:
    out = []
    for f in findings:
        if f.status != "FAIL":
            continue
        if sel.rule_id and f.rule_id != _norm_rule(sel.rule_id):
            continue
        if sel.filename and Path(f.filename).name != Path(sel.filename).name and f.filename != sel.filename:
            continue
        if sel.resource and f.resource != sel.resource:
            continue
        if sel.start_line is not None and f.start_line != sel.start_line:
            continue
        out.append(f)
    out.sort(key=lambda f: (f.filename, f.start_line, f.rule_id))
    return out


def required_fields_missing(f: Finding) -> List[str]:
    """대상 finding 으로 쓰기 위한 필수 정보 (없으면 INPUT_ERROR)."""
    missing = []
    if not f.rule_id or f.rule_id == "AVD-?":
        missing.append("rule_id")
    if not f.filename:
        missing.append("filename")
    if not f.resource:
        missing.append("resource")
    if not f.start_line:
        missing.append("start_line")
    return missing


# ---------------------------------------------------------------------------
# 스캔 ↔ 원본 정합
# ---------------------------------------------------------------------------
@dataclass
class SourceCheck:
    ok: bool
    method: str
    cause_lines_checked: int
    mismatches: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    scan_created_at: str = ""
    files_modified_after_scan: List[str] = field(default_factory=list)
    file_sha256: Dict[str, str] = field(default_factory=dict)


def _cause_lines(report: Dict[str, Any], finding: Finding) -> List[Dict[str, Any]]:
    """finding 에 해당하는 Trivy 원문 항목의 Code.Lines 중 IsCause=True 인 줄."""
    for r in report.get("Results") or []:
        if str(r.get("Target") or "") != finding.filename:
            continue
        for m in r.get("Misconfigurations") or []:
            rid = m.get("AVDID") or m.get("ID") or ""
            rid = rid if str(rid).startswith("AVD-") else "AVD-" + str(rid)
            cm = m.get("CauseMetadata") or {}
            if rid == finding.rule_id and cm.get("Resource") == finding.resource and int(cm.get("StartLine") or 0) == finding.start_line:
                return [l for l in ((cm.get("Code") or {}).get("Lines") or []) if l.get("IsCause")]
    return []


def check_source_consistency(report: Dict[str, Any], finding: Finding, tf_dir: str | Path, files: Dict[str, str]) -> SourceCheck:
    lines = _cause_lines(report, finding)
    chk = SourceCheck(ok=True, method="cause-line content match (Trivy CauseMetadata.Code.Lines ↔ 원본 파일 줄)", cause_lines_checked=0)
    chk.scan_created_at = str(report.get("CreatedAt") or "")
    for name, text in files.items():
        chk.file_sha256[name] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    src = files.get(finding.filename)
    if src is None:
        chk.ok = False
        chk.notes.append(f"finding 이 가리키는 파일 {finding.filename} 이 원본 디렉터리에 없다")
        return chk
    src_lines = src.splitlines()
    if not lines:
        chk.notes.append("Trivy JSON 에 원인 줄(IsCause) 정보가 없어 줄 내용 비교를 할 수 없다 → 정합 미확인")
        chk.method = "none (no cause lines in report)"
    for l in lines:
        n = int(l.get("Number") or 0)
        content = str(l.get("Content") or "")
        chk.cause_lines_checked += 1
        actual = src_lines[n - 1] if 0 < n <= len(src_lines) else None
        if actual is None or actual.strip() != content.strip():
            chk.ok = False
            chk.mismatches.append({"line": n, "scan_content": content.strip(), "file_content": (actual or "<없음>").strip()})
    # mtime 보조 정보 (git checkout 이후에는 의미가 없으므로 결과에 영향 주지 않음)
    try:
        created = _dt.datetime.fromisoformat(chk.scan_created_at.replace("Z", "+00:00")) if chk.scan_created_at else None
    except ValueError:
        created = None
    if created is not None:
        for name in files:
            p = Path(tf_dir) / name
            try:
                mtime = _dt.datetime.fromtimestamp(p.stat().st_mtime, tz=_dt.timezone.utc)
            except OSError:
                continue
            if mtime > created.astimezone(_dt.timezone.utc):
                chk.files_modified_after_scan.append(name)
        if chk.files_modified_after_scan:
            chk.notes.append("일부 파일의 수정 시각이 스캔 시각보다 늦다 (git checkout 만으로도 생기는 현상이라 참고용). 줄 내용 비교 결과를 우선한다")
    if chk.ok and lines:
        chk.notes.append("지목된 원인 줄이 원본에 그대로 있다. 다른 줄의 변경은 이 방법으로 잡지 못한다 (A 가 source_commit 을 넘기면 완전 확인 가능)")
    return chk
