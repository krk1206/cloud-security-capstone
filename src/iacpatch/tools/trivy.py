"""Trivy(IaC 모드, `trivy config`) 어댑터.

- 바이너리: 환경변수 TRIVY_BIN (기본 "trivy")
- 항상 --include-non-failures 로 실행해 PASS 기록까지 보존한다 (0 FAIL 이 "검사 후 통과"인지 "검사 안 함"인지 구분하기 위해).
- 결과 JSON 은 변경 없이 저장하고, 파이프라인용 Finding 목록은 별도로 파싱한다.
- --tf-vars 는 선택. trivy config 는 기본적으로 tfvars 를 읽지 않는다 (worklog 2026-09-11 확인 사실).
"""
from __future__ import annotations

import json
import re
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Finding
from .runner import ToolNotFound, run, which


def normalize_rule_id(m: Dict[str, Any]) -> str:
    rid = m.get("AVDID") or m.get("ID") or "?"
    rid = str(rid)
    if rid.startswith("AWS-") or rid.startswith("GEN-") or rid.startswith("DS-"):
        rid = "AVD-" + rid
    return rid


def parse_findings(report: Dict[str, Any], include_pass: bool = False) -> List[Finding]:
    out: List[Finding] = []
    for r in report.get("Results") or []:
        target = str(r.get("Target") or "")
        for m in r.get("Misconfigurations") or []:
            status = str(m.get("Status") or "FAIL")
            if status != "FAIL" and not include_pass:
                continue
            cm = m.get("CauseMetadata") or {}
            out.append(Finding(
                rule_id=normalize_rule_id(m),
                severity=str(m.get("Severity") or "UNKNOWN"),
                resource=str(cm.get("Resource") or ""),
                filename=target,
                start_line=int(cm.get("StartLine") or 0),
                end_line=int(cm.get("EndLine") or 0),
                title=str(m.get("Title") or ""),
                message=str(m.get("Message") or ""),
                resolution=str(m.get("Resolution") or ""),
                status=status,
                references=list(m.get("References") or []),
            ))
    return out


def scan_summary(report: Dict[str, Any]) -> Dict[str, int]:
    succ = fail = 0
    for r in report.get("Results") or []:
        s = r.get("MisconfSummary") or {}
        succ += int(s.get("Successes") or 0)
        fail += int(s.get("Failures") or 0)
    return {"successes": succ, "failures": fail, "checks_executed": succ + fail}


@dataclass
class TrivyScan:
    ok: bool
    report: Dict[str, Any]
    findings: List[Finding]
    summary: Dict[str, int]
    version: str
    error: str = ""
    argv: List[str] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)   # stderr 의 "[terraform parser] Error parsing file …" — Trivy 는 못 읽은 파일을 건너뛰고 exit 0 + 검사 '성공' 으로 센다 (팀 PC 실습 09-29)


class TrivyAdapter:
    def __init__(self, binary: Optional[str] = None, skip_check_update: Optional[bool] = None):
        self.binary = binary or os.environ.get("TRIVY_BIN") or "trivy"
        env = os.environ.get("TRIVY_SKIP_CHECK_UPDATE")
        self.skip_check_update = skip_check_update if skip_check_update is not None else (env == "1")

    def available(self) -> bool:
        return which(self.binary) is not None or os.path.exists(self.binary)

    _ENV = {"TRIVY_SKIP_VERSION_CHECK": "true"}   # --version 도 check.trivy.dev 에 접속한다 → 끈다 (네트워크 0)

    def version(self) -> str:
        if not self.available():
            return ""
        r = run([self.binary, "--version"], timeout=60, env=self._ENV)
        return (r.stdout.strip().splitlines() or [""])[0].replace("Version:", "").strip()

    def scan_dir(self, target_dir: str | Path, output_json: Optional[str | Path] = None,
                 tf_vars: Optional[str] = None, timeout: int = 600) -> TrivyScan:
        # --quiet 를 쓰지 않는다: 파싱 실패("[terraform parser] Error parsing file")가 stderr 로만 나오는데 --quiet 가 그것까지 숨긴다. 리포트는 --output 파일로 받는다
        argv = [self.binary, "config", str(target_dir), "--format", "json", "--include-non-failures", "--skip-version-check"]
        if self.skip_check_update:
            argv += ["--skip-check-update"]   # 내장 체크 번들 사용 (번들 갱신 없음). 버전 확인(check.trivy.dev)은 항상 끈다 = 네트워크 0
        if tf_vars:
            argv += ["--tf-vars", str(tf_vars)]
        if output_json:
            argv += ["--output", str(output_json)]
        try:
            r = run(argv, timeout=timeout, env=self._ENV)
        except ToolNotFound as e:
            return TrivyScan(False, {}, [], {}, "", str(e), argv)
        if r.timed_out:
            return TrivyScan(False, {}, [], {}, "", "trivy timed out", argv)
        if r.returncode != 0:
            return TrivyScan(False, {}, [], {}, "", (r.stderr or r.stdout)[:2000], argv)
        try:
            text = Path(output_json).read_text(encoding="utf-8") if output_json else r.stdout
            report = json.loads(text)
        except (OSError, json.JSONDecodeError) as e:
            return TrivyScan(False, {}, [], {}, "", f"cannot parse trivy output: {e}", argv)
        ver = str((report.get("Trivy") or {}).get("Version") or self.version())
        return TrivyScan(True, report, parse_findings(report), scan_summary(report), ver, "", argv, parse_errors(r.stderr))


def parse_errors(stderr: str) -> List[str]:
    """Trivy stderr 에서 HCL 파싱 실패 줄만 뽑는다 (중복 제거). 파싱 실패 파일은 검사 대상에서 빠지므로 '경고 없음' 이 '안전' 이 아니다."""
    out: List[str] = []
    for line in (stderr or "").splitlines():
        if "Error parsing file" in line or "failed to parse" in line.lower():
            m = re.search(r'err="([^"]*)"', line)
            msg = (m.group(1) if m else line.strip()).replace('\\"', '"')
            if msg not in out:
                out.append(msg[:300])
    return out


def load_report(path: str | Path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
