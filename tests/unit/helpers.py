"""테스트 공통 도우미. (unittest 기반 — 외부 의존성 없음)"""
from __future__ import annotations

import copy
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

FIXTURES = ROOT / "tests" / "fixtures"
PLANS = FIXTURES / "plans"
TRIVY = FIXTURES / "trivy"
CASES_SRC = FIXTURES / "src"

# 테스트용 승인 출처. 10.0.0.0/8 은 사설 대역이며 실험 케이스(07/08 등)가 사용한 값과 맞춘 것이다. 실제 팀 값이 아니다.
INTENT_TEMPLATE: Dict[str, Any] = {
    "intent_version": "1",
    "intent_id": "unit-test",
    "status": "active",
    "target_dir": "tests/fixtures/src",
    "targets": {"security_groups": ["__TARGET__"], "attachment_points": []},
    "guarded_services": [
        {"label": "ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
         "approved_sources": {"cidrs_v4": ["10.0.0.0/8"], "cidrs_v6": [], "security_group_refs": [], "prefix_list_refs": []}},
        {"label": "rdp", "direction": "ingress", "protocol": "tcp", "from_port": 3389, "to_port": 3389,
         "approved_sources": {"cidrs_v4": [], "cidrs_v6": [], "security_group_refs": [], "prefix_list_refs": []}},
    ],
    "required_access": [
        {"label": "admin-ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "source_cidr": "10.0.0.0/8"}
    ],
}


def intent_for(target: str, *, sg_refs: Optional[List[str]] = None, v6: Optional[List[str]] = None,
               v4: Optional[List[str]] = None, required: Optional[List[Dict[str, Any]]] = None):
    from iacpatch.intent import parse_intent
    d = copy.deepcopy(INTENT_TEMPLATE)
    d["targets"]["security_groups"] = [target]
    ap = d["guarded_services"][0]["approved_sources"]
    if sg_refs is not None:
        ap["security_group_refs"] = sg_refs
    if v6 is not None:
        ap["cidrs_v6"] = v6
    if v4 is not None:
        ap["cidrs_v4"] = v4
    if required is not None:
        d["required_access"] = required
    return parse_intent(d)


def load_case_plan(case: str) -> Dict[str, Any]:
    return json.loads((PLANS / case / "plan.json").read_text(encoding="utf-8"))


def load_case_sources(case: str) -> Dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in (CASES_SRC / case).glob("*.tf")}


def load_case_trivy(case: str):
    from iacpatch.tools.trivy import TrivyScan, parse_findings, scan_summary
    report = json.loads((TRIVY / f"{case}.json").read_text(encoding="utf-8"))
    return TrivyScan(True, report, parse_findings(report), scan_summary(report), str(report.get("Trivy", {}).get("Version", "")))


FROZEN = bool(getattr(sys, "frozen", False))   # PyInstaller exe 안에서 `IaCPatch.exe --unittest` 로 도는 중


def py_cmd(script: str, *args: str) -> List[str]:
    """저장소 스크립트를 돌리는 명령. exe 안에서는 python 이 없으므로 exe 자신을 --exec 로 다시 띄운다 (app._script_cmd 와 같은 규칙)."""
    if FROZEN:
        return [sys.executable, "--exec", str(script), *args]
    return [sys.executable, str(script), *args]


def tools_available() -> bool:
    from iacpatch.tools.runner import which
    tf = os.environ.get("TERRAFORM_BIN", "terraform")
    tv = os.environ.get("TRIVY_BIN", "trivy")
    return (which(tf) is not None or os.path.exists(tf)) and (which(tv) is not None or os.path.exists(tv))
