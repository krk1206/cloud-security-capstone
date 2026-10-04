"""Claude Code 후보 수집용 케이스 레지스트리 — cc_prompt.py / cc_add.py 가 같이 쓴다.

케이스 이름:
  SG  : a-probe 의 폴더 이름 그대로 (예: 00-baseline)              → scenarios/eval/a-probe/<case>, 룰 AVD-AWS-0107
  IAM : "iam-" + iam-probe 의 폴더 이름 (예: iam-00-literal-list)  → scenarios/eval/iam-probe/<case>, 룰 AVD-AWS-0345
  ARCH: arch-sg / arch-iam (2026-10-02)                             → scenarios/arch/webapp-2tier (B 의 아키텍처, 파일 여러 개),
        대상 파일은 Trivy finding 이 가리키는 파일(security_groups.tf / iam.tf), 스캔은 experiments/arch-webapp-2tier/trivy-scan.json
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parents[1]

SETS: Dict[str, Dict[str, str]] = {
    "sg": {"dir": "scenarios/eval/a-probe", "rule": "AVD-AWS-0107", "prefix": ""},
    "iam": {"dir": "scenarios/eval/iam-probe", "rule": "AVD-AWS-0345", "prefix": "iam-"},
}


ARCH: Dict[str, Dict[str, str]] = {
    "arch-sg": {"kind": "sg", "tf_dir": "scenarios/arch/webapp-2tier", "trivy_json": "experiments/arch-webapp-2tier/trivy-scan.json",
                "rule": "AVD-AWS-0107", "resource": "aws_security_group.web",
                "intent": "experiments/candidate-sets/arch-webapp-sg/intents/arch-webapp-sg.json"},
    "arch-iam": {"kind": "iam", "tf_dir": "scenarios/arch/webapp-2tier", "trivy_json": "experiments/arch-webapp-2tier/trivy-scan.json",
                 "rule": "AVD-AWS-0345", "resource": "aws_iam_policy.web_assets",
                 "intent": "experiments/candidate-sets/arch-webapp-iam/intents/arch-webapp-web-role.json"},
}


def case_info(case: str) -> Dict[str, object]:
    """case 이름 → dict(kind, name, cdir, tf_dir, intent_rel, rule, trivy_json(상대경로), resource(없으면 None))."""
    if case in ARCH:
        a = ARCH[case]
        return {"kind": a["kind"], "name": case, "cdir": ROOT / a["tf_dir"], "tf_dir": a["tf_dir"], "intent_rel": a["intent"],
                "rule": a["rule"], "trivy_json": a["trivy_json"], "resource": a["resource"]}
    kind, name, d, tf_dir, intent_rel, rule = resolve(case)
    return {"kind": kind, "name": name, "cdir": d, "tf_dir": tf_dir, "intent_rel": intent_rel, "rule": rule,
            "trivy_json": f"{tf_dir}/trivy-scan.json", "resource": None}


def resolve(case: str):
    """case 이름 → (kind, 폴더 이름, 케이스 폴더 Path, tf_dir 상대경로, intent 상대경로, rule)."""
    if case in ARCH:
        a = ARCH[case]
        return a["kind"], case, ROOT / a["tf_dir"], a["tf_dir"], a["intent"], a["rule"]
    if case.startswith("iam-"):
        name = case[4:]
        d = ROOT / SETS["iam"]["dir"] / name
        return "iam", name, d, f"{SETS['iam']['dir']}/{name}", "experiments/candidate-sets/eval-seeded-iam/intent.json", SETS["iam"]["rule"]
    d = ROOT / SETS["sg"]["dir"] / case
    return "sg", case, d, f"{SETS['sg']['dir']}/{case}", f"experiments/candidate-sets/a-probe-dev/intents/{case}.json", SETS["sg"]["rule"]


def all_cases():
    out = []
    for kind in ("sg", "iam"):
        base = ROOT / SETS[kind]["dir"]
        if base.is_dir():
            out += [SETS[kind]["prefix"] + p.name for p in sorted(base.iterdir()) if p.is_dir()]
    out += [c for c in ARCH if (ROOT / ARCH[c]["tf_dir"]).is_dir()]
    return out
