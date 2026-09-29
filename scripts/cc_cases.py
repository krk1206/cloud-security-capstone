"""Claude Code 후보 수집용 케이스 레지스트리 — cc_prompt.py / cc_add.py 가 같이 쓴다.

케이스 이름:
  SG  : a-probe 의 폴더 이름 그대로 (예: 00-baseline)              → scenarios/eval/a-probe/<case>, 룰 AVD-AWS-0107
  IAM : "iam-" + iam-probe 의 폴더 이름 (예: iam-00-literal-list)  → scenarios/eval/iam-probe/<case>, 룰 AVD-AWS-0345
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parents[1]

SETS: Dict[str, Dict[str, str]] = {
    "sg": {"dir": "scenarios/eval/a-probe", "rule": "AVD-AWS-0107", "prefix": ""},
    "iam": {"dir": "scenarios/eval/iam-probe", "rule": "AVD-AWS-0345", "prefix": "iam-"},
}


def resolve(case: str):
    """case 이름 → (kind, 폴더 이름, 케이스 폴더 Path, tf_dir 상대경로, intent 상대경로, rule)."""
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
    return out
