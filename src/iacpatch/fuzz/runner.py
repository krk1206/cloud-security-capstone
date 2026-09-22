"""변형 하나를 스캐너(Trivy)와 오라클(V6)에 나란히 넣는다. 결과는 판정만이 아니라 원문(스캔 JSON·plan JSON)도 남긴다.

    from iacpatch.fuzz.runner import run_variants
    results = run_variants(settings, kind="sg", out_dir=Path("experiments/fuzz/<stamp>/sg"))

각 변형: 임시 작업 폴더에 main.tf 를 쓰고 → trivy config (내장 체크, 네트워크 없음) → terraform init/validate/plan/show (오프라인, provider 템플릿)
→ plan JSON 으로 오라클 판정. 어떤 것도 AWS 에 닿지 않는다. 판정 규칙:
  SG  truth open/unapproved → 오라클 FAIL 이어야, approved → PASS 여야. Trivy 열은 AVD-AWS-0107 이 FAIL 로 잡혔는가.
  IAM truth excess/breaks → 오라클 FAIL, least → PASS, unknown → UNKNOWN. Trivy 열은 aws_iam_* 리소스에 FAIL 이 하나라도 있는가.
"""
from __future__ import annotations

import copy
import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Settings
from ..iam_intent import load_iam_intent
from ..intent import parse_intent
from ..tools.terraform import TerraformAdapter
from ..tools.trivy import TrivyAdapter
from ..verify.iam_oracle import build_iam_world
from ..verify.iam_oracle import evaluate as evaluate_iam
from ..verify.plan_model import build_world
from ..verify.sg_oracle import evaluate as evaluate_sg
from . import iam_variants, sg_variants

ROOT = Path(__file__).resolve().parents[3]
IAM_INTENT = ROOT / "experiments" / "candidate-sets" / "eval-seeded-iam" / "intent.json"
SG_INTENT = {
    "intent_version": "1", "intent_id": "fuzz-sg", "status": "active", "target_dir": "fuzz",
    "targets": {"security_groups": [sg_variants.TARGET], "attachment_points": []},
    "guarded_services": [
        {"label": "ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
         "approved_sources": {"cidrs_v4": [sg_variants.APPROVED], "cidrs_v6": [], "security_group_refs": [], "prefix_list_refs": []}},
        {"label": "rdp", "direction": "ingress", "protocol": "tcp", "from_port": 3389, "to_port": 3389,
         "approved_sources": {"cidrs_v4": [], "cidrs_v6": [], "security_group_refs": [], "prefix_list_refs": []}},
    ],
    "required_access": [{"label": "admin-ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "source_cidr": sg_variants.APPROVED}],
}
EXPECT = {"sg": {"open": "FAIL", "unapproved": "FAIL", "approved": "PASS"},
          "iam": {"excess": "FAIL", "breaks": "FAIL", "least": "PASS", "unknown": "UNKNOWN"}}


@dataclass
class FuzzResult:
    kind: str
    name: str
    family: str
    truth: str
    note: str
    trivy_flagged: Optional[bool] = None      # None = trivy 없음
    trivy_rules: List[str] = field(default_factory=list)
    plan_ok: Optional[bool] = None
    plan_error: str = ""
    oracle: str = "-"                          # PASS/FAIL/UNKNOWN/ERROR/-
    oracle_summary: str = ""
    expected: str = ""
    verdict: str = ""                          # 사람이 읽는 판정 (아래 classify)
    seconds: float = 0.0
    dir: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def classify(r: FuzzResult) -> str:
    if r.plan_ok is False:
        return "plan 실패 (V4 에서 걸림)"
    if r.oracle == "ERROR":
        return "오라클 오류"
    want = r.expected
    if want == "FAIL":
        if r.oracle == "FAIL":
            return "둘 다 탐지" if r.trivy_flagged else "스캐너 사각 · 오라클 탐지"
        if r.oracle == "UNKNOWN":
            return "오라클 판단 불가 → 사람" + ("" if r.trivy_flagged else " (스캐너도 사각)")
        return "**오라클 사각** (버그 후보)" + ("" if r.trivy_flagged else " · 스캐너도 사각")
    if want == "PASS":
        parts = []
        if r.oracle != "PASS":
            parts.append(f"오라클 오탐({r.oracle})")
        if r.trivy_flagged:
            parts.append("스캐너 오탐")
        return " · ".join(parts) if parts else "정상 통과"
    if want == "UNKNOWN":
        if r.oracle == "UNKNOWN":
            return "판단 불가 (설계대로 사람에게)"
        if r.oracle == "FAIL":
            return "FAIL (보수적, 허용)"
        return "**PASS 로 샘** (버그 후보)"
    return "?"


def _sg_intent(kwargs: Dict[str, Any]):
    d = copy.deepcopy(SG_INTENT)
    if "v6" in kwargs:
        d["guarded_services"][0]["approved_sources"]["cidrs_v6"] = kwargs["v6"]
    return parse_intent(d)


def run_one(settings: Settings, kind: str, v, out_dir: Path, trivy: TrivyAdapter, tf: TerraformAdapter, tf_ok: bool, iam_intent=None) -> FuzzResult:
    t0 = time.time()
    r = FuzzResult(kind, v.name, v.family, v.truth, v.note, expected=EXPECT[kind][v.truth])
    wd = out_dir / v.name
    if wd.exists():
        shutil.rmtree(wd)
    wd.mkdir(parents=True)
    (wd / "main.tf").write_text(v.hcl, encoding="utf-8")
    r.dir = str(wd)
    # ---- 스캐너
    if trivy.available():
        scan = trivy.scan_dir(wd, wd / "trivy.json")
        if scan.ok:
            fails = [f for f in scan.findings if f.status == "FAIL"]
            r.trivy_rules = sorted({f.rule_id for f in fails})
            if kind == "sg":
                r.trivy_flagged = any(f.rule_id == "AVD-AWS-0107" for f in fails)
            else:
                r.trivy_flagged = any(f.resource.startswith("aws_iam_") for f in fails)
        else:
            r.trivy_flagged = None
    # ---- plan + 오라클
    if tf_ok:
        steps = tf.plan_pipeline(wd, True, write_plan_json_to=wd / "plan.json")
        r.plan_ok = bool(steps.get("show") and steps["show"].ok)
        if not r.plan_ok:
            bad = next((s for s in steps.values() if not s.ok), None)
            r.plan_error = (bad.error if bad else "?")[:300]
        else:
            try:
                plan = json.loads((wd / "plan.json").read_text(encoding="utf-8"))
                if kind == "sg":
                    world = build_world(plan, {"main.tf": v.hcl})
                    rep = evaluate_sg(world, _sg_intent(v.intent_kwargs))
                else:
                    rep = evaluate_iam(build_iam_world(plan), iam_intent)
                r.oracle = rep.verdict.value
                r.oracle_summary = rep.summary[:300]
            except Exception as e:  # 오라클이 예외를 내면 그것도 결과다
                r.oracle = "ERROR"; r.oracle_summary = f"{type(e).__name__}: {e}"[:300]
        shutil.rmtree(wd / ".terraform", ignore_errors=True)
        for junk in ("plan.bin", "terraform.tfstate"):
            (wd / junk).unlink(missing_ok=True)
    r.verdict = classify(r)
    r.seconds = round(time.time() - t0, 1)
    return r


def run_variants(settings: Settings, kind: str, out_dir: Path, limit: Optional[int] = None, only: Optional[List[str]] = None,
                 log=print) -> List[FuzzResult]:
    vs = sg_variants.variants() if kind == "sg" else iam_variants.variants()
    if only:
        vs = [v for v in vs if v.name in only or v.family in only]
    if limit:
        vs = vs[:limit]
    trivy = TrivyAdapter(settings.trivy_bin)
    tf = TerraformAdapter(settings.terraform_bin, settings.aws_region, template_dir=settings.tf_template_dir())
    tf_ok = tf.info().available
    iam_intent = load_iam_intent(IAM_INTENT) if kind == "iam" else None
    out: List[FuzzResult] = []
    for i, v in enumerate(vs, 1):
        r = run_one(settings, kind, v, out_dir, trivy, tf, tf_ok, iam_intent)
        out.append(r)
        log(f"[{i:2d}/{len(vs)}] {kind} {v.name:26s} truth={v.truth:10s} trivy={'FAIL' if r.trivy_flagged else ('PASS' if r.trivy_flagged is False else '-'):5s} "
            f"oracle={r.oracle:8s} → {r.verdict}  ({r.seconds}s)")
    return out
