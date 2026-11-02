"""V6 Intent Oracle 계층 래퍼: plan JSON + 소스 HCL + Intent → LayerResult.

Trivy 결과를 입력으로 받지 않는다. 대상 SG 는 intent 가 정한다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..iam_intent import IamIntentSpec
from ..intent import IntentSpec
from ..models import LayerResult, Verdict
from .iam_oracle import build_iam_world
from .iam_oracle import evaluate as evaluate_iam
from .plan_model import PlanParseError, build_world
from .sg_oracle import OracleReport, evaluate


def v6_intent_oracle(candidate_plan: Optional[Dict[str, Any]], sources: Optional[Dict[str, str]], intent: Optional[IntentSpec],
                     intent_error: Optional[str] = None, external_prefix_lists: Optional[Dict[str, List[str]]] = None) -> LayerResult:
    if intent is None:
        return LayerResult("V6", "intent oracle", Verdict.UNKNOWN, f"intent unavailable: {intent_error or 'not provided'} — cannot judge effective state", {}, False)
    if candidate_plan is None:
        return LayerResult("V6", "intent oracle", Verdict.SKIPPED, "candidate plan json missing (V4 did not run)", {}, False)
    if isinstance(intent, IamIntentSpec):
        try:
            iam_world = build_iam_world(candidate_plan)
        except PlanParseError as e:
            return LayerResult("V6", "intent oracle", Verdict.ERROR, f"plan parse error: {e}", {}, True)
        rep = evaluate_iam(iam_world, intent)
        d = rep.to_dict()
        d["disclaimer"] = ("Proves the ALLOW set of the evaluated policy documents only (Tier 1: Allow statements, '*' wildcards). "
                           "Deny/NotAction/Condition/managed policies are UNKNOWN, never PASS. Effective permissions in the account "
                           "(SCP, permission boundary, resource policies) are not evaluated.")
        return LayerResult("V6", "intent oracle", rep.verdict, rep.summary[:1500], d, True, "iacpatch.iam_oracle")
    try:
        world = build_world(candidate_plan, sources or {}, external_prefix_lists)
    except PlanParseError as e:
        return LayerResult("V6", "intent oracle", Verdict.ERROR, f"plan parse error: {e}", {}, True)
    report: OracleReport = evaluate(world, intent)
    details = report.to_dict()
    details["disclaimer"] = ("Proves the effective ALLOW set at security-group level only. "
                             "Real reachability (NACL, routing, public IP, host firewall, listening service) is not proven here.")
    return LayerResult("V6", "intent oracle", report.verdict, report.summary[:1500], details, True, "iacpatch.sg_oracle")
