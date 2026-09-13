"""검증 축 종합 (Validity). 위험도와 섞지 않는다.

규칙:
  - 필수 계층 중 하나라도 FAIL → FAIL
  - FAIL 은 없지만 UNKNOWN / SKIPPED / ERROR 가 있으면 → INCOMPLETE (통과라고 말하지 않는다. 자동 승인 금지)
  - 전부 PASS 또는 WARN → PASS (WARN 은 기록으로 남긴다)
"""
from __future__ import annotations

from typing import List

from ..models import LayerResult, Validity, ValidityReport, Verdict

PRE_DEPLOY_REQUIRED = ["V1", "V2", "V3", "V4", "V5", "V6"]
POST_DEPLOY_REQUIRED = ["V7", "V8"]


def combine(phase: str, layers: List[LayerResult]) -> ValidityReport:
    required = PRE_DEPLOY_REQUIRED if phase == "pre_deploy" else POST_DEPLOY_REQUIRED
    by = {l.layer: l for l in layers}
    fails = [l for l in layers if l.verdict == Verdict.FAIL]
    incomplete = [l for l in layers if l.verdict in (Verdict.UNKNOWN, Verdict.SKIPPED, Verdict.ERROR)]
    missing = [name for name in required if name not in by]
    if fails:
        validity = Validity.FAIL
        summary = "FAIL at " + ", ".join(f"{l.layer}({l.summary[:80]})" for l in fails)
    elif incomplete or missing:
        validity = Validity.INCOMPLETE
        parts = [f"{l.layer}={l.verdict.value}" for l in incomplete] + [f"{m}=missing" for m in missing]
        summary = "INCOMPLETE: " + ", ".join(parts) + " — not a pass; human review required"
    else:
        validity = Validity.PASS
        warns = [l.layer for l in layers if l.verdict == Verdict.WARN]
        summary = "all required layers passed" + (f" (warnings: {', '.join(warns)})" if warns else "")
    return ValidityReport(phase, layers, validity, summary)
