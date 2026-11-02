"""Gate — 검증 축(Validity)과 위험도 축(Risk)을 합쳐 최종 동작을 정한다.

    정책 위반            → BLOCK  (등급 무관)
    검증 FAIL            → BLOCK  (등급 무관. "위험도가 낮으니 통과"는 없다)
    검증 INCOMPLETE      → HOLD_FOR_HUMAN (자동 승인 금지)
    검증 PASS:
        자율성 HIGH      → CREATE_PR_AUTO      (PR 자동 생성, 병합 전 경량 확인. 무인 apply 금지)
        자율성 MEDIUM    → CREATE_PR_APPROVAL  (PR + 전체 증거 첨부 + 승인 필수)
        자율성 LOW       → REPORT_ONLY         (패치 커밋 안 함)

LLM 이 제안한 자율성은 **낮추는 방향으로만** 반영된다. 상한(Risk Rubric)을 넘는 제안은 무시하고 기록한다.
"""
from __future__ import annotations

from typing import List, Optional

from ..models import (
    AUTONOMY_ORDER,
    AutonomyLevel,
    GateAction,
    GateDecision,
    PolicyResult,
    RiskDecision,
    Validity,
    ValidityReport,
)


def parse_autonomy(value: Optional[str]) -> Optional[AutonomyLevel]:
    if value is None:
        return None
    v = str(value).strip().upper()
    try:
        return AutonomyLevel(v)
    except ValueError:
        return None


def decide(validity: ValidityReport, policy: PolicyResult, risk: Optional[RiskDecision],
           llm_proposed: Optional[str] = None) -> GateDecision:
    reasons: List[str] = []
    proposed = parse_autonomy(llm_proposed)
    if llm_proposed is not None and proposed is None:
        reasons.append(f"llm proposed autonomy {llm_proposed!r} is not a valid level; ignored")

    if not policy.ok:
        reasons.append("policy violation: " + "; ".join(policy.violations[:5]))
        return GateDecision(GateAction.BLOCK, validity.validity, False, risk.risk_level if risk else None,
                            risk.autonomy_cap if risk else None, proposed, None, reasons)
    if validity.validity == Validity.FAIL:
        reasons.append("verification failed: " + validity.summary)
        return GateDecision(GateAction.BLOCK, validity.validity, True, risk.risk_level if risk else None,
                            risk.autonomy_cap if risk else None, proposed, None, reasons)
    if validity.validity == Validity.INCOMPLETE or risk is None:
        reasons.append("verification incomplete: " + validity.summary if risk is not None else "risk decision unavailable")
        return GateDecision(GateAction.HOLD_FOR_HUMAN, validity.validity, True, risk.risk_level if risk else None,
                            risk.autonomy_cap if risk else None, proposed, None, reasons)

    final = risk.autonomy_cap
    if proposed is not None:
        if AUTONOMY_ORDER[proposed] < AUTONOMY_ORDER[final]:
            final = proposed
            reasons.append(f"llm proposed lower autonomy {proposed.value}; applied (cap was {risk.autonomy_cap.value})")
        elif AUTONOMY_ORDER[proposed] > AUTONOMY_ORDER[final]:
            reasons.append(f"llm proposed {proposed.value} above cap {risk.autonomy_cap.value}; ignored (cap enforced)")
        else:
            reasons.append(f"llm proposal equals cap ({final.value})")
    reasons.append(f"risk {risk.risk_level.value} (score {risk.score}) → autonomy cap {risk.autonomy_cap.value}")
    action = {
        AutonomyLevel.HIGH: GateAction.CREATE_PR_AUTO,
        AutonomyLevel.MEDIUM: GateAction.CREATE_PR_APPROVAL,
        AutonomyLevel.LOW: GateAction.REPORT_ONLY,
    }[final]
    return GateDecision(action, validity.validity, True, risk.risk_level, risk.autonomy_cap, proposed, final, reasons)
