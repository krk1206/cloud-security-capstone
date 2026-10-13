"""검토 수준(ReviewLevel) 판정 — 검증 상태와 위험도를 합쳐 "사람이 어떤 검토를 해야 하는가"를 정한다.

이 버전에는 '자동 반영' 이 없다. 위험도 LOW 라도 사람 확인(LIGHT_REVIEW) 이 필요하고, apply 는 항상 사람이 한다.

    정책 위반            → BLOCKED
    검증 FAIL            → BLOCKED           (위험도와 무관)
    검증 INCOMPLETE      → PENDING           (NOT_RUN/UNKNOWN 이 남아 있음 — 검토 수준을 정할 수 없다)
    위험도 근거 부족      → REPORT_ONLY
    위험도 HIGH          → REPORT_ONLY       (패치 반영 금지, 리포트만)
    위험도 MEDIUM        → FULL_REVIEW
    위험도 LOW           → LIGHT_REVIEW      (필수 정보 누락(needs_info) 이 있으면 FULL_REVIEW 로 올린다)
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from ..models import PolicyResult, ReviewLevel, RiskDecision, RiskLevel, Validity, ValidityReport


def decide_review_level(validity: ValidityReport, policy: Optional[PolicyResult], risk: Optional[RiskDecision],
                        needs_info: List[str]) -> Tuple[ReviewLevel, List[str]]:
    reasons: List[str] = []
    if policy is not None and not policy.ok:
        reasons.append("정책 위반: " + "; ".join(policy.violations[:3]))
        return ReviewLevel.BLOCKED, reasons
    if validity.validity == Validity.FAIL:
        reasons.append("검증 실패: " + validity.summary)
        return ReviewLevel.BLOCKED, reasons
    if validity.validity == Validity.INCOMPLETE:
        reasons.append("검증 대기: " + validity.summary)
        reasons.append("검증 결과가 전부 있기 전에는 검토 수준을 정하지 않는다 (위험도는 참고용으로만 표시)")
        return ReviewLevel.PENDING, reasons
    if risk is None:
        reasons.append("위험도 판정 없음 → 리포트만")
        return ReviewLevel.REPORT_ONLY, reasons
    if any(f.get("factor") == "insufficient_basis" for f in risk.factors):
        reasons.append("위험도 판정 근거 부족 (HCL 구조를 읽지 못함) → 리포트만")
        return ReviewLevel.REPORT_ONLY, reasons
    reasons.append(f"위험도 {risk.risk_level.value} (점수 {risk.score}, {risk.rubric_version})")
    if risk.risk_level == RiskLevel.HIGH:
        reasons.append("위험도 HIGH → 패치 반영 금지, 리포트만")
        return ReviewLevel.REPORT_ONLY, reasons
    if risk.risk_level == RiskLevel.MEDIUM:
        return ReviewLevel.FULL_REVIEW, reasons
    if needs_info:
        reasons.append("필수 정보 누락(" + "; ".join(needs_info) + ") → 경량 검토 대신 정식 검토")
        return ReviewLevel.FULL_REVIEW, reasons
    reasons.append("경량 검토: 사람 1인이 diff 와 검증 표를 확인한 뒤 진행 (자동 반영 아님)")
    return ReviewLevel.LIGHT_REVIEW, reasons
