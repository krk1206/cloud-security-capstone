"""Risk Rubric Scorer — 결정론적 위험도 산정 → 자율성 상한.

입력은 전부 검증 계층/plan 에서 나온 사실이다. LLM 출력(확신도 등)은 입력이 아니다.
  - V5 details: removed / added / changed / plan_actions_delete / plan_actions_replace / provider_config_diff
  - 후보 plan 의 SGWorld: 변경된 SG 가 붙은 부착 지점 수, 외부/미확정 SG 여부
  - Policy Validator diff 통계: 변경 줄 수, 파일 수
  - V6 report: partial rules / caveats 여부 (증거 충분성)

출력: RiskDecision(risk_level, autonomy_cap, score, factors). "High = 안전"이 아니라 "사전 기준상 상대적으로 자동화 가능"이다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models import RISK_TO_AUTONOMY_CAP, RiskDecision, RiskLevel
from ..verify.sgmodel import SGWorld


def score_risk(rubric: Dict[str, Any], v5_details: Dict[str, Any], world: Optional[SGWorld],
               diff_stats: Dict[str, Any], v6_details: Optional[Dict[str, Any]] = None) -> RiskDecision:
    pts = rubric.get("points") or {}
    th = rubric.get("thresholds") or {"low_max": 2, "medium_max": 5}
    hard = rubric.get("hard_high_conditions") or {}
    iam_prefixes = tuple(rubric.get("iam_type_prefixes") or ["aws_iam_"])
    network_types = set(rubric.get("network_types") or [])
    factors: List[Dict[str, Any]] = []
    score = 0
    hard_hit: List[str] = []

    def add(factor: str, value: Any, points: int, note: str = "") -> None:
        nonlocal score
        score += points
        factors.append({"factor": factor, "value": value, "points": points, "note": note})

    removed = list(v5_details.get("removed") or [])
    added = list(v5_details.get("added") or [])
    changed = dict(v5_details.get("changed") or {})
    deletes = list(v5_details.get("plan_actions_delete") or [])
    replaces = list(v5_details.get("plan_actions_replace") or [])
    pdiff = list(v5_details.get("provider_config_diff") or [])

    touched_types: List[str] = []
    for a in added:
        touched_types.append(str(a.get("type") if isinstance(a, dict) else a))
    if world is not None:
        for addr in list(changed) + removed:
            t = addr.split(".")[0] if not addr.startswith("module.") else addr.split(".")[-2]
            touched_types.append(t)
    else:
        for addr in list(changed) + removed:
            touched_types.append(addr.split(".")[0])

    # hard conditions
    if hard.get("iam_resource_touched") and any(t.startswith(iam_prefixes) for t in touched_types):
        hard_hit.append("iam_resource_touched")
    if hard.get("resource_deleted") and (removed or deletes):
        hard_hit.append("resource_deleted")
    if hard.get("resource_replaced") and replaces:
        hard_hit.append("resource_replaced")
    if hard.get("provider_config_changed") and pdiff:
        hard_hit.append("provider_config_changed")
    for h in hard_hit:
        factors.append({"factor": h, "value": True, "points": 0, "note": "hard condition → HIGH risk regardless of score"})

    # points
    non_network = [t for t in touched_types if t not in network_types]
    add("non_network_resource_touched", non_network, pts.get("non_network_resource_touched", 2) if non_network else 0)
    n_touched = len(removed) + len(added) + len(changed)
    if n_touched > 3:
        add("resources_touched", n_touched, pts.get("resources_touched_over_3", 3))
    elif n_touched >= 2:
        add("resources_touched", n_touched, pts.get("resources_touched_2_to_3", 1))
    else:
        add("resources_touched", n_touched, 0)
    n_new = len(added)
    add("new_resources_created", n_new, min(n_new * pts.get("new_resource_created_each", 1), pts.get("new_resource_created_cap", 2)))

    # blast radius from attachments of changed SGs
    ap_count = 0
    ext = False
    if world is not None:
        changed_sgs = [a for a in list(changed) + [x.get("address") if isinstance(x, dict) else x for x in added] if str(a).startswith("aws_security_group.")]
        # 별도 규칙 리소스가 바뀐 경우 그 규칙이 붙는 SG 도 포함
        for sg in world.security_groups.values():
            for r in sg.rules:
                if r.origin in changed or any(r.origin == (x.get("address") if isinstance(x, dict) else x) for x in added):
                    changed_sgs.append(sg.address)
        seen = set()
        for sg_addr in changed_sgs:
            for ap in world.attachments_of(sg_addr):
                if ap.address in seen:
                    continue
                seen.add(ap.address)
                ap_count += 1
                if ap.external_sg_ids or ap.unknown:
                    ext = True
    if ap_count >= 2:
        add("attachment_points", ap_count, pts.get("attachment_points_2_or_more", 2))
    elif ap_count == 1:
        add("attachment_points", ap_count, pts.get("attachment_points_1", 1))
    else:
        add("attachment_points", ap_count, 0, "no attachment in plan (standalone SG)")
    add("attachment_has_external_or_unknown_sg", ext, pts.get("attachment_has_external_or_unknown_sg", 2) if ext else 0)

    egress_changed = any("egress" in attrs for attrs in changed.values())
    add("egress_changed", egress_changed, pts.get("egress_changed", 1) if egress_changed else 0)
    non_rule_attr = any(any(a not in ("ingress", "egress") for a in attrs) for attrs in changed.values())
    add("non_rule_attribute_changed", non_rule_attr, pts.get("non_rule_attribute_changed", 1) if non_rule_attr else 0)

    partial_or_caveat = False
    if v6_details:
        for t in v6_details.get("targets") or []:
            for sc in t.get("scopes") or []:
                if any(s.get("partial_rules") for s in sc.get("services") or []):
                    partial_or_caveat = True
                # 'inline egress not declared' 류의 caveat 은 흔하므로 ingress 관련 caveat 만 센다
                if any("ingress" in c for c in sc.get("caveats") or []):
                    partial_or_caveat = True
    add("oracle_partial_rules_or_caveats", partial_or_caveat, pts.get("oracle_partial_rules_or_caveats", 1) if partial_or_caveat else 0)

    lines = int(diff_stats.get("added_lines", 0)) + int(diff_stats.get("removed_lines", 0))
    add("patch_lines", lines, pts.get("patch_lines_over_40", 1) if lines > 40 else 0)
    files = int(diff_stats.get("files", 1))
    add("files_changed", files, pts.get("multiple_files_changed", 1) if files > 1 else 0)

    if hard_hit:
        level = RiskLevel.HIGH
    elif score <= int(th.get("low_max", 2)):
        level = RiskLevel.LOW
    elif score <= int(th.get("medium_max", 5)):
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.HIGH
    return RiskDecision(level, RISK_TO_AUTONOMY_CAP[level], score, factors, str(rubric.get("rubric_version", "")))
