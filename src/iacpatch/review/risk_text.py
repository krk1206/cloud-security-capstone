"""B 4주차 — plan 없이(HCL 텍스트 근거로) 하는 잠정 위험도 판정.

정직성 원칙:
  - 텍스트 diff 로 알 수 있는 것만 근거로 쓴다: 어떤 최상위 블록(resource/provider/...)이 바뀌었는지, 리소스 블록이
    사라졌는지/새로 생겼는지, 리소스 안에서 어떤 속성 이름이 바뀌었는지, 줄 수.
  - 알 수 없는 것은 "미확정" 으로 남긴다: 실제 삭제/교체 여부(plan 액션), 같은 ENI 에 붙은 다른 SG(영향 범위), provider 설정의 의미 동등성.
  - plan JSON 이 있으면 policy/risk.score_risk(plan 기반) 결과가 우선이고, 이 모듈은 보조 근거만 보탠다.
  - 점수·조건은 policy/risk_rubric.json 의 잠정 기준표를 그대로 읽는다. 근거 없는 확률/점수는 만들지 않는다.
  - 위험도 LOW ≠ 자동 반영 가능. 검토 수준은 review/level.py 가 따로 정한다.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..models import RISK_TO_AUTONOMY_CAP, RiskDecision, RiskLevel
from ..policy.validator import extract_top_level_blocks

_RES_HEADER_RE = re.compile(r'^resource\s+"([^"]+)"\s+"([^"]+)"$')
_ATTR_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(=|\{)')


@dataclass
class HclChange:
    """원본 ↔ 후보의 최상위 블록 수준 변경 요약 (텍스트 근거)."""
    removed_resources: List[str] = field(default_factory=list)      # "aws_security_group.x"
    added_resources: List[str] = field(default_factory=list)
    changed_resources: Dict[str, List[str]] = field(default_factory=dict)   # 주소 → 바뀐 속성/블록 이름
    type_changed: List[str] = field(default_factory=list)            # 같은 이름, 다른 타입
    non_resource_blocks_changed: List[str] = field(default_factory=list)    # provider/terraform/variable/...
    unparsable: List[str] = field(default_factory=list)              # 블록을 못 읽은 파일
    added_lines: int = 0
    removed_lines: int = 0
    files_changed: List[str] = field(default_factory=list)

    def resource_types(self) -> List[str]:
        out = []
        for a in self.removed_resources + self.added_resources + list(self.changed_resources):
            out.append(a.split(".")[0])
        return out


def _norm_body(body: str) -> str:
    return "\n".join(l.strip() for l in body.strip().splitlines() if l.strip())


def _changed_attr_names(a: str, b: str) -> List[str]:
    """두 블록 본문의 줄 diff 에서 바뀐 줄의 속성/블록 이름을 모은다 (중첩 깊이는 구분하지 않는다)."""
    names: List[str] = []
    for line in difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="", n=0):
        if line.startswith(("+++", "---", "@@")):
            continue
        if line[:1] in "+-":
            m = _ATTR_RE.match(line[1:])
            if m and m.group(1) not in names:
                names.append(m.group(1))
    # 속성 이름을 못 찾은 변경(값 줄만 바뀐 리스트 원소 등)은 'ingress'/'egress' 같은 블록 안일 수 있으므로 상위 블록 이름을 찾는다
    return names


def _enclosing_block_names(a: str, b: str) -> List[str]:
    """변경된 줄이 속한 중첩 블록(ingress/egress/...) 이름. 줄 단위 중괄호 추적(휴리스틱)."""
    def stack_at(lines: List[str]) -> List[List[str]]:
        stacks: List[List[str]] = []
        st: List[str] = []
        for line in lines:
            stacks.append(list(st))
            s = line.strip()
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\{', s)
            if m:
                st.append(m.group(1))
            if s.startswith("}") or s.endswith("}"):
                if st:
                    st.pop()
        return stacks
    al, bl = a.splitlines(), b.splitlines()
    sa, sb = stack_at(al), stack_at(bl)
    out: List[str] = []
    sm = difflib.SequenceMatcher(a=al, b=bl)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        for i in range(i1, min(i2, len(sa))):
            if sa[i] and sa[i][0] not in out:
                out.append(sa[i][0])
        for j in range(j1, min(j2, len(sb))):
            if sb[j] and sb[j][0] not in out:
                out.append(sb[j][0])
    return out


def diff_hcl(original: Dict[str, str], candidate: Dict[str, str]) -> HclChange:
    ch = HclChange()
    for name, new in candidate.items():
        old = original.get(name, "")
        if old == new:
            continue
        ch.files_changed.append(name)
        for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
            if line.startswith("+") and not line.startswith("+++"):
                ch.added_lines += 1
            elif line.startswith("-") and not line.startswith("---"):
                ch.removed_lines += 1
        try:
            ob = extract_top_level_blocks(old)
            nb = extract_top_level_blocks(new)
        except Exception:  # pragma: no cover - 방어
            ch.unparsable.append(name)
            continue
        if new.strip() and not nb and "{" in new:
            ch.unparsable.append(name)
        o_res: Dict[Tuple[str, str], str] = {}
        n_res: Dict[Tuple[str, str], str] = {}
        o_other: Dict[str, str] = {}
        n_other: Dict[str, str] = {}
        for header, body in ob:
            m = _RES_HEADER_RE.match(header)
            (o_res.__setitem__((m.group(1), m.group(2)), body) if m else o_other.__setitem__(header, _norm_body(body)))
        for header, body in nb:
            m = _RES_HEADER_RE.match(header)
            (n_res.__setitem__((m.group(1), m.group(2)), body) if m else n_other.__setitem__(header, _norm_body(body)))
        o_names = {n: t for (t, n) in o_res}
        n_names = {n: t for (t, n) in n_res}
        for key, body in o_res.items():
            t, n = key
            if key not in n_res:
                if n in n_names and n_names[n] != t:
                    ch.type_changed.append(f"{t}.{n} → {n_names[n]}.{n}")
                else:
                    ch.removed_resources.append(f"{t}.{n}")
            elif _norm_body(body) != _norm_body(n_res[key]):
                attrs = _changed_attr_names(body, n_res[key])
                blocks = _enclosing_block_names(body, n_res[key])
                names = []
                for x in blocks + attrs:
                    if x not in names:
                        names.append(x)
                ch.changed_resources[f"{t}.{n}"] = names or ["(속성 이름 식별 불가)"]
        for key in n_res:
            if key not in o_res and key[1] not in o_names:
                ch.added_resources.append(f"{key[0]}.{key[1]}")
        for h in sorted(set(o_other) | set(n_other)):
            if o_other.get(h) != n_other.get(h):
                ch.non_resource_blocks_changed.append(h)
    return ch


def score_risk_text(rubric: Dict[str, Any], change: HclChange) -> RiskDecision:
    """텍스트 근거만으로 잠정 위험도를 낸다. 미확정 항목은 factors 에 points=0, note='미확정' 으로 남긴다."""
    pts = rubric.get("points") or {}
    th = rubric.get("thresholds") or {"low_max": 2, "medium_max": 5}
    hard = rubric.get("hard_high_conditions") or {}
    iam_prefixes = tuple(rubric.get("iam_type_prefixes") or ["aws_iam_"])
    network_types = set(rubric.get("network_types") or [])
    replace_attrs = rubric.get("replace_forcing_attributes") or {}
    factors: List[Dict[str, Any]] = []
    score = 0
    hard_hit: List[str] = []

    def add(factor: str, value: Any, points: int, note: str = "") -> None:
        nonlocal score
        score += points
        factors.append({"factor": factor, "value": value, "points": points, "note": note, "basis": "text"})

    if change.unparsable:
        factors.append({"factor": "hcl_unparsable", "value": change.unparsable, "points": 0, "note": "블록 구조를 읽지 못해 근거 부족", "basis": "text"})

    types = change.resource_types()
    iam_touched = any(t.startswith(iam_prefixes) for t in types)
    if hard.get("iam_resource_touched") and iam_touched:
        hard_hit.append("iam_resource_touched")
    trust_changed = [a for a, attrs in change.changed_resources.items() if a.startswith("aws_iam_role.") and "assume_role_policy" in attrs]
    if hard.get("iam_trust_policy_changed") and trust_changed:
        hard_hit.append("iam_trust_policy_changed")
    if hard.get("resource_deleted") and (change.removed_resources or change.type_changed):
        hard_hit.append("resource_block_removed_or_retyped (plan 으로 삭제/교체 확정 필요)")
    for h in hard_hit:
        factors.append({"factor": h, "value": True, "points": 0, "note": "hard condition → HIGH (점수와 무관)", "basis": "text"})

    non_network = [t for t in types if t not in network_types]
    add("non_network_resource_touched", non_network, pts.get("non_network_resource_touched", 2) if non_network else 0)
    n_touched = len(change.removed_resources) + len(change.added_resources) + len(change.changed_resources) + len(change.type_changed)
    if n_touched > 3:
        add("resources_touched", n_touched, pts.get("resources_touched_over_3", 3))
    elif n_touched >= 2:
        add("resources_touched", n_touched, pts.get("resources_touched_2_to_3", 1))
    else:
        add("resources_touched", n_touched, 0)
    add("new_resource_blocks", change.added_resources, min(len(change.added_resources) * pts.get("new_resource_created_each", 1), pts.get("new_resource_created_cap", 2)))
    egress = any("egress" in attrs for attrs in change.changed_resources.values())
    add("egress_changed", egress, pts.get("egress_changed", 1) if egress else 0)
    replace_risk = []
    other_attr = False
    # SG 규칙 블록(ingress/egress) 안의 속성은 "규칙 변경" 이지 "규칙 밖 속성 변경" 이 아니다
    rule_attrs = {"ingress", "egress", "description", "tags", "tags_all", "(속성 이름 식별 불가)",
                  "cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids", "security_groups", "self", "from_port", "to_port", "protocol",
                  "cidr_ipv4", "cidr_ipv6", "prefix_list_id", "referenced_security_group_id", "ip_protocol"}
    for addr, attrs in change.changed_resources.items():
        t = addr.split(".")[0]
        for a in attrs:
            if a in (replace_attrs.get(t) or []):
                replace_risk.append(f"{addr}.{a}")
            elif a not in rule_attrs:
                other_attr = True
    add("replace_forcing_attribute_changed", replace_risk, pts.get("replace_forcing_attribute_changed_text_basis", 3) if replace_risk else 0,
        "교체(destroy+create) 가능성 — plan 으로 확정 필요" if replace_risk else "")
    add("non_rule_attribute_changed", other_attr, pts.get("non_rule_attribute_changed", 1) if other_attr else 0)
    add("non_resource_block_changed", change.non_resource_blocks_changed, pts.get("non_resource_block_changed", 2) if change.non_resource_blocks_changed else 0,
        "provider/terraform/variable 등 리소스 밖 블록 변경" if change.non_resource_blocks_changed else "")
    lines = change.added_lines + change.removed_lines
    add("patch_lines", lines, pts.get("patch_lines_over_40", 1) if lines > 40 else 0)
    add("files_changed", len(change.files_changed), pts.get("multiple_files_changed", 1) if len(change.files_changed) > 1 else 0)
    for u in rubric.get("text_basis_undetermined") or []:
        factors.append({"factor": "undetermined", "value": u, "points": 0, "note": "미확정 — plan/AWS 정보 필요", "basis": "text"})

    if change.unparsable and not change.changed_resources and not change.removed_resources and not change.added_resources:
        level = RiskLevel.HIGH
        factors.append({"factor": "insufficient_basis", "value": True, "points": 0, "note": "판정 근거 부족 → 보수적으로 HIGH", "basis": "text"})
    elif hard_hit:
        level = RiskLevel.HIGH
    elif score <= int(th.get("low_max", 2)):
        level = RiskLevel.LOW
    elif score <= int(th.get("medium_max", 5)):
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.HIGH
    floor = rubric.get("medium_floor_conditions") or {}
    if floor.get("iam_resource_touched") and iam_touched:
        raised = level == RiskLevel.LOW
        if raised:
            level = RiskLevel.MEDIUM
        factors.append({"factor": "iam_resource_touched", "value": True, "points": 0,
                        "note": "medium floor → 최소 MEDIUM (사람 승인 필수)" + ("" if raised else " (score already above LOW)"), "basis": "text"})
    return RiskDecision(level, RISK_TO_AUTONOMY_CAP[level], score, factors, str(rubric.get("rubric_version", "")) + " [text basis]")


def merge_with_plan_based(text_decision: RiskDecision, plan_decision: Optional[RiskDecision]) -> RiskDecision:
    """plan 기반 판정이 있으면 그것을 우선하고, 텍스트 근거를 factors 뒤에 덧붙인다 (두 등급 중 높은 쪽)."""
    if plan_decision is None:
        return text_decision
    order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}
    level = plan_decision.risk_level if order[plan_decision.risk_level] >= order[text_decision.risk_level] else text_decision.risk_level
    factors = [dict(f, basis=f.get("basis", "plan")) for f in plan_decision.factors] + [f for f in text_decision.factors if f["factor"] != "undetermined"]
    return RiskDecision(level, RISK_TO_AUTONOMY_CAP[level], plan_decision.score + text_decision.score, factors,
                        plan_decision.rubric_version + " [plan basis + text basis]")
