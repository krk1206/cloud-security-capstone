"""Rule-based baseline 생성기 (비교 실험용).

의도적으로 단순하다. Trivy 가 지목한 줄을 중심으로 **리터럴** CIDR 만 승인 출처로 치환한다.

지원:
  - aws_security_group inline 블록의  cidr_blocks = ["..."] / ipv6_cidr_blocks = ["..."]  (리터럴 리스트)
  - aws_vpc_security_group_ingress_rule 의 cidr_ipv4 = "..." / cidr_ipv6 = "..." (승인 출처가 정확히 1개일 때만)
미지원 → status NOT_SUPPORTED (실패로 기록, 숨기지 않음):
  - 변수/locals/함수 경유 (var.x, local.x, join(...)), dynamic 블록, prefix list, 참조 SG, 모듈
  - 승인 출처가 비어 있어 규칙 삭제가 필요한 경우 (삭제는 정책상 금지)

IAM (Tier 1, intent kind=iam):
  - Trivy 가 지목한 aws_iam_policy / aws_iam_role_policy 블록 안에 **Statement 가 하나**이고 Action/Resource 가 리터럴(문자열 또는
    문자열 리스트)일 때, intent 의 approved_permissions 가 **하나**면 그 actions/resources 로 통째로 치환한다.
  - 미지원 → NOT_SUPPORTED: Statement 2개 이상, NotAction/Condition/Deny, 변수·함수 경유, data.aws_iam_policy_document,
    approved_permissions 가 2개 이상(문을 나눠야 함), 신뢰 정책(assume_role_policy) 이 지목된 경우.

이 한계가 곧 연구 질문 3(변형 대응력)의 비교 기준이다.
"""
from __future__ import annotations

import re
import uuid
from typing import Dict, List, Optional, Tuple

from ..models import EvidenceBundle, PatchCandidate

_RES_HEADER_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
_IAM_ATTR_RE = re.compile(r'^(\s*)(Action|Resource|NotAction|NotResource|Effect|Condition|Principal)(\s*=\s*)(.*)$')
_LIST_LITERAL_RE = re.compile(r'^(\s*)(cidr_blocks|ipv6_cidr_blocks)(\s*=\s*)\[([^\]]*)\](.*)$')
_SINGLE_LITERAL_RE = re.compile(r'^(\s*)(cidr_ipv4|cidr_ipv6)(\s*=\s*)"([^"]*)"(.*)$')
_PORT_RE = re.compile(r'^\s*(from_port|to_port)\s*=\s*(\d+)')
_STR_ITEM_RE = re.compile(r'"([^"]*)"')


def _fmt_list(items: List[str]) -> str:
    return "[" + ", ".join(f'"{c}"' for c in items) + "]"


def _enclosing_block_range(lines: List[str], idx: int) -> Tuple[int, int]:
    """idx 줄을 포함하는 가장 안쪽 `{ ... }` 블록의 (시작, 끝) 인덱스 (휴리스틱: 줄 단위 중괄호 카운트)."""
    depth = 0
    start = idx
    for i in range(idx, -1, -1):
        opens = lines[i].count("{")
        closes = lines[i].count("}")
        depth += closes - opens
        if depth < 0:
            start = i
            break
    depth = 0
    end = idx
    for i in range(idx, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth < 0:
            end = i
            break
    return start, end


def _services_by_port(bundle: EvidenceBundle) -> Dict[Tuple[int, int], Dict[str, List[str]]]:
    out: Dict[Tuple[int, int], Dict[str, List[str]]] = {}
    for g in (bundle.intent.get("guarded_services") or []):
        try:
            key = (int(g["from_port"]), int(g["to_port"]))
        except (KeyError, TypeError, ValueError):
            continue
        ap = g.get("approved_sources") or {}
        out[key] = {"v4": list(ap.get("cidrs_v4") or []), "v6": list(ap.get("cidrs_v6") or [])}
    return out


class RuleBasedGenerator:
    name = "rule_based"
    VERSION = "rule-v1"

    def generate(self, bundle: EvidenceBundle, feedback: Optional[str] = None, attempt: int = 1) -> PatchCandidate:
        cid = f"cand-{uuid.uuid4().hex[:8]}"
        base = dict(candidate_id=cid, origin="rule_based", generator=f"rule_based:{self.VERSION}", attempt=attempt, model="")
        if not bundle.intent:
            return PatchCandidate(status="INSUFFICIENT_INFO", files={}, rationale="no intent (approved sources) available", **base)
        if str(bundle.intent.get("kind", "")).lower() == "iam":
            return self._generate_iam(bundle, base)
        fname = bundle.finding.filename
        text = bundle.files.get(fname)
        if text is None:
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"flagged file {fname} not in bundle", **base)
        lines = text.splitlines()
        idx = bundle.finding.start_line - 1
        if idx < 0 or idx >= len(lines):
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error="flagged line out of range", **base)
        services = _services_by_port(bundle)
        start, end = _enclosing_block_range(lines, idx)
        block = lines[start:end + 1]
        ports: Dict[str, int] = {}
        for l in block:
            m = _PORT_RE.match(l)
            if m:
                ports[m.group(1)] = int(m.group(2))
        if "from_port" not in ports or "to_port" not in ports:
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error="could not determine port range in the enclosing block (non-literal ports?)", **base)
        key = (ports["from_port"], ports["to_port"])
        if key not in services:
            return PatchCandidate(status="INSUFFICIENT_INFO", files={}, rationale=f"no guarded service in intent for ports {key}", **base)
        approved = services[key]
        changed = False
        notes: List[str] = []
        for i in range(start, end + 1):
            line = lines[i]
            m = _LIST_LITERAL_RE.match(line)
            if m:
                indent, attr, eq, inner, tail = m.groups()
                if inner.strip() and not _STR_ITEM_RE.search(inner):
                    return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"{attr} is not a literal list: {inner.strip()!r}", **base)
                if any(tok.strip() and not tok.strip().startswith('"') for tok in inner.split(",")):
                    return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"{attr} contains non-literal items: {inner.strip()!r}", **base)
                target = approved["v4"] if attr == "cidr_blocks" else approved["v6"]
                current = _STR_ITEM_RE.findall(inner)
                if attr == "cidr_blocks" and not target:
                    return PatchCandidate(status="NOT_SUPPORTED", files={}, error="approved IPv4 sources empty; rule removal required (deletion not allowed for baseline)", **base)
                if current != target:
                    lines[i] = f"{indent}{attr}{eq}{_fmt_list(target)}{tail}"
                    changed = True
                    notes.append(f"{attr}: {current} → {target}")
                continue
            m = _SINGLE_LITERAL_RE.match(line)
            if m:
                indent, attr, eq, val, tail = m.groups()
                target = approved["v4"] if attr == "cidr_ipv4" else approved["v6"]
                if len(target) != 1:
                    return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"{attr} is a single value but {len(target)} approved sources; baseline cannot split rules", **base)
                if val != target[0]:
                    lines[i] = f'{indent}{attr}{eq}"{target[0]}"{tail}'
                    changed = True
                    notes.append(f"{attr}: {val} → {target[0]}")
        if not changed:
            flagged = lines[idx].strip()
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"no literal CIDR attribute found in the enclosing block (flagged line: {flagged!r})", **base)
        new_text = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        return PatchCandidate(status="PATCH", files={fname: new_text}, rationale="rule-based literal replacement: " + "; ".join(notes),
                              proposed_autonomy=None, assumptions=["literal CIDR replacement only"], **base)


    # ------------------------------------------------------------------ IAM (Tier 1)
    def _generate_iam(self, bundle: EvidenceBundle, base: Dict) -> PatchCandidate:
        fname = bundle.finding.filename
        text = bundle.files.get(fname)
        if text is None:
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"flagged file {fname} not in bundle", **base)
        lines = text.splitlines()
        idx = bundle.finding.start_line - 1
        if idx < 0 or idx >= len(lines):
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error="flagged line out of range", **base)
        approved = bundle.intent.get("approved_permissions") or []
        if len(approved) != 1:
            return PatchCandidate(status="NOT_SUPPORTED", files={},
                                  error=f"baseline handles exactly one approved_permissions entry (got {len(approved)}); splitting statements is not supported", **base)
        actions = [str(a) for a in (approved[0].get("actions") or [])]
        resources = [str(r) for r in (approved[0].get("resources") or [])]
        if not actions or not resources:
            return PatchCandidate(status="INSUFFICIENT_INFO", files={}, rationale="approved_permissions entry has empty actions/resources", **base)
        # 지목된 줄을 포함하는 resource 블록 찾기 (위로 헤더, 아래로 짝 닫힘)
        start = None
        for i in range(idx, -1, -1):
            m = _RES_HEADER_RE.match(lines[i])
            if m:
                start = i
                rtype, rname = m.group(1), m.group(2)
                break
        if start is None:
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error="flagged line is not inside a resource block", **base)
        if rtype not in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"flagged resource type {rtype} is not an inline-policy resource (trust policy or attachment?)", **base)
        depth = 0
        end = start
        for i in range(start, len(lines)):
            depth += lines[i].count("{") - lines[i].count("}")
            if depth <= 0 and i > start:
                end = i
                break
        block = lines[start:end + 1]
        if any("data.aws_iam_policy_document" in l or "file(" in l or "templatefile(" in l or "var." in l or "local." in l for l in block):
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error="policy is built from a data source / variable / file — not a literal document", **base)
        attr_lines: Dict[str, List[int]] = {}
        for i in range(start, end + 1):
            m = _IAM_ATTR_RE.match(lines[i])
            if m:
                attr_lines.setdefault(m.group(2), []).append(i)
        if len(attr_lines.get("Effect", [])) != 1 or "Statement" not in "".join(block):
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"baseline handles exactly one Statement (found {len(attr_lines.get('Effect', []))} Effect lines)", **base)
        for bad in ("NotAction", "NotResource", "Condition", "Principal"):
            if bad in attr_lines:
                return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"{bad} present — baseline only rewrites plain Allow Action/Resource", **base)
        eff = lines[attr_lines["Effect"][0]]
        if '"Allow"' not in eff:
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error="statement is not a plain Allow", **base)
        if len(attr_lines.get("Action", [])) != 1 or len(attr_lines.get("Resource", [])) != 1:
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error="need exactly one literal Action and one literal Resource line", **base)
        notes: List[str] = []
        changed = False
        for attr, target in (("Action", actions), ("Resource", resources)):
            i = attr_lines[attr][0]
            m = _IAM_ATTR_RE.match(lines[i])
            indent, _a, eq, val = m.group(1), m.group(2), m.group(3), m.group(4).strip()
            if not (val.startswith('"') or val.startswith("[")):
                return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"{attr} is not a literal: {val!r}", **base)
            if val.startswith("[") and any(tok.strip() and not tok.strip().startswith('"') for tok in val.strip("[]").split(",") if tok.strip()):
                return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"{attr} list contains non-literal items: {val!r}", **base)
            current = _STR_ITEM_RE.findall(val)
            if current != target:
                lines[i] = f"{indent}{attr}{eq}{_fmt_list(target)}"
                changed = True
                notes.append(f"{attr}: {current} → {target}")
        if not changed:
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error="Action/Resource already equal the approved set; nothing to change", **base)
        new_text = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        return PatchCandidate(status="PATCH", files={fname: new_text},
                              rationale="rule-based IAM literal replacement (single Allow statement → approved actions/resources): " + "; ".join(notes),
                              proposed_autonomy=None, assumptions=["single-statement literal Action/Resource replacement only"], **base)
