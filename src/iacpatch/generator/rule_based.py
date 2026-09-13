"""Rule-based baseline 생성기 (비교 실험용).

의도적으로 단순하다. Trivy 가 지목한 줄을 중심으로 **리터럴** CIDR 만 승인 출처로 치환한다.

지원:
  - aws_security_group inline 블록의  cidr_blocks = ["..."] / ipv6_cidr_blocks = ["..."]  (리터럴 리스트)
  - aws_vpc_security_group_ingress_rule 의 cidr_ipv4 = "..." / cidr_ipv6 = "..." (승인 출처가 정확히 1개일 때만)
미지원 → status NOT_SUPPORTED (실패로 기록, 숨기지 않음):
  - 변수/locals/함수 경유 (var.x, local.x, join(...)), dynamic 블록, prefix list, 참조 SG, 모듈
  - 승인 출처가 비어 있어 규칙 삭제가 필요한 경우 (삭제는 정책상 금지)

이 한계가 곧 연구 질문 3(변형 대응력)의 비교 기준이다.
"""
from __future__ import annotations

import re
import uuid
from typing import Dict, List, Optional, Tuple

from ..models import EvidenceBundle, PatchCandidate

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
