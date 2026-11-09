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

설계도(intent kind=topology, D-45 · 2026-11-03):
  - 연결한 프로젝트의 설계도(③)에는 포트별 승인 출처가 없고 "누가 → 어느 계층 : 포트" 화살표(flows)만 있다. 그래서 지목된 규칙이 속한
    보안 그룹 → 그 보안 그룹을 단 계층(tiers[].security_group) → 그 계층으로 들어오는 flows 가운데 **외부(external) 출발** 인 것의
    cidrs_v4 를 포트별 승인 출처로 바꿔 쓴다 (_services_from_topology). 그 뒤는 위와 같은 리터럴 치환이다.
  - 미지원 → NOT_SUPPORTED: 그 포트가 설계도에서 **다른 계층(보안 그룹 참조)에서만** 들어오는 경우 (규칙 기반은 IP 목록만 바꾸고
    보안 그룹 참조로 바꾸지 못한다), 설계도에 그 포트로 들어오는 통신이 없는 경우 (규칙 삭제가 필요 — 삭제 금지).
  - INSUFFICIENT_INFO: 지목된 보안 그룹이 설계도의 어느 계층에도 없는 경우 (③ 에서 계층으로 넣어야 한다).
  설계도가 0.0.0.0/0 을 허용하면 바꿀 것이 없어 NOT_SUPPORTED("설계도와 이미 같음") — 설계도 자체가 공개를 허용한 것이므로 ③ 에서 고친다.

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


_SG_REF_RE = re.compile(r'security_group_id\s*=\s*aws_security_group\.([A-Za-z0-9_-]+)\.id\b')


def _enclosing_resource(lines: List[str], idx: int) -> Optional[Tuple[str, str, int, int]]:
    """idx 줄을 포함하는 resource 블록 (type, name, start, end). 없으면 None."""
    start = None
    for i in range(idx, -1, -1):
        m = _RES_HEADER_RE.match(lines[i])
        if m:
            start, rtype, rname = i, m.group(1), m.group(2)
            break
    if start is None:
        return None
    depth = 0
    end = start
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0 and i > start:
            end = i
            break
    return rtype, rname, start, end


def flagged_security_group(bundle: EvidenceBundle, lines: List[str], idx: int) -> Optional[str]:
    """지목된 줄이 속한 보안 그룹 주소 ('aws_security_group.<이름>'). inline 규칙이면 그 블록, 따로 쓴 규칙 리소스면 security_group_id 참조."""
    res = _enclosing_resource(lines, idx)
    if res is not None:
        rtype, rname, start, end = res
        if rtype == "aws_security_group":
            return f"aws_security_group.{rname}"
        if rtype in ("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule", "aws_security_group_rule"):
            m = _SG_REF_RE.search("\n".join(lines[start:end + 1]))
            return f"aws_security_group.{m.group(1)}" if m else None
    addr = str(bundle.finding.resource or "")
    return addr if addr.startswith("aws_security_group.") and addr.count(".") == 1 else None


class TopologyAdapterError(Exception):
    """설계도 → 포트별 승인 출처 변환 실패. status 는 INSUFFICIENT_INFO | NOT_SUPPORTED."""

    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status


def _services_from_topology(bundle: EvidenceBundle, sg_addr: Optional[str]) -> Tuple[Dict[Tuple[int, int], Dict[str, List[str]]], Dict[Tuple[int, int], List[str]], List[str]]:
    """설계도(kind=topology) → {(from_port,to_port): {"v4": [...], "v6": []}} (외부 출발 flows 만), {(포트): [출발 계층 이름]} (계층 출발 flows), 설명 줄.

    규칙 기반은 IP 목록(리터럴 CIDR)만 바꾼다. 계층 → 계층 통신은 보안 그룹 참조라서 여기서는 승인 출처가 되지 않는다 (호출한 쪽이 NOT_SUPPORTED 로 만든다)."""
    it = bundle.intent or {}
    if not sg_addr:
        raise TopologyAdapterError("NOT_SUPPORTED", "지목된 줄이 속한 보안 그룹을 코드에서 찾지 못함 (resource 블록 밖이거나 security_group_id 가 참조가 아님)")
    tiers = [t for t in (it.get("tiers") or []) if isinstance(t, dict)]
    mine = [str(t.get("id")) for t in tiers if str(t.get("security_group") or "") == sg_addr]
    if not mine:
        raise TopologyAdapterError("INSUFFICIENT_INFO", f"설계도에 이 보안 그룹({sg_addr})을 단 계층이 없음 — ③ 설계도에서 이 보안 그룹을 계층으로 넣고 들어오는 통신을 그려야 규칙 기반 수정이 가능")
    label = {str(t.get("id")): str(t.get("label") or t.get("id")) for t in tiers}
    ext: Dict[str, List[str]] = {}
    for e in (it.get("external") or []):
        if isinstance(e, dict) and e.get("id"):
            ext[str(e["id"])] = [str(c) for c in (e.get("cidrs_v4") or [])]
            label[str(e["id"])] = str(e.get("label") or e["id"])
    services: Dict[Tuple[int, int], Dict[str, List[str]]] = {}
    tier_src: Dict[Tuple[int, int], List[str]] = {}
    notes: List[str] = []
    for f in (it.get("flows") or []):
        if not isinstance(f, dict) or str(f.get("to") or "") not in mine:
            continue
        proto = str(f.get("protocol", "tcp")).lower()
        if proto == "-1":
            notes.append(f"flow {f.get('id')}: 프로토콜 전체(-1) 는 규칙 기반이 다루지 않음")
            continue
        try:
            lo = int(f.get("from_port", f.get("port")))
            hi = int(f.get("to_port", f.get("port")))
        except (TypeError, ValueError):
            continue
        src = str(f.get("from") or "")
        if src in ext:
            s = services.setdefault((lo, hi), {"v4": [], "v6": []})
            for c in ext[src]:
                if c not in s["v4"]:
                    s["v4"].append(c)
            notes.append(f"{label.get(src, src)} → {label.get(str(f.get('to')), f.get('to'))} :{lo if lo == hi else f'{lo}-{hi}'} = {', '.join(ext[src]) or '(출처 비어 있음)'}")
        else:
            tier_src.setdefault((lo, hi), []).append(label.get(src, src))
    return services, tier_src, notes


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
        topo = str(bundle.intent.get("kind", "")).lower() == "topology"
        tier_src: Dict[Tuple[int, int], List[str]] = {}
        design_notes: List[str] = []
        if topo:
            try:
                services, tier_src, design_notes = _services_from_topology(bundle, flagged_security_group(bundle, lines, idx))
            except TopologyAdapterError as e:
                if e.status == "INSUFFICIENT_INFO":
                    return PatchCandidate(status="INSUFFICIENT_INFO", files={}, rationale=str(e), **base)
                return PatchCandidate(status="NOT_SUPPORTED", files={}, error=str(e), **base)
        else:
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
        pk = f"{key[0]}" if key[0] == key[1] else f"{key[0]}-{key[1]}"
        if key not in services:
            if topo and key in tier_src:
                return PatchCandidate(status="NOT_SUPPORTED", files={},
                                      error=f"설계도에서 포트 {pk} 는 다른 계층({', '.join(tier_src[key])})에서만 들어온다 — 규칙 기반은 IP 목록(리터럴 CIDR)만 바꾸고 보안 그룹 참조로는 바꾸지 못함 (AI 수정 또는 직접 수정 필요)", **base)
            if topo:
                return PatchCandidate(status="NOT_SUPPORTED", files={},
                                      error=f"설계도에 포트 {pk} 로 이 계층에 들어오는 통신이 없다 — 이 규칙은 지워야 하는데 규칙 기반은 규칙을 지우지 않음 (삭제 금지)", **base)
            return PatchCandidate(status="INSUFFICIENT_INFO", files={}, rationale=f"no guarded service in intent for ports {key}", **base)
        approved = services[key]
        changed = False
        seen_literal = False
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
                seen_literal = True
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
                seen_literal = True
                target = approved["v4"] if attr == "cidr_ipv4" else approved["v6"]
                if len(target) != 1:
                    return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"{attr} is a single value but {len(target)} approved sources; baseline cannot split rules", **base)
                if val != target[0]:
                    lines[i] = f'{indent}{attr}{eq}"{target[0]}"{tail}'
                    changed = True
                    notes.append(f"{attr}: {val} → {target[0]}")
        if not changed:
            flagged = lines[idx].strip()
            if seen_literal and topo:
                return PatchCandidate(status="NOT_SUPPORTED", files={},
                                      error=f"설계도와 이미 같음 — 설계도가 포트 {pk} 에 {', '.join(approved['v4'])} 를 허용한다. 공개를 막으려면 ③ 설계도에서 그 통신의 출처를 좁혀야 함", **base)
            return PatchCandidate(status="NOT_SUPPORTED", files={}, error=f"no literal CIDR attribute found in the enclosing block (flagged line: {flagged!r})", **base)
        new_text = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        why = ("rule-based literal replacement from design flows (" + "; ".join(design_notes) + "): " if topo else "rule-based literal replacement: ") + "; ".join(notes)
        return PatchCandidate(status="PATCH", files={fname: new_text}, rationale=why,
                              proposed_autonomy=None, assumptions=["literal CIDR replacement only"] + (["approved sources = design flows from external entities only"] if topo else []), **base)


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
