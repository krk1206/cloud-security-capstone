"""terraform plan JSON(`terraform show -json plan.bin`) → SGWorld.

지원 범위 (명시):
  - 루트 모듈의 aws_security_group (inline ingress/egress)
  - aws_vpc_security_group_ingress_rule / aws_vpc_security_group_egress_rule
  - aws_security_group_rule (구형)
  - aws_ec2_managed_prefix_list (같은 plan 안에 선언된 것만 전개. 외부 pl-... ID 는 resolver 가 없으면 UNKNOWN)
  - 부착 지점: aws_security_group 을 참조하는 다른 managed 리소스 전부 (aws_instance, aws_network_interface,
    aws_launch_template, aws_db_instance, aws_lambda_function 등). aws_network_interface_sg_attachment 포함.
  - 자식 모듈: planned_values 는 읽지만, 참조 해석(configuration.expressions)은 루트 모듈만 지원한다.
    자식 모듈 리소스의 미확정 값은 UNKNOWN 으로 남는다.

미확정(unknown) 값 처리 원칙:
  - resource_changes[].change.after_unknown 에 표시된 값은 "모른다"로 취급한다.
  - 참조(configuration.expressions.*.references)로 **모호하지 않게** 해석되는 경우에만 값을 채운다.
  - 모호하면 Source(kind="unknown") 으로 남기고, 오라클은 그 서비스에 대해 UNKNOWN 을 낸다.
  - inline ingress 블록 전체가 미확정인데 설정에 ingress 표현식도 dynamic "ingress" 블록도 없으면
    "선언된 inline 규칙 없음(provider computed)" 으로 보고 caveat 을 남긴다. 소스 HCL 을 볼 수 없으면 UNKNOWN.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .sgmodel import (
    AttachmentPoint,
    PrefixListModel,
    Rule,
    SGWorld,
    SecurityGroupModel,
    Source,
    normalize_protocol,
)

SG_TYPE = "aws_security_group"
PL_TYPE = "aws_ec2_managed_prefix_list"
RULE_TYPES = {
    "aws_vpc_security_group_ingress_rule": "ingress",
    "aws_vpc_security_group_egress_rule": "egress",
    "aws_security_group_rule": None,  # type 속성으로 결정
}
ENI_ATTACH_TYPE = "aws_network_interface_sg_attachment"
NON_ATTACHMENT_TYPES = {SG_TYPE, PL_TYPE, ENI_ATTACH_TYPE, *RULE_TYPES.keys()}

_SG_REF_RE = re.compile(r"^(aws_security_group\.[A-Za-z0-9_\-]+(\[[^\]]+\])?)")
_PL_REF_RE = re.compile(r"^(aws_ec2_managed_prefix_list\.[A-Za-z0-9_\-]+(\[[^\]]+\])?)")
_MODULE_PREFIX_RE = re.compile(r"^module\.")


class PlanParseError(ValueError):
    pass


# ---------------------------------------------------------------------------
# 로딩 / 평탄화
# ---------------------------------------------------------------------------
def load_plan(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise PlanParseError(f"cannot read plan json {p}: {e}") from e
    if not isinstance(data, dict) or "format_version" not in data:
        raise PlanParseError(f"{p} is not a terraform plan json (no format_version)")
    return data


def iter_planned_resources(plan: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """planned_values 의 모든 모듈을 순회한다 (주소에 module.* 접두어 포함)."""
    root = (plan.get("planned_values") or {}).get("root_module") or {}

    def walk(mod: Dict[str, Any]):
        for r in mod.get("resources") or []:
            yield r
        for child in mod.get("child_modules") or []:
            yield from walk(child)

    yield from walk(root)


def after_unknown_map(plan: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for rc in plan.get("resource_changes") or []:
        ch = rc.get("change") or {}
        out[rc.get("address")] = ch.get("after_unknown") or {}
    return out


def resource_actions(plan: Dict[str, Any]) -> Dict[str, List[str]]:
    return {rc.get("address"): list((rc.get("change") or {}).get("actions") or []) for rc in plan.get("resource_changes") or []}


def root_config_resources(plan: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    cfg = (plan.get("configuration") or {}).get("root_module") or {}
    return {r.get("address"): r for r in cfg.get("resources") or []}


# ---------------------------------------------------------------------------
# 참조 해석 도우미
# ---------------------------------------------------------------------------
def _refs_in_expression(expr: Any) -> List[str]:
    """expression(dict 또는 list) 안의 references 를 전부 모은다 (중첩 블록 포함)."""
    out: List[str] = []
    if isinstance(expr, dict):
        refs = expr.get("references")
        if isinstance(refs, list):
            out.extend(r for r in refs if isinstance(r, str))
        for k, v in expr.items():
            if k == "references":
                continue
            out.extend(_refs_in_expression(v))
    elif isinstance(expr, list):
        for v in expr:
            out.extend(_refs_in_expression(v))
    return out


def _resource_addresses_from_refs(refs: Iterable[str], pattern: re.Pattern) -> List[str]:
    """['aws_security_group.a.id', 'aws_security_group.a'] → ['aws_security_group.a'] (중복 제거, 순서 유지)."""
    seen: List[str] = []
    for r in refs:
        m = pattern.match(r)
        if m:
            addr = m.group(1)
            if addr not in seen:
                seen.append(addr)
    return seen


def _is_unknown(marker: Any) -> bool:
    return marker is True


def _list_unknown_flags(marker: Any, length: int) -> List[bool]:
    """after_unknown 의 리스트 표시를 원소별 bool 로. True 면 전체 미확정."""
    if marker is True:
        return [True] * max(length, 1)
    if isinstance(marker, list):
        flags = [bool(x is True) for x in marker]
        if len(flags) < length:
            flags += [False] * (length - len(flags))
        return flags
    return [False] * length


# ---------------------------------------------------------------------------
# HCL 텍스트 보조 (dynamic 블록 존재 확인용 — 휴리스틱, 결과는 caveat 로 기록)
# ---------------------------------------------------------------------------
def find_resource_block(text: str, rtype: str, rname: str) -> Optional[str]:
    """resource "<type>" "<name>" { ... } 블록 본문을 반환 (중괄호 매칭, 문자열/주석 안의 중괄호는 무시)."""
    pat = re.compile(r'resource\s+"%s"\s+"%s"\s*\{' % (re.escape(rtype), re.escape(rname)))
    m = pat.search(text)
    if not m:
        return None
    i = m.end()
    depth = 1
    in_str = False
    esc = False
    n = len(text)
    while i < n and depth > 0:
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "#" or (ch == "/" and text[i:i + 2] == "//"):
                j = text.find("\n", i)
                i = n if j < 0 else j
                continue
            elif text[i:i + 2] == "/*":
                j = text.find("*/", i + 2)
                i = n if j < 0 else j + 2
                continue
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        i += 1
    return text[m.end():i - 1] if depth == 0 else None


SG_LIST_ATTRS = ("vpc_security_group_ids", "security_group_ids", "security_groups", "security_group_id")
_SG_LITERAL_RE = re.compile(r'^"(sg-[0-9a-f]{8,17})"$')
_SG_REF_EXPR_RE = re.compile(r'^(aws_security_group\.[A-Za-z0-9_\-]+)(\[[^\]]+\])?\.id$')


def _split_top_level(s: str) -> List[str]:
    """리스트 본문을 최상위 콤마 기준으로 나눈다 (괄호/문자열 안의 콤마는 무시)."""
    out: List[str] = []
    depth = 0
    in_str = False
    cur: List[str] = []
    for ch in s:
        if in_str:
            cur.append(ch)
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return [x for x in out if x]


def hcl_sg_list_elements(block_body: str) -> Optional[Dict[str, List[str]]]:
    """리소스 블록 본문에서 SG 목록 속성의 원소를 분류한다.

    returns {"refs": [aws_security_group.x, ...], "literals": ["sg-..."], "opaque": ["var.x", ...]}
            속성을 못 찾거나 리스트 리터럴이 아니면 None (판단 불가).
    """
    found = False
    refs: List[str] = []
    lits: List[str] = []
    opaque: List[str] = []
    for attr in SG_LIST_ATTRS:
        for m in re.finditer(r'(?m)^\s*%s\s*=\s*(.+)$' % re.escape(attr), block_body):
            rhs = m.group(1).strip()
            found = True
            if attr == "security_group_id":
                elems = [rhs]
            else:
                if not rhs.startswith("["):
                    return None  # var.x / concat(...) 등 → 원소 수를 알 수 없음
                # 여러 줄 리스트: 시작 위치부터 대괄호 매칭
                start = m.start(1)
                depth = 0
                end = None
                for i in range(start, len(block_body)):
                    ch = block_body[i]
                    if ch == "[":
                        depth += 1
                    elif ch == "]":
                        depth -= 1
                        if depth == 0:
                            end = i
                            break
                if end is None:
                    return None
                inner = block_body[start + 1:end]
                inner = re.sub(r'#.*', '', inner)
                elems = _split_top_level(inner)
            for e in elems:
                e = e.strip().rstrip(",")
                lm = _SG_LITERAL_RE.match(e)
                rm = _SG_REF_EXPR_RE.match(e)
                if lm:
                    lits.append(lm.group(1))
                elif rm:
                    refs.append(rm.group(1))
                else:
                    opaque.append(e)
    if not found:
        return None
    return {"refs": refs, "literals": lits, "opaque": opaque}


def hcl_declares_block(sources: Dict[str, str], rtype: str, rname: str, block: str) -> Optional[bool]:
    """소스 텍스트에서 해당 리소스가 block(예: ingress) 을 정적/동적으로 선언하는지.

    returns True/False, 리소스 블록을 못 찾으면 None.
    """
    for _, text in sources.items():
        body = find_resource_block(text, rtype, rname)
        if body is None:
            continue
        if re.search(r'(^|\s)%s\s*\{' % re.escape(block), body):
            return True
        if re.search(r'dynamic\s+"%s"' % re.escape(block), body):
            return True
        return False
    return None


# ---------------------------------------------------------------------------
# 핵심: plan → SGWorld
# ---------------------------------------------------------------------------
def build_world(
    plan: Dict[str, Any],
    sources: Optional[Dict[str, str]] = None,
    external_prefix_lists: Optional[Dict[str, List[str]]] = None,
) -> SGWorld:
    """plan JSON 을 SGWorld 로 변환한다.

    sources: {파일명: HCL 텍스트}. inline 블록 미확정 판정에 쓴다 (없으면 보수적으로 UNKNOWN).
    external_prefix_lists: {'pl-...': [cidr, ...]} 외부 prefix list 전개 결과 (V7 이 채움). 없으면 UNKNOWN.
    """
    sources = sources or {}
    external_prefix_lists = external_prefix_lists or {}
    unknown = after_unknown_map(plan)
    cfg = root_config_resources(plan)
    world = SGWorld(source="plan", security_groups={}, meta={
        "format_version": str(plan.get("format_version", "")),
        "terraform_version": str(plan.get("terraform_version", "")),
    })

    planned = list(iter_planned_resources(plan))
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for r in planned:
        if r.get("mode") != "managed":
            continue
        by_type.setdefault(r.get("type", ""), []).append(r)

    # 1) prefix lists (같은 plan 안)
    for r in by_type.get(PL_TYPE, []):
        addr = r["address"]
        vals = r.get("values") or {}
        au = unknown.get(addr, {})
        entries = vals.get("entry")
        cidrs: Optional[List[str]] = None
        note = ""
        if isinstance(entries, list) and not _is_unknown(au.get("entry")):
            cidrs = []
            entry_unknown = au.get("entry") if isinstance(au.get("entry"), list) else []
            for i, e in enumerate(entries):
                eu = entry_unknown[i] if i < len(entry_unknown) and isinstance(entry_unknown[i], dict) else {}
                c = (e or {}).get("cidr")
                if c is None or _is_unknown(eu.get("cidr")):
                    cidrs = None
                    note = "entry cidr unknown at plan time"
                    break
                cidrs.append(c)
        else:
            note = "entries unknown at plan time"
        world.prefix_lists[addr] = PrefixListModel(addr, cidrs, str(vals.get("address_family") or "IPv4"), note)
    for pl_id, cidrs in external_prefix_lists.items():
        world.prefix_lists[pl_id] = PrefixListModel(pl_id, list(cidrs), "IPv4" if all(":" not in c for c in cidrs) else "IPv6", "external (resolved by caller)")

    # 2) security groups (inline rules)
    for r in by_type.get(SG_TYPE, []):
        addr = r["address"]
        vals = r.get("values") or {}
        au = unknown.get(addr, {})
        sg = SecurityGroupModel(address=addr, name=vals.get("name") if isinstance(vals.get("name"), str) else None)
        conf = cfg.get(addr) or {}
        expr = conf.get("expressions") or {}
        for direction in ("ingress", "egress"):
            rules = vals.get(direction)
            marker = au.get(direction)
            if _is_unknown(marker) and not isinstance(rules, list):
                # inline 블록 전체 미확정. 설정에 선언이 없으면 provider computed 로 본다.
                declared_in_expr = direction in expr
                declared_in_hcl = hcl_declares_block(sources, SG_TYPE, r.get("name", ""), direction) if sources else None
                if not declared_in_expr and declared_in_hcl is False:
                    sg.caveats.append(
                        f"inline {direction} not declared in config (provider-computed/unknown at plan); "
                        f"treated as no inline {direction} rules — V7 must confirm actual state")
                    continue
                reason = "inline block unknown at plan time"
                if declared_in_hcl is None and not declared_in_expr:
                    reason += " and source HCL unavailable to confirm absence of dynamic block"
                elif declared_in_hcl:
                    reason += " (dynamic/static block present but values unresolved)"
                sg.inline_unknown[direction] = reason
                continue
            if not isinstance(rules, list):
                continue
            rule_unknown = marker if isinstance(marker, list) else [{}] * len(rules)
            # 표현식 참조는 블록 단위로 풀링된다 → 모호성 판정에 사용
            refs = _refs_in_expression(expr.get(direction))
            ref_sgs = _resource_addresses_from_refs(refs, _SG_REF_RE)
            ref_pls = _resource_addresses_from_refs(refs, _PL_REF_RE)
            pending: List[Tuple[int, str, int]] = []   # (rule index, kind, unknown slot count)
            built: List[Rule] = []
            for i, rv in enumerate(rules):
                rv = rv or {}
                ru = rule_unknown[i] if i < len(rule_unknown) and isinstance(rule_unknown[i], dict) else {}
                unknown_fields: List[str] = []
                srcs: List[Source] = []
                # cidr v4/v6
                for fld, kind in (("cidr_blocks", "cidr4"), ("ipv6_cidr_blocks", "cidr6")):
                    lst = rv.get(fld)
                    if _is_unknown(ru.get(fld)) or (fld not in rv and _is_unknown(ru.get(fld))):
                        unknown_fields.append(fld)
                        srcs.append(Source("unknown", "", note=f"{fld} unknown"))
                        continue
                    if isinstance(lst, list):
                        flags = _list_unknown_flags(ru.get(fld), len(lst))
                        for j, c in enumerate(lst):
                            if flags[j] or c is None:
                                unknown_fields.append(f"{fld}[{j}]")
                                srcs.append(Source("unknown", "", note=f"{fld}[{j}] unknown"))
                            else:
                                srcs.append(Source(kind, str(c)))
                # prefix lists
                pl_list = rv.get("prefix_list_ids")
                pl_marker = ru.get("prefix_list_ids")
                if _is_unknown(pl_marker):
                    pending.append((i, "prefix_list", 1))
                    unknown_fields.append("prefix_list_ids")
                elif isinstance(pl_list, list):
                    flags = _list_unknown_flags(pl_marker, len(pl_list))
                    n_unknown = sum(1 for f in flags if f)
                    for j, pid in enumerate(pl_list):
                        if not flags[j] and pid is not None:
                            srcs.append(_prefix_source(str(pid), world))
                    if n_unknown:
                        pending.append((i, "prefix_list", n_unknown))
                        unknown_fields.append("prefix_list_ids")
                # referenced security groups
                sg_list = rv.get("security_groups")
                sg_marker = ru.get("security_groups")
                if _is_unknown(sg_marker):
                    pending.append((i, "sg", 1))
                    unknown_fields.append("security_groups")
                elif isinstance(sg_list, list):
                    flags = _list_unknown_flags(sg_marker, len(sg_list))
                    n_unknown = sum(1 for f in flags if f)
                    for j, sid in enumerate(sg_list):
                        if not flags[j] and sid is not None:
                            srcs.append(Source("sg", str(sid)))
                    if n_unknown:
                        pending.append((i, "sg", n_unknown))
                        unknown_fields.append("security_groups")
                if rv.get("self") is True:
                    srcs.append(Source("self", addr))
                proto = normalize_protocol(rv.get("protocol"))
                fp, tp = rv.get("from_port"), rv.get("to_port")
                if _is_unknown(ru.get("protocol")) or _is_unknown(ru.get("from_port")) or _is_unknown(ru.get("to_port")):
                    unknown_fields.extend(f for f in ("protocol", "from_port", "to_port") if _is_unknown(ru.get(f)))
                built.append(Rule(direction, proto, _port(fp, proto), _port(tp, proto), srcs, f"{addr}#{direction}[{i}]", unknown_fields))
            # 미확정 슬롯을 참조로 해석 (모호하지 않을 때만)
            _resolve_pending(pending, built, ref_sgs, ref_pls, world)
            sg.rules.extend(built)
        world.security_groups[addr] = sg

    # 3) 별도 규칙 리소스
    for rtype, fixed_dir in RULE_TYPES.items():
        for r in by_type.get(rtype, []):
            addr = r["address"]
            vals = r.get("values") or {}
            au = unknown.get(addr, {})
            conf = cfg.get(addr) or {}
            expr = conf.get("expressions") or {}
            # 어느 SG 에 붙는 규칙인가
            sg_target = vals.get("security_group_id") if not _is_unknown(au.get("security_group_id")) else None
            if sg_target is None:
                cands = _resource_addresses_from_refs(_refs_in_expression(expr.get("security_group_id")), _SG_REF_RE)
                sg_target = cands[0] if len(cands) == 1 else None
            direction = fixed_dir or (vals.get("type") if isinstance(vals.get("type"), str) else None)
            if direction not in ("ingress", "egress"):
                world.notes.append(f"{addr}: direction unknown; rule ignored (marked unknown)")
                direction = "ingress"
                unknown_dir = True
            else:
                unknown_dir = False
            srcs: List[Source] = []
            unknown_fields: List[str] = []
            if rtype in ("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"):
                fields = (("cidr_ipv4", "cidr4"), ("cidr_ipv6", "cidr6"), ("prefix_list_id", "prefix_list"), ("referenced_security_group_id", "sg"))
                for fld, kind in fields:
                    if _is_unknown(au.get(fld)):
                        refs = _refs_in_expression(expr.get(fld))
                        pat = _PL_REF_RE if kind == "prefix_list" else _SG_REF_RE
                        cands = _resource_addresses_from_refs(refs, pat)
                        if len(cands) == 1 and kind in ("prefix_list", "sg"):
                            srcs.append(_prefix_source(cands[0], world) if kind == "prefix_list" else Source("sg", cands[0]))
                        else:
                            unknown_fields.append(fld)
                            srcs.append(Source("unknown", "", note=f"{fld} unknown"))
                        continue
                    v = vals.get(fld)
                    if v is None:
                        continue
                    srcs.append(_prefix_source(str(v), world) if kind == "prefix_list" else Source(kind, str(v)))
                proto = normalize_protocol(vals.get("ip_protocol"))
                fp, tp = vals.get("from_port"), vals.get("to_port")
                for f in ("ip_protocol", "from_port", "to_port"):
                    if _is_unknown(au.get(f)):
                        unknown_fields.append(f)
            else:  # aws_security_group_rule
                for fld, kind in (("cidr_blocks", "cidr4"), ("ipv6_cidr_blocks", "cidr6")):
                    lst = vals.get(fld)
                    if _is_unknown(au.get(fld)):
                        unknown_fields.append(fld)
                        srcs.append(Source("unknown", "", note=f"{fld} unknown"))
                    elif isinstance(lst, list):
                        flags = _list_unknown_flags(au.get(fld), len(lst))
                        for j, c in enumerate(lst):
                            if flags[j] or c is None:
                                unknown_fields.append(f"{fld}[{j}]")
                                srcs.append(Source("unknown", "", note=f"{fld}[{j}] unknown"))
                            else:
                                srcs.append(Source(kind, str(c)))
                pls = vals.get("prefix_list_ids")
                if _is_unknown(au.get("prefix_list_ids")) or (isinstance(pls, list) and any(_list_unknown_flags(au.get("prefix_list_ids"), len(pls)))):
                    cands = _resource_addresses_from_refs(_refs_in_expression(expr.get("prefix_list_ids")), _PL_REF_RE)
                    known = [p for p in (pls or []) if p is not None] if isinstance(pls, list) else []
                    n_unknown = (len(pls) - len(known)) if isinstance(pls, list) else 1
                    if len(cands) == n_unknown:
                        srcs.extend(_prefix_source(c, world) for c in cands)
                    else:
                        unknown_fields.append("prefix_list_ids")
                        srcs.append(Source("unknown", "", note="prefix_list_ids unknown (ambiguous references)"))
                    srcs.extend(_prefix_source(str(p), world) for p in known)
                elif isinstance(pls, list):
                    srcs.extend(_prefix_source(str(p), world) for p in pls if p is not None)
                ssg = vals.get("source_security_group_id")
                if _is_unknown(au.get("source_security_group_id")):
                    cands = _resource_addresses_from_refs(_refs_in_expression(expr.get("source_security_group_id")), _SG_REF_RE)
                    if len(cands) == 1:
                        srcs.append(Source("sg", cands[0]))
                    else:
                        unknown_fields.append("source_security_group_id")
                        srcs.append(Source("unknown", "", note="source_security_group_id unknown"))
                elif ssg:
                    srcs.append(Source("sg", str(ssg)))
                if vals.get("self") is True:
                    srcs.append(Source("self", sg_target or addr))
                proto = normalize_protocol(vals.get("protocol"))
                fp, tp = vals.get("from_port"), vals.get("to_port")
                for f in ("protocol", "from_port", "to_port"):
                    if _is_unknown(au.get(f)):
                        unknown_fields.append(f)
            if unknown_dir:
                unknown_fields.append("type")
            rule = Rule(direction, proto, _port(fp, proto), _port(tp, proto), srcs, addr, unknown_fields)
            if sg_target is None:
                world.notes.append(f"{addr}: security_group_id unresolvable → rule kept as orphan (UNKNOWN attachment)")
                orphan = world.security_groups.setdefault("<unresolved-sg>", SecurityGroupModel("<unresolved-sg>", caveats=["rules whose SG could not be resolved"]))
                orphan.rules.append(rule)
                continue
            sg = world.security_groups.get(sg_target)
            if sg is None:
                # plan 밖의 기존 SG(sg-...) 에 규칙을 붙이는 경우: 그 SG 의 나머지 규칙은 볼 수 없다
                sg = SecurityGroupModel(address=sg_target, caveats=["security group not in plan; only rules declared in this plan are visible"], aws_id=sg_target if sg_target.startswith("sg-") else None)
                sg.inline_unknown["ingress"] = "external security group; existing rules not visible in plan"
                sg.inline_unknown["egress"] = "external security group; existing rules not visible in plan"
                world.security_groups[sg_target] = sg
            sg.rules.append(rule)

    # 4) 부착 지점
    for r in planned:
        if r.get("mode") != "managed":
            continue
        rtype = r.get("type", "")
        addr = r["address"]
        if rtype in NON_ATTACHMENT_TYPES and rtype != ENI_ATTACH_TYPE:
            continue
        conf = cfg.get(addr) or {}
        refs = _refs_in_expression(conf.get("expressions"))
        sg_refs = _resource_addresses_from_refs(refs, _SG_REF_RE)
        vals = r.get("values") or {}
        au = unknown.get(addr, {})
        literal_ids: List[str] = []
        for k, v in vals.items():
            if k in SG_LIST_ATTRS and v:
                items = v if isinstance(v, list) else [v]
                literal_ids.extend(str(x) for x in items if isinstance(x, str) and x.startswith("sg-"))
        _nested_literal_sg_ids(vals, literal_ids)
        list_unknown = any(_is_unknown(au.get(k)) for k in SG_LIST_ATTRS) or _nested_unknown_sg_list(au)
        attach_unknown_note = ""
        if list_unknown:
            # plan 만으로는 원소 수를 모른다 (참조와 리터럴이 섞이면 리터럴이 보이지 않는다) → HCL 로 원소를 센다
            body = None
            for _, text in sources.items():
                body = find_resource_block(text, rtype, r.get("name", ""))
                if body is not None:
                    break
            elems = hcl_sg_list_elements(body) if body is not None else None
            if elems is None:
                attach_unknown_note = ("security group list unknown at plan time and not enumerable from HCL "
                                       "(non-literal list or source unavailable)")
            else:
                for lit in elems["literals"]:
                    if lit not in literal_ids:
                        literal_ids.append(lit)
                if elems["opaque"]:
                    attach_unknown_note = f"security group list contains non-enumerable elements: {elems['opaque']}"
                for ref in elems["refs"]:
                    if ref not in sg_refs:
                        sg_refs.append(ref)
        if not sg_refs and not literal_ids and not attach_unknown_note:
            continue
        if rtype == ENI_ATTACH_TYPE:
            eni_refs = [x for x in refs if x.startswith("aws_network_interface.")]
            target = eni_refs[0] if eni_refs else (str(vals.get("network_interface_id")) if vals.get("network_interface_id") else addr)
            note = "aws_network_interface_sg_attachment"
        else:
            target = addr
            note = ""
        existing = next((a for a in world.attachments if a.address == target), None)
        if existing is None:
            existing = AttachmentPoint(address=target, resource_type=rtype, sg_refs=[], note=note)
            world.attachments.append(existing)
        for s in sg_refs:
            if s not in existing.sg_refs:
                existing.sg_refs.append(s)
        for s in literal_ids:
            if s not in existing.external_sg_ids:
                existing.external_sg_ids.append(s)
                if s not in existing.sg_refs:
                    existing.sg_refs.append(s)
        if attach_unknown_note:
            existing.unknown = True
            existing.note = (existing.note + "; " if existing.note else "") + attach_unknown_note

    # 자식 모듈 리소스에 대한 안내
    if any(_MODULE_PREFIX_RE.match(r.get("address", "")) for r in planned):
        world.notes.append("child module resources present: reference resolution is root-module only; unresolved values stay UNKNOWN")
    return world


def _nested_unknown_sg_list(au: Any) -> bool:
    """after_unknown 트리 안에서 SG 목록 속성이 통째로 unknown 인지 (launch_template.network_interfaces 등)."""
    if isinstance(au, dict):
        for k, v in au.items():
            if k in SG_LIST_ATTRS and v is True:
                return True
            if isinstance(v, (dict, list)) and _nested_unknown_sg_list(v):
                return True
    elif isinstance(au, list):
        return any(_nested_unknown_sg_list(v) for v in au)
    return False


def _nested_literal_sg_ids(vals: Any, out: List[str]) -> None:
    """launch_template.network_interfaces[].security_groups, lambda vpc_config[].security_group_ids 등 중첩 탐색."""
    if isinstance(vals, dict):
        for k, v in vals.items():
            if k in ("security_groups", "security_group_ids", "vpc_security_group_ids") and isinstance(v, list):
                out.extend(str(x) for x in v if isinstance(x, str) and x.startswith("sg-"))
            elif isinstance(v, (dict, list)):
                _nested_literal_sg_ids(v, out)
    elif isinstance(vals, list):
        for v in vals:
            _nested_literal_sg_ids(v, out)


def _port(v: Any, proto: str) -> Optional[int]:
    if proto == "-1":
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v)
    return None


def _prefix_source(ref: str, world: SGWorld) -> Source:
    pl = world.prefix_lists.get(ref)
    if pl is None:
        return Source("prefix_list", ref, None, note="prefix list not in plan and no external resolver → cannot expand")
    if pl.cidrs is None:
        return Source("prefix_list", ref, None, note=pl.note or "entries unknown")
    return Source("prefix_list", ref, list(pl.cidrs), note="expanded")


def _resolve_pending(pending: List[Tuple[int, str, int]], rules: List[Rule], ref_sgs: List[str], ref_pls: List[str], world: SGWorld) -> None:
    """inline 블록의 미확정 prefix_list/security_groups 슬롯을 블록 단위 참조로 해석한다.

    규칙: 같은 kind 의 미확정 슬롯을 가진 규칙이 정확히 하나이고, 슬롯 수 == 참조 리소스 수일 때만 채운다.
    그 외에는 unknown 으로 남긴다 (어느 규칙에 어느 참조가 들어갔는지 plan JSON 만으로는 알 수 없다).
    """
    for kind, refs in (("prefix_list", ref_pls), ("sg", ref_sgs)):
        items = [(i, n) for (i, k, n) in pending if k == kind]
        if not items:
            continue
        total_slots = sum(n for _, n in items)
        if len(items) == 1 and total_slots == len(refs) and refs:
            i = items[0][0]
            for ref in refs:
                rules[i].sources.append(_prefix_source(ref, world) if kind == "prefix_list" else Source("sg", ref))
            rules[i].unknown_fields = [f for f in rules[i].unknown_fields if f not in ("prefix_list_ids", "security_groups")]
        else:
            for i, n in items:
                why = ("no references found" if not refs else f"ambiguous: {len(items)} rules with unknown slots, {total_slots} slots, {len(refs)} referenced resources")
                rules[i].sources.append(Source("unknown", "", note=f"{kind} slot unresolved ({why})"))
