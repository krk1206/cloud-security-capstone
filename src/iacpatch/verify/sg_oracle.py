"""Intent Oracle (V6 핵심 계산). Security Group 전용.

입력: SGWorld (plan 또는 AWS 실측을 정규화한 것) + IntentSpec
출력: OracleReport (대상 SG 마다, 부착 범위(scope) 마다, 보호 서비스 마다 판정)

판정 원칙 (요구사항 그대로):
  1. CIDR 은 문자열이 아니라 집합으로 계산한다 → 0.0.0.0/1 + 128.0.0.0/1 은 0.0.0.0/0 이다.
  2. IPv4/IPv6 는 분리하고, 방향·프로토콜·포트 범위를 반영한다.
  3. "인터넷 전체를 덮지 않는다"로 통과시키지 않는다. 사람이 정의한 승인 출처 **밖의** 접근이 남아 있으면
     EXCESS → FAIL. 필요한 접근(required_access)이 사라졌으면 MISSING → FAIL.
  4. 같은 부착 지점(인스턴스/ENI)에 붙은 SG 들을 합산한다. 다른 부착 지점의 규칙은 섞지 않는다.
  5. 참조 SG 는 "그 SG 가 붙은 ENI 에서 오는 트래픽"이라는 별도 출처 종류다. 참조 SG 의 인바운드 규칙을
     상속하지 않는다. 승인 목록(security_group_refs)에 없으면 EXCESS 다.
  6. prefix list 는 같은 plan 안(또는 호출자가 전개해 준 것)만 전개한다. 전개 불가·미확정 값 → UNKNOWN.
  7. Trivy 결과는 입력이 아니다. (대상 SG 선택은 intent 가 정한다.)
  8. 이 계층이 증명하는 것은 "SG 규칙상 허용 집합"이다. 실제 인터넷 도달 가능성(NACL, 라우팅, 공인 IP,
     호스트 방화벽, 서비스 리스닝)은 증명하지 않는다 — 그 확인은 V8 의 몫이며, 그마저도 제한적이다.

우선순위: 알려진 EXCESS/MISSING 이 하나라도 있으면 FAIL. FAIL 이 없고 UNKNOWN 이 있으면 UNKNOWN. 둘 다 없으면 PASS.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..intent import GuardedService, IntentSpec
from ..models import ServiceSpec, Verdict
from .netset import CidrParseError, NetSet, parse_cidr
from .sgmodel import Rule, SGWorld, Source


@dataclass
class ServiceEval:
    service_id: str
    label: str
    verdict: Verdict
    effective_v4: List[str]
    effective_v6: List[str]
    effective_sg_refs: List[str]
    approved_v4: List[str]
    approved_v6: List[str]
    excess_v4: List[str]
    excess_v6: List[str]
    excess_sg_refs: List[str]
    unknown_reasons: List[str]
    partial_rules: List[str]
    contributing_rules: List[str]
    covers_entire_internet_v4: bool
    covers_entire_internet_v6: bool
    notes: List[str] = field(default_factory=list)


@dataclass
class RequiredEval:
    label: str
    service_id: str
    source_cidr: str
    verdict: Verdict
    reason: str


@dataclass
class ScopeEval:
    scope_id: str                 # 부착 지점 주소 또는 "standalone:<sg>"
    scope_kind: str               # "attachment" | "standalone"
    security_groups: List[str]
    verdict: Verdict
    services: List[ServiceEval]
    required: List[RequiredEval]
    caveats: List[str]


@dataclass
class TargetEval:
    target: str
    verdict: Verdict
    scopes: List[ScopeEval]
    reason: str = ""


@dataclass
class OracleReport:
    verdict: Verdict
    targets: List[TargetEval]
    world_source: str
    summary: str
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        import dataclasses
        def conv(o):
            if isinstance(o, Verdict):
                return o.value
            if dataclasses.is_dataclass(o) and not isinstance(o, type):
                return {k: conv(v) for k, v in dataclasses.asdict(o).items()}
            if isinstance(o, list):
                return [conv(x) for x in o]
            if isinstance(o, dict):
                return {k: conv(v) for k, v in o.items()}
            return o
        return conv(self)


# ---------------------------------------------------------------------------
def _combine(verdicts: List[Verdict]) -> Verdict:
    if any(v == Verdict.FAIL for v in verdicts):
        return Verdict.FAIL
    if any(v == Verdict.UNKNOWN for v in verdicts):
        return Verdict.UNKNOWN
    return Verdict.PASS


def _normalize_sg_ref(ref: str, aliases: Dict[str, str]) -> str:
    return aliases.get(ref, ref)


def _collect_sources(rules: List[Tuple[Rule, str]], svc: ServiceSpec, world: SGWorld, aliases: Dict[str, str]):
    """서비스에 해당하는 규칙들의 출처를 집합으로 모은다.

    returns (v4 NetSet, v6 NetSet, sg_refs set, unknown reasons, partial rule origins, contributing origins,
             full-coverage v4 NetSet, full-coverage v6 NetSet)
    """
    v4 = NetSet(4)
    v6 = NetSet(6)
    full_v4 = NetSet(4)
    full_v6 = NetSet(6)
    sg_refs: List[str] = []
    unknown: List[str] = []
    partial: List[str] = []
    contributing: List[str] = []
    for rule, owner in rules:
        rel = rule.matches_service(svc.direction, svc.protocol, svc.from_port, svc.to_port)
        if rel == "none":
            continue
        if any(f in rule.unknown_fields for f in ("protocol", "from_port", "to_port", "ip_protocol", "type")):
            unknown.append(f"{rule.origin}: protocol/port unknown at plan time")
        contributing.append(rule.origin)
        if rel == "partial":
            partial.append(rule.origin)
        for s in rule.sources:
            if s.kind == "cidr4":
                try:
                    n = parse_cidr(s.value)
                except CidrParseError as e:
                    unknown.append(f"{rule.origin}: unparsable cidr {s.value!r} ({e})")
                    continue
                if n.version != 4:
                    unknown.append(f"{rule.origin}: {s.value} in cidr_blocks is not IPv4")
                    continue
                v4 = v4.union(NetSet(4, [n]))
                if rel == "full":
                    full_v4 = full_v4.union(NetSet(4, [n]))
            elif s.kind == "cidr6":
                try:
                    n = parse_cidr(s.value)
                except CidrParseError as e:
                    unknown.append(f"{rule.origin}: unparsable cidr {s.value!r} ({e})")
                    continue
                if n.version != 6:
                    unknown.append(f"{rule.origin}: {s.value} in ipv6_cidr_blocks is not IPv6")
                    continue
                v6 = v6.union(NetSet(6, [n]))
                if rel == "full":
                    full_v6 = full_v6.union(NetSet(6, [n]))
            elif s.kind == "prefix_list":
                if s.resolved_cidrs is None:
                    unknown.append(f"{rule.origin}: prefix list {s.value} could not be expanded ({s.note})")
                    continue
                for c in s.resolved_cidrs:
                    try:
                        n = parse_cidr(c)
                    except CidrParseError as e:
                        unknown.append(f"{rule.origin}: prefix list {s.value} entry {c!r} unparsable ({e})")
                        continue
                    if n.version == 4:
                        v4 = v4.union(NetSet(4, [n]))
                        if rel == "full":
                            full_v4 = full_v4.union(NetSet(4, [n]))
                    else:
                        v6 = v6.union(NetSet(6, [n]))
                        if rel == "full":
                            full_v6 = full_v6.union(NetSet(6, [n]))
            elif s.kind == "sg":
                ref = _normalize_sg_ref(s.value, aliases)
                if ref not in sg_refs:
                    sg_refs.append(ref)
            elif s.kind == "self":
                ref = "self:" + _normalize_sg_ref(s.value, aliases)
                if ref not in sg_refs:
                    sg_refs.append(ref)
            elif s.kind == "unknown":
                unknown.append(f"{rule.origin}: {s.note or 'source unknown'}")
            else:
                unknown.append(f"{rule.origin}: unsupported source kind {s.kind}")
    return v4, v6, sg_refs, unknown, partial, contributing, full_v4, full_v6


def _evaluate_scope(scope_id: str, scope_kind: str, sg_addrs: List[str], world: SGWorld, intent: IntentSpec,
                    aliases: Dict[str, str]) -> ScopeEval:
    caveats: List[str] = []
    rules: List[Tuple[Rule, str]] = []
    inline_unknown_dirs: Dict[str, List[str]] = {"ingress": [], "egress": []}
    for addr in sg_addrs:
        sg = world.security_groups.get(addr)
        if sg is None:
            # 부착 지점에 plan 밖의 SG(sg-...)가 함께 붙어 있음 → 그 SG 규칙을 볼 수 없다
            inline_unknown_dirs["ingress"].append(f"{addr}: security group not visible in {world.source} (rules unknown)")
            inline_unknown_dirs["egress"].append(f"{addr}: security group not visible in {world.source} (rules unknown)")
            continue
        caveats.extend(f"{addr}: {c}" for c in sg.caveats)
        for d, why in sg.inline_unknown.items():
            inline_unknown_dirs.setdefault(d, []).append(f"{addr}: {why}")
        rules.extend((r, addr) for r in sg.rules)

    services: List[ServiceEval] = []
    for gs in intent.guarded_services:
        svc = gs.service
        v4, v6, sg_refs, unknown, partial, contributing, full_v4, full_v6 = _collect_sources(rules, svc, world, aliases)
        unknown = list(unknown) + inline_unknown_dirs.get(svc.direction, [])
        approved_v4 = NetSet.from_cidrs(4, gs.approved.cidrs_v4)
        approved_v6 = NetSet.from_cidrs(6, gs.approved.cidrs_v6)
        # 승인된 prefix list 참조는 전개 결과가 승인 CIDR 안에 있어야 하므로 별도 가산 없음 (CIDR 집합으로만 판정)
        approved_sg = [_normalize_sg_ref(x, aliases) for x in gs.approved.security_group_refs]
        excess_v4 = v4.difference(approved_v4)
        excess_v6 = v6.difference(approved_v6)
        excess_sg = [r for r in sg_refs if r not in approved_sg and not (r.startswith("self:") and "self" in approved_sg)]
        if excess_v4.is_empty() and excess_v6.is_empty() and not excess_sg:
            verdict = Verdict.UNKNOWN if unknown else Verdict.PASS
        else:
            verdict = Verdict.FAIL
        notes: List[str] = []
        if v4.covers_everything():
            notes.append("effective IPv4 sources cover the entire internet (0.0.0.0/0 after set collapse)")
        if v6.covers_everything():
            notes.append("effective IPv6 sources cover the entire internet (::/0 after set collapse)")
        if partial:
            notes.append("some rules cover only part of the service port range; they count toward EXCESS but not toward required coverage")
        services.append(ServiceEval(
            service_id=svc.id, label=svc.label or svc.id, verdict=verdict,
            effective_v4=v4.to_list(), effective_v6=v6.to_list(), effective_sg_refs=sg_refs,
            approved_v4=approved_v4.to_list(), approved_v6=approved_v6.to_list(),
            excess_v4=excess_v4.to_list(), excess_v6=excess_v6.to_list(), excess_sg_refs=excess_sg,
            unknown_reasons=unknown, partial_rules=partial, contributing_rules=contributing,
            covers_entire_internet_v4=v4.covers_everything(), covers_entire_internet_v6=v6.covers_everything(),
            notes=notes,
        ))

    required: List[RequiredEval] = []
    scope_sgs = {_normalize_sg_ref(a, aliases) for a in sg_addrs} | set(sg_addrs)
    for req in intent.required_access:
        # targets 가 적힌 필수 접근은 그 SG 가 이 범위에 있을 때만 요구한다 (웹 SG 의 '80 공개' 를 앱 SG 에 요구하지 않도록)
        if req.targets and not any(_normalize_sg_ref(t, aliases) in scope_sgs or t in scope_sgs for t in req.targets):
            continue
        svc = req.service
        v4, v6, sg_refs, unknown, partial, contributing, full_v4, full_v6 = _collect_sources(rules, svc, world, aliases)
        unknown = list(unknown) + inline_unknown_dirs.get(svc.direction, [])
        net = parse_cidr(req.source_cidr)
        covered = (full_v4 if net.version == 4 else full_v6).contains_network(net)
        if covered:
            verdict, reason = Verdict.PASS, "required source is fully covered by declared rules"
        elif unknown:
            verdict, reason = Verdict.UNKNOWN, "required source not covered by known rules; unknown sources remain: " + "; ".join(unknown[:3])
        else:
            verdict, reason = Verdict.FAIL, f"required access {req.source_cidr} → {svc.id} is not allowed after the change (MISSING)"
        required.append(RequiredEval(req.label or svc.id, svc.id, req.source_cidr, verdict, reason))

    verdict = _combine([s.verdict for s in services] + [r.verdict for r in required])
    return ScopeEval(scope_id, scope_kind, list(sg_addrs), verdict, services, required, caveats)


def evaluate(world: SGWorld, intent: IntentSpec, aliases: Optional[Dict[str, str]] = None) -> OracleReport:
    """대상 SG 별로 부착 범위를 정해 평가한다.

    aliases: 주소 ↔ AWS ID 매핑 (V7 에서 plan 주소를 실제 GroupId 로 바꿔 평가할 때 사용).
    """
    aliases = aliases or {}
    targets: List[TargetEval] = []
    for target in intent.target_security_groups:
        t = _normalize_sg_ref(target, aliases)
        if t not in world.security_groups:
            targets.append(TargetEval(target, Verdict.FAIL, [], reason=(
                f"target security group {target} is absent from the {world.source} state. "
                "Deleting or renaming the target removes the finding but does not satisfy the intent (required access cannot be verified).")))
            continue
        attachments = world.attachments_of(t)
        if intent.attachment_points:
            wanted = {_normalize_sg_ref(a, aliases) for a in intent.attachment_points}
            attachments = [a for a in attachments if a.address in wanted]
        scopes: List[ScopeEval] = []
        if not attachments:
            se = _evaluate_scope(f"standalone:{t}", "standalone", [t], world, intent, aliases)
            se.caveats.append("no attachment point found in plan; evaluated the security group alone. "
                              "Other security groups attached to the same ENI at runtime are not visible here (V7 checks that).")
            scopes.append(se)
        for a in attachments:
            sg_addrs = list(a.sg_refs)
            se = _evaluate_scope(a.address, "attachment", sg_addrs, world, intent, aliases)
            if a.unknown:
                for s in se.services:
                    s.unknown_reasons.append(f"{a.address}: attached security group list unknown at plan time")
                    if s.verdict == Verdict.PASS:
                        s.verdict = Verdict.UNKNOWN
                se.verdict = _combine([s.verdict for s in se.services] + [r.verdict for r in se.required])
            if a.note:
                se.caveats.append(f"{a.address}: {a.note}")
            scopes.append(se)
        targets.append(TargetEval(target, _combine([s.verdict for s in scopes]), scopes))
    verdict = _combine([t.verdict for t in targets]) if targets else Verdict.UNKNOWN
    summary = _summarize(verdict, targets)
    return OracleReport(verdict, targets, world.source, summary, list(world.notes))


def _summarize(verdict: Verdict, targets: List[TargetEval]) -> str:
    parts: List[str] = []
    for t in targets:
        if t.reason:
            parts.append(f"{t.target}: {t.verdict.value} — {t.reason}")
            continue
        for sc in t.scopes:
            for s in sc.services:
                if s.verdict == Verdict.FAIL:
                    ex = []
                    if s.excess_v4:
                        if s.covers_entire_internet_v4:
                            ex.append(f"v4 entire internet (effective set collapses to 0.0.0.0/0) minus approved {s.approved_v4}")
                        else:
                            ex.append("v4 " + ",".join(s.excess_v4[:4]) + ("…" if len(s.excess_v4) > 4 else ""))
                    if s.excess_v6:
                        if s.covers_entire_internet_v6:
                            ex.append(f"v6 entire internet (::/0) minus approved {s.approved_v6}")
                        else:
                            ex.append("v6 " + ",".join(s.excess_v6[:4]) + ("…" if len(s.excess_v6) > 4 else ""))
                    if s.excess_sg_refs:
                        ex.append("sg " + ",".join(s.excess_sg_refs))
                    parts.append(f"{sc.scope_id} {s.label}: EXCESS beyond approved sources: {'; '.join(ex)}")
                elif s.verdict == Verdict.UNKNOWN:
                    parts.append(f"{sc.scope_id} {s.label}: UNKNOWN — {s.unknown_reasons[0] if s.unknown_reasons else 'unresolved'}")
            for r in sc.required:
                if r.verdict != Verdict.PASS:
                    parts.append(f"{sc.scope_id} required {r.label}: {r.verdict.value} — {r.reason}")
    if not parts:
        parts.append("all guarded services within approved sources and all required access preserved")
    return f"{verdict.value}: " + " | ".join(parts)
