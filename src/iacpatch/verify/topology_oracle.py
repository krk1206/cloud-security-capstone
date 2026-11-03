"""V6 구조 검사 — 설계도(topology intent)의 화살표와 실제 보안 그룹 규칙을 비교한다 (2026-10-20).

입력: SGWorld (plan_model.build_world 결과 — 보안 그룹, 규칙, 부착 지점) + TopologyIntentSpec.
판정:
  ① 설계도에 없는 통신이 열려 있으면 FAIL (excess).
       - 출처가 다른 계층의 보안 그룹이면: 그 계층 → 대상 계층 통신이 설계도에 있는지
       - 출처가 IP 대역이면: 같은 대상·포트로 들어오는 모든 IP 대역의 합집합을 구해, 설계도가 허용한 외부 대역(인터넷/관리자 목록)
         밖의 부분이 남는지 (0.0.0.0/1 + 128.0.0.0/1 처럼 나눠 적어도 합치면 잡힌다). VPC 안 대역은 "VPC 안 모든 서버" 로 본다
         — IP 대역으로는 어느 계층인지 구분할 수 없으므로 계층 사이 통신을 IP 대역으로 연 것은 설계 위반이다.
       - 포트: 규칙의 포트 범위 전체를 덮는 설계 통신이 있어야 한다 (설계는 3306 만인데 규칙이 전체 포트면 위반).
  ② 설계도에 있는 통신이 막혀 있으면 FAIL (broken) — 서비스 경로나 관리자 접속이 끊긴 것.
  ③ 값이 확정되지 않은 출처(plan 시점 unknown, 펼칠 수 없는 prefix list)는 UNKNOWN — PASS 로 치지 않는다.
  ④ 설계도에 없는 리소스로 들어오는 통신도 FAIL (2026-11-01, D-30). 설계도는 허용 목록이다 — 설계도의 어느 계층에도 속하지 않는
     리소스(보안 그룹이 붙는 리소스)가 인바운드 허용을 받으면 '설계에 없는 연결'. 설계도에서 구성요소를 지웠는데 코드에 남아 있는
     경우가 여기서 잡힌다 (예: 설계에서 Redis 를 빼면 API → Redis 6379 허용이 위반). 들어오는 허용이 없는 리소스는 기록(notes)만 한다.
     이전 판(10-20~10-31)은 설계도에 적힌 계층의 보안 그룹만 봤다 — 그때 기록은 그 기준으로 남아 있고 다시 판정하지 않는다.
한 서버에 여러 보안 그룹이 붙으면 실효 규칙은 합집합이다 (부착 지점 기준). 들어오는 방향(ingress)만 본다.
실제 도달 가능성(NACL, 라우팅, 서비스가 포트를 실제로 여는지)은 여기서 증명하지 않는다 — 배포 후 검사(V7·V8)의 몫이다.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Tuple

from ..models import Verdict
from ..topology_intent import Flow, TopologyIntentSpec
from .netset import NetSet
from .sgmodel import Rule, SGWorld


@dataclass
class TopologyReport:
    verdict: Verdict
    summary: str
    flows: List[Dict[str, Any]] = field(default_factory=list)
    excess: List[Dict[str, Any]] = field(default_factory=list)
    tiers: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    undesigned: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": "topology", "verdict": self.verdict.value, "summary": self.summary, "flows": self.flows,
                "excess": self.excess, "tiers": self.tiers, "notes": self.notes, "undesigned": self.undesigned,
                "oracle_version": ORACLE_VERSION}


# 판정 기준 판 — 기록에 같이 남긴다. 2: 설계도에 없는 리소스로 들어오는 통신도 위반 (D-30)
ORACLE_VERSION = "topology-2"


def _short(address: str) -> str:
    """aws_elasticache_replication_group.redis → elasticache_replication_group.redis (화면용)"""
    a = str(address)
    return a[4:] if a.startswith("aws_") else a


def _ports(rule: Rule) -> Tuple[str, int, int]:
    """(protocol, lo, hi). 전체 프로토콜(-1)·0~0 관례·icmp 는 전체 범위로 본다."""
    if rule.protocol == "-1":
        return "-1", 0, 65535
    if rule.protocol in ("icmp", "icmpv6"):
        return rule.protocol, 0, 65535
    lo, hi = rule.from_port, rule.to_port
    if lo is None or hi is None or (lo == 0 and hi == 0):
        return rule.protocol, 0, 65535
    return rule.protocol, int(lo), int(hi)


def _port_text(proto: str, lo: int, hi: int) -> str:
    if proto == "-1":
        return "모든 프로토콜·포트"
    if lo == 0 and hi == 65535:
        return f"{proto.upper()} 전체 포트"
    return f"{lo}" if lo == hi else f"{lo}-{hi}"


def _covers(flow: Flow, proto: str, lo: int, hi: int) -> bool:
    """설계 통신 하나가 규칙의 (프로토콜, 포트 범위) 를 전부 덮는가."""
    if flow.protocol == "-1":
        return True
    if proto == "-1" or flow.protocol != proto:
        return False
    return flow.from_port <= lo and flow.to_port >= hi


def _flow_matches_port(flow: Flow, proto: str, lo: int, hi: int) -> bool:
    """규칙이 설계 통신의 포트 범위를 전부 여는가 (필수 통신 확인용)."""
    if proto == "-1":
        return True
    if flow.protocol == "-1":
        return False
    return proto == flow.protocol and lo <= flow.from_port and hi >= flow.to_port


def evaluate(world: SGWorld, spec: TopologyIntentSpec) -> TopologyReport:
    notes: List[str] = []
    vpc = NetSet.from_cidrs(4, [spec.vpc_cidr])
    tiers = {t.id: t for t in spec.tiers}
    ext = {e.id: e for e in spec.external}

    # 1) 계층의 실제 자원(부착 지점)과 그 자원에 붙은 보안 그룹 전부
    tier_attach: Dict[str, List[Any]] = {tid: [a for a in world.attachments if t.security_group in a.sg_refs] for tid, t in tiers.items()}
    tier_sgs: Dict[str, Set[str]] = {}
    tier_rows: List[Dict[str, Any]] = []
    for tid, t in tiers.items():
        sgs = {t.security_group}
        for a in tier_attach[tid]:
            sgs.update(a.sg_refs)
            if a.external_sg_ids or a.unknown:
                notes.append(f"{t.label}: {a.address} 에 plan 으로 확인 불가한 보안 그룹 연결 — 해당 규칙 판정 불가")
        extra = sorted(sgs - {t.security_group})
        tier_sgs[tid] = sgs
        if t.security_group not in world.security_groups:
            notes.append(f"{t.label}: 설계도의 보안 그룹 {t.security_group} 이 plan 에 없음")
        if not tier_attach[tid]:
            notes.append(f"{t.label}: 보안 그룹 {t.security_group} 이 어떤 리소스에도 연결되지 않음")
        tier_rows.append({"id": tid, "label": t.label, "security_group": t.security_group,
                          "attached": [a.address for a in tier_attach[tid]], "extra_security_groups": extra,
                          "sg_in_code": t.security_group in world.security_groups})
        for x in extra:
            other = [o for o, ot in tiers.items() if ot.security_group == x]
            if other:
                notes.append(f"{t.label} 리소스에 {tiers[other[0]].label} 의 보안 그룹도 연결 — 두 계층 규칙 합산")

    # 보안 그룹 X 를 단 자원이 어느 계층인가 (출처 SG → 출처 계층)
    def tiers_carrying(sg: str) -> Set[str]:
        out = {tid for tid, sgs in tier_sgs.items() if sg in sgs and tier_attach[tid]}
        out |= {tid for tid, t in tiers.items() if t.security_group == sg}
        return out

    def non_tier_attachments(sg: str) -> List[str]:
        tier_addrs = {a.address for lst in tier_attach.values() for a in lst}
        return [a.address for a in world.attachments if sg in a.sg_refs and a.address not in tier_addrs]

    excess: List[Dict[str, Any]] = []
    unknown_items: List[str] = []
    # 필수 통신 확인용: (대상 계층) → [(proto, lo, hi, 출처 종류, 값)]
    allowed: Dict[str, List[Tuple[str, int, int, str, Any]]] = defaultdict(list)
    unknown_cover: Dict[str, List[Tuple[str, int, int]]] = defaultdict(list)   # 출처를 확정 못 한 규칙 (계층, 프로토콜, 포트) — 설계 통신이 '끊김' 인지 '판단 불가' 인지 가른다

    for tid, t in tiers.items():
        flows_in = [f for f in spec.flows if f.dst == tid]
        # IP 대역 출처는 (프로토콜, 포트 범위) 별로 합집합을 낸다
        cidr_groups: Dict[Tuple[str, int, int], List[Tuple[str, str]]] = defaultdict(list)
        for sg in sorted(tier_sgs[tid]):
            model = world.security_groups.get(sg)
            if model is None:
                continue
            if model.inline_unknown.get("ingress"):
                unknown_items.append(f"{t.label}: {sg} 의 인바운드 규칙 미확정 ({model.inline_unknown['ingress']})")
                unknown_cover[tid].append(("-1", 0, 65535))
            for rule in model.rules:
                if rule.direction != "ingress":
                    continue
                proto, lo, hi = _ports(rule)
                covering = [f for f in flows_in if _covers(f, proto, lo, hi)]
                for src in rule.sources:
                    if src.kind == "cidr4":
                        cidr_groups[(proto, lo, hi)].append((src.value, rule.origin))
                        allowed[tid].append((proto, lo, hi, "cidr4", src.value))
                    elif src.kind == "cidr6":
                        if not any(f.src in ext and NetSet.from_cidrs(4, ext[f.src].cidrs_v4).covers_everything() for f in covering):
                            excess.append({"src": "internet", "src_label": "인터넷 (IPv6)", "dst": tid, "dst_label": t.label,
                                           "protocol": proto, "ports": _port_text(proto, lo, hi), "kind": "not_designed",
                                           "detail": f"IPv6 출발지 {src.value} — 설계도에 IPv6 통신 없음", "rule": rule.origin})
                    elif src.kind in ("sg", "self"):
                        ref = sg if src.kind == "self" else src.value
                        srcs = {tid} if src.kind == "self" else tiers_carrying(ref)
                        if not srcs:
                            others = non_tier_attachments(ref)
                            if others:
                                excess.append({"src": "unknown", "src_label": f"설계 외 서버 ({', '.join(others[:3])})", "dst": tid,
                                               "dst_label": t.label, "protocol": proto, "ports": _port_text(proto, lo, hi),
                                               "kind": "not_designed", "detail": f"보안 그룹 {ref} 연결 리소스는 설계도의 어느 계층에도 속하지 않음",
                                               "rule": rule.origin})
                            elif ref.startswith("sg-") or ref not in world.security_groups:
                                unknown_items.append(f"{t.label}: 출발지 보안 그룹 {ref} 를 plan 에서 확인 불가 ({rule.origin})")
                                unknown_cover[tid].append((proto, lo, hi))
                            continue
                        for s in sorted(srcs):
                            allowed[tid].append((proto, lo, hi, "tier", s))
                            if not any(f.src == s for f in covering):
                                partial = [f for f in flows_in if f.src == s]
                                why = (f"설계 기준은 {', '.join(f.ports for f in partial)} 만 — 규칙은 {_port_text(proto, lo, hi)}" if partial
                                       else "설계 외 허용 경로")
                                excess.append({"src": s, "src_label": spec.label_of(s), "dst": tid, "dst_label": t.label,
                                               "protocol": proto, "ports": _port_text(proto, lo, hi),
                                               "kind": "ports" if partial else "not_designed", "detail": why, "rule": rule.origin})
                    elif src.kind == "prefix_list":
                        if src.resolved_cidrs is None:
                            unknown_items.append(f"{t.label}: prefix list {src.value} 내용 확인 불가 ({rule.origin})")
                            unknown_cover[tid].append((proto, lo, hi))
                        else:
                            for c in src.resolved_cidrs:
                                cidr_groups[(proto, lo, hi)].append((c, rule.origin))
                                allowed[tid].append((proto, lo, hi, "cidr4", c))
                    else:
                        unknown_items.append(f"{t.label}: 출발지 미확정 규칙 ({rule.origin}) {src.note}".strip())
                        unknown_cover[tid].append((proto, lo, hi))

        # IP 대역 합집합 판정
        for (proto, lo, hi), items in sorted(cidr_groups.items()):
            union = NetSet.from_cidrs(4, [c for c, _ in items])
            covering = [f for f in flows_in if _covers(f, proto, lo, hi) and f.src in ext]
            cover = NetSet(4)
            for f in covering:
                cover = cover.union(NetSet.from_cidrs(4, ext[f.src].cidrs_v4))
            rest = union.difference(cover)
            if rest.is_empty():
                continue
            outside = rest.difference(vpc)
            inside = rest.intersection(vpc)
            origins = sorted({o for _, o in items})
            cidrs = sorted({c for c, _ in items})
            approved = [c for f in covering for c in ext[f.src].cidrs_v4]
            whole = " (합집합 = 인터넷 전체 0.0.0.0/0)" if union.covers_everything() and len(cidrs) > 1 else ""
            if not outside.is_empty():
                lbl = "인터넷 (허용 목록 밖)" if approved else "인터넷"
                excess.append({"src": "internet", "src_label": lbl, "dst": tid, "dst_label": t.label, "protocol": proto,
                               "ports": _port_text(proto, lo, hi), "kind": "outside_approved" if approved else "not_designed",
                               "detail": (f"허용 대역 {', '.join(cidrs)}{whole} — 허용 목록 {', '.join(approved)} 밖까지 허용" if approved
                                          else f"허용 대역 {', '.join(cidrs)}{whole} — 설계도에 이 출발지의 통신 없음"),
                               "cidrs": cidrs, "excess_sample": outside.to_list()[:4], "rule": ", ".join(origins)})
            # 같은 규칙이 인터넷 쪽까지 열었으면 한 건으로 센다 (0.0.0.0/0 은 VPC 대역도 포함하지만 문제는 하나다)
            if not inside.is_empty() and outside.is_empty():
                excess.append({"src": "vpc", "src_label": "VPC 내 모든 서버", "dst": tid, "dst_label": t.label, "protocol": proto,
                               "ports": _port_text(proto, lo, hi), "kind": "vpc_wide",
                               "detail": f"VPC 대역 {', '.join(inside.to_list()[:3])} 허용 — IP 대역으로는 계층 구분 불가, VPC 안의 모든 서버가 접근 가능",
                               "cidrs": cidrs, "rule": ", ".join(origins)})

    # ④ 설계도에 없는 리소스로 들어오는 통신 (D-30) — 계층 보안 그룹이 아닌 보안 그룹을 단 리소스. 보안 그룹 단위로 묶는다
    #    (한 보안 그룹이 리소스 여러 개에 붙어도 규칙은 하나). 계층 보안 그룹의 규칙은 위에서 이미 봤다.
    all_tier_sgs: Set[str] = set().union(*tier_sgs.values()) if tier_sgs else set()
    tier_addrs = {a.address for lst in tier_attach.values() for a in lst}
    undesigned_rows: List[Dict[str, Any]] = []
    for sg in sorted({r for a in world.attachments if a.address not in tier_addrs for r in a.sg_refs} - all_tier_sgs):
        holders = [a.address for a in world.attachments if sg in a.sg_refs and a.address not in tier_addrs]
        model = world.security_groups.get(sg)
        node_id = f"res:{holders[0]}"
        label = f"설계에 없는 리소스 {_short(holders[0])}" + (f" 외 {len(holders) - 1}개" if len(holders) > 1 else "")
        row = {"id": node_id, "label": label, "security_group": sg, "resources": holders, "inbound": 0}
        undesigned_rows.append(row)
        if model is None:
            if sg.startswith("sg-"):
                unknown_items.append(f"{label}: 보안 그룹 {sg} 를 plan 에서 확인 불가")
            continue
        if model.inline_unknown.get("ingress"):
            unknown_items.append(f"{label}: {sg} 의 인바운드 규칙 미확정 ({model.inline_unknown['ingress']})")
        groups: Dict[Tuple[str, int, int], List[Tuple[str, str]]] = defaultdict(list)

        def add(src_id: str, src_label: str, proto: str, lo: int, hi: int, detail: str, origin: str, **extra: Any) -> None:
            row["inbound"] += 1
            excess.append({"src": src_id, "src_label": src_label, "dst": node_id, "dst_label": label, "protocol": proto,
                           "ports": _port_text(proto, lo, hi), "kind": "undesigned_target", "security_group": sg, "resources": holders,
                           "detail": detail, "rule": origin, **extra})
        for rule in model.rules:
            if rule.direction != "ingress":
                continue
            proto, lo, hi = _ports(rule)
            why = f"{', '.join(holders[:3])} 는 설계도의 어느 계층에도 없음 — 들어오는 허용 규칙이 있으면 설계 위반"
            for src in rule.sources:
                if src.kind == "cidr4":
                    groups[(proto, lo, hi)].append((src.value, rule.origin))
                elif src.kind == "cidr6":
                    add("internet", "인터넷 (IPv6)", proto, lo, hi, f"IPv6 출발지 {src.value} — {why}", rule.origin)
                elif src.kind in ("sg", "self"):
                    ref = sg if src.kind == "self" else src.value
                    if src.kind == "self" or ref == sg:
                        add(node_id, label, proto, lo, hi, f"같은 보안 그룹끼리 허용 — {why}", rule.origin)
                        continue
                    srcs = tiers_carrying(ref)
                    if srcs:
                        for s in sorted(srcs):
                            add(s, spec.label_of(s), proto, lo, hi, why, rule.origin)
                    else:
                        others = non_tier_attachments(ref)
                        add("unknown", f"설계 외 서버 ({', '.join(others[:3])})" if others else f"확인할 수 없는 출처 ({ref})",
                            proto, lo, hi, why, rule.origin)
                elif src.kind == "prefix_list" and src.resolved_cidrs is not None:
                    for c in src.resolved_cidrs:
                        groups[(proto, lo, hi)].append((c, rule.origin))
                else:
                    add("unknown", "확인할 수 없는 출처", proto, lo, hi, f"출발지 미확정 규칙 {src.note or ''} — {why}".strip(), rule.origin)
        for (proto, lo, hi), items in sorted(groups.items()):
            union = NetSet.from_cidrs(4, [c for c, _ in items])
            cidrs = sorted({c for c, _ in items})
            origins = ", ".join(sorted({o for _, o in items}))
            if not union.difference(vpc).is_empty():
                add("internet", "인터넷", proto, lo, hi, f"허용 대역 {', '.join(cidrs)} — {holders[0]} 는 설계도에 없음", origins, cidrs=cidrs)
            else:
                add("vpc", "VPC 내 모든 서버", proto, lo, hi, f"VPC 대역 {', '.join(cidrs)} 허용 — {holders[0]} 는 설계도에 없음", origins, cidrs=cidrs)
        if row["inbound"] == 0:
            notes.append(f"{label}: 들어오는 허용 규칙 없음 — 판정에 영향 없음 (설계도에 넣을지는 사람이 정함)")

    # 2) 설계도의 통신이 실제로 열려 있는가
    flow_rows: List[Dict[str, Any]] = []
    for f in spec.flows:
        reasons: List[str] = []
        status = "ok"
        rules_here = [x for x in allowed.get(f.dst, []) if _flow_matches_port(f, x[0], x[1], x[2])]
        if f.src in ext:
            need = NetSet.from_cidrs(4, ext[f.src].cidrs_v4)
            have = NetSet.from_cidrs(4, [v for (_, _, _, k, v) in rules_here if k == "cidr4"])
            missing = need.difference(have)
            if not missing.is_empty():
                status = "broken"
                # 사람이 읽을 수 있게: 허용 목록의 대역별로 '전체' 또는 '일부' 가 막혔다고 적는다 (잘게 쪼갠 CIDR 를 늘어놓지 않음)
                parts = []
                for c in ext[f.src].cidrs_v4:
                    one = NetSet.from_cidrs(4, [c])
                    lost = one.intersection(missing)
                    if lost.is_empty():
                        continue
                    parts.append(f"{c} 전체" if lost == one else f"{c} 일부")
                reasons.append(f"{spec.label_of(f.src)} 중 {', '.join(parts) or ', '.join(missing.to_list()[:4])}: {f.ports}번 포트 허용 규칙 없음 (필수 통신)")
        else:
            ok = any(k == "tier" and v == f.src for (_, _, _, k, v) in rules_here)
            if not ok:
                ok = any(k == "cidr4" and NetSet.from_cidrs(4, [v]).intersection(vpc) == vpc for (_, _, _, k, v) in rules_here)
            if not ok:
                status = "broken"
                reasons.append(f"{spec.label_of(f.src)} → {spec.label_of(f.dst)} {f.ports} 허용 규칙 없음 (필수 통신)")
        if status == "broken" and any(_flow_matches_port(f, p, a, b) or p == "-1" for (p, a, b) in unknown_cover.get(f.dst, [])):
            # 막혔다고 단정할 수 없다: 이 포트를 여는 규칙이 있는데 출처를 plan 에서 확정하지 못했다
            status = "unknown"
            reasons = [f"{spec.label_of(f.dst)} 에 출발지 미확정 {f.ports} 규칙 존재 — 이 경로의 허용 여부 판정 불가"]
        flow_rows.append({"id": f.id, "src": f.src, "dst": f.dst, "src_label": spec.label_of(f.src), "dst_label": spec.label_of(f.dst),
                          "protocol": f.protocol, "ports": f.ports, "label": f.label, "status": status, "reasons": reasons})

    broken = [r for r in flow_rows if r["status"] == "broken"]
    undecided = [r for r in flow_rows if r["status"] == "unknown"]
    if excess or broken:
        verdict = Verdict.FAIL
    elif unknown_items or undecided:
        verdict = Verdict.UNKNOWN
    else:
        verdict = Verdict.PASS
    parts = [f"{e['src_label']} → {e['dst_label']} {e['ports']}" for e in excess] + \
            [f"허용 규칙 없는 필수 통신: {r['src_label']} → {r['dst_label']} {r['ports']}" for r in broken]
    if verdict == Verdict.PASS:
        summary = f"설계 기준과 일치 — 정상 통신 경로 {len(flow_rows)}개 모두 허용, 설계 외 허용 경로 없음"
    elif verdict == Verdict.UNKNOWN:
        summary = "판정 불가 — " + "; ".join(unknown_items[:3])
    else:
        summary = f"설계 기준과 불일치 {len(excess) + len(broken)}건: " + "; ".join(parts[:6])
    return TopologyReport(verdict, summary, flow_rows, excess, tier_rows, notes + unknown_items, undesigned_rows)
