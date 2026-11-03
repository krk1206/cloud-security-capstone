"""자체 보안 그룹 검사 — 설계도 없이 코드(plan)만으로 (2026-11-01, B 문서 1-B '자체 보안 정책 분석').

입력: SGWorld (plan_model.build_world). 판정 단위: '보안 그룹이 붙는 리소스 묶음' (같은 보안 그룹 조합을 단 리소스들 — 실효 규칙은
붙은 보안 그룹들의 합집합). 들어오는 방향(ingress)만 본다.

검사 유형 (구현 · 단위 시험 있음):
  mgmt_public      관리 포트(22 SSH · 3389 RDP)가 인터넷 전체에 열림
  highrisk_public  고위험 포트가 인터넷 전체에 열림 — 포트 목록은 AWS Security Hub EC2.19 의 blockedPorts 그대로
                   (20,21,22,23,25,110,135,143,445,1433,1434,3000,3306,3389,4333,5000,5432,5500,5601,8080,8088,8888,9200,9300;
                    https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html, 2026-11-01 확인). 22 · 3389 는 mgmt_public 으로.
  all_ports_public 모든 포트(프로토콜 전체 · 0-65535)가 인터넷 전체에 열림
  split_any        IP 대역 여러 개를 합치면 인터넷 전체 (예: 0.0.0.0/1 + 128.0.0.0/1) — 문자열로 0.0.0.0/0 을 찾는 규칙은 못 본다
  ipv6_any         IPv6 전체(::/0) 허용
  vpc_wide         VPC 대역 전체(IP 대역 출처)가 고위험 포트에 접근 — 어느 서버인지 구분 못 함 (주의 등급)
  undecidable      출처를 plan 에서 확정 못 함 (값 미확정 · 펼칠 수 없는 prefix list · plan 밖 보안 그룹 ID) → 판정 불가
'인터넷 전체' = 같은 (프로토콜, 포트 범위)로 들어오는 IPv4 대역의 합집합이 0.0.0.0/0 을 덮는 경우. 인터넷에 열린 포트라도 위 목록 밖
(예: 443)은 문제로 세지 않는다 — 공개 입구일 수 있다. 그것이 고객이 원하는 것인지는 설계도 비교(V6)가 판단한다.
실제 도달 가능성(NACL · 라우팅 · 공인 IP)은 보지 않는다.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .netset import NetSet
from .sgmodel import SGWorld

MGMT_PORTS = {22: "SSH", 3389: "RDP"}
# AWS Security Hub EC2.19 blockedPorts (변경 불가 파라미터) — 위 docstring 출처
EC2_19_PORTS = {20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 135: "RPC", 143: "IMAP", 445: "CIFS",
                1433: "MSSQL", 1434: "MSSQL", 3000: "웹 개발 서버", 3306: "MySQL", 3389: "RDP", 4333: "ahsp", 5000: "웹 개발 서버",
                5432: "PostgreSQL", 5500: "fcp-addr-srvr1", 5601: "OpenSearch Dashboards", 8080: "프록시", 8088: "HTTP(구)",
                8888: "HTTP(대체)", 9200: "OpenSearch", 9300: "OpenSearch"}
SOURCE = "AWS Security Hub EC2.19 (blockedPorts)"

KIND_KO = {
    "mgmt_public": "관리 포트가 인터넷 전체에 열림",
    "highrisk_public": "고위험 포트가 인터넷 전체에 열림",
    "all_ports_public": "모든 포트가 인터넷 전체에 열림",
    "split_any": "여러 IP 대역을 합치면 인터넷 전체",
    "ipv6_any": "IPv6 전체(::/0)에 열림",
    "vpc_wide": "VPC 안 모든 서버가 고위험 포트에 접근 가능",
    "undecidable": "출처를 확정할 수 없음 (판정 불가)",
}
SEVERITY = {"all_ports_public": "CRITICAL", "mgmt_public": "CRITICAL", "highrisk_public": "HIGH", "split_any": "HIGH", "ipv6_any": "HIGH",
            "vpc_wide": "MEDIUM", "undecidable": "UNKNOWN"}


def _ports(rule: Any) -> Tuple[str, int, int]:
    if rule.protocol == "-1":
        return "-1", 0, 65535
    if rule.protocol in ("icmp", "icmpv6"):
        return rule.protocol, 0, 65535
    lo, hi = rule.from_port, rule.to_port
    if lo is None or hi is None or (lo == 0 and hi == 0):
        return rule.protocol, 0, 65535
    return rule.protocol, int(lo), int(hi)


def port_text(proto: str, lo: int, hi: int) -> str:
    if proto == "-1":
        return "모든 프로토콜 · 포트"
    if lo == 0 and hi == 65535:
        return f"{proto.upper()} 전체 포트"
    return f"{lo}" if lo == hi else f"{lo}-{hi}"


def _named(ports: Dict[int, str], lo: int, hi: int) -> List[Tuple[int, str]]:
    return [(p, n) for p, n in sorted(ports.items()) if lo <= p <= hi]


def groups(world: SGWorld) -> List[Dict[str, Any]]:
    """같은 보안 그룹 조합을 단 리소스 묶음. key = 보안 그룹 주소 정렬 튜플."""
    by: Dict[Tuple[str, ...], List[Any]] = defaultdict(list)
    for a in world.attachments:
        by[tuple(sorted(a.sg_refs))].append(a)
    out = []
    for key, atts in sorted(by.items()):
        out.append({"key": key, "security_groups": list(key), "resources": [a.address for a in atts],
                    "types": sorted({a.resource_type for a in atts}), "unknown": any(a.unknown or a.external_sg_ids for a in atts)})
    return out


def scan(world: SGWorld, vpc_cidr: Optional[str] = None) -> Dict[str, Any]:
    """{"findings": [...], "checked_groups": n, "notes": [...]}. finding 마다 kind · severity · 보안 그룹 · 리소스 · 포트 · 출처 · 규칙 위치."""
    vpc = NetSet.from_cidrs(4, [vpc_cidr]) if vpc_cidr else None
    findings: List[Dict[str, Any]] = []
    notes: List[str] = []
    gs = groups(world)

    def add(kind: str, g: Dict[str, Any], proto: str, lo: int, hi: int, sources: List[str], rules: List[str], detail: str, port_names: str = "") -> None:
        sg = g["security_groups"][0] if g["security_groups"] else ""
        findings.append({"id": f"sg:{kind}:{'+'.join(g['security_groups'])}:{proto}:{lo}-{hi}", "kind": kind, "title": KIND_KO[kind],
                         "severity": SEVERITY[kind], "security_group": sg, "security_groups": g["security_groups"], "resources": g["resources"],
                         "protocol": proto, "from_port": lo, "to_port": hi, "ports": port_text(proto, lo, hi), "port_names": port_names,
                         "sources": sources, "rules": sorted(set(rules)), "detail": detail})

    for g in gs:
        cidr4: Dict[Tuple[str, int, int], List[Tuple[str, str]]] = defaultdict(list)
        for sg in g["security_groups"]:
            model = world.security_groups.get(sg)
            if model is None:
                if sg.startswith("sg-"):
                    add("undecidable", g, "-1", 0, 65535, [sg], [], f"보안 그룹 {sg} 는 plan 밖 (규칙을 볼 수 없음)")
                continue
            if model.inline_unknown.get("ingress"):
                add("undecidable", g, "-1", 0, 65535, [], [sg], f"{sg} 의 인바운드 규칙이 plan 시점에 미확정 ({model.inline_unknown['ingress']})")
            for rule in model.rules:
                if rule.direction != "ingress":
                    continue
                proto, lo, hi = _ports(rule)
                for src in rule.sources:
                    if src.kind == "cidr4":
                        cidr4[(proto, lo, hi)].append((src.value, rule.origin))
                    elif src.kind == "cidr6":
                        if src.value in ("::/0",):
                            named = _named(EC2_19_PORTS, lo, hi)
                            add("ipv6_any", g, proto, lo, hi, [src.value], [rule.origin],
                                "IPv6 출발지 ::/0 — 인터넷 전체(IPv6)" + (f" · 고위험 포트 {', '.join(f'{p} {n}' for p, n in named[:4])}" if named else ""),
                                ", ".join(f"{p} {n}" for p, n in named[:6]))
                    elif src.kind == "prefix_list":
                        if src.resolved_cidrs is None:
                            add("undecidable", g, proto, lo, hi, [src.value], [rule.origin], f"prefix list {src.value} 내용을 plan 에서 확인 불가")
                        else:
                            for c in src.resolved_cidrs:
                                cidr4[(proto, lo, hi)].append((c, rule.origin))
                    elif src.kind in ("sg", "self"):
                        continue
                    else:
                        add("undecidable", g, proto, lo, hi, [], [rule.origin], f"출발지 미확정 규칙 {src.note or ''}".strip())
        for (proto, lo, hi), items in sorted(cidr4.items()):
            cidrs = sorted({c for c, _ in items})
            rules = [o for _, o in items]
            union = NetSet.from_cidrs(4, cidrs)
            if union.covers_everything():
                whole = proto == "-1" or (lo == 0 and hi == 65535)
                split = "0.0.0.0/0" not in cidrs and len(cidrs) > 1
                if whole:
                    add("all_ports_public", g, proto, lo, hi, cidrs, rules, f"출발지 {', '.join(cidrs[:4])} — 모든 포트를 인터넷 전체에 엶")
                else:
                    mg = _named(MGMT_PORTS, lo, hi)
                    hr = [(p, n) for p, n in _named(EC2_19_PORTS, lo, hi) if p not in MGMT_PORTS]
                    if mg:
                        add("mgmt_public", g, proto, lo, hi, cidrs, rules, f"관리 포트 {', '.join(f'{p} {n}' for p, n in mg)} 를 인터넷 전체에 엶",
                            ", ".join(f"{p} {n}" for p, n in mg))
                    if hr:
                        add("highrisk_public", g, proto, lo, hi, cidrs, rules,
                            f"고위험 포트 {', '.join(f'{p} {n}' for p, n in hr[:5])}{' 외' if len(hr) > 5 else ''} 를 인터넷 전체에 엶 ({SOURCE})",
                            ", ".join(f"{p} {n}" for p, n in hr[:6]))
                if split and (whole or mg or hr):      # 위험 포트를 쪼갠 대역으로 연 경우만 (443 같은 공개 입구를 쪼갠 것은 같은 뜻이라 세지 않음)
                    add("split_any", g, proto, lo, hi, cidrs, rules,
                        f"대역 {', '.join(cidrs[:4])} 을 합치면 0.0.0.0/0 (인터넷 전체) — '0.0.0.0/0' 문자열이 없어 문자열 규칙으로는 안 보임")
            elif vpc is not None and union.intersection(vpc) == vpc:
                hr = _named(EC2_19_PORTS, lo, hi) if not (proto == "-1" or (lo == 0 and hi == 65535)) else [(0, "전체 포트")]
                if hr:
                    add("vpc_wide", g, proto, lo, hi, cidrs, rules,
                        f"VPC 대역 {vpc_cidr} 전체가 {', '.join(f'{p} {n}' if p else n for p, n in hr[:4])} 에 접근 — IP 대역으로는 어느 서버인지 구분 못 함",
                        ", ".join(f"{p} {n}" if p else n for p, n in hr[:6]))
    unattached = sorted(set(world.security_groups) - {s for g in gs for s in g["security_groups"]} - {"<unresolved-sg>"})
    if unattached:
        notes.append(f"리소스에 붙지 않은 보안 그룹 {len(unattached)}개 — 규칙이 있어도 닿는 서버가 없어 검사에서 뺌: {', '.join(unattached[:5])}")
    return {"findings": findings, "checked_groups": len(gs), "notes": notes, "unattached_security_groups": unattached,
            "port_source": SOURCE}
