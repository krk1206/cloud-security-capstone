"""코드에서 직접 그리는 인프라 그림 (2026-11-01, B 문서 화면 2 '내 인프라가 지금 어떻게 구성되어 있지?').

설계도 없이 Terraform plan(오프라인) + 소스만으로 만든다. 고정 그림 없음 — 코드가 다르면 그림도 다르다.
  노드 = 보안 그룹이 붙는 리소스 묶음(같은 보안 그룹 조합을 단 리소스들) + 외부 출처(IP 대역 · prefix list)
  선   = 인바운드 규칙 (출처 → 대상, 포트). 같은 두 노드 사이 규칙은 한 선으로 합친다
  위험 표시 = 자체 보안 그룹 검사(verify/sg_scan.py) 결과가 가리키는 선
그 밖의 리소스(S3 · IAM · CloudFront · 라우팅 · NACL 등)는 그림이 아니라 목록(inventory)으로 — 보안 그룹 통신 분석 대상이 아님을 밝힌다.
그림 모델 형식은 topomodel.model 과 같다 (화면의 같은 배치기 topolayout.js 로 그린다).
공개/비공개 구역 = 외부 출처가 바로 들어오는 묶음이면 '외부에서 바로 닿음' (실제 서브넷 · 라우팅은 검사하지 않음).
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from ..verify.netset import NetSet
from . import topomodel

TYPE_KO = {
    "aws_instance": "서버 (EC2)", "aws_launch_template": "서버 묶음 (시작 템플릿)", "aws_autoscaling_group": "오토 스케일링", "aws_lb": "로드밸런서",
    "aws_alb": "로드밸런서", "aws_elb": "로드밸런서 (Classic)", "aws_db_instance": "데이터베이스 (RDS)", "aws_rds_cluster": "데이터베이스 클러스터",
    "aws_elasticache_replication_group": "캐시 (ElastiCache)", "aws_elasticache_cluster": "캐시 (ElastiCache)", "aws_lambda_function": "Lambda 함수",
    "aws_ecs_service": "컨테이너 서비스 (ECS)", "aws_eks_cluster": "쿠버네티스 (EKS)", "aws_efs_mount_target": "파일 시스템 (EFS)",
    "aws_vpc_endpoint": "VPC 엔드포인트", "aws_network_interface": "네트워크 인터페이스", "aws_elasticsearch_domain": "검색 (OpenSearch)",
    "aws_opensearch_domain": "검색 (OpenSearch)", "aws_neptune_cluster": "그래프 DB (Neptune)", "aws_docdb_cluster": "문서 DB",
    "aws_security_group": "보안 그룹", "aws_security_group_rule": "보안 그룹 규칙", "aws_vpc_security_group_ingress_rule": "보안 그룹 인바운드 규칙",
    "aws_vpc_security_group_egress_rule": "보안 그룹 아웃바운드 규칙", "aws_vpc": "VPC", "aws_subnet": "서브넷", "aws_route_table": "라우팅 테이블",
    "aws_route_table_association": "라우팅 연결", "aws_route": "라우팅", "aws_internet_gateway": "인터넷 게이트웨이", "aws_nat_gateway": "NAT 게이트웨이",
    "aws_eip": "고정 IP (EIP)", "aws_network_acl": "네트워크 ACL", "aws_network_acl_rule": "네트워크 ACL 규칙", "aws_s3_bucket": "S3 버킷",
    "aws_s3_bucket_policy": "S3 버킷 정책", "aws_s3_bucket_public_access_block": "S3 공개 차단", "aws_iam_role": "IAM 역할", "aws_iam_policy": "IAM 정책",
    "aws_iam_role_policy": "IAM 역할 정책", "aws_iam_role_policy_attachment": "IAM 정책 연결", "aws_iam_instance_profile": "인스턴스 프로파일",
    "aws_iam_user": "IAM 사용자", "aws_cloudfront_distribution": "CloudFront", "aws_route53_zone": "Route 53 영역", "aws_route53_record": "DNS 레코드",
    "aws_acm_certificate": "인증서 (ACM)", "aws_wafv2_web_acl": "WAF", "aws_cloudwatch_log_group": "로그 그룹", "aws_cloudwatch_metric_alarm": "경보",
    "aws_lb_listener": "로드밸런서 리스너", "aws_lb_target_group": "대상 그룹", "aws_db_subnet_group": "DB 서브넷 그룹",
    "aws_elasticache_subnet_group": "캐시 서브넷 그룹", "aws_kms_key": "암호화 키 (KMS)",
}
NET_INFRA = ("aws_vpc", "aws_subnet", "aws_route", "aws_route_table", "aws_route_table_association", "aws_internet_gateway", "aws_nat_gateway",
             "aws_eip", "aws_network_acl", "aws_network_acl_rule", "aws_default_network_acl", "aws_default_route_table", "aws_vpc_endpoint",
             "aws_egress_only_internet_gateway", "aws_vpc_peering_connection", "aws_db_subnet_group", "aws_elasticache_subnet_group")
SG_TYPES = ("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
            "aws_default_security_group")
RISK_ORDER = {"all_ports_public": 0, "mgmt_public": 1, "highrisk_public": 2, "split_any": 3, "ipv6_any": 4, "vpc_wide": 5}


def type_ko(t: str) -> str:
    return TYPE_KO.get(t) or (t[4:] if t.startswith("aws_") else t)


def short(addr: str) -> str:
    """aws_security_group.db → db, module.net.aws_security_group.x → net.x"""
    a = str(addr)
    mods = re.findall(r"module\.([A-Za-z0-9_-]+)\.", a)
    return ".".join(mods + [a.rsplit(".", 1)[-1]])


def vpc_cidr(plan: Dict[str, Any]) -> Optional[str]:
    for r in ((plan.get("planned_values") or {}).get("root_module") or {}).get("resources") or []:
        if r.get("type") == "aws_vpc" and (r.get("values") or {}).get("cidr_block"):
            return str(r["values"]["cidr_block"])
    return None


def _slug(s: str, used: set) -> str:
    base = re.sub(r"[^a-z0-9_-]+", "-", str(s).lower()).strip("-")[:36] or "n"
    if not re.match(r"^[a-z0-9]", base):
        base = "n" + base
    x, i = base, 2
    while x in used:
        x, i = f"{base}-{i}", i + 1
    used.add(x)
    return x


def _merge_ports(items: List[Tuple[str, int, int]]) -> str:
    seen, out = set(), []
    for proto, lo, hi in sorted(items, key=lambda t: (t[0] != "tcp", t[1], t[2])):
        txt = "전체" if proto == "-1" else ((f"{lo}" if lo == hi else f"{lo}-{hi}") + ("" if proto == "tcp" else f"/{proto}"))
        if lo == 0 and hi == 65535 and proto != "-1":
            txt = f"{proto.upper()} 전체"
        if txt not in seen:
            seen.add(txt)
            out.append(txt)
    return ", ".join(out[:4]) + (f" 외 {len(out) - 4}" if len(out) > 4 else "")


def build(plan: Dict[str, Any], sources: Dict[str, str], sg_findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    from ..verify.plan_model import PlanParseError, build_world
    from ..verify.sg_scan import _ports, groups
    try:
        world = build_world(plan, sources)
    except PlanParseError as e:
        return {"ok": False, "reason": f"plan 해석 실패: {e}", "nodes": [], "flows": [], "inventory": inventory(plan, set())}
    vc = vpc_cidr(plan)
    vpc = NetSet.from_cidrs(4, [vc]) if vc else None
    gs = groups(world)
    used: set = set()
    nodes: Dict[str, Dict[str, Any]] = {}
    carry: Dict[str, List[str]] = defaultdict(list)            # 보안 그룹 → 그것을 단 묶음 id
    for g in gs:
        lab = " + ".join(short(s) for s in g["security_groups"]) or "보안 그룹 미확정"
        nid = _slug(short(g["security_groups"][0]) if g["security_groups"] else "unknown", used)
        icon = topomodel._icon_from_types(g["resources"]) or "ec2"
        kinds = sorted({type_ko(t) for t in g["types"]})
        n = len(g["resources"])
        nodes[nid] = {"id": nid, "label": lab, "kind": "tier", "zone": "private", "icon": icon, "icon_source": "attached",
                      "sub": f"{kinds[0]}{f' · {n}개' if n > 1 else ''}" if kinds else "", "security_group": g["security_groups"][0] if g["security_groups"] else "",
                      "security_groups": g["security_groups"], "resources": g["resources"], "extra_security_groups": g["security_groups"][1:],
                      "code": "present", "unknown": g["unknown"]}
        for s in g["security_groups"]:
            carry[s].append(nid)
    ext: Dict[str, Dict[str, Any]] = {}

    def ext_node(key: str, label: str, sub: str, cidrs: List[str], icon: str = "client") -> str:
        if key not in ext:
            ext[key] = {"id": key, "label": label, "kind": "external", "zone": "out", "icon": icon, "sub": sub, "cidrs": cidrs}
        return key

    edges: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def edge(src: str, dst: str, proto: str, lo: int, hi: int, origin: str, cidrs: Optional[List[str]] = None) -> None:
        e = edges.setdefault((src, dst), {"ports": [], "rules": set(), "cidrs": set()})
        e["ports"].append((proto, lo, hi))
        if origin:
            e["rules"].add(origin)
        for c in cidrs or []:
            e["cidrs"].add(c)

    for nid, n in nodes.items():
        for sg in n["security_groups"]:
            model = world.security_groups.get(sg)
            if model is None:
                ext_node("unknown", "확인할 수 없는 출처", "plan 밖 보안 그룹", [sg])
                continue
            for rule in model.rules:
                if rule.direction != "ingress":
                    continue
                proto, lo, hi = _ports(rule)
                pub = []
                for src in rule.sources:
                    if src.kind == "cidr4":
                        one = NetSet.from_cidrs(4, [src.value])
                        if one.covers_everything():
                            edge(ext_node("internet", "인터넷 전체", "0.0.0.0/0", ["0.0.0.0/0"], "users"), nid, proto, lo, hi, rule.origin, [src.value])
                        elif vpc is not None and one.difference(vpc).is_empty():
                            edge(ext_node(f"vpc:{src.value}", f"VPC 대역 {src.value}", "VPC 안 · 어느 서버인지 모름", [src.value]), nid, proto, lo, hi, rule.origin, [src.value])
                        else:
                            pub.append(src.value)
                    elif src.kind == "cidr6":
                        if src.value == "::/0":
                            edge(ext_node("internet6", "인터넷 전체 (IPv6)", "::/0", ["::/0"], "users"), nid, proto, lo, hi, rule.origin, [src.value])
                        else:
                            edge(ext_node(f"v6:{src.value}", f"IPv6 {src.value}", "외부 대역", [src.value]), nid, proto, lo, hi, rule.origin, [src.value])
                    elif src.kind in ("sg", "self"):
                        ref = sg if src.kind == "self" else src.value
                        srcs = carry.get(ref) or []
                        if not srcs:
                            if ref in world.security_groups:
                                k = ext_node(f"sg:{ref}", f"{short(ref)} (붙은 리소스 없음)", "보안 그룹 참조", [])
                            else:
                                k = ext_node("unknown", "확인할 수 없는 출처", "plan 밖 보안 그룹", [ref])
                            edge(k, nid, proto, lo, hi, rule.origin)
                        for s in srcs:
                            edge(s, nid, proto, lo, hi, rule.origin)
                    elif src.kind == "prefix_list":
                        if src.resolved_cidrs:
                            pub.extend(src.resolved_cidrs)
                        else:
                            edge(ext_node(f"pl:{src.value}", f"prefix list {short(src.value)}", "내용 확인 불가", []), nid, proto, lo, hi, rule.origin)
                    else:
                        edge(ext_node("unknown", "확인할 수 없는 출처", "plan 시점 미확정", []), nid, proto, lo, hi, rule.origin)
                if pub:
                    pub = sorted(set(pub))
                    key = "ext:" + ",".join(pub)
                    lab = pub[0] if len(pub) == 1 else f"외부 대역 {len(pub)}개"
                    edge(ext_node(key, lab, ", ".join(pub[:3]) + (" …" if len(pub) > 3 else ""), pub), nid, proto, lo, hi, rule.origin, pub)
    # 외부 출처가 바로 들어오는 묶음 = 외부에서 바로 닿음
    for (s, d) in edges:
        if s in ext and (s.startswith("internet") or s.startswith("ext:") or s.startswith("v6:")) and d in nodes:
            nodes[d]["zone"] = "public"
    flows = []
    for i, ((s, d), e) in enumerate(sorted(edges.items(), key=lambda kv: (kv[0][1], kv[0][0]))):
        flows.append({"id": f"c{i + 1}", "src": s, "dst": d, "ports": _merge_ports(e["ports"]), "port_ranges": [list(p) for p in e["ports"]],
                      "protocol": e["ports"][0][0], "label": ", ".join(sorted(e["rules"]))[:160], "rules": sorted(e["rules"]), "cidrs": sorted(e["cidrs"]),
                      "risk": None})
    if sg_findings:
        mark_risks(flows, nodes, sg_findings)
    in_pic = {r for n in nodes.values() for r in n["resources"]}
    return {"ok": True, "source": "code", "vpc_cidr": vc, "nodes": list(ext.values()) + list(nodes.values()), "flows": flows,
            "zone_titles": {"pub": "외부 노출", "priv": "내부"},
            "design": {"intent_id": None, "intent_version": None}, "inventory": inventory(plan, in_pic), "notes": list(world.notes)}


def mark_risks(flows: List[Dict[str, Any]], nodes: Dict[str, Dict[str, Any]], findings: List[Dict[str, Any]]) -> None:
    """자체 검사 결과 → 그 선에 위험 종류 표시 (같은 대상 묶음 · 겹치는 출처 대역 · 겹치는 포트)."""
    by_key = {tuple(n["security_groups"]): nid for nid, n in nodes.items()}
    for f in findings:
        if f.get("kind") not in RISK_ORDER:
            continue
        dst = by_key.get(tuple(f.get("security_groups") or []))
        if not dst:
            continue
        for fl in flows:
            if fl["dst"] != dst or not set(fl["cidrs"]) & set(f.get("sources") or []):
                continue
            if not any(_overlap((p, a, b), (f["protocol"], f["from_port"], f["to_port"])) for p, a, b in fl["port_ranges"]):
                continue
            if fl["risk"] is None or RISK_ORDER[f["kind"]] < RISK_ORDER.get(fl["risk"], 99):
                fl["risk"] = f["kind"]
                fl["risk_id"] = f["id"]


def _overlap(a: Tuple[str, int, int], b: Tuple[str, int, int]) -> bool:
    if a[0] != b[0] and "-1" not in (a[0], b[0]):
        return False
    return a[1] <= b[2] and b[1] <= a[2]


def inventory(plan: Dict[str, Any], in_picture: set) -> Dict[str, Any]:
    """plan 의 리소스 전부 — 그림에 있는 것 / 그림에 없는 것(왜 없는지). 지어내지 않는다: plan 에 있는 것만."""
    rows = []
    for r in plan.get("resource_changes") or []:
        addr, t = r.get("address", ""), r.get("type", "")
        if r.get("mode") == "data":
            rows.append({"address": addr, "type": t, "type_ko": f"AWS 조회 (data) · {type_ko(t)}", "group": "data", "why": "plan 시점 AWS 조회 — 통신 분석 안 함"})
            continue
        if addr in in_picture:
            g, why = "picture", "그림의 노드 (보안 그룹 통신 분석함)"
        elif t in SG_TYPES:
            g, why = "sg", "그림의 선(규칙)으로 표시"
        elif t in NET_INFRA:
            g, why = "network", "통신 분석에 쓰지 않음 — 라우팅 · NACL · 서브넷은 검사 안 함 (실제 연결은 V8 측정에서만)"
        elif t.startswith("aws_iam_"):
            g, why = "iam", "권한 — Trivy 탐지 + 자체 IAM 검사(요구사항이 있을 때)"
        elif t.startswith("aws_s3_"):
            g, why = "s3", "저장소 — Trivy 탐지만 (자체 수정 · 설계 비교 미지원)"
        else:
            g, why = "other", "Trivy 탐지만 (자체 분석 없음)"
        rows.append({"address": addr, "type": t, "type_ko": type_ko(t), "group": g, "why": why})
    counts: Dict[str, int] = defaultdict(int)
    for x in rows:
        counts[x["group"]] += 1
    return {"rows": rows, "counts": dict(counts), "total": len(rows)}


def draft_design(model: Dict[str, Any], intent_id: str, target_dir: str) -> Dict[str, Any]:
    """현재 코드 그림 → 설계도 초안 (토폴로지 형식). 지금 코드의 통신이 '그대로' 들어간다 — 원하지 않는 통신은 사람이 지워야 한다.
    VPC 대역 · 확인 불가 출처의 규칙은 설계도에 넣을 수 없다(어느 서버인지 모름) → 빼고 notes 에 적는다."""
    nodes = {n["id"]: n for n in model.get("nodes") or []}
    used: set = set()
    tid, eid = {}, {}
    tiers, external, flows, notes = [], [], [], []
    for n in nodes.values():
        if n["kind"] == "tier" and n.get("security_group"):
            tid[n["id"]] = _slug(n["id"], used)
            row = {"id": tid[n["id"]], "label": n["label"], "security_group": n["security_group"]}
            if n.get("icon") in topomodel.KIND_KO:
                row["type"] = n["icon"]
            tiers.append(row)
    for n in nodes.values():
        if n["kind"] == "external" and (n["id"] == "internet" or n["id"].startswith("ext:")):
            eid[n["id"]] = _slug("internet" if n["id"] == "internet" else "ext", used)
            external.append({"id": eid[n["id"]], "label": "사용자(인터넷)" if n["id"] == "internet" else f"외부 대역 {n['label']}", "cidrs_v4": list(n.get("cidrs") or [])})
    seen = set()
    for f in model.get("flows") or []:
        s = tid.get(f["src"]) or eid.get(f["src"])
        d = tid.get(f["dst"])
        if not d:
            continue
        if not s:
            notes.append(f"{nodes.get(f['src'], {}).get('label', f['src'])} → {nodes[f['dst']]['label']} {f['ports']}: 설계도에 넣을 수 없는 출처 (어느 서버인지 모름) — 뺌")
            continue
        for p, lo, hi in f.get("port_ranges") or []:
            row: Dict[str, Any] = {"from": s, "to": d, "protocol": p}
            if p != "-1":
                if lo == hi:
                    row["port"] = lo
                else:
                    row["from_port"], row["to_port"] = lo, hi
            k = (s, d, p, lo, hi)
            if k in seen:
                continue
            seen.add(k)
            row["id"] = f"{s}-{d}-{lo}" if p != "-1" else f"{s}-{d}-all"
            if row["id"] in {x["id"] for x in flows}:
                row["id"] += f"-{len(flows)}"
            flows.append(row)
    risky = _draft_risks(flows, external, tiers)
    for fid, why in risky.items():
        f = next(x for x in flows if x["id"] == fid)
        lab = {**{t["id"]: t["label"] for t in tiers}, **{e["id"]: e["label"] for e in external}}
        port = "전체" if f["protocol"] == "-1" else str(f.get("port", f"{f.get('from_port')}-{f.get('to_port')}"))
        notes.insert(0, f"⚠ {lab.get(f['from'], f['from'])} → {lab.get(f['to'], f['to'])} :{port} — {why}. 고객이 원하지 않으면 지우거나 출발지를 관리자 대역으로 바꾸고 확정하세요")
    return {"kind": "topology", "intent_version": "1", "intent_id": intent_id, "status": "active",
            "description": "지금 코드에서 만든 설계도 초안 — 원하지 않는 통신은 지우고 확정할 것", "target_dir": target_dir,
            "vpc_cidr": model.get("vpc_cidr") or "10.0.0.0/16", "tiers": tiers, "external": external, "flows": flows, "draft_notes": notes,
            "draft_risky": risky}


def _draft_risks(flows: List[Dict[str, Any]], external: List[Dict[str, Any]], tiers: List[Dict[str, Any]]) -> Dict[str, str]:
    """초안의 통신 중 '인터넷 전체 → 관리 포트 · 고위험 포트 · 모든 포트' (자체 보안 그룹 검사와 같은 기준). 저장할 때는 버려진다(normalize)."""
    import ipaddress
    from ..verify.sg_scan import EC2_19_PORTS, MGMT_PORTS
    anyx = set()
    for e in external:
        try:
            nets = list(ipaddress.collapse_addresses(ipaddress.ip_network(c, strict=False) for c in e.get("cidrs_v4") or []))
        except ValueError:
            continue
        if any(n.prefixlen == 0 for n in nets):
            anyx.add(e["id"])
    out: Dict[str, str] = {}
    for f in flows:
        if f["from"] not in anyx:
            continue
        if f["protocol"] == "-1":
            out[f["id"]] = "인터넷 전체에 모든 포트가 열림"
            continue
        lo, hi = int(f.get("port", f.get("from_port", 0))), int(f.get("port", f.get("to_port", 0)))
        mg = [f"{n}({p})" for p, n in MGMT_PORTS.items() if lo <= p <= hi]
        hr = [f"{n}({p})" for p, n in EC2_19_PORTS.items() if lo <= p <= hi and p not in MGMT_PORTS]
        if mg:
            out[f["id"]] = f"인터넷 전체 → 관리 포트 {', '.join(mg)}"
        elif hr:
            out[f["id"]] = f"인터넷 전체 → 고위험 포트 {', '.join(hr[:3])}{' 외' if len(hr) > 3 else ''} (AWS Security Hub EC2.19)"
    return out
