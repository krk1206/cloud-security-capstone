"""설계도(토폴로지) 그림 모델 — 노드 · 연결만 만든다. 좌표(배치)는 화면(static/app/topolayout.js)이 계산한다.

고정 그림을 쓰지 않는다 (2026-10-31 B 요청: "후보대로 토폴로지가 바뀌게, 고정 토폴로지 안 해도 됨").
  - 노드 = 고객 설계도의 외부 출처(external) + 계층(tiers). 설계도가 바뀌면 노드 · 연결도 바뀐다.
  - 아이콘 = 그 계층 보안 그룹이 실제로 붙은 리소스 종류 (V6 결과의 tiers[].attached — 후보 코드 기준).
    붙은 리소스를 모르면(검사 전) 설계도의 type → 이름 낱말 → 서버 순으로 정한다. 어느 것으로 정했는지 icon_source 에 남긴다.
  - 공개/비공개 서브넷 = 설계도에서 외부 출처가 바로 들어오는 계층이면 '공개' (설계도 기준 배치 — 실제 서브넷은 검사하지 않음).
  - 후보마다 달라지는 것: 연결 상태(정상 · 허용 규칙 없음 · 판정 불가)와 설계 밖 연결(excess) — 화면이 V6 결과로 칠한다.
판정은 만들지 않는다. V6 결과(flows · excess · tiers)를 그대로 옮긴다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# 리소스 종류 → 아이콘 파일 이름(static/app/aws/<이름>.svg). 앞에서부터 처음 맞는 것.
_TYPE_ICON: List[Tuple[str, str]] = [
    ("aws_lb", "elb"), ("aws_alb", "elb"), ("aws_elb", "elb"),
    ("aws_db_instance", "rds"), ("aws_rds_cluster", "rds"),
    ("aws_elasticache_", "elasticache"),
    ("aws_ecs_service", "ecs"),
    ("aws_instance", "ec2"), ("aws_launch_template", "ec2"), ("aws_launch_configuration", "ec2"), ("aws_autoscaling_group", "ec2"),
]
_WORD_ICON: List[Tuple[str, Tuple[str, ...]]] = [
    ("elb", ("alb", "nlb", "elb", "load balancer", "로드밸런서", "로드 밸런서")),
    ("rds", ("mysql", "postgres", "rds", "aurora", "database", "데이터베이스", " db", "db ")),
    ("elasticache", ("redis", "memcached", "elasticache", "cache", "캐시")),
    ("ecs", ("ecs", "fargate", "container", "컨테이너")),
]
KIND_KO = {"elb": "로드밸런서", "ec2": "서버 (EC2)", "ecs": "컨테이너 서비스 (ECS)", "rds": "데이터베이스 (RDS)", "elasticache": "캐시 (ElastiCache)"}
ICONS = ("users", "client", "elb", "ec2", "ecs", "rds", "elasticache")


def _icon_from_types(addrs: List[str]) -> Optional[str]:
    for a in addrs:
        t = str(a).split(".")[0]
        for pre, icon in _TYPE_ICON:
            if t.startswith(pre):
                return icon
    return None


def _icon_from_words(tier: Dict[str, Any]) -> Optional[str]:
    text = f" {tier.get('id', '')} {tier.get('label', '')} ".lower()
    for icon, words in _WORD_ICON:
        if any(w in text for w in words):
            return icon
    return None


def _ports(f: Dict[str, Any]) -> str:
    if str(f.get("protocol")) == "-1":
        return "전체"
    if f.get("port") is not None:
        return str(f.get("port"))
    a, b = f.get("from_port"), f.get("to_port")
    return str(a) if a == b else f"{a}-{b}"


def unmapped_resources(plan: Optional[Dict[str, Any]], tiers: Optional[List[Dict[str, Any]]],
                       sources: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """후보 코드(plan)에 있지만 설계도의 어느 계층에도 속하지 않는 리소스 — 보안 그룹이 붙는 리소스만.
    V6 와 같은 plan 해석(verify/plan_model.build_world)을 쓴다. 해석이 안 되면 빈 목록 (그림에 안 그릴 뿐 판정과 무관)."""
    if not plan or not tiers:
        return []
    try:
        from ..verify.plan_model import build_world
        world = build_world(plan, sources or {})
    except Exception:  # noqa: BLE001 — 그림용 부가 정보
        return []
    known = {a for t in tiers for a in (t.get("attached") or [])}
    tier_sgs = {t.get("security_group") for t in tiers}
    out = []
    for ap in world.attachments:
        if ap.address in known or (ap.sg_refs and set(ap.sg_refs) & tier_sgs):
            continue
        out.append({"address": ap.address, "type": ap.resource_type, "security_groups": list(ap.sg_refs)})
    return out[:8]


def _code_state(row: Optional[Dict[str, Any]]) -> Optional[str]:
    """설계도 구성요소가 코드에 있는가 (V6 tiers 행). None = 코드를 안 봤음(설계도만)."""
    if row is None:
        return None
    if row.get("sg_in_code") is False:
        return "missing"          # 설계도에는 있는데 코드에 그 보안 그룹이 없음
    if not row.get("attached"):
        return "unattached"       # 보안 그룹은 있는데 붙은 리소스가 없음
    return "present"


CODE_SUB = {"missing": "코드에 없음", "unattached": "붙은 리소스 없음"}


def model(design: Optional[Dict[str, Any]], tiers: Optional[List[Dict[str, Any]]] = None, source: str = "design",
          unmapped: Optional[List[Dict[str, Any]]] = None, undesigned: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """design: 토폴로지 설계도 dict (kind=topology). tiers: V6 결과의 tiers (있으면 실제 붙은 리소스로 아이콘 · 코드에 있는지).
    source: 'design'(설계도만) · 'current'(원본 코드 검사) · 'record'(후보 검사 기록) · 'draft'(편집 중 미리보기).
    undesigned: V6 결과의 undesigned (D-30) — 코드에만 있는 리소스. 없으면(예전 기록) unmapped(unmapped_resources)를 쓴다.
    노드의 code: present(설계도 = 코드) · missing(코드에 없음) · unattached(붙은 리소스 없음) · extra(설계도에 없음) · None(코드 안 봄)."""
    d = design or {}
    if d.get("kind") not in (None, "topology") or not d.get("tiers"):
        return {"ok": False, "reason": "토폴로지 형식 설계도가 아님 — 그림 없음", "nodes": [], "flows": []}
    ext = d.get("external") or []
    ext_ids = {str(e.get("id")) for e in ext}
    flows = d.get("flows") or []
    att = {str(t.get("id")): list(t.get("attached") or []) for t in (tiers or [])}
    extra_sg = {str(t.get("id")): list(t.get("extra_security_groups") or []) for t in (tiers or [])}
    rows = {str(t.get("id")): t for t in (tiers or [])}
    from_ext = {str(f.get("to")) for f in flows if str(f.get("from")) in ext_ids}
    nodes: List[Dict[str, Any]] = []
    for e in ext:
        wide = "0.0.0.0/0" in (e.get("cidrs_v4") or []) or "::/0" in (e.get("cidrs_v6") or [])
        nodes.append({"id": str(e.get("id")), "label": str(e.get("label") or e.get("id")), "kind": "external", "zone": "out",
                      "icon": "users" if wide else "client", "sub": "외부 · 인터넷 전체" if wide else "외부 · 허용 대역",
                      "cidrs": list(e.get("cidrs_v4") or []) + list(e.get("cidrs_v6") or [])})
    for t in d.get("tiers") or []:
        tid = str(t.get("id"))
        icon, how = _icon_from_types(att.get(tid) or []), "attached"
        if icon is None and str(t.get("type") or "") in KIND_KO:
            icon, how = str(t.get("type")), "design_type"
        if icon is None:
            icon, how = _icon_from_words(t), "name"
        if icon is None:
            icon, how = "ec2", "default"
        code = _code_state(rows.get(tid)) if tiers is not None else None
        nodes.append({"id": tid, "label": str(t.get("label") or tid), "kind": "tier", "zone": "public" if tid in from_ext else "private",
                      "icon": icon, "icon_source": how, "sub": CODE_SUB.get(code or "", KIND_KO[icon]), "security_group": t.get("security_group"),
                      "resources": att.get(tid) or [], "extra_security_groups": extra_sg.get(tid) or [], "code": code, "type": t.get("type")})
    if undesigned is not None:
        for u in undesigned:
            addr = (u.get("resources") or [str(u.get("id", "")).replace("res:", "", 1)])[0]
            icon = _icon_from_types(list(u.get("resources") or [addr])) or "ec2"
            nodes.append({"id": str(u.get("id")), "label": addr.split(".", 1)[-1], "kind": "unmapped", "zone": "private", "icon": icon,
                          "icon_source": "attached", "sub": "설계도에 없는 리소스", "security_group": str(u.get("security_group") or ""),
                          "resources": list(u.get("resources") or []), "extra_security_groups": [], "code": "extra", "inbound": u.get("inbound", 0)})
    for r in (unmapped or []) if undesigned is None else []:
        icon = _icon_from_types([r["address"]]) or "ec2"
        nodes.append({"id": f"res:{r['address']}", "label": r["address"].split(".", 1)[-1], "kind": "unmapped", "zone": "private",
                      "icon": icon, "icon_source": "attached", "sub": "설계도에 없는 리소스", "security_group": ", ".join(r.get("security_groups") or []),
                      "resources": [r["address"]], "extra_security_groups": [], "code": "extra"})
    out_flows = [{"id": str(f.get("id")), "src": str(f.get("from")), "dst": str(f.get("to")), "ports": _ports(f),
                  "protocol": str(f.get("protocol") or "tcp"), "label": str(f.get("label") or "")} for f in flows]
    return {"ok": True, "source": source, "design": {"intent_id": d.get("intent_id"), "intent_version": d.get("intent_version")},
            "vpc_cidr": d.get("vpc_cidr"), "nodes": nodes, "flows": out_flows}
