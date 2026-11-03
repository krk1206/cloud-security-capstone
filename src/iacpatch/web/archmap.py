"""코드의 리소스 전부를 그리는 구성도 (2026-11-01 갈아엎기 5차, D-33 — B: "토폴로지를 저것만 해? 리소스 전부").

Terraform plan JSON(오프라인) 하나로 만든다. 고정 그림 없음 — 코드가 다르면 그림도 다르다. 지어내지 않는다: plan 에 있는 것만.
  상자   = 주요 리소스 (서버 · 서버 묶음 · 컨테이너 서비스 · Lambda · 로드밸런서 · DB · 캐시 · S3 · IAM 역할 · 게이트웨이 · CloudFront …)
           같은 리소스의 count/for_each 는 상자 하나 (×N). 딸린 리소스는 주인 상자에 합친다 (시작 템플릿 → 오토 스케일링 그룹,
           작업 정의 → ECS 서비스, 인스턴스 프로파일 → IAM 역할, 마운트 대상 → EFS …)
  틀     = VPC 상자 · 서브넷 띠. 서브넷은 같은 리소스 이름끼리 한 띠 (aws_subnet.public[0..1] → 'public'). 공개 여부는 코드의 라우팅으로
           정한다: 연결된 라우팅 테이블에 인터넷 게이트웨이 경로가 있으면 공개, NAT 경로면 비공개(NAT), 없으면 비공개 — 코드 기준이지 실제 AWS 확인 아님
  선     = ① 보안 그룹 허용 (출처 → 대상, 포트) — V6 와 같은 계산 재료(plan_model.build_world · sg_scan.groups). 위험 표시는 자체 검사 결과
           ② 요청 경로 (리스너 → 대상 그룹 → 대상, CloudFront 원본, DNS 별칭, API Gateway 연동, 이벤트 연결, DB 복제)
           ③ 권한 (서버 · 서비스 → IAM 역할 → 정책이 허용한 리소스. 정책 내용을 plan 에서 읽을 수 있으면 동작 · 대상까지)
그림은 화면(static/app/archlayout.js · archview.js)이 배치한다. 이 모듈은 판정을 만들지 않는다 (위험 표시 = sg_scan 결과 · 정책 문서 그대로).
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from ..verify.netset import NetSet
from .codetopo import _merge_ports

# 리소스 종류 → (분류, 아이콘, 한국어). 분류: edge(VPC 앞단) · gw(게이트웨이) · lb · compute · data(VPC 안 저장소) · store(VPC 밖 저장소)
#                                           · msg(메시지 · 이벤트) · iam · sec(키 · 비밀 · 인증서) · ops(로그 · 경보)
NODE_TYPES: Dict[str, Tuple[str, str, str]] = {
    "aws_instance": ("compute", "ec2", "서버 (EC2)"),
    "aws_autoscaling_group": ("compute", "autoscaling", "서버 묶음 (Auto Scaling)"),
    "aws_launch_template": ("compute", "ec2", "서버 시작 템플릿"),
    "aws_launch_configuration": ("compute", "ec2", "서버 시작 구성"),
    "aws_ecs_service": ("compute", "ecs", "컨테이너 서비스 (ECS)"),
    "aws_ecs_cluster": ("compute", "ecs", "ECS 클러스터"),
    "aws_ecs_task_definition": ("compute", "ecs", "ECS 작업 정의"),
    "aws_lambda_function": ("compute", "lambda", "Lambda 함수"),
    "aws_eks_cluster": ("compute", "eks", "쿠버네티스 (EKS)"),
    "aws_elastic_beanstalk_environment": ("compute", "beanstalk", "Elastic Beanstalk"),
    "aws_lb": ("lb", "elb", "로드밸런서"),
    "aws_alb": ("lb", "elb", "로드밸런서"),
    "aws_elb": ("lb", "elb", "로드밸런서 (Classic)"),
    "aws_db_instance": ("data", "rds", "데이터베이스 (RDS)"),
    "aws_rds_cluster": ("data", "aurora", "DB 클러스터 (Aurora)"),
    "aws_elasticache_replication_group": ("data", "elasticache", "캐시 (ElastiCache)"),
    "aws_elasticache_cluster": ("data", "elasticache", "캐시 (ElastiCache)"),
    "aws_docdb_cluster": ("data", "docdb", "문서 DB (DocumentDB)"),
    "aws_neptune_cluster": ("data", "neptune", "그래프 DB (Neptune)"),
    "aws_opensearch_domain": ("data", "opensearch", "검색 (OpenSearch)"),
    "aws_elasticsearch_domain": ("data", "opensearch", "검색 (OpenSearch)"),
    "aws_redshift_cluster": ("data", "redshift", "데이터 웨어하우스 (Redshift)"),
    "aws_efs_file_system": ("data", "efs", "파일 시스템 (EFS)"),
    "aws_dynamodb_table": ("store", "dynamodb", "DynamoDB 테이블"),
    "aws_s3_bucket": ("store", "s3", "S3 버킷"),
    "aws_ecr_repository": ("store", "ecr", "컨테이너 이미지 저장소 (ECR)"),
    "aws_sqs_queue": ("msg", "sqs", "SQS 큐"),
    "aws_sns_topic": ("msg", "sns", "SNS 주제"),
    "aws_cloudwatch_event_rule": ("msg", "eventbridge", "EventBridge 규칙"),
    "aws_kinesis_stream": ("msg", "kinesis", "Kinesis 스트림"),
    "aws_sfn_state_machine": ("msg", "stepfunctions", "Step Functions"),
    "aws_iam_role": ("iam", "iam-role", "IAM 역할"),
    "aws_iam_user": ("iam", "iam", "IAM 사용자"),
    "aws_iam_group": ("iam", "iam", "IAM 그룹"),
    "aws_kms_key": ("sec", "kms", "암호화 키 (KMS)"),
    "aws_secretsmanager_secret": ("sec", "secrets", "비밀 (Secrets Manager)"),
    "aws_acm_certificate": ("sec", "acm", "인증서 (ACM)"),
    "aws_cognito_user_pool": ("sec", "cognito", "사용자 풀 (Cognito)"),
    "aws_cloudwatch_log_group": ("ops", "cloudwatch", "로그 그룹 (CloudWatch)"),
    "aws_cloudwatch_metric_alarm": ("ops", "cloudwatch", "경보 (CloudWatch)"),
    "aws_cloudtrail": ("ops", "cloudtrail", "CloudTrail"),
    "aws_backup_plan": ("ops", "backup", "백업 계획"),
    "aws_ssm_parameter": ("sec", "ssm", "파라미터 (SSM)"),
    "aws_cloudfront_distribution": ("edge", "cloudfront", "CloudFront"),
    "aws_route53_zone": ("edge", "route53", "DNS (Route 53)"),
    "aws_wafv2_web_acl": ("edge", "waf", "WAF"),
    "aws_waf_web_acl": ("edge", "waf", "WAF"),
    "aws_api_gateway_rest_api": ("edge", "apigw", "API Gateway"),
    "aws_apigatewayv2_api": ("edge", "apigw", "API Gateway"),
    "aws_internet_gateway": ("gw", "igw", "인터넷 게이트웨이"),
    "aws_nat_gateway": ("gw", "nat", "NAT 게이트웨이"),
    "aws_vpc_endpoint": ("gw", "endpoint", "VPC 엔드포인트"),
    "aws_ec2_transit_gateway": ("gw", "tgw", "Transit Gateway"),
    "aws_networkfirewall_firewall": ("gw", "netfw", "Network Firewall"),
}
# 딸린 리소스 → (주인 리소스 종류들, 주인을 가리키는 설정 속성 · 반대 방향이면 주인이 이것을 가리킴)
MEMBER_OF: Dict[str, Tuple[Tuple[str, ...], str]] = {
    "aws_launch_template": (("aws_autoscaling_group",), "owner_refs"),
    "aws_launch_configuration": (("aws_autoscaling_group",), "owner_refs"),
    "aws_ecs_task_definition": (("aws_ecs_service",), "owner_refs"),
    "aws_ecs_cluster": (("aws_ecs_service",), "owner_refs"),
    "aws_iam_instance_profile": (("aws_iam_role",), "refs"),
    "aws_rds_cluster_instance": (("aws_rds_cluster",), "refs"),
    "aws_efs_mount_target": (("aws_efs_file_system",), "refs"),
    "aws_eks_node_group": (("aws_eks_cluster",), "refs"),
    "aws_eip": (("aws_nat_gateway", "aws_instance"), "either"),
}
# 그림 상자가 아니라 선 · 띠 · 상자 안 정보로 쓰는 리소스 (목록에서 '그림에 반영' 으로 센다)
DRAWN_AS_LINK = ("aws_lb_listener", "aws_lb_listener_rule", "aws_alb_listener", "aws_lb_target_group", "aws_alb_target_group", "aws_lb_target_group_attachment",
                 "aws_autoscaling_attachment", "aws_route53_record", "aws_wafv2_web_acl_association", "aws_api_gateway_integration",
                 "aws_apigatewayv2_integration", "aws_lambda_event_source_mapping", "aws_sns_topic_subscription", "aws_iam_role_policy",
                 "aws_iam_role_policy_attachment", "aws_iam_policy", "aws_iam_policy_attachment", "aws_security_group", "aws_security_group_rule",
                 "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule", "aws_default_security_group")
DRAWN_AS_FRAME = ("aws_vpc", "aws_subnet", "aws_route_table", "aws_route_table_association", "aws_route", "aws_default_route_table",
                  "aws_db_subnet_group", "aws_elasticache_subnet_group", "aws_redshift_subnet_group", "aws_docdb_subnet_group", "aws_neptune_subnet_group")
OPS_MERGE = ("ops",)          # 로그 · 경보는 종류별로 상자 하나 (×N) — 그림이 넘치지 않게
RISK_ORDER = {"all_ports_public": 0, "mgmt_public": 1, "highrisk_public": 2, "split_any": 3, "ipv6_any": 4, "vpc_wide": 5}
SKIP_REF = ("var.", "local.", "count.", "each.", "path.", "data.", "module.", "self.", "terraform.")
SUBNET_KIND_KO = {"public": "공개 서브넷", "private_nat": "비공개 서브넷 (NAT 경유 인터넷)", "private": "비공개 서브넷", "unknown": "서브넷"}


def base(addr: str) -> str:
    """aws_subnet.public[0] → aws_subnet.public"""
    return re.sub(r"\[[^\]]*\]", "", str(addr or ""))


def rtype(addr: str) -> str:
    parts = base(addr).split(".")
    return parts[-2] if len(parts) >= 2 else ""


def rname(addr: str) -> str:
    return base(addr).split(".")[-1]


def _ref_base(r: str) -> Optional[str]:
    if not r or r.startswith(SKIP_REF):
        return None
    parts = r.split(".")
    if len(parts) < 2 or not parts[0].startswith("aws_"):
        return None
    name = re.sub(r"\[.*", "", parts[1])
    return f"{parts[0]}.{name}"


def _collect(expr: Any, out: Set[str]) -> None:
    if isinstance(expr, dict):
        for k, v in expr.items():
            if k == "references" and isinstance(v, list):
                for r in v:
                    b = _ref_base(str(r))
                    if b:
                        out.add(b)
            else:
                _collect(v, out)
    elif isinstance(expr, list):
        for v in expr:
            _collect(v, out)


def refs_at(exprs: Dict[str, Any], *path: str) -> Set[str]:
    """설정 식에서 특정 속성(중첩 블록 포함) 아래의 리소스 참조 (주소에서 [i] · 속성 이름은 뗌)."""
    cur: List[Any] = [exprs or {}]
    for key in path:
        nxt: List[Any] = []
        for c in cur:
            if isinstance(c, list):
                for x in c:
                    if isinstance(x, dict) and key in x:
                        nxt.append(x[key])
            elif isinstance(c, dict) and key in c:
                nxt.append(c[key])
        cur = nxt
    out: Set[str] = set()
    for c in cur:
        _collect(c, out)
    return out


def _vals(pv: Dict[str, List[Dict[str, Any]]], b: str) -> List[Dict[str, Any]]:
    return [x.get("values") or {} for x in pv.get(b, [])]


def _az_short(az: str) -> str:
    m = re.search(r"(\d[a-z])$", str(az or ""))
    return m.group(1) if m else str(az or "")


def _policy_statements(doc: Any) -> Optional[List[Dict[str, Any]]]:
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return None
    if not isinstance(doc, dict):
        return None
    st = doc.get("Statement")
    if isinstance(st, dict):
        st = [st]
    return [s for s in st if isinstance(s, dict)] if isinstance(st, list) else None


def _as_list(x: Any) -> List[str]:
    if x is None:
        return []
    return [str(v) for v in x] if isinstance(x, list) else [str(x)]


def _actions_text(acts: List[str]) -> str:
    acts = sorted(set(acts))
    if not acts:
        return "권한"
    return acts[0] if len(acts) == 1 else f"{acts[0]} 외 {len(acts) - 1}"


def build(plan: Dict[str, Any], sources: Optional[Dict[str, str]] = None, sg_findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    from ..verify.plan_model import PlanParseError, build_world
    from ..verify.sg_scan import _ports, groups as sg_groups
    from .codetopo import inventory as _inventory
    root = (plan.get("planned_values") or {}).get("root_module") or {}
    pv: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in root.get("resources") or []:
        if r.get("mode") == "managed":
            pv[base(r.get("address", ""))].append(r)
    cfg: Dict[str, Dict[str, Any]] = {}
    for r in ((plan.get("configuration") or {}).get("root_module") or {}).get("resources") or []:
        if r.get("mode") == "managed":
            cfg[r["address"]] = r.get("expressions") or {}
    managed = sorted(set(pv) | set(cfg))
    refs: Dict[str, Set[str]] = {a: refs_at({"_": cfg.get(a, {})}, "_") for a in managed}
    rev: Dict[str, Set[str]] = defaultdict(set)
    for a, rs in refs.items():
        for b in rs:
            rev[b].add(a)
    count = {a: max(1, len(pv.get(a, [])) or 1) for a in managed}

    # ---------------------------------------------------------------- 1) 상자: 주요 리소스 + 딸린 리소스 합치기
    owner: Dict[str, str] = {}               # 딸린 리소스 → 주인 리소스
    for a in managed:
        t = rtype(a)
        if t not in MEMBER_OF:
            continue
        kinds, how = MEMBER_OF[t]
        hit = None
        if how in ("owner_refs", "either"):
            hit = next((o for o in sorted(rev.get(a, ())) if rtype(o) in kinds), None)
        if hit is None and how in ("refs", "either"):
            hit = next((o for o in sorted(refs.get(a, ())) if rtype(o) in kinds), None)
        if hit:
            owner[a] = hit
    nodes: Dict[str, Dict[str, Any]] = {}
    node_of: Dict[str, str] = {}             # 리소스 주소(기본) → 상자 id
    for a in managed:
        t = rtype(a)
        if t not in NODE_TYPES or a in owner:
            continue
        cat, icon, ko = NODE_TYPES[t]
        nid = f"n:{a}"
        if cat in OPS_MERGE:
            nid = f"n:ops:{icon}"
            if nid in nodes:
                nodes[nid]["addresses"].append(a)
                nodes[nid]["count"] += count[a]
                nodes[nid]["kinds"][ko] = nodes[nid]["kinds"].get(ko, 0) + count[a]
                node_of[a] = nid
                continue
        nodes[nid] = {"id": nid, "type": t, "cat": cat, "icon": icon, "type_ko": ko, "label": rname(a) if cat not in OPS_MERGE else ko.split(" (")[-1].rstrip(")"),
                      "addresses": [a], "members": [], "count": count[a], "facts": [], "sgs": [], "place": None, "kinds": {ko: count[a]}}
        node_of[a] = nid
    for a, o in owner.items():
        if o in node_of:
            node_of[a] = node_of[o]
            nodes[node_of[o]]["members"].append(a)

    def nid_of(a: str) -> Optional[str]:
        return node_of.get(base(a))

    # ---------------------------------------------------------------- 2) 틀: VPC · 서브넷 띠 (공개 여부 = 코드의 라우팅)
    vpcs: Dict[str, Dict[str, Any]] = {}
    for a in managed:
        if rtype(a) == "aws_vpc":
            v = (_vals(pv, a) or [{}])[0]
            vpcs[a] = {"id": f"vpc:{a}", "address": a, "label": f"VPC {rname(a)}", "cidr": v.get("cidr_block")}
    route_kind: Dict[str, str] = {}          # 라우팅 테이블 → public / private_nat / private
    for a in managed:
        t = rtype(a)
        if t in ("aws_route_table", "aws_default_route_table"):
            rs = refs.get(a, set())
            route_kind[a] = "public" if any(rtype(x) == "aws_internet_gateway" for x in rs) else (
                "private_nat" if any(rtype(x) == "aws_nat_gateway" for x in rs) else "private")
    for a in managed:                        # aws_route 리소스로 따로 적은 경로
        if rtype(a) == "aws_route":
            rs = refs.get(a, set())
            rt = next((x for x in rs if rtype(x) == "aws_route_table"), None)
            if rt:
                if any(rtype(x) == "aws_internet_gateway" for x in rs):
                    route_kind[rt] = "public"
                elif any(rtype(x) == "aws_nat_gateway" for x in rs) and route_kind.get(rt) != "public":
                    route_kind[rt] = "private_nat"
    subnet_kind: Dict[str, str] = {}
    for a in managed:
        if rtype(a) == "aws_route_table_association":
            rs = refs.get(a, set())
            sn = [x for x in rs if rtype(x) == "aws_subnet"]
            rt = [x for x in rs if x in route_kind]
            for s in sn:
                for r in rt:
                    k = route_kind[r]
                    if subnet_kind.get(s) != "public":
                        subnet_kind[s] = k if subnet_kind.get(s) != "private_nat" or k == "public" else "private_nat"
    has_routes = any(rtype(a) == "aws_route_table_association" for a in managed)
    subnets: Dict[str, Dict[str, Any]] = {}
    for a in managed:
        if rtype(a) != "aws_subnet":
            continue
        vals = _vals(pv, a)
        vpc = next((v for v in refs.get(a, set()) if v in vpcs), None)
        kind = subnet_kind.get(a) or ("private" if has_routes else "unknown")
        if kind != "public" and any(v.get("map_public_ip_on_launch") for v in vals) and not has_routes:
            kind = "public"
        azs = sorted({_az_short(v.get("availability_zone")) for v in vals if v.get("availability_zone")})
        subnets[a] = {"id": f"sn:{a}", "address": a, "name": rname(a), "vpc": vpcs[vpc]["id"] if vpc else None, "kind": kind,
                      "label": SUBNET_KIND_KO[kind], "azs": azs, "count": count[a], "cidrs": [v.get("cidr_block") for v in vals if v.get("cidr_block")]}

    def subnets_of(a: str) -> List[str]:
        """리소스가 놓이는 서브넷 (직접 참조 또는 DB · 캐시 서브넷 그룹을 거쳐서)."""
        out: Set[str] = set()
        for x in refs.get(a, set()):
            t = rtype(x)
            if t == "aws_subnet":
                out.add(x)
            elif t.endswith("_subnet_group"):
                out |= {y for y in refs.get(x, set()) if rtype(y) == "aws_subnet"}
        return sorted(out)

    def vpc_of(a: str, sns: List[str]) -> Optional[str]:
        for s in sns:
            if s in subnets and subnets[s]["vpc"]:
                return subnets[s]["vpc"]
        v = next((x for x in refs.get(a, set()) if x in vpcs), None)
        if v:
            return vpcs[v]["id"]
        for x in refs.get(a, set()):           # 대상 그룹 · 보안 그룹을 거쳐 VPC 를 아는 경우
            v = next((y for y in refs.get(x, set()) if y in vpcs), None)
            if v and rtype(x) in ("aws_security_group", "aws_lb_target_group"):
                return vpcs[v]["id"]
        return None

    for n in nodes.values():
        addrs = n["addresses"] + n["members"]
        sns = sorted({s for a in addrs for s in subnets_of(a)})
        cat = n["cat"]
        if cat in ("edge", "store", "msg", "iam", "sec", "ops"):
            n["place"] = {"area": "edge" if cat == "edge" else "outside"}
            continue
        if n["type"] == "aws_internet_gateway":
            v = vpc_of(n["addresses"][0], [])
            n["place"] = {"area": "vpc_gw", "vpc": v} if v else {"area": "outside"}
            continue
        if n["type"] == "aws_lambda_function" and not sns:
            n["place"] = {"area": "outside"}
            continue
        v = vpc_of(addrs[0], sns) or next((vpc_of(a, sns) for a in addrs[1:] if vpc_of(a, sns)), None)
        if sns:
            key = "+".join(sns)
            n["place"] = {"area": "subnet", "vpc": v, "subnets": [subnets[s]["id"] for s in sns if s in subnets], "band": key}
        elif v:
            n["place"] = {"area": "vpc", "vpc": v}
        else:
            n["place"] = {"area": "outside"}
    for a in managed:            # 읽기 복제본은 원본 DB 의 서브넷 그룹을 따른다 (코드에 서브넷이 따로 없으면)
        if rtype(a) == "aws_db_instance" and nid_of(a):
            n = nodes[nid_of(a)]
            src = next(iter(refs_at(cfg.get(a, {}), "replicate_source_db")), None)
            if src and nid_of(src) and (n["place"] or {}).get("area") == "vpc" and (nodes[nid_of(src)]["place"] or {}).get("area") == "subnet":
                n["place"] = dict(nodes[nid_of(src)]["place"])
                n["facts"].append(("서브넷", "원본 DB 와 같음 (읽기 복제본)"))
    # 띠 = 상자가 놓인 서브넷 조합 (공개 · 비공개가 섞이면 그 조합 그대로 — 지어내지 않는다)
    bands: Dict[str, Dict[str, Any]] = {}
    for n in nodes.values():
        p = n["place"] or {}
        if p.get("area") != "subnet":
            continue
        key = p["band"]
        if key not in bands:
            sns = [subnets[s] for s in key.split("+") if s in subnets]
            kinds = {s["kind"] for s in sns}
            kind = kinds.pop() if len(kinds) == 1 else "mixed"
            azs = sorted({z for s in sns for z in s["azs"]})
            label = (SUBNET_KIND_KO.get(kind) or "공개 · 비공개 서브넷에 걸침")
            bands[key] = {"id": f"band:{key}", "vpc": p.get("vpc"), "kind": kind, "label": label, "names": [s["name"] for s in sns],
                          "azs": azs, "subnets": [s["id"] for s in sns], "cidrs": [c for s in sns for c in s["cidrs"]]}
        p["band"] = bands[key]["id"]

    # ---------------------------------------------------------------- 3) 보안 그룹 허용 (출처 → 대상, 포트) — V6 와 같은 계산 재료
    edges: List[Dict[str, Any]] = []
    ext: Dict[str, Dict[str, Any]] = {}
    sg_nodes: Dict[str, List[str]] = defaultdict(list)          # 보안 그룹 주소 → 그것을 단 상자들
    notes: List[str] = []
    world = None
    try:
        world = build_world(plan, sources or {})
    except PlanParseError as e:
        notes.append(f"보안 그룹 해석 실패 — 통신 선을 그리지 못함: {e}")
    vpc_cidrs = [v["cidr"] for v in vpcs.values() if v.get("cidr")]
    vpc_net = NetSet.from_cidrs(4, vpc_cidrs) if vpc_cidrs else None

    def ext_node(key: str, label: str, sub: str, cidrs: List[str], icon: str = "client") -> str:
        if key not in ext:
            ext[key] = {"id": key, "type": "external", "cat": "external", "icon": icon, "type_ko": "외부 출처", "label": label, "sub": sub,
                        "cidrs": cidrs, "addresses": [], "members": [], "count": 1, "facts": [], "sgs": [], "place": {"area": "external"}}
            if key.startswith("x:vpc:"):
                ext[key]["place"] = {"area": "vpc_src"}
        return key

    sg_edges: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def sg_edge(src: str, dst: str, proto: str, lo: int, hi: int, origin: str, cidrs: Optional[List[str]] = None,
                dst_sg: str = "", src_sg: str = "") -> None:
        if src == dst:
            return
        e = sg_edges.setdefault((src, dst), {"ports": [], "rules": set(), "cidrs": set(), "dst_sgs": set(), "src_sgs": set(), "rule_ranges": defaultdict(set)})
        e["ports"].append((proto, lo, hi))
        if origin:
            e["rules"].add(origin)
            e["rule_ranges"][origin].add((proto, lo, hi))
        e["cidrs"].update(cidrs or [])
        if dst_sg:
            e["dst_sgs"].add(dst_sg)
        if src_sg:
            e["src_sgs"].add(src_sg)

    group_nodes: Dict[Tuple[str, ...], List[str]] = {}
    if world is not None:
        gs = sg_groups(world)
        carry: Dict[str, List[str]] = defaultdict(list)
        for g in gs:
            ids = sorted({nid_of(r) for r in g["resources"] if nid_of(r)})
            group_nodes[tuple(g["security_groups"])] = ids
            for sg in g["security_groups"]:
                for i in ids:
                    if i not in carry[sg]:
                        carry[sg].append(i)
                    if i not in sg_nodes[sg]:
                        sg_nodes[sg].append(i)
            for i in ids:
                for sg in g["security_groups"]:
                    if sg not in nodes[i]["sgs"]:
                        nodes[i]["sgs"].append(sg)
        for g in gs:
            ids = group_nodes.get(tuple(g["security_groups"])) or []
            for sg in g["security_groups"]:
                model = world.security_groups.get(sg)
                if model is None:
                    continue
                for rule in model.rules:
                    if rule.direction != "ingress":
                        continue
                    proto, lo, hi = _ports(rule)
                    pub: List[str] = []
                    for src in rule.sources:
                        targets: List[Tuple[str, List[str]]] = []
                        if src.kind == "cidr4":
                            one = NetSet.from_cidrs(4, [src.value])
                            if one.covers_everything():
                                targets.append((ext_node("x:internet", "인터넷 전체", "0.0.0.0/0", ["0.0.0.0/0"], "users"), [src.value]))
                            elif vpc_net is not None and one.difference(vpc_net).is_empty():
                                targets.append((ext_node(f"x:vpc:{src.value}", "VPC 안 모든 서버", src.value, [src.value]), [src.value]))
                            else:
                                pub.append(src.value)
                        elif src.kind == "cidr6":
                            k = ext_node("x:internet6", "인터넷 전체 (IPv6)", "::/0", ["::/0"], "users") if src.value == "::/0" else \
                                ext_node(f"x:v6:{src.value}", f"IPv6 {src.value}", "외부 대역", [src.value])
                            targets.append((k, [src.value]))
                        elif src.kind in ("sg", "self"):
                            ref = sg if src.kind == "self" else src.value
                            srcs = carry.get(ref) or []
                            if not srcs:
                                k = (ext_node(f"x:sg:{ref}", f"{rname(ref)} (붙은 리소스 없음)", "보안 그룹 참조", []) if ref in world.security_groups
                                     else ext_node("x:unknown", "확인할 수 없는 출처", "plan 밖 보안 그룹", [ref]))
                                targets.append((k, []))
                            targets += [(s, []) for s in srcs]
                        elif src.kind == "prefix_list":
                            if src.resolved_cidrs:
                                pub.extend(src.resolved_cidrs)
                            else:
                                targets.append((ext_node(f"x:pl:{src.value}", f"prefix list {rname(src.value)}", "내용 확인 불가", []), []))
                        else:
                            targets.append((ext_node("x:unknown", "확인할 수 없는 출처", "plan 시점 미확정", []), []))
                        ref_sg = (sg if src.kind == "self" else src.value) if src.kind in ("sg", "self") else ""
                        for s, cs in targets:
                            for d in ids:
                                sg_edge(s, d, proto, lo, hi, rule.origin, cs, dst_sg=sg, src_sg=ref_sg)
                    if pub:
                        pub = sorted(set(pub))
                        key = "x:cidr:" + ",".join(pub)
                        lab = pub[0] if len(pub) == 1 else f"외부 대역 {len(pub)}개"
                        k = ext_node(key, lab, ", ".join(pub[:3]) + (" …" if len(pub) > 3 else ""), pub)
                        for d in ids:
                            sg_edge(k, d, proto, lo, hi, rule.origin, pub, dst_sg=sg)
        if world.notes:
            notes.extend(world.notes)
    for (s, d), e in sorted(sg_edges.items()):
        edges.append({"src": s, "dst": d, "kind": "sg", "ports": _merge_ports(e["ports"]), "port_ranges": [list(p) for p in sorted(set(e["ports"]))],
                      "rules": sorted(e["rules"]), "cidrs": sorted(e["cidrs"]), "dst_sgs": sorted(e["dst_sgs"]), "src_sgs": sorted(e["src_sgs"]),
                      "rule_ranges": {o: [list(r) for r in sorted(rs)] for o, rs in sorted(e["rule_ranges"].items())}, "risk": None, "label": ""})
    if sg_findings:
        _mark_risks(edges, group_nodes, sg_findings)
    for e in edges:                 # 포트 하나하나 (위험한 포트만 빨갛게 그리려고)
        risky = {tuple(r) for r in e.pop("risk_ranges", [])}
        items: List[Dict[str, Any]] = []
        for pr in sorted({tuple(x) for x in e["port_ranges"]}, key=lambda t: (t[0] != "tcp", t[1], t[2])):
            txt = _merge_ports([pr])
            hit = next((it for it in items if it["text"] == txt), None)
            if hit is None:
                items.append({"text": txt, "risk": bool(pr in risky), "range": list(pr)})
            elif pr in risky:
                hit["risk"] = True
        e["port_items"] = items

    # ---------------------------------------------------------------- 4) 요청 경로
    def addr_vals(a: str) -> Dict[str, Any]:
        return (_vals(pv, a) or [{}])[0]

    def link(src: Optional[str], dst: Optional[str], kind: str, label: str = "", **extra: Any) -> None:
        if not src or not dst or src == dst:
            return
        for e in edges:
            if e["src"] == src and e["dst"] == dst and e["kind"] == kind:
                if label and label not in e["label"].split(" · "):
                    e["label"] = (e["label"] + " · " + label).strip(" ·")
                return
        edges.append({"src": src, "dst": dst, "kind": kind, "label": label, "ports": "", "port_ranges": [], "rules": [], "cidrs": [], "risk": None, **extra})

    tg_targets: Dict[str, Set[str]] = defaultdict(set)
    for a in managed:
        t = rtype(a)
        ex = cfg.get(a, {})
        if t == "aws_autoscaling_group":
            for tg in refs_at(ex, "target_group_arns"):
                tg_targets[tg].add(nid_of(a) or "")
        elif t == "aws_ecs_service":
            for tg in refs_at(ex, "load_balancer", "target_group_arn"):
                tg_targets[tg].add(nid_of(a) or "")
        elif t == "aws_lb_target_group_attachment":
            for tg in refs_at(ex, "target_group_arn"):
                for tid in refs_at(ex, "target_id"):
                    tg_targets[tg].add(nid_of(tid) or "")
        elif t == "aws_autoscaling_attachment":
            for tg in refs_at(ex, "lb_target_group_arn") | refs_at(ex, "alb_target_group_arn"):
                for asg in refs_at(ex, "autoscaling_group_name"):
                    tg_targets[tg].add(nid_of(asg) or "")
    listener_text: Dict[str, List[str]] = defaultdict(list)
    for a in managed:
        t = rtype(a)
        ex = cfg.get(a, {})
        if t in ("aws_lb_listener", "aws_alb_listener"):
            v = addr_vals(a)
            lbs = refs_at(ex, "load_balancer_arn")
            tgs = refs_at(ex, "default_action", "target_group_arn") | refs_at(ex, "default_action", "forward", "target_group", "arn")
            txt = f"{v.get('protocol') or ''} {v.get('port') or ''}".strip()
            for lb in lbs:
                if nid_of(lb):
                    listener_text[nid_of(lb)].append(txt)
                for tg in tgs:
                    tv = addr_vals(tg)
                    lab = txt + (f" → {tv.get('port')}" if tv.get("port") and str(tv.get("port")) not in txt.split() else "")
                    for tid in tg_targets.get(tg, ()):
                        link(nid_of(lb), tid, "traffic", lab)
        elif t == "aws_lb_listener_rule":
            for lst in refs_at(ex, "listener_arn"):
                for lb in refs.get(lst, set()):
                    if rtype(lb) in ("aws_lb", "aws_alb"):
                        for tg in refs_at(ex, "action", "target_group_arn"):
                            for tid in tg_targets.get(tg, ()):
                                link(nid_of(lb), tid, "traffic", "규칙")
        elif t == "aws_elb":
            for i in refs_at(ex, "instances"):
                link(nid_of(a), nid_of(i), "traffic", "리스너")
        elif t == "aws_wafv2_web_acl_association":
            for w in refs_at(ex, "web_acl_arn"):
                for r in refs_at(ex, "resource_arn"):
                    link(nid_of(w), nid_of(r), "protect", "보호")
        elif t == "aws_cloudfront_distribution":
            for w in refs_at(ex, "web_acl_id"):
                link(nid_of(w), nid_of(a), "protect", "보호")
            for o in refs_at(ex, "origin", "domain_name"):
                link(nid_of(a), nid_of(o), "traffic", "원본")
        elif t == "aws_route53_record":
            zone = next(iter(refs_at(ex, "zone_id")), None)
            name = addr_vals(a).get("name") or rname(a)
            for tgt in refs_at(ex, "alias", "name"):
                link(nid_of(zone) if zone else None, nid_of(tgt), "traffic", f"{name}")
        elif t in ("aws_api_gateway_integration", "aws_apigatewayv2_integration"):
            api = next(iter(refs_at(ex, "rest_api_id") | refs_at(ex, "api_id")), None)
            for tgt in refs_at(ex, "uri") | refs_at(ex, "integration_uri"):
                link(nid_of(api) if api else None, nid_of(tgt), "traffic", "연동")
        elif t == "aws_lambda_event_source_mapping":
            for s in refs_at(ex, "event_source_arn"):
                for fn in refs_at(ex, "function_name"):
                    link(nid_of(s), nid_of(fn), "traffic", "이벤트")
        elif t == "aws_sns_topic_subscription":
            for s in refs_at(ex, "topic_arn"):
                for d in refs_at(ex, "endpoint"):
                    link(nid_of(s), nid_of(d), "traffic", "구독")
        elif t == "aws_db_instance":
            for p in refs_at(ex, "replicate_source_db"):
                link(nid_of(p), nid_of(a), "replica", "복제")
    # CloudFront 원본 이름 = DNS 레코드 이름 → 그 레코드의 별칭 대상 (설정 참조가 없을 때 값으로 잇는다)
    rec_target: Dict[str, Set[str]] = defaultdict(set)
    for a in managed:
        if rtype(a) == "aws_route53_record":
            name = str(addr_vals(a).get("name") or "").rstrip(".")
            if name:
                rec_target[name] |= {x for x in refs_at(cfg.get(a, {}), "alias", "name")}
    for a in managed:
        if rtype(a) != "aws_cloudfront_distribution":
            continue
        for o in addr_vals(a).get("origin") or []:
            dn = str((o or {}).get("domain_name") or "").rstrip(".")
            for tgt in rec_target.get(dn, ()):
                link(nid_of(a), nid_of(tgt), "traffic", "원본")
            if dn.endswith(".s3.amazonaws.com") or ".s3." in dn:
                b = dn.split(".s3")[0]
                hit = next((x for x in managed if rtype(x) == "aws_s3_bucket" and addr_vals(x).get("bucket") == b), None)
                link(nid_of(a), nid_of(hit) if hit else None, "traffic", "원본")
    # 인터넷 게이트웨이 → 공개 서브넷의 로드밸런서 (인터넷 공개 LB 만, 코드 값 기준)
    for n in nodes.values():
        if n["cat"] == "lb":
            v = addr_vals(n["addresses"][0])
            internal = v.get("internal")
            n["facts"].append(("공개 여부", "내부용 (internal)" if internal else "인터넷 공개" if internal is False else "모름"))
            if listener_text.get(n["id"]):
                n["facts"].append(("리스너", ", ".join(sorted(set(listener_text[n["id"]])))))

    # ---------------------------------------------------------------- 5) 권한: 서버 · 서비스 → IAM 역할 → 정책이 허용한 리소스
    role_of: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)   # 상자 → (역할, 어떤 역할)
    for a in managed:
        t = rtype(a)
        ex = cfg.get(a, {})
        holder = nid_of(a)
        if not holder:
            continue
        pairs: List[Tuple[Set[str], str]] = []
        if t in ("aws_instance", "aws_launch_template", "aws_launch_configuration"):
            pairs.append((refs_at(ex, "iam_instance_profile"), "인스턴스 역할"))
        elif t == "aws_ecs_task_definition":
            pairs.append((refs_at(ex, "task_role_arn"), "작업 역할"))
            pairs.append((refs_at(ex, "execution_role_arn"), "실행 역할"))
        elif t == "aws_lambda_function":
            pairs.append((refs_at(ex, "role"), "실행 역할"))
        elif t == "aws_eks_cluster":
            pairs.append((refs_at(ex, "role_arn"), "클러스터 역할"))
        elif t == "aws_eks_node_group":
            pairs.append((refs_at(ex, "node_role_arn"), "노드 역할"))
        for rs, why in pairs:
            for r in rs:
                role = r if rtype(r) == "aws_iam_role" else next((x for x in refs.get(r, set()) if rtype(x) == "aws_iam_role"), None)
                if role and nid_of(role):
                    role_of[holder].add((nid_of(role), why))
    for holder, rs in role_of.items():
        for rid, why in sorted(rs):
            link(holder, rid, "role", why)
    # 역할 → 정책 문서들 (인라인 · 연결된 관리형 · 직접 만든 정책)
    policies_of: Dict[str, List[Tuple[str, Optional[List[Dict[str, Any]]], Set[str]]]] = defaultdict(list)
    for a in managed:
        t = rtype(a)
        ex = cfg.get(a, {})
        if t == "aws_iam_role_policy":
            for r in refs_at(ex, "role"):
                if nid_of(r):
                    policies_of[nid_of(r)].append((a, _policy_statements(addr_vals(a).get("policy")), refs_at(ex, "policy")))
        elif t in ("aws_iam_role_policy_attachment", "aws_iam_policy_attachment"):
            pol = refs_at(ex, "policy_arn")
            roles = refs_at(ex, "role") | refs_at(ex, "roles")
            managed_arn = addr_vals(a).get("policy_arn")
            for r in roles:
                if not nid_of(r):
                    continue
                for p in pol:
                    policies_of[nid_of(r)].append((p, _policy_statements(addr_vals(p).get("policy")), refs_at(cfg.get(p, {}), "policy")))
                if not pol and managed_arn:
                    nodes[nid_of(r)]["facts"].append(("AWS 관리형 정책", str(managed_arn).split("/")[-1]))
        elif t == "aws_iam_role":
            for blk in addr_vals(a).get("inline_policy") or []:
                if nid_of(a):
                    policies_of[nid_of(a)].append((a, _policy_statements((blk or {}).get("policy")), set()))
    allres = None
    for rid, pols in policies_of.items():
        for paddr, stmts, prefs in pols:
            if stmts is None:
                for x in sorted(prefs):
                    link(rid, nid_of(x), "perm", "권한 (미확정)", policy=paddr,
                         why="정책 내용이 plan 시점에 정해지지 않아(다른 리소스 값을 참조) 어떤 동작을 허용하는지 그림에서 알 수 없음 — 코드에서 확인")
                if not prefs:
                    nodes[rid]["facts"].append(("정책", f"{paddr} — 내용은 plan 시점 미확정"))
                continue
            for st in stmts:
                if str(st.get("Effect", "Allow")) != "Allow":
                    continue
                acts = _as_list(st.get("Action"))
                ress = _as_list(st.get("Resource"))
                broad = any(x == "*" or x.endswith(":*") for x in acts)
                if "*" in ress:
                    if allres is None:
                        allres = ext_node("x:allres", "모든 리소스 (*)", "정책의 Resource \"*\"", [], "iam")
                        ext[allres]["place"] = {"area": "outside"}
                        ext[allres]["cat"] = "iam"
                    link(rid, allres, "perm", _actions_text(acts), policy=paddr, risk="broad_perm" if broad else None)
                for x in sorted(prefs):
                    if nid_of(x) and nid_of(x) != rid:
                        link(rid, nid_of(x), "perm", _actions_text(acts), policy=paddr, risk="broad_perm" if broad and "*" in ress else None)

    # ---------------------------------------------------------------- 6) 상자 설명 · 보안 그룹 · 위치
    for n in nodes.values():
        a = n["addresses"][0]
        v = addr_vals(a)
        t = n["type"]
        if t == "aws_instance":
            n["facts"].append(("종류", str(v.get("instance_type") or "")))
        elif t == "aws_autoscaling_group":
            n["facts"].append(("개수", f"최소 {v.get('min_size')} · 최대 {v.get('max_size')}"))
        elif t == "aws_ecs_service":
            n["facts"].append(("작업 수", str(v.get("desired_count"))))
            if v.get("launch_type"):
                n["facts"].append(("실행 방식", str(v.get("launch_type"))))
        elif t in ("aws_db_instance", "aws_rds_cluster"):
            n["facts"].append(("엔진", f"{v.get('engine') or ''} {v.get('engine_version') or ''}".strip()))
            if v.get("publicly_accessible"):
                n["facts"].append(("공개 접속", "켜짐 (publicly_accessible)"))
        elif t == "aws_s3_bucket" and v.get("bucket"):
            n["facts"].append(("버킷 이름", str(v.get("bucket"))))
        if n["members"]:
            n["facts"].append(("함께 묶은 리소스", ", ".join(n["members"][:4]) + (" 외" if len(n["members"]) > 4 else "")))
        if n["sgs"]:
            n["facts"].append(("보안 그룹", ", ".join(rname(s) for s in n["sgs"])))
        n["sub"] = n["type_ko"] + (f" ×{n['count']}" if n["count"] > 1 else "")
        if n["cat"] in OPS_MERGE:
            n["sub"] = " · ".join(f"{k.split(' (')[0]} {v}" for k, v in sorted(n.get("kinds", {}).items()))

    # ---------------------------------------------------------------- 7) 소유 관계: 지적(Trivy 등)을 어느 상자 · 틀에 붙일지
    owners: Dict[str, List[str]] = {}
    for a in managed:
        if a in node_of:
            owners[a] = [node_of[a]]
        elif a in vpcs:
            owners[a] = [vpcs[a]["id"]]
        elif a in subnets:
            owners[a] = [b["id"] for b in bands.values() if subnets[a]["id"] in b["subnets"]] or [subnets[a]["id"]]
        elif rtype(a) in ("aws_security_group", "aws_default_security_group"):
            owners[a] = list(sg_nodes.get(a, []))
        else:
            near = [node_of[x] for x in sorted(refs.get(a, set())) if x in node_of]
            if not near:     # 정책 → 그 정책을 붙인 역할
                near = [node_of[r] for x in sorted(rev.get(a, set())) for r in sorted(refs.get(x, set())) if r in node_of and rtype(r) == "aws_iam_role"]
            owners[a] = sorted(set(near))[:3]

    in_pic = {x for n in nodes.values() for x in n["addresses"] + n["members"]}
    inv = _inventory(plan, set())
    for row in inv["rows"]:
        b = base(row["address"])
        t = row["type"]
        if row["group"] == "data":
            continue
        if b in in_pic:
            row["group"], row["why"] = "picture", "그림의 상자"
        elif t in DRAWN_AS_LINK:
            row["group"], row["why"] = "link", ("그림의 선 · 상자 설명으로 반영" if not t.startswith("aws_security_group") and "security_group" not in t
                                                else "그림의 선 (보안 그룹 허용 규칙 — 통신 구조 검사 대상)")
        elif t in DRAWN_AS_FRAME:
            row["group"], row["why"] = "frame", "그림의 틀 (VPC · 서브넷 띠 · 공개 여부 판단) — 실제 AWS 라우팅 확인은 아님"
        else:
            row["group"], row["why"] = "list", "목록만 (그림에 없음) — Trivy 탐지 대상"
    counts: Dict[str, int] = defaultdict(int)
    for x in inv["rows"]:
        counts[x["group"]] += 1
    inv["counts"] = dict(counts)

    all_nodes = list(ext.values()) + list(nodes.values())
    for i, e in enumerate(edges):
        e["id"] = f"e{i + 1}"
    return {"ok": True, "source": "code", "vpcs": list(vpcs.values()), "bands": list(bands.values()), "nodes": all_nodes, "edges": edges,
            "sg_nodes": {k: v for k, v in sg_nodes.items()}, "owners": owners, "inventory": inv, "notes": notes,
            "vpc_cidr": vpc_cidrs[0] if vpc_cidrs else None}


def _mark_risks(edges: List[Dict[str, Any]], group_nodes: Dict[Tuple[str, ...], List[str]], findings: List[Dict[str, Any]]) -> None:
    """자체 보안 그룹 검사(sg_scan) 결과 → 그 선에 위험 종류 (같은 대상 묶음 · 겹치는 출처 대역 · 겹치는 포트)."""
    from .codetopo import _overlap
    for f in findings:
        if f.get("kind") not in RISK_ORDER:
            continue
        dsts = set(group_nodes.get(tuple(f.get("security_groups") or []), []))
        for e in edges:
            if e["kind"] != "sg" or e["dst"] not in dsts or not set(e["cidrs"]) & set(f.get("sources") or []):
                continue
            hit = [[p, a, b] for p, a, b in e["port_ranges"] if _overlap((p, a, b), (f["protocol"], f["from_port"], f["to_port"]))]
            if not hit:
                continue
            e.setdefault("risk_ranges", []).extend(hit)
            if f.get("id") and f["id"] not in e.setdefault("risk_ids", []):
                e["risk_ids"].append(f["id"])
            if e["risk"] is None or RISK_ORDER[f["kind"]] < RISK_ORDER.get(e["risk"], 99):
                e["risk"] = f["kind"]
                e["risk_id"] = f["id"]


# ----------------------------------------------------------------------------- 설계도(원하는 구조) 겹쳐 그리기
def overlay(model: Dict[str, Any], topo: Optional[Dict[str, Any]], design: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """V6 구조 검사 결과(설계도 vs 이 코드)를 구성도 선 · 상자에 옮긴다. 판정은 만들지 않는다 — V6 결과 그대로.
      설계에 없는 연결(excess) → 그 규칙이 만든 보안 그룹 선 = 'excess' (빨강)
      설계도의 통신인데 허용 규칙 없음(broken) → 유령 선 'missing' (점선)
      설계도의 출처가 코드에 없는 대역(예: 운영팀 사무실) → 유령 출처 상자 + 선 'desired'
      판정 불가 → 'unknown'"""
    out: Dict[str, Any] = {"edges": {}, "ghost_nodes": [], "ghost_edges": [], "nodes": {}, "computed": bool(topo)}
    if not topo or not design:
        return out
    tiers = {t["id"]: t for t in (topo.get("tiers") or design.get("tiers") or [])}
    sgn = model.get("sg_nodes") or {}
    nodes = {n["id"]: n for n in model.get("nodes") or []}

    def tier_nodes(tid: str) -> List[str]:
        t = tiers.get(tid) or next((x for x in design.get("tiers") or [] if x.get("id") == tid), None)
        return list(sgn.get((t or {}).get("security_group") or "", [])) if t else []
    for e in model.get("edges") or []:
        if e["kind"] == "sg":
            out["edges"][e["id"]] = {"state": "ok"}
    for x in topo.get("excess") or []:
        origins = {o.strip() for o in str(x.get("rule") or "").split(",") if o.strip()}
        dst_ids = set(tier_nodes(x.get("dst"))) if not str(x.get("dst", "")).startswith("res:") else \
            {i for i, n in nodes.items() if set(n.get("addresses", []) + n.get("members", [])) & {base(r) for r in x.get("resources") or []}}
        for e in model.get("edges") or []:
            if e["kind"] == "sg" and e["dst"] in dst_ids and origins & set(e["rules"]):
                prev = out["edges"].get(e["id"]) or {}
                rr = (prev.get("ranges") or []) + [r for o in sorted(origins & set(e["rules"])) for r in (e.get("rule_ranges") or {}).get(o, [])]
                why = "; ".join(w for w in [prev.get("why") if prev.get("state") == "excess" else "", x.get("detail") or ""] if w)
                out["edges"][e["id"]] = {"state": "excess", "why": why, "kind": x.get("kind"), "ports": x.get("ports"), "ranges": rr}
    ext_by_cidrs = {tuple(sorted(n.get("cidrs") or [])): n["id"] for n in nodes.values() if n.get("cat") == "external" and n.get("cidrs")}
    dext = {e["id"]: e for e in design.get("external") or []}
    for f in topo.get("flows") or []:
        st = f.get("status")
        dsts = tier_nodes(f.get("dst"))
        if f.get("src") in dext:
            e = dext[f["src"]]
            key = tuple(sorted(e.get("cidrs_v4") or []))
            srcs = [ext_by_cidrs[key]] if key in ext_by_cidrs else []
            if not srcs:
                gid = f"g:ext:{f['src']}"
                if not any(g["id"] == gid for g in out["ghost_nodes"]):
                    out["ghost_nodes"].append({"id": gid, "type": "external", "cat": "external", "icon": "client", "label": e.get("label") or f["src"],
                                               "sub": ", ".join(key), "cidrs": list(key), "place": {"area": "external"}, "ghost": True,
                                               "addresses": [], "members": [], "facts": [], "sgs": [], "type_ko": "원하는 구조의 출처"})
                srcs = [gid]
        else:
            srcs = tier_nodes(f.get("src"))
        state = {"ok": "desired", "broken": "missing", "unknown": "unknown"}.get(str(st), "desired")
        for s in srcs:
            for d in dsts:
                same = [e for e in model.get("edges") or [] if e["kind"] == "sg" and e["src"] == s and e["dst"] == d]
                if same and st == "ok":
                    continue          # 코드의 선이 이미 그 통신을 그림 — 따로 그리지 않음
                out["ghost_edges"].append({"id": f"g{len(out['ghost_edges']) + 1}", "src": s, "dst": d, "kind": "ghost", "state": state,
                                           "ports": str(f.get("ports") or ""), "label": f"{f.get('src_label')} → {f.get('dst_label')} {f.get('ports')}",
                                           "flow": f.get("id"), "why": "; ".join(f.get("reasons") or [])})
        if not dsts:
            t = tiers.get(f.get("dst")) or {}
            gid = f"g:tier:{f.get('dst')}"
            if t and not any(g["id"] == gid for g in out["ghost_nodes"]):
                out["ghost_nodes"].append({"id": gid, "type": "tier", "cat": "compute", "icon": t.get("type") or "ec2", "label": t.get("label") or f.get("dst"),
                                           "sub": "코드에 없음 (설계도에만)", "place": {"area": "vpc"}, "ghost": True, "addresses": [], "members": [],
                                           "facts": [("보안 그룹", str(t.get("security_group") or ""))], "sgs": [t.get("security_group")], "type_ko": "설계도의 구성요소"})
    for u in topo.get("undesigned") or []:
        if u.get("inbound"):
            for i, n in nodes.items():
                if set(n.get("addresses", []) + n.get("members", [])) & {base(r) for r in u.get("resources") or []}:
                    out["nodes"][i] = {"state": "undesigned", "why": "원하는 구조에 없는 리소스인데 들어오는 허용 규칙이 있음"}
    return out


# ----------------------------------------------------------------------------- 설계도만 그린 그림 (③ · ⑤ 왼쪽, 2026-11-01 6차 · D-34)
def _flow_range(f: Dict[str, Any]) -> Tuple[str, int, int]:
    p = str(f.get("protocol") or "tcp")
    if p == "-1":
        return p, 0, 65535
    lo = f.get("from_port", f.get("port"))
    hi = f.get("to_port", f.get("port"))
    return p, int(lo if lo is not None else 0), int(hi if hi is not None else 0)


def design_view(model: Optional[Dict[str, Any]], design: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """설계도(원하는 구조)만 그린 그림 — B (11-01): "설계도랑 토폴로지를 합치면 어떡해, 따로". 그리지 않고 옮기기만 한다:
      상자 · 틀 = 지금 코드 그림(build)의 것 그대로 (같은 아이콘 · 같은 자리 → ② · ⑤ 그림과 바로 비교)
      선      = 설계도의 통신(flows)만. 코드의 보안 그룹 선은 쓰지 않는다
      core    = 설계도 구성요소(보안 그룹)가 붙은 상자 · 설계도의 출처 — 화면의 '통신 관련만' 보기는 core 만 그린다.
                core 가 아닌 상자 · 요청 경로 · 권한 선은 '전체 보기' 에서 위치를 알려 주는 용도
      구성요소의 보안 그룹이 코드에 없으면 유령 상자('코드에 없음'), 출처 대역이 코드에 없으면 설계도의 출처 상자를 새로 만든다."""
    if not model or not model.get("ok") or not isinstance(design, dict) or design.get("kind") != "topology":
        return None
    nodes = {n["id"]: n for n in model.get("nodes") or []}
    sgn = model.get("sg_nodes") or {}
    tiers = {t["id"]: t for t in design.get("tiers") or [] if t.get("id")}
    exts = {e["id"]: e for e in design.get("external") or [] if e.get("id")}
    by_cidrs = {tuple(sorted(n.get("cidrs") or [])): i for i, n in nodes.items() if n.get("cat") == "external" and n.get("cidrs")}
    out: Dict[str, Dict[str, Any]] = {i: {**n, "core": False} for i, n in nodes.items() if n.get("cat") != "external"}

    def tier_ids(tid: str) -> List[str]:
        t = tiers.get(tid)
        if t is None:
            return []
        ids = [i for i in sgn.get(t.get("security_group") or "", []) if i in out]
        for i in ids:
            out[i]["core"] = True
        if ids:
            return ids
        gid = f"g:tier:{tid}"
        if gid not in out:
            out[gid] = {"id": gid, "type": "tier", "cat": "compute", "icon": t.get("type") or "ec2", "label": t.get("label") or tid,
                        "sub": "코드에 없음 (설계도에만)", "place": {"area": "vpc"}, "ghost": True, "core": True, "addresses": [], "members": [],
                        "facts": [("보안 그룹", str(t.get("security_group") or ""))], "sgs": [t["security_group"]] if t.get("security_group") else [],
                        "type_ko": "설계도의 구성요소", "count": 1}
        return [gid]

    def ext_ids(eid: str) -> List[str]:
        e = exts[eid]
        key = tuple(sorted(e.get("cidrs_v4") or []))
        hit = by_cidrs.get(key)
        if hit:
            out[hit] = {**nodes[hit], "label": e.get("label") or nodes[hit].get("label"), "core": True}
            return [hit]
        gid = f"g:ext:{eid}"
        if gid not in out:
            out[gid] = {"id": gid, "type": "external", "cat": "external", "icon": "users" if key == ("0.0.0.0/0",) else "client",
                        "label": e.get("label") or eid, "sub": ", ".join(key[:3]) + (" …" if len(key) > 3 else ""), "cidrs": list(key),
                        "place": {"area": "external"}, "core": True, "addresses": [], "members": [], "facts": [], "sgs": [],
                        "type_ko": "설계도의 출처", "count": 1}
        return [gid]

    for tid in tiers:              # 들어오는 통신이 없는 구성요소도 설계도에 있는 것 (아무것도 못 들어옴)
        tier_ids(tid)
    pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for f in design.get("flows") or []:
        src, dst = f.get("from"), f.get("to")
        ss = ext_ids(src) if src in exts else tier_ids(src)
        ds = tier_ids(dst)
        try:
            rng = _flow_range(f)
        except (TypeError, ValueError):
            continue
        for s in ss:
            for d in ds:
                if s == d:
                    continue
                p = pairs.setdefault((s, d), {"ranges": [], "flows": []})
                if rng not in p["ranges"]:
                    p["ranges"].append(rng)
                if f.get("id") not in p["flows"]:
                    p["flows"].append(f.get("id"))
    edges: List[Dict[str, Any]] = [dict(e) for e in model.get("edges") or [] if e["kind"] != "sg" and e["src"] in out and e["dst"] in out]
    for k, ((s, d), p) in enumerate(sorted(pairs.items()), 1):
        rs = sorted(p["ranges"], key=lambda r: (r[0] != "tcp", r[1], r[2]))
        edges.append({"id": f"d{k}", "src": s, "dst": d, "kind": "sg", "ports": _merge_ports(rs), "port_ranges": [list(r) for r in rs],
                      "port_items": [{"text": _merge_ports([r]), "risk": False, "range": list(r)} for r in rs],
                      "rules": [], "cidrs": [], "dst_sgs": [], "src_sgs": [], "flows": p["flows"], "risk": None, "label": ""})
    return {"ok": True, "source": "design", "vpcs": model.get("vpcs") or [], "bands": model.get("bands") or [], "nodes": list(out.values()),
            "edges": edges, "sg_nodes": {}, "owners": {}, "inventory": {"rows": [], "counts": {}, "total": 0}, "notes": [],
            "vpc_cidr": model.get("vpc_cidr")}


def name_externals(model: Optional[Dict[str, Any]], design: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """코드 그림의 외부 출처 상자 이름을 설계도의 이름으로 (대역이 똑같을 때만 — 예: '외부 대역 2개' → '관리자 접속 허용 목록').
    ⑤ 의 설계도 · 적용 후 그림이 같은 출처를 같은 이름으로 부르게. 대역(sub)은 그대로 보인다. 사본을 돌려준다."""
    if not model or not isinstance(design, dict):
        return model
    lab = {tuple(sorted(e.get("cidrs_v4") or [])): e.get("label") for e in design.get("external") or [] if e.get("label") and e.get("cidrs_v4")}
    if not lab:
        return model
    nodes = []
    for n in model.get("nodes") or []:
        k = tuple(sorted(n.get("cidrs") or []))
        nodes.append({**n, "label": lab[k]} if n.get("cat") == "external" and k in lab else n)
    return {**model, "nodes": nodes}


# ----------------------------------------------------------------------------- 문제 → 그림 위치 (④ 강조 · ② 상자 배지)
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
INGRESS_TRIVY = ("AVD-AWS-0107",)       # 보안 그룹 · 규칙의 '공개 인바운드' 지적


def owners_of(model: Dict[str, Any], address: str) -> List[str]:
    """리소스 주소 → 그 리소스를 그린 상자들 (보안 그룹이면 그것을 단 상자들)."""
    b = base(address)
    if rtype(b) in ("aws_security_group", "aws_default_security_group"):
        return list((model.get("sg_nodes") or {}).get(b) or [])
    return list((model.get("owners") or {}).get(b) or [])


def focus_for(model: Dict[str, Any], issue: Dict[str, Any]) -> Dict[str, List[str]]:
    """문제 하나 → 그림에서 강조할 상자 · 선 (판정 아님: 그 문제의 리소스 · 규칙이 그려진 자리)."""
    edges = model.get("edges") or []
    nodes: List[str] = []
    eids: List[str] = []
    res = str(issue.get("resource") or "")
    srcs = set(issue.get("sources") or [])
    rid = issue.get("sg_id") or (issue.get("id") if "sg" in srcs and not str(issue.get("id", "")).startswith(("trivy:", "design:", "req:")) else None)
    if rid:
        eids += [e["id"] for e in edges if rid in (e.get("risk_ids") or [])]
    rule = str((issue.get("flow_rule") or ""))
    if rule:
        origins = {o.strip() for o in rule.split(",") if o.strip()}
        eids += [e["id"] for e in edges if e["kind"] == "sg" and origins & set(e.get("rules") or [])]
    if res:
        for r in [x.strip() for x in res.split(",") if x.strip()]:
            nodes += owners_of(model, r)
            # 보안 그룹 지적 중 들어오는 규칙(공개 인바운드)만 선을 강조 — 나가는 규칙(egress) · 설명 누락 같은 지적은 선으로 그리지 않음
            if rtype(base(r)) in ("aws_security_group", "aws_default_security_group") and not eids and issue.get("rule") in INGRESS_TRIVY:
                into = [e for e in edges if e["kind"] == "sg" and base(r) in (e.get("dst_sgs") or [])]
                risky = [e for e in into if e.get("risk")]
                eids += [e["id"] for e in (risky or into)]
    for e in edges:
        if e["id"] in eids:
            nodes.append(e["dst"])
    return {"nodes": sorted(set(nodes)), "edges": sorted(set(eids), key=lambda x: int(x[1:]) if x[1:].isdigit() else 0)}


def badges(issues: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """상자마다 보안 문제 수 · 가장 높은 심각도 (④ 목록과 같은 문제 — 한 문제가 여러 상자에 걸치면 각 상자에 센다)."""
    out: Dict[str, Dict[str, Any]] = {}
    for it in issues:
        if it.get("group") == "undecidable":
            continue
        for n in set((it.get("focus") or {}).get("nodes") or []):
            b = out.setdefault(n, {"n": 0, "sev": "LOW", "ids": []})
            b["n"] += 1
            b["ids"].append(it["id"])
            if SEV_RANK.get(it.get("severity"), 9) < SEV_RANK.get(b["sev"], 9):
                b["sev"] = it.get("severity")
    return out


# ----------------------------------------------------------------------------- 수정 전 → 후 (⑤ · ⑥: 새로 생긴 · 없어진 통신)
def diff(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """보안 그룹 허용(선)을 (출발 상자, 도착 상자, 포트 범위) 로 비교. 상자 id = 리소스 주소 · 외부 대역이라 전후가 같은 이름이면 같은 상자."""
    def ranges(m: Dict[str, Any]) -> Dict[Tuple[str, str], Set[Tuple[str, int, int]]]:
        out: Dict[Tuple[str, str], Set[Tuple[str, int, int]]] = defaultdict(set)
        for e in m.get("edges") or []:
            if e["kind"] == "sg":
                out[(e["src"], e["dst"])] |= {tuple(r) for r in e.get("port_ranges") or []}
        return out
    kb, ka = ranges(before), ranges(after)
    nb = {n["id"]: n for n in before.get("nodes") or []}
    na = {n["id"]: n for n in after.get("nodes") or []}
    lab = lambda nid: (na.get(nid) or nb.get(nid) or {}).get("label") or nid  # noqa: E731
    added: Dict[str, List[List[Any]]] = {}
    added_list: List[Dict[str, str]] = []
    for e in after.get("edges") or []:
        if e["kind"] != "sg":
            continue
        new = sorted({tuple(r) for r in e.get("port_ranges") or []} - kb.get((e["src"], e["dst"]), set()))
        if new:
            added[e["id"]] = [list(r) for r in new]
            added_list.append({"src": lab(e["src"]), "dst": lab(e["dst"]), "port": _merge_ports(new), "edge": e["id"]})
    removed: List[Dict[str, Any]] = []
    removed_list: List[Dict[str, str]] = []
    ghost_nodes: Dict[str, Dict[str, Any]] = {}
    for (s, d), rs in sorted(kb.items()):
        gone = sorted(rs - ka.get((s, d), set()))
        if not gone:
            continue
        removed_list.append({"src": lab(s), "dst": lab(d), "port": _merge_ports(gone)})
        for nid in (s, d):
            if nid not in na and nid in nb:
                ghost_nodes[nid] = {**nb[nid], "ghost": True, "sub": "이 수정으로 없어짐", "type_ko": nb[nid].get("type_ko")}
        removed.append({"id": f"rm{len(removed) + 1}", "src": s, "dst": d, "kind": "ghost", "state": "removed", "ports": _merge_ports(gone),
                        "port_items": [{"text": _merge_ports([r]), "risk": False} for r in gone], "why": "이 수정으로 없어진 통신 (적용 전에는 있었음)"})
    return {"added": added, "removed": removed, "ghost_nodes": list(ghost_nodes.values()), "added_list": added_list, "removed_list": removed_list}
