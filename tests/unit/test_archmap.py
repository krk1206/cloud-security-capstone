"""코드의 리소스 전부를 그리는 구성도 (web/archmap.py, 2026-11-01 갈아엎기 5차 · D-33).

plan 은 손으로 만든 '주문 API' 모양 plan JSON (tofu 없이): VPC · 공개/비공개 서브넷(라우팅으로 구분) · 인터넷/NAT 게이트웨이 ·
ALB → ECS 서비스 → PostgreSQL · 운영 서버 · IAM 역할(s3:* 정책) · S3 · 로그. 판정(위험 · 설계 위반)은 sg_scan · V6 오라클 그대로 —
여기서는 '코드 → 상자 · 틀 · 선' 변환과 겹쳐 그리기 · 문제 위치 · 수정 전후 비교가 맞는지 본다.
"""
import copy
import json
import unittest

from helpers import ROOT  # noqa: F401  (sys.path 설정)

from iacpatch.topology_intent import parse_topology_intent
from iacpatch.verify.plan_model import build_world
from iacpatch.verify.sg_scan import scan
from iacpatch.verify.v6 import v6_intent_oracle
from iacpatch.web import archmap, codetopo

VPC = "aws_vpc.main"


def ref(*addrs):
    return {"references": [x for a in addrs for x in (f"{a}.id", a)]}


def rule(port, cidrs, sg=False):
    r = {"cidr_blocks": list(cidrs), "description": "", "from_port": port, "ipv6_cidr_blocks": [], "prefix_list_ids": [],
         "protocol": "tcp", "self": False, "to_port": port}
    if not sg:
        r["security_groups"] = []
    return r


def make_plan(res):
    planned, rc, cfg = [], [], []
    for t, n, v, ex, au, idx in res:
        addr = f"{t}.{n}" + (f"[{idx}]" if idx is not None else "")
        row = {"address": addr, "type": t, "name": n, "mode": "managed", "values": v}
        if idx is not None:
            row["index"] = idx
        planned.append(row)
        rc.append({"address": addr, "type": t, "name": n, "mode": "managed", "change": {"actions": ["create"], "after_unknown": au or {}}})
        if ex is not None and idx in (None, 0):
            cfg.append({"address": f"{t}.{n}", "type": t, "name": n, "mode": "managed", "expressions": ex})
    return {"format_version": "1.2", "planned_values": {"root_module": {"resources": planned}}, "resource_changes": rc,
            "configuration": {"root_module": {"resources": cfg}}}


def orders_plan(ssh=("0.0.0.0/0",)):
    pol = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
    return make_plan([
        ("aws_vpc", "main", {"cidr_block": "10.20.0.0/16"}, {}, None, None),
        ("aws_subnet", "public", {"cidr_block": "10.20.1.0/24", "availability_zone": "ap-northeast-2a", "map_public_ip_on_launch": True}, {"vpc_id": ref(VPC)}, None, 0),
        ("aws_subnet", "public", {"cidr_block": "10.20.2.0/24", "availability_zone": "ap-northeast-2c", "map_public_ip_on_launch": True}, None, None, 1),
        ("aws_subnet", "private", {"cidr_block": "10.20.11.0/24", "availability_zone": "ap-northeast-2a"}, {"vpc_id": ref(VPC)}, None, 0),
        ("aws_subnet", "private", {"cidr_block": "10.20.12.0/24", "availability_zone": "ap-northeast-2c"}, None, None, 1),
        ("aws_internet_gateway", "main", {}, {"vpc_id": ref(VPC)}, None, None),
        ("aws_eip", "nat", {"domain": "vpc"}, {}, None, None),
        ("aws_nat_gateway", "main", {}, {"subnet_id": ref("aws_subnet.public[0]"), "allocation_id": ref("aws_eip.nat")}, None, None),
        ("aws_route_table", "public", {}, {"vpc_id": ref(VPC), "route": [{"gateway_id": ref("aws_internet_gateway.main")}]}, None, None),
        ("aws_route_table", "private", {}, {"vpc_id": ref(VPC), "route": [{"nat_gateway_id": ref("aws_nat_gateway.main")}]}, None, None),
        ("aws_route_table_association", "public", {}, {"subnet_id": ref("aws_subnet.public"), "route_table_id": ref("aws_route_table.public")}, None, 0),
        ("aws_route_table_association", "public", {}, None, None, 1),
        ("aws_route_table_association", "private", {}, {"subnet_id": ref("aws_subnet.private"), "route_table_id": ref("aws_route_table.private")}, None, 0),
        ("aws_route_table_association", "private", {}, None, None, 1),
        ("aws_security_group", "alb", {"name": "alb", "ingress": [rule(80, ["0.0.0.0/0"])], "egress": []}, {"vpc_id": ref(VPC)}, None, None),
        ("aws_security_group", "api", {"name": "api", "ingress": [rule(8080, [], sg=True)], "egress": []},
         {"vpc_id": ref(VPC), "ingress": ref("aws_security_group.alb")}, {"ingress": [{"security_groups": True}]}, None),
        ("aws_security_group", "db", {"name": "db", "ingress": [rule(5432, ["10.20.0.0/16"]), rule(5432, [], sg=True)], "egress": []},
         {"vpc_id": ref(VPC), "ingress": ref("aws_security_group.api")}, {"ingress": [{}, {"security_groups": True}]}, None),
        ("aws_security_group", "ops", {"name": "ops", "ingress": [rule(22, list(ssh))], "egress": []}, {"vpc_id": ref(VPC)}, None, None),
        ("aws_lb", "public", {"internal": False, "load_balancer_type": "application"},
         {"subnets": ref("aws_subnet.public"), "security_groups": ref("aws_security_group.alb")}, None, None),
        ("aws_lb_target_group", "api", {"port": 8080, "protocol": "HTTP", "target_type": "ip"}, {"vpc_id": ref(VPC)}, None, None),
        ("aws_lb_listener", "http", {"port": 80, "protocol": "HTTP"},
         {"load_balancer_arn": ref("aws_lb.public"), "default_action": [{"target_group_arn": ref("aws_lb_target_group.api")}]}, None, None),
        ("aws_ecs_cluster", "main", {"name": "orders"}, {}, None, None),
        ("aws_iam_role", "task", {"name": "orders-task"}, {}, None, None),
        ("aws_iam_role", "task_exec", {"name": "orders-task-exec"}, {}, None, None),
        ("aws_iam_role_policy", "task", {"policy": pol}, {"role": ref("aws_iam_role.task")}, None, None),
        ("aws_ecs_task_definition", "api", {"family": "orders-api"},
         {"task_role_arn": ref("aws_iam_role.task"), "execution_role_arn": ref("aws_iam_role.task_exec")}, None, None),
        ("aws_ecs_service", "api", {"desired_count": 2, "launch_type": "FARGATE"},
         {"cluster": ref("aws_ecs_cluster.main"), "task_definition": ref("aws_ecs_task_definition.api"),
          "load_balancer": [{"target_group_arn": ref("aws_lb_target_group.api")}],
          "network_configuration": [{"subnets": ref("aws_subnet.private"), "security_groups": ref("aws_security_group.api")}]}, None, None),
        ("aws_db_subnet_group", "main", {}, {"subnet_ids": ref("aws_subnet.private")}, None, None),
        ("aws_db_instance", "orders", {"engine": "postgres", "engine_version": "16", "publicly_accessible": False},
         {"db_subnet_group_name": ref("aws_db_subnet_group.main"), "vpc_security_group_ids": ref("aws_security_group.db")}, None, None),
        ("aws_instance", "ops", {"instance_type": "t3.micro"},
         {"subnet_id": ref("aws_subnet.public[0]"), "vpc_security_group_ids": ref("aws_security_group.ops")}, None, None),
        ("aws_s3_bucket", "reports", {"bucket": "orders-reports"}, {}, None, None),
        ("aws_cloudwatch_log_group", "api", {"name": "/ecs/orders-api"}, {}, None, None),
    ])


def arch_of(plan):
    sc = scan(build_world(plan, {}), codetopo.vpc_cidr(plan))
    return archmap.build(plan, {}, sc["findings"]), sc


def edge(m, src, dst, kind="sg"):
    return next((e for e in m["edges"] if e["src"] == src and e["dst"] == dst and e["kind"] == kind), None)


AUTO = {"kind": "topology", "intent_version": "1", "intent_id": "orders-design", "status": "active", "target_dir": "x", "vpc_cidr": "10.20.0.0/16",
        "tiers": [{"id": "alb", "label": "alb", "security_group": "aws_security_group.alb"}, {"id": "api", "label": "api", "security_group": "aws_security_group.api"},
                  {"id": "db", "label": "db", "security_group": "aws_security_group.db"}, {"id": "ops", "label": "ops", "security_group": "aws_security_group.ops"}],
        "external": [{"id": "internet", "label": "사용자(인터넷)", "cidrs_v4": ["0.0.0.0/0"]}],
        "flows": [{"id": "a", "from": "internet", "to": "alb", "protocol": "tcp", "port": 80}, {"id": "b", "from": "alb", "to": "api", "protocol": "tcp", "port": 8080},
                  {"id": "c", "from": "api", "to": "db", "protocol": "tcp", "port": 5432}]}


class ArchMapTests(unittest.TestCase):
    def setUp(self):
        self.m, self.sc = arch_of(orders_plan())
        self.nodes = {n["id"]: n for n in self.m["nodes"]}

    def test_boxes_are_the_code_resources(self):
        n = self.nodes
        for nid in ("n:aws_lb.public", "n:aws_ecs_service.api", "n:aws_db_instance.orders", "n:aws_instance.ops", "n:aws_iam_role.task",
                    "n:aws_iam_role.task_exec", "n:aws_s3_bucket.reports", "n:aws_internet_gateway.main", "n:aws_nat_gateway.main", "n:ops:cloudwatch"):
            self.assertIn(nid, n)
        # 딸린 리소스는 주인 상자에 합친다 (작업 정의 · 클러스터 → ECS 서비스, EIP → NAT)
        self.assertEqual(sorted(n["n:aws_ecs_service.api"]["members"]), ["aws_ecs_cluster.main", "aws_ecs_task_definition.api"])
        self.assertIn("aws_eip.nat", n["n:aws_nat_gateway.main"]["members"])
        self.assertNotIn("n:aws_ecs_task_definition.api", n)
        # 서브넷 · 라우팅 · 보안 그룹은 상자가 아니라 틀 · 선
        self.assertFalse(any(k.startswith(("n:aws_subnet", "n:aws_route", "n:aws_security_group")) for k in n))

    def test_subnet_bands_from_routing(self):
        bands = {b["kind"]: b for b in self.m["bands"]}
        self.assertEqual(sorted(bands), ["private_nat", "public"])
        self.assertEqual(bands["public"]["azs"], ["2a", "2c"])
        self.assertEqual(bands["public"]["label"], "공개 서브넷")
        place = lambda nid: self.nodes[nid]["place"]  # noqa: E731
        self.assertEqual(place("n:aws_lb.public")["band"], bands["public"]["id"])
        self.assertEqual(place("n:aws_instance.ops")["band"], bands["public"]["id"])
        self.assertEqual(place("n:aws_ecs_service.api")["band"], bands["private_nat"]["id"])
        self.assertEqual(place("n:aws_db_instance.orders")["band"], bands["private_nat"]["id"])      # DB 서브넷 그룹을 거쳐
        self.assertEqual(place("n:aws_internet_gateway.main")["area"], "vpc_gw")
        self.assertEqual(place("n:aws_iam_role.task")["area"], "outside")

    def test_security_group_lines_and_risks(self):
        m = self.m
        e = edge(m, "x:internet", "n:aws_instance.ops")
        self.assertEqual((e["ports"], e["risk"], e["dst_sgs"]), ("22", "mgmt_public", ["aws_security_group.ops"]))
        self.assertEqual(e["port_items"], [{"text": "22", "risk": True, "range": ["tcp", 22, 22]}])
        e = edge(m, "n:aws_ecs_service.api", "n:aws_db_instance.orders")
        self.assertEqual((e["ports"], e["risk"], e["src_sgs"]), ("5432", None, ["aws_security_group.api"]))
        e = edge(m, "x:vpc:10.20.0.0/16", "n:aws_db_instance.orders")
        self.assertEqual(e["risk"], "vpc_wide")
        self.assertEqual(self.nodes["x:vpc:10.20.0.0/16"]["place"]["area"], "vpc_src")
        self.assertIsNone(edge(m, "x:internet", "n:aws_lb.public")["risk"])

    def test_request_paths_roles_and_permissions(self):
        m = self.m
        t = edge(m, "n:aws_lb.public", "n:aws_ecs_service.api", "traffic")
        self.assertEqual(t["label"], "HTTP 80 → 8080")
        self.assertTrue(edge(m, "n:aws_lb.public", "n:aws_ecs_service.api", "sg"))
        roles = {(e["dst"], e["label"]) for e in m["edges"] if e["kind"] == "role"}
        self.assertEqual(roles, {("n:aws_iam_role.task", "작업 역할"), ("n:aws_iam_role.task_exec", "실행 역할")})
        p = edge(m, "n:aws_iam_role.task", "x:allres", "perm")
        self.assertEqual((p["label"], p["risk"]), ("s3:*", "broad_perm"))

    def test_inventory_says_where_every_resource_went(self):
        inv = self.m["inventory"]
        g = {r["address"]: r["group"] for r in inv["rows"]}
        self.assertEqual(g["aws_ecs_task_definition.api"], "picture")
        self.assertEqual(g["aws_lb_listener.http"], "link")
        self.assertEqual(g["aws_security_group.db"], "link")
        self.assertEqual(g["aws_route_table.public"], "frame")
        self.assertEqual(g["aws_subnet.private[1]"], "frame")
        self.assertEqual(sum(inv["counts"].values()), inv["total"])

    def test_focus_and_badges(self):
        ingress = {"id": "t1", "resource": "aws_security_group.ops", "rule": "AVD-AWS-0107", "sources": ["trivy"], "severity": "HIGH", "group": "public_mgmt"}
        egress = {"id": "t2", "resource": "aws_security_group.ops", "rule": "AVD-AWS-0104", "sources": ["trivy"], "severity": "CRITICAL", "group": "egress"}
        s3 = {"id": "t3", "resource": "aws_s3_bucket.reports", "rule": "AVD-AWS-0089", "sources": ["trivy"], "severity": "LOW", "group": "s3"}
        f1 = archmap.focus_for(self.m, ingress)
        self.assertEqual(f1["nodes"], ["n:aws_instance.ops"])
        self.assertEqual(f1["edges"], [edge(self.m, "x:internet", "n:aws_instance.ops")["id"]])
        self.assertEqual(archmap.focus_for(self.m, egress)["edges"], [], "나가는 규칙 지적은 들어오는 선을 강조하지 않음")
        self.assertEqual(archmap.focus_for(self.m, s3), {"nodes": ["n:aws_s3_bucket.reports"], "edges": []})
        vpcw = next(f for f in self.sc["findings"] if f["kind"] == "vpc_wide")
        f4 = archmap.focus_for(self.m, {"id": vpcw["id"], "sg_id": vpcw["id"], "resource": "aws_security_group.db", "sources": ["sg"], "rule": "vpc_wide"})
        self.assertEqual(f4["edges"], [edge(self.m, "x:vpc:10.20.0.0/16", "n:aws_db_instance.orders")["id"]])
        its = []
        for it in (ingress, egress, s3):
            its.append({**it, "focus": archmap.focus_for(self.m, it)})
        b = archmap.badges(its)
        self.assertEqual((b["n:aws_instance.ops"]["n"], b["n:aws_instance.ops"]["sev"]), (2, "CRITICAL"))
        self.assertEqual(b["n:aws_s3_bucket.reports"]["n"], 1)

    def test_overlay_maps_v6_result_onto_lines(self):
        plan = orders_plan()
        lr = v6_intent_oracle(plan, {}, parse_topology_intent(AUTO))
        ov = archmap.overlay(self.m, lr.details, AUTO)
        st = {e["id"]: ov["edges"][e["id"]]["state"] for e in self.m["edges"] if e["kind"] == "sg"}
        self.assertEqual(st[edge(self.m, "x:internet", "n:aws_instance.ops")["id"]], "excess")
        self.assertEqual(st[edge(self.m, "x:vpc:10.20.0.0/16", "n:aws_db_instance.orders")["id"]], "excess")
        self.assertEqual(st[edge(self.m, "n:aws_ecs_service.api", "n:aws_db_instance.orders")["id"]], "ok")
        self.assertEqual(st[edge(self.m, "n:aws_lb.public", "n:aws_ecs_service.api")["id"]], "ok")
        self.assertEqual(ov["edges"][edge(self.m, "x:internet", "n:aws_instance.ops")["id"]]["ranges"], [["tcp", 22, 22]])
        # 원하는 구조에 코드에 없는 출처(사무실 대역)가 있으면 유령 상자 + 선. 코드가 0.0.0.0/0 으로 열어 사무실도 들어올 수 있으니 V6 는 그 통신을 'ok'
        # → 'desired' (원하는 구조의 통신, 출처가 코드와 다름). 인터넷 전체 → 22 는 따로 '설계에 없는 연결'
        d = copy.deepcopy(AUTO)
        d["external"].append({"id": "office", "label": "운영팀 사무실", "cidrs_v4": ["203.0.113.0/24"]})
        d["flows"].append({"id": "d", "from": "office", "to": "ops", "protocol": "tcp", "port": 22})
        ov2 = archmap.overlay(self.m, v6_intent_oracle(plan, {}, parse_topology_intent(d)).details, d)
        self.assertEqual([g["id"] for g in ov2["ghost_nodes"]], ["g:ext:office"])
        self.assertEqual([(g["src"], g["dst"], g["state"]) for g in ov2["ghost_edges"]], [("g:ext:office", "n:aws_instance.ops", "desired")])

    def test_diff_before_after(self):
        after, _ = arch_of(orders_plan(ssh=("203.0.113.0/24",)))
        df = archmap.diff(self.m, after)
        self.assertEqual(df["removed_list"], [{"src": "인터넷 전체", "dst": "ops", "port": "22"}])
        self.assertEqual([(x["src"], x["dst"], x["port"]) for x in df["added_list"]], [("203.0.113.0/24", "ops", "22")])
        self.assertEqual(df["removed"][0]["state"], "removed")
        self.assertEqual(df["ghost_nodes"], [], "인터넷 출처는 ALB 80 때문에 수정 뒤에도 남아 있음")

    # ---------------------------------------------------------------- 6차 (D-34): 설계도만 그린 그림 · 같은 출처는 같은 이름
    def test_design_view_draws_only_the_design(self):
        d = copy.deepcopy(AUTO)
        d["external"].append({"id": "office", "label": "운영팀 사무실", "cidrs_v4": ["203.0.113.0/24"]})
        d["flows"].append({"id": "d", "from": "office", "to": "ops", "protocol": "tcp", "port": 22})
        d["tiers"].append({"id": "cache", "label": "cache", "security_group": "aws_security_group.cache"})     # 코드에 없는 구성요소
        v = archmap.design_view(self.m, d)
        nodes = {n["id"]: n for n in v["nodes"]}
        self.assertEqual(sorted(i for i, n in nodes.items() if n["core"]),
                         sorted(["n:aws_lb.public", "n:aws_ecs_service.api", "n:aws_db_instance.orders", "n:aws_instance.ops", "x:internet", "g:ext:office", "g:tier:cache"]))
        self.assertEqual(nodes["x:internet"]["label"], "사용자(인터넷)", "출처 이름은 설계도의 이름")
        self.assertTrue(nodes["g:tier:cache"]["ghost"])
        self.assertNotIn("x:vpc:10.20.0.0/16", nodes, "설계도에 없는 출처(VPC 대역)는 그리지 않음")
        sg = sorted((e["src"], e["dst"], e["ports"]) for e in v["edges"] if e["kind"] == "sg")
        self.assertEqual(sg, sorted([("x:internet", "n:aws_lb.public", "80"), ("n:aws_lb.public", "n:aws_ecs_service.api", "8080"),
                                     ("n:aws_ecs_service.api", "n:aws_db_instance.orders", "5432"), ("g:ext:office", "n:aws_instance.ops", "22")]))
        self.assertFalse(any(e["src"] == "x:internet" and e["dst"] == "n:aws_instance.ops" for e in v["edges"]), "코드에만 있는 통신(인터넷 → 22)은 그리지 않음")
        self.assertTrue(any(e["kind"] == "perm" for e in v["edges"]), "요청 경로 · 권한 선은 '전체 보기' 용으로 남음")
        self.assertFalse(nodes["n:aws_s3_bucket.reports"]["core"])
        self.assertEqual(v["source"], "design")
        self.assertIsNone(archmap.design_view(self.m, {"kind": "sg"}))

    def test_name_externals_uses_design_names(self):
        after, _ = arch_of(orders_plan(ssh=("203.0.113.0/24",)))
        d = copy.deepcopy(AUTO)
        d["external"].append({"id": "office", "label": "운영팀 사무실", "cidrs_v4": ["203.0.113.0/24"]})
        lab = {n["id"]: n["label"] for n in archmap.name_externals(after, d)["nodes"]}
        self.assertEqual((lab["x:cidr:203.0.113.0/24"], lab["x:internet"]), ("운영팀 사무실", "사용자(인터넷)"))
        self.assertEqual({n["id"]: n["label"] for n in after["nodes"]}["x:cidr:203.0.113.0/24"], "203.0.113.0/24", "원본은 그대로 (사본을 돌려줌)")


if __name__ == "__main__":
    unittest.main()
