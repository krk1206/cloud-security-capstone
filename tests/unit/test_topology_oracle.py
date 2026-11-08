"""설계도(토폴로지) 기준 구조 검사 — SGWorld 를 직접 만들어 판정 규칙만 확인한다.

plan → SGWorld 변환은 plan_model 테스트가 맡는다. 여기서는 scenarios/arch/webapp-3tier 와 같은 계층 구조를
손으로 만든 세계에 넣어 '설계도에 없는 통신 = 위반, 설계도의 통신이 막힘 = 위반' 이 맞게 나오는지 본다.
"""
import copy
import json
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch.models import Verdict
from iacpatch.topology_intent import IntentError, load_topology_intent, parse_topology_intent
from iacpatch.verify.sgmodel import AttachmentPoint, Rule, SecurityGroupModel, SGWorld, Source
from iacpatch.verify.topology_oracle import evaluate

INTENT = ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "intents" / "arch-3tier-flows.json"
ADMIN = ["203.0.113.0/24", "198.51.100.0/24"]


def sg_rule(port, ref, origin):
    return Rule("ingress", "tcp", port, port, [Source("sg", f"aws_security_group.{ref}")], origin)


def cidr_rule(port, cidrs, origin, proto="tcp"):
    return Rule("ingress", proto, port, port, [Source("cidr4", c) for c in cidrs], origin)


def original_world():
    """원본(시험 재료): Bastion SSH 0.0.0.0/0 + 웹 → MySQL 직결."""
    sgs = {
        "alb": [cidr_rule(443, ["0.0.0.0/0"], "alb#0")],
        "bastion": [cidr_rule(22, ["0.0.0.0/0"], "bastion#0")],
        "web": [sg_rule(80, "alb", "web#0"), sg_rule(22, "bastion", "web#1")],
        "nlb": [sg_rule(8080, "web", "nlb#0")],
        "api": [sg_rule(8080, "nlb", "api#0"), sg_rule(22, "bastion", "api#1")],
        "redis": [sg_rule(6379, "api", "redis#0")],
        "db": [sg_rule(3306, "api", "db#0"), sg_rule(3306, "web", "db#1")],
    }
    models = {f"aws_security_group.{k}": SecurityGroupModel(f"aws_security_group.{k}", rules=v) for k, v in sgs.items()}
    attach = [
        AttachmentPoint("aws_lb.alb", "aws_lb", ["aws_security_group.alb"]),
        AttachmentPoint("aws_instance.bastion[0]", "aws_instance", ["aws_security_group.bastion"]),
        AttachmentPoint("aws_launch_template.web", "aws_launch_template", ["aws_security_group.web"]),
        AttachmentPoint("aws_lb.nlb", "aws_lb", ["aws_security_group.nlb"]),
        AttachmentPoint("aws_launch_template.api", "aws_launch_template", ["aws_security_group.api"]),
        AttachmentPoint("aws_elasticache_replication_group.redis", "aws_elasticache_replication_group", ["aws_security_group.redis"]),
        AttachmentPoint("aws_db_instance.primary", "aws_db_instance", ["aws_security_group.db"]),
    ]
    return SGWorld("plan", models, attachments=attach)


def set_rules(world, sg, rules):
    w = copy.deepcopy(world)
    w.security_groups[f"aws_security_group.{sg}"].rules = rules
    return w


def fixed_world():
    w = set_rules(original_world(), "bastion", [cidr_rule(22, ADMIN, "bastion#0")])
    return set_rules(w, "db", [sg_rule(3306, "api", "db#0")])


class TopologyIntentTests(unittest.TestCase):
    def test_intent_file_loads(self):
        spec = load_topology_intent(INTENT)
        self.assertEqual(len(spec.flows), 9)
        self.assertIn("aws_security_group.db", spec.target_security_groups)

    def test_bad_intent_rejected(self):
        data = json.loads(INTENT.read_text(encoding="utf-8"))
        bad = copy.deepcopy(data); bad["flows"][0]["to"] = "internet"          # 대상은 계층이어야 한다
        with self.assertRaises(IntentError):
            parse_topology_intent(bad)
        bad = copy.deepcopy(data); bad["external"][1]["cidrs_v4"] = ["TODO"]   # 자리표시자
        with self.assertRaises(IntentError):
            parse_topology_intent(bad)


class TopologyOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = load_topology_intent(INTENT)

    def keys(self, rep):
        return {(e["src"], e["dst"]) for e in rep.excess}

    def test_original_has_two_structure_errors(self):
        rep = evaluate(original_world(), self.spec)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertEqual(self.keys(rep), {("internet", "bastion"),   # Trivy 도 찾는 것
                                          ("web", "db")})            # Trivy 는 못 찾는 것 (보안 그룹 참조)
        self.assertEqual(len(rep.excess), 2)                          # 0.0.0.0/0 한 규칙을 '인터넷'·'VPC' 두 건으로 세지 않는다
        self.assertTrue(all(f["status"] == "ok" for f in rep.flows))

    def test_design_fix_passes(self):
        rep = evaluate(fixed_world(), self.spec)
        self.assertEqual(rep.verdict, Verdict.PASS, rep.summary)
        self.assertEqual(rep.excess, [])

    def test_only_flagged_fix_still_fails_on_web_to_db(self):
        w = set_rules(original_world(), "bastion", [cidr_rule(22, ADMIN, "bastion#0")])
        rep = evaluate(w, self.spec)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertEqual(self.keys(rep), {("web", "db")})

    def test_split_cidrs_are_unioned(self):
        w = set_rules(fixed_world(), "bastion", [cidr_rule(22, ["0.0.0.0/1"], "b#0"), cidr_rule(22, ["128.0.0.0/1"], "b#1")])
        rep = evaluate(w, self.spec)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        e = next(x for x in rep.excess if x["dst"] == "bastion" and x["src"] == "internet")
        self.assertIn("합집합 = 인터넷 전체", e["detail"])

    def test_private_range_breaks_admin_access_and_opens_vpc(self):
        w = set_rules(fixed_world(), "bastion", [cidr_rule(22, ["10.0.0.0/16"], "b#0")])
        rep = evaluate(w, self.spec)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertIn(("vpc", "bastion"), self.keys(rep))
        broken = {f["id"] for f in rep.flows if f["status"] == "broken"}
        self.assertEqual(broken, {"admin-bastion"})

    def test_single_admin_ip_breaks_other_admins(self):
        w = set_rules(fixed_world(), "bastion", [cidr_rule(22, ["203.0.113.10/32"], "b#0")])
        rep = evaluate(w, self.spec)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertEqual(rep.excess, [])
        f = next(f for f in rep.flows if f["id"] == "admin-bastion")
        self.assertEqual(f["status"], "broken")
        self.assertIn("198.51.100.0/24", " ".join(f["reasons"]))

    def test_db_opened_to_vpc_is_caught_even_though_api_still_works(self):
        w = set_rules(fixed_world(), "db", [cidr_rule(3306, ["10.0.0.0/16"], "db#0")])
        rep = evaluate(w, self.spec)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertEqual(self.keys(rep), {("vpc", "db")})
        self.assertTrue(all(f["status"] == "ok" for f in rep.flows))   # API → DB 는 여전히 된다 (끊김이 아니라 과다 허용)

    def test_all_ports_from_designed_source_is_excess(self):
        w = set_rules(fixed_world(), "db", [Rule("ingress", "tcp", 0, 65535, [Source("sg", "aws_security_group.api")], "db#0")])
        rep = evaluate(w, self.spec)
        e = next(x for x in rep.excess if x["dst"] == "db")
        self.assertEqual(e["kind"], "ports")

    def test_removed_rule_breaks_service_path(self):
        w = set_rules(fixed_world(), "nlb", [])
        rep = evaluate(w, self.spec)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertEqual({f["id"] for f in rep.flows if f["status"] == "broken"}, {"web-nlb"})

    def test_extra_sg_attached_to_tier_is_merged(self):
        w = fixed_world()
        w.security_groups["aws_security_group.debug"] = SecurityGroupModel("aws_security_group.debug", rules=[cidr_rule(8080, ["0.0.0.0/0"], "debug#0")])
        api = next(a for a in w.attachments if a.address == "aws_launch_template.api")
        api.sg_refs.append("aws_security_group.debug")
        rep = evaluate(w, self.spec)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertIn(("internet", "api"), self.keys(rep))

    def test_unknown_source_is_not_pass(self):
        w = set_rules(fixed_world(), "redis", [Rule("ingress", "tcp", 6379, 6379, [Source("unknown", "", note="plan unknown")], "r#0"),
                                               sg_rule(6379, "api", "redis#0")])
        rep = evaluate(w, self.spec)
        self.assertEqual(rep.verdict, Verdict.UNKNOWN)


# ----------------------------------------------------------------------------- 실제 plan 모양 (팀 PC Terraform 1.16.1, 2026-10-20 실측)
DB_HCL = """
resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = aws_vpc.main.id

  ingress {
    description     = "MySQL from the API tier"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.api.id]
  }

  ingress {
    description     = "MySQL from the web tier"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
}
"""


def db_plan(desc_web="MySQL from the web tier"):
    """inline ingress 2개의 security_groups 가 plan 시점에 둘 다 미확정인 모양 — plan JSON 의 순서는 소스와 다를 수 있다."""
    rule = lambda d: {"cidr_blocks": [], "description": d, "from_port": 3306, "ipv6_cidr_blocks": [], "prefix_list_ids": [],
                      "protocol": "tcp", "self": False, "to_port": 3306}
    unk = {"cidr_blocks": [], "ipv6_cidr_blocks": [], "prefix_list_ids": [], "security_groups": True}
    return {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": [
            {"address": "aws_security_group.db", "type": "aws_security_group", "name": "db", "mode": "managed",
             "values": {"name": "db", "ingress": [rule(desc_web), rule("MySQL from the API tier")]}}]}},   # 순서 뒤바뀜
        "resource_changes": [{"address": "aws_security_group.db", "type": "aws_security_group", "name": "db",
                              "change": {"actions": ["create"], "after_unknown": {"ingress": [dict(unk), dict(unk)]}}}],
        "configuration": {"root_module": {"resources": [
            {"address": "aws_security_group.db", "type": "aws_security_group", "name": "db",
             "expressions": {"ingress": {"references": ["aws_security_group.api.id", "aws_security_group.api",
                                                        "aws_security_group.web.id", "aws_security_group.web"]}}}]}},
    }


class PlanSlotResolutionTests(unittest.TestCase):
    def test_two_unknown_sg_slots_matched_by_source_block(self):
        from iacpatch.verify.plan_model import build_world
        w = build_world(db_plan(), {"sg.tf": DB_HCL})
        got = {r.origin: [(s.kind, s.value) for s in r.sources] for r in w.security_groups["aws_security_group.db"].rules if r.direction == "ingress"}
        # plan 의 0번 = 웹 규칙(설명으로 짝지음), 1번 = API 규칙
        self.assertEqual(got["aws_security_group.db#ingress[0]"], [("sg", "aws_security_group.web")])
        self.assertEqual(got["aws_security_group.db#ingress[1]"], [("sg", "aws_security_group.api")])

    def test_no_unique_match_stays_unknown(self):
        from iacpatch.verify.plan_model import build_world
        w = build_world(db_plan(desc_web="MySQL from the API tier"), {"sg.tf": DB_HCL})   # 두 규칙이 구분 안 됨
        kinds = {s.kind for r in w.security_groups["aws_security_group.db"].rules for s in r.sources}
        self.assertEqual(kinds, {"unknown"})

    def test_without_source_stays_unknown(self):
        from iacpatch.verify.plan_model import build_world
        w = build_world(db_plan(), {})
        kinds = {s.kind for r in w.security_groups["aws_security_group.db"].rules for s in r.sources}
        self.assertEqual(kinds, {"unknown"})


class UnknownFlowTests(unittest.TestCase):
    def test_unresolved_source_means_undecided_not_broken(self):
        spec = load_topology_intent(INTENT)
        w = set_rules(fixed_world(), "web", [Rule("ingress", "tcp", 80, 80, [Source("unknown", "", note="sg slot unresolved")], "web#0"),
                                             sg_rule(22, "bastion", "web#1")])
        rep = evaluate(w, spec)
        st = {f["id"]: f["status"] for f in rep.flows}
        self.assertEqual(st["alb-web"], "unknown")          # 끊겼다고 단정하지 않는다
        self.assertEqual(rep.verdict, Verdict.UNKNOWN)


if __name__ == "__main__":
    unittest.main()


class UndesignedResourceTests(unittest.TestCase):
    """D-30 (2026-11-01): 설계도는 허용 목록 — 설계도에 없는 리소스로 들어오는 통신도 위반. 설계도에서 구성요소를 지우면 바로 드러난다."""

    def design(self):
        return json.loads(INTENT.read_text(encoding="utf-8"))

    def without(self, data, tier_id):
        d = copy.deepcopy(data)
        d["tiers"] = [t for t in d["tiers"] if t["id"] != tier_id]
        d["flows"] = [f for f in d["flows"] if tier_id not in (f["from"], f["to"])]
        return parse_topology_intent(d)

    def test_fixed_code_still_passes_original_design(self):
        rep = evaluate(fixed_world(), load_topology_intent(INTENT))
        self.assertEqual(rep.verdict, Verdict.PASS, rep.summary)
        self.assertEqual(rep.undesigned, [])
        self.assertTrue(all(t["sg_in_code"] for t in rep.tiers))

    def test_removing_redis_from_design_flags_api_to_redis(self):
        rep = evaluate(fixed_world(), self.without(self.design(), "redis"))
        self.assertEqual(rep.verdict, Verdict.FAIL)
        und = [e for e in rep.excess if e["kind"] == "undesigned_target"]
        self.assertEqual(len(und), 1, rep.excess)
        e = und[0]
        self.assertEqual((e["src"], e["dst"], e["ports"]), ("api", "res:aws_elasticache_replication_group.redis", "6379"))
        self.assertEqual(e["security_group"], "aws_security_group.redis")
        self.assertEqual(rep.undesigned[0]["inbound"], 1)
        self.assertIn("설계에 없는 리소스", e["dst_label"])

    def test_undesigned_resource_without_inbound_is_only_a_note(self):
        w = copy.deepcopy(fixed_world())
        w.security_groups["aws_security_group.batch"] = SecurityGroupModel("aws_security_group.batch", rules=[])
        w.attachments.append(AttachmentPoint("aws_instance.batch", "aws_instance", ["aws_security_group.batch"]))
        rep = evaluate(w, load_topology_intent(INTENT))
        self.assertEqual(rep.verdict, Verdict.PASS, rep.summary)
        self.assertEqual([u["resources"] for u in rep.undesigned], [["aws_instance.batch"]])
        self.assertTrue(any("들어오는 허용 규칙 없음" in n for n in rep.notes))

    def test_undesigned_resource_open_to_internet(self):
        w = copy.deepcopy(fixed_world())
        w.security_groups["aws_security_group.batch"] = SecurityGroupModel("aws_security_group.batch", rules=[cidr_rule(8443, ["0.0.0.0/0"], "batch#0")])
        w.attachments.append(AttachmentPoint("aws_instance.batch", "aws_instance", ["aws_security_group.batch"]))
        rep = evaluate(w, load_topology_intent(INTENT))
        self.assertEqual(rep.verdict, Verdict.FAIL)
        e = [x for x in rep.excess if x["kind"] == "undesigned_target"][0]
        self.assertEqual((e["src"], e["dst"], e["ports"]), ("internet", "res:aws_instance.batch", "8443"))

    def test_design_component_missing_in_code(self):
        d = self.design()
        d["tiers"].append({"id": "pg", "label": "PostgreSQL", "security_group": "aws_security_group.pg"})
        d["flows"].append({"id": "api-pg", "from": "api", "to": "pg", "protocol": "tcp", "port": 5432})
        rep = evaluate(fixed_world(), parse_topology_intent(d))
        self.assertEqual(rep.verdict, Verdict.FAIL)
        row = next(t for t in rep.tiers if t["id"] == "pg")
        self.assertFalse(row["sg_in_code"])
        self.assertEqual(next(f for f in rep.flows if f["id"] == "api-pg")["status"], "broken")

    def test_report_carries_oracle_version(self):
        self.assertEqual(evaluate(fixed_world(), load_topology_intent(INTENT)).to_dict()["oracle_version"], "topology-2")
