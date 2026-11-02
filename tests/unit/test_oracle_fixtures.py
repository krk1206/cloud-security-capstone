"""V6 Intent Oracle — 실제 plan JSON fixture(tests/fixtures/plans, OpenTofu 1.10.6 로 생성) 기반 회귀 테스트.

기대값은 케이스 **내용**을 읽고 정했다 (이름이 아니라). 특히:
  - 00-baseline 은 취약한 대조군이므로 FAIL 이 맞다. "정상 패치"는 00b-baseline-fixed 다.
  - 07-ipv6-only 는 Trivy 가 잡지만(FAIL) 오라클도 잡아야 한다 (v6 ::/0).
"""
import unittest

from helpers import intent_for, load_case_plan, load_case_sources

from iacpatch.models import Verdict
from iacpatch.verify.plan_model import build_world
from iacpatch.verify.sg_oracle import evaluate


def run_case(case: str, target: str, **kw):
    world = build_world(load_case_plan(case), load_case_sources(case))
    return evaluate(world, intent_for(target, **kw)), world


def ssh_eval(report):
    for t in report.targets:
        for sc in t.scopes:
            for s in sc.services:
                if s.label == "ssh":
                    return sc, s
    return None, None


class OracleFixtureTests(unittest.TestCase):
    # --- 기존 실험 케이스 9종 (00~08) --------------------------------------------------
    def test_00_baseline_is_vulnerable_control(self):
        r, _ = run_case("00-baseline", "aws_security_group.baseline")
        self.assertEqual(r.verdict, Verdict.FAIL)
        sc, s = ssh_eval(r)
        self.assertTrue(s.covers_entire_internet_v4)
        self.assertEqual(s.effective_v4, ["0.0.0.0/0"])

    def test_00b_fixed_passes(self):
        r, _ = run_case("00b-baseline-fixed", "aws_security_group.baseline")
        self.assertEqual(r.verdict, Verdict.PASS, r.summary)
        sc, s = ssh_eval(r)
        self.assertEqual(s.excess_v4, [])
        self.assertTrue(all(x.verdict == Verdict.PASS for x in sc.required))

    def test_01_cidr_split_detected_by_set_math(self):
        r, _ = run_case("01-cidr-split", "aws_security_group.cidr_split")
        self.assertEqual(r.verdict, Verdict.FAIL)
        sc, s = ssh_eval(r)
        self.assertEqual(s.effective_v4, ["0.0.0.0/0"])  # 0.0.0.0/1 + 128.0.0.0/1 collapse
        self.assertTrue(s.covers_entire_internet_v4)

    def test_02_03_04_terraform_resolved_variants(self):
        for case, tgt in (("02-var-default", "aws_security_group.var_default"), ("03-string-build", "aws_security_group.string_build"),
                          ("04-dynamic", "aws_security_group.dynamic_rules")):
            r, _ = run_case(case, tgt)
            self.assertEqual(r.verdict, Verdict.FAIL, case)

    def test_05_separate_rule_resource_attached_via_reference(self):
        r, world = run_case("05-separate", "aws_security_group.clean")
        self.assertEqual(r.verdict, Verdict.FAIL)
        sg = world.security_groups["aws_security_group.clean"]
        self.assertTrue(any(rule.origin == "aws_vpc_security_group_ingress_rule.ssh_open" for rule in sg.rules))
        self.assertNotIn("ingress", sg.inline_unknown)  # inline 미선언 → caveat 로 처리

    def test_06_prefix_list_expanded_from_plan(self):
        r, world = run_case("06-prefix-list", "aws_security_group.prefix_list")
        self.assertEqual(r.verdict, Verdict.FAIL)
        sc, s = ssh_eval(r)
        self.assertEqual(s.effective_v4, ["0.0.0.0/0"])
        self.assertIn("aws_ec2_managed_prefix_list.world", world.prefix_lists)

    def test_07_ipv6_open(self):
        r, _ = run_case("07-ipv6-only", "aws_security_group.ipv6_only")
        self.assertEqual(r.verdict, Verdict.FAIL)
        sc, s = ssh_eval(r)
        self.assertEqual(s.excess_v4, [])          # v4 는 승인 안
        self.assertEqual(s.excess_v6, ["::/0"])    # v6 가 문제

    def test_08_second_sg_on_same_instance_is_summed(self):
        r, world = run_case("08-second-sg", "aws_security_group.app")
        self.assertEqual(r.verdict, Verdict.FAIL)
        sc, s = ssh_eval(r)
        self.assertEqual(sc.scope_kind, "attachment")
        self.assertEqual(sc.scope_id, "aws_instance.app")
        self.assertEqual(sorted(sc.security_groups), ["aws_security_group.app", "aws_security_group.legacy"])
        self.assertTrue(s.covers_entire_internet_v4)

    # --- 추가 케이스 ------------------------------------------------------------------
    def test_09_partial_port_range_rule_counts(self):
        r, _ = run_case("09-partial-port-range", "aws_security_group.partial")
        self.assertEqual(r.verdict, Verdict.FAIL)

    def test_10_all_protocols(self):
        r, _ = run_case("10-all-protocols", "aws_security_group.allproto")
        self.assertEqual(r.verdict, Verdict.FAIL)
        sc, s = ssh_eval(r)
        self.assertTrue(s.covers_entire_internet_v4)

    def test_11_sg_reference_is_not_inherited(self):
        # bastion 이 전세계에 열려 있어도 app 의 출처는 'bastion SG 참조' 하나뿐. 승인 목록에 없으면 EXCESS.
        r, _ = run_case("11-sg-ref-source", "aws_security_group.app")
        sc, s = ssh_eval(r)
        self.assertEqual(s.effective_v4, [])                 # bastion 의 0.0.0.0/0 을 상속하지 않는다
        self.assertEqual(s.excess_sg_refs, ["aws_security_group.bastion"])
        # 승인 목록에 참조를 넣고 CIDR 필수 접근을 빼면 PASS
        r2, _ = run_case("11-sg-ref-source", "aws_security_group.app", sg_refs=["aws_security_group.bastion"], required=[])
        self.assertEqual(r2.verdict, Verdict.PASS, r2.summary)
        # bastion 자체를 대상으로 하면 FAIL
        r3, _ = run_case("11-sg-ref-source", "aws_security_group.bastion")
        self.assertEqual(r3.verdict, Verdict.FAIL)

    def test_12_different_enis_are_not_mixed(self):
        r, _ = run_case("12-two-enis", "aws_security_group.app")
        self.assertEqual(r.verdict, Verdict.PASS, r.summary)
        sc, s = ssh_eval(r)
        self.assertEqual(sc.security_groups, ["aws_security_group.app"])
        r2, _ = run_case("12-two-enis", "aws_security_group.legacy")
        self.assertEqual(r2.verdict, Verdict.FAIL)

    def test_13_external_sg_on_same_instance_is_unknown(self):
        r, world = run_case("13-external-sg-attached", "aws_security_group.app")
        self.assertEqual(r.verdict, Verdict.UNKNOWN, r.summary)
        self.assertIn("sg-0123456789abcdef0", world.attachments[0].external_sg_ids)
        # HCL 없이 plan 만 주면 원소를 셀 수 없으므로 여전히 UNKNOWN
        r2 = evaluate(build_world(load_case_plan("13-external-sg-attached"), {}), intent_for("aws_security_group.app"))
        self.assertEqual(r2.verdict, Verdict.UNKNOWN)

    def test_14_target_deleted_is_fail_not_pass(self):
        r, _ = run_case("14-target-deleted", "aws_security_group.baseline")
        self.assertEqual(r.verdict, Verdict.FAIL)
        self.assertIn("absent", r.targets[0].reason)

    def test_15_separate_rules_fixed_passes_with_caveat(self):
        r, _ = run_case("15-separate-rules-fixed", "aws_security_group.clean")
        self.assertEqual(r.verdict, Verdict.PASS, r.summary)
        sc, s = ssh_eval(r)
        self.assertTrue(any("inline ingress" in c for c in sc.caveats))

    def test_17_unknown_value_blocks_auto_approval(self):
        r, _ = run_case("17-unknown-value", "aws_security_group.eip_sg")
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        sc, s = ssh_eval(r)
        self.assertTrue(any("cidr_blocks unknown" in u for u in s.unknown_reasons))

    def test_18_self_reference(self):
        r, _ = run_case("18-self-ref", "aws_security_group.cluster")
        sc, s = ssh_eval(r)
        self.assertEqual(s.excess_sg_refs, ["self:aws_security_group.cluster"])
        r2, _ = run_case("18-self-ref", "aws_security_group.cluster", sg_refs=["self"], required=[])
        self.assertEqual(r2.verdict, Verdict.PASS, r2.summary)

    def test_19_ipv6_approved_exact_vs_narrower(self):
        r, _ = run_case("19-ipv6-approved", "aws_security_group.v6ok", v6=["2001:db8::/32"])
        self.assertEqual(r.verdict, Verdict.PASS, r.summary)
        r2, _ = run_case("19-ipv6-approved", "aws_security_group.v6ok", v6=["2001:db8::/33"])
        self.assertEqual(r2.verdict, Verdict.FAIL)
        sc, s = ssh_eval(r2)
        self.assertEqual(s.excess_v6, ["2001:db8:8000::/33"])

    def test_20_icmp_does_not_affect_tcp_service(self):
        r, _ = run_case("20-icmp-only", "aws_security_group.icmp")
        self.assertEqual(r.verdict, Verdict.PASS, r.summary)

    def test_21_rdp_open_fails_on_rdp_service_only(self):
        r, _ = run_case("21-rdp-open", "aws_security_group.rdp")
        self.assertEqual(r.verdict, Verdict.FAIL)
        verdicts = {s.label: s.verdict for sc in r.targets[0].scopes for s in sc.services}
        self.assertEqual(verdicts["ssh"], Verdict.PASS)
        self.assertEqual(verdicts["rdp"], Verdict.FAIL)

    def test_22_legacy_rule_resource_split(self):
        r, _ = run_case("22-sg-rule-legacy", "aws_security_group.legacy_rule")
        self.assertEqual(r.verdict, Verdict.FAIL)
        sc, s = ssh_eval(r)
        self.assertTrue(s.covers_entire_internet_v4)

    def test_not_whole_internet_but_unapproved_is_still_fail(self):
        # 승인 출처를 172.16.0.0/12 로 바꾸면 00b(10.0.0.0/8) 는 "인터넷 전체는 아니지만 승인 밖" → FAIL + required MISSING
        r, _ = run_case("00b-baseline-fixed", "aws_security_group.baseline", v4=["172.16.0.0/12"],
                        required=[{"label": "x", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "source_cidr": "172.16.0.0/12"}])
        self.assertEqual(r.verdict, Verdict.FAIL)
        sc, s = ssh_eval(r)
        self.assertFalse(s.covers_entire_internet_v4)
        self.assertEqual(s.excess_v4, ["10.0.0.0/8"])
        self.assertEqual(sc.required[0].verdict, Verdict.FAIL)


if __name__ == "__main__":
    unittest.main()
