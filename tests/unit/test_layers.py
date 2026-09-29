"""V1 / V2 (Trivy fixture 기반) 와 V5 (plan fixture 기반) 테스트."""
import copy
import json
import unittest

from helpers import ROOT, load_case_plan, load_case_trivy

from iacpatch.models import Finding, Verdict
from iacpatch.tools.trivy import TrivyScan
from iacpatch.verify.layers import v1_target_finding, v2_finding_diff, v5_plan_diff

POLICY = json.loads((ROOT / "policy" / "patch_policy.json").read_text(encoding="utf-8"))


def target_of(scan: TrivyScan, rule="AVD-AWS-0107") -> Finding:
    return next(f for f in scan.findings if f.rule_id == rule)


class V1Tests(unittest.TestCase):
    def test_fixed_removes_target(self):
        before, after = load_case_trivy("00-baseline"), load_case_trivy("00b-baseline-fixed")
        r = v1_target_finding(target_of(before), before, after)
        self.assertEqual(r.verdict, Verdict.PASS)

    def test_cidr_split_passes_v1_that_is_the_point(self):
        # 스캐너는 01 을 통과시킨다 → V1 만으로는 성공 판정이 부적절함을 보여주는 회귀 테스트
        before, after = load_case_trivy("00-baseline"), load_case_trivy("01-cidr-split")
        r = v1_target_finding(target_of(before), before, after)
        self.assertEqual(r.verdict, Verdict.PASS)
        self.assertGreater(after.summary["checks_executed"], 0)

    def test_still_present_fails(self):
        before = load_case_trivy("00-baseline")
        r = v1_target_finding(target_of(before), before, before)
        self.assertEqual(r.verdict, Verdict.FAIL)

    def test_zero_checks_is_error_not_pass(self):
        before = load_case_trivy("00-baseline")
        empty = TrivyScan(True, {"Results": []}, [], {"successes": 0, "failures": 0, "checks_executed": 0}, "0.74.0")
        r = v1_target_finding(target_of(before), before, empty)
        self.assertEqual(r.verdict, Verdict.ERROR)

    def test_resource_absent_is_noted(self):
        before, after = load_case_trivy("00-baseline"), load_case_trivy("14-target-deleted")
        r = v1_target_finding(target_of(before), before, after, candidate_resource_present=False)
        self.assertEqual(r.verdict, Verdict.PASS)
        self.assertTrue(r.details.get("resource_absent_in_candidate"))


class V2Tests(unittest.TestCase):
    def test_no_new_findings(self):
        r = v2_finding_diff(load_case_trivy("00-baseline"), load_case_trivy("00b-baseline-fixed"))
        self.assertEqual(r.verdict, Verdict.PASS)
        self.assertEqual(len(r.details["new"]), 0)
        self.assertEqual(len(r.details["resolved"]), 1)

    def test_new_critical_blocks(self):
        # 05-separate 는 egress 전체 개방(AWS-0104 CRITICAL) 이 새로 생긴다
        r = v2_finding_diff(load_case_trivy("00-baseline"), load_case_trivy("05-separate"))
        self.assertEqual(r.verdict, Verdict.FAIL)
        self.assertTrue(any(f["rule_id"] == "AVD-AWS-0104" for f in r.details["new"]))

    def test_new_low_is_warn_not_block(self):
        # 04-dynamic 은 description 누락(AWS-0124 LOW) 이 새로 생긴다. 리소스 이름을 baseline 과 맞춰 '같은 리소스' 로 만든다.
        before, after = load_case_trivy("00-baseline"), load_case_trivy("04-dynamic")
        for f in after.findings:
            f.resource = "aws_security_group.baseline"
        r = v2_finding_diff(before, after)
        self.assertEqual(r.verdict, Verdict.WARN, r.summary)
        self.assertEqual([f["rule_id"] for f in r.details["new"]], ["AVD-AWS-0124"])

    def test_key_based_not_count_based(self):
        # 같은 개수(1개)지만 다른 리소스에 붙은 finding 은 '새 finding' 으로 잡혀야 한다
        before = load_case_trivy("00-baseline")
        after = copy.deepcopy(before)
        after.findings = [copy.deepcopy(f) for f in before.findings]
        after.findings[0].resource = "aws_security_group.other"
        r = v2_finding_diff(before, after)
        self.assertEqual(r.details["before_count"], r.details["after_count"])
        self.assertEqual(len(r.details["new"]), 1)
        self.assertEqual(r.verdict, Verdict.FAIL)  # HIGH 룰이 새 리소스에 → 차단

    def test_ignore_rules(self):
        before = load_case_trivy("00-baseline")
        after = copy.deepcopy(before)
        extra = copy.deepcopy(before.findings[0])
        extra.rule_id, extra.severity = "AVD-AWS-0104", "CRITICAL"
        after.findings = list(before.findings) + [extra]
        self.assertEqual(v2_finding_diff(before, after).verdict, Verdict.FAIL)
        self.assertEqual(v2_finding_diff(before, after, ignore_rules=["AVD-AWS-0104"]).verdict, Verdict.WARN)

    def test_moved_finding_is_reported_as_new_and_resolved(self):
        # inline → 별도 규칙 리소스로 옮기면 키가 바뀌어 new+resolved 로 나타난다 (possibly_moved 로 표시)
        before, after = load_case_trivy("00-baseline"), load_case_trivy("05-separate")
        r = v2_finding_diff(before, after, ignore_rules=["AVD-AWS-0104", "AVD-AWS-0124"])
        self.assertEqual(r.verdict, Verdict.FAIL)  # 0107 이 새 리소스에서 여전히 FAIL
        self.assertTrue(any(m["rule"] == "AVD-AWS-0107" for m in r.details["possibly_moved"]))


class V5Tests(unittest.TestCase):
    def test_in_place_ingress_change_ok(self):
        r = v5_plan_diff(load_case_plan("00-baseline"), load_case_plan("00b-baseline-fixed"), POLICY)
        self.assertEqual(r.verdict, Verdict.PASS, r.summary)
        self.assertEqual(r.details["changed"], {"aws_security_group.baseline": ["description", "ingress"]})

    def test_deleted_resource_fails(self):
        r = v5_plan_diff(load_case_plan("00-baseline"), load_case_plan("14-target-deleted"), POLICY)
        self.assertEqual(r.verdict, Verdict.FAIL)
        self.assertIn("aws_security_group.baseline", r.details["removed"])

    def test_new_disallowed_resource_type_fails(self):
        base = load_case_plan("00-baseline")
        cand = load_case_plan("06-prefix-list")
        # 주소를 맞춰 '같은 SG 를 수정 + prefix list 추가' 상황으로 만든다
        for r in cand["planned_values"]["root_module"]["resources"]:
            if r["type"] == "aws_security_group":
                r["address"] = "aws_security_group.baseline"
        res = v5_plan_diff(base, cand, POLICY)
        self.assertEqual(res.verdict, Verdict.FAIL)
        self.assertTrue(any("aws_ec2_managed_prefix_list" in v for v in res.details["violations"]))

    def test_allowed_new_rule_resource_ok(self):
        base = load_case_plan("15-separate-rules-fixed")
        cand = copy.deepcopy(base)
        cand["planned_values"]["root_module"]["resources"].append({
            "address": "aws_vpc_security_group_ingress_rule.extra", "mode": "managed", "type": "aws_vpc_security_group_ingress_rule",
            "name": "extra", "values": {"cidr_ipv4": "10.0.0.0/8", "from_port": 22, "to_port": 22, "ip_protocol": "tcp"}})
        r = v5_plan_diff(base, cand, POLICY)
        self.assertEqual(r.verdict, Verdict.PASS, r.summary)

    def test_stateful_delete_and_replace_actions(self):
        base = load_case_plan("00-baseline")
        cand = copy.deepcopy(base)
        cand["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
        r = v5_plan_diff(base, cand, POLICY)
        self.assertEqual(r.verdict, Verdict.FAIL)
        self.assertIn("aws_security_group.baseline", r.details["plan_actions_replace"])

    def test_disallowed_attribute_change(self):
        base = load_case_plan("00-baseline")
        cand = copy.deepcopy(base)
        cand["planned_values"]["root_module"]["resources"][0]["values"]["name"] = "renamed"
        r = v5_plan_diff(base, cand, POLICY)
        self.assertEqual(r.verdict, Verdict.FAIL)
        self.assertTrue(any("outside allowlist" in v for v in r.details["violations"]))

    def test_provider_config_change(self):
        base = load_case_plan("00-baseline")
        cand = copy.deepcopy(base)
        cand["configuration"]["provider_config"]["aws"]["expressions"]["region"] = {"constant_value": "us-east-1"}
        r = v5_plan_diff(base, cand, POLICY)
        self.assertEqual(r.verdict, Verdict.FAIL)

    def test_missing_plan_is_skipped(self):
        r = v5_plan_diff(None, load_case_plan("00-baseline"), POLICY)
        self.assertEqual(r.verdict, Verdict.SKIPPED)


if __name__ == "__main__":
    unittest.main()


class TrivyParseErrorTests(unittest.TestCase):
    """Trivy 는 HCL 을 못 읽으면 그 파일을 건너뛰고 exit 0 + 검사 '성공' 으로 센다 → '경고 없음' 이 통과로 보이면 안 된다 (팀 PC 실습 09-29: 속성 중복 파일이 V1 PASS)."""

    STDERR = ('2026-09-29T02:45:20Z\tERROR\t[terraform parser] Error parsing file\tmodule="root" file_path="main.tf" '
              'cause="    cidr_blocks = [\\"0.0.0.0/2\\"]" err="main.tf:15,5-16: Attribute redefined; The argument \\"cidr_blocks\\" was already set at main.tf:14,5-16. Each argument may be set only once."\n'
              '2026-09-29T02:45:20Z\tINFO\t[terraform parser] No files found, nothing to do.\tmodule="root"\n')

    def test_parse_errors_extracted_from_stderr(self):
        from iacpatch.tools.trivy import parse_errors
        errs = parse_errors(self.STDERR)
        self.assertEqual(len(errs), 1)
        self.assertIn("Attribute redefined", errs[0])
        self.assertEqual(parse_errors(""), [])

    def test_v1_and_v2_error_instead_of_pass_when_candidate_unparseable(self):
        from iacpatch.tools.trivy import TrivyScan
        from iacpatch.verify.layers import v1_target_finding, v2_finding_diff
        before = load_case_trivy("00-baseline")
        target = next(f for f in before.findings if f.rule_id == "AVD-AWS-0107")
        after = TrivyScan(True, {"Results": [{"Target": ".", "MisconfSummary": {"Successes": 51, "Failures": 0}}]}, [],
                          {"successes": 51, "failures": 0, "checks_executed": 51}, "0.74.0", "", [], ["main.tf:15,5-16: Attribute redefined"])
        self.assertEqual(v1_target_finding(target, before, after).verdict, Verdict.ERROR)
        self.assertEqual(v2_finding_diff(before, after).verdict, Verdict.ERROR)
        clean = TrivyScan(True, after.report, [], after.summary, "0.74.0", "", [], [])
        self.assertEqual(v1_target_finding(target, before, clean).verdict, Verdict.PASS)   # 파싱 오류가 없을 때만 PASS
