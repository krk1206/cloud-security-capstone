import json
import unittest

from helpers import ROOT, load_case_plan, load_case_sources

from iacpatch.models import AutonomyLevel, GateAction, LayerResult, PatchCandidate, PolicyResult, RiskLevel, Validity, ValidityReport, Verdict
from iacpatch.policy.gate import decide
from iacpatch.policy.risk import score_risk
from iacpatch.policy.validator import extract_top_level_blocks, validate_candidate
from iacpatch.verify.layers import v5_plan_diff
from iacpatch.verify.plan_model import build_world

POLICY = json.loads((ROOT / "policy" / "patch_policy.json").read_text(encoding="utf-8"))
RUBRIC = json.loads((ROOT / "policy" / "risk_rubric.json").read_text(encoding="utf-8"))
BASE_MAIN = (ROOT / "infrastructure" / "sg-baseline" / "main.tf").read_text(encoding="utf-8")
BASE_PROVIDER = (ROOT / "infrastructure" / "sg-baseline" / "provider.tf").read_text(encoding="utf-8")
BASELINE = {"main.tf": BASE_MAIN, "provider.tf": BASE_PROVIDER, "variables.tf": "variable \"vpc_id\" {}\n"}


def cand(files, status="PATCH"):
    return PatchCandidate("c1", "mock", "mock", status, files)


class PolicyValidatorTests(unittest.TestCase):
    def test_ok(self):
        r = validate_candidate(cand({"main.tf": BASE_MAIN.replace("0.0.0.0/0\"]\n  }\n\n  egress", "10.0.0.0/8\"]\n  }\n\n  egress")}), BASELINE, POLICY, "infrastructure/sg-baseline")
        self.assertTrue(r.ok, r.violations)

    def test_path_traversal_and_protected(self):
        r = validate_candidate(cand({"../../policy/patch_policy.json": "{}"}), BASELINE, POLICY, "infrastructure/sg-baseline")
        self.assertFalse(r.ok)
        r = validate_candidate(cand({"provider.tf": BASE_PROVIDER + "\n# x\n"}), BASELINE, POLICY, "infrastructure/sg-baseline")
        self.assertFalse(r.ok)
        self.assertTrue(any("provider" in v for v in r.violations))

    def test_non_tf_and_new_file(self):
        self.assertFalse(validate_candidate(cand({"notes.md": "x"}), BASELINE, POLICY).ok)
        self.assertFalse(validate_candidate(cand({"extra.tf": "resource \"aws_security_group\" \"x\" {}"}), BASELINE, POLICY).ok)

    def test_forbidden_token_introduced(self):
        bad = BASE_MAIN + '\nresource "null_resource" "x" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n'
        r = validate_candidate(cand({"main.tf": bad}), BASELINE, POLICY)
        self.assertFalse(r.ok)
        self.assertTrue(any("forbidden_tokens" in v for v in r.violations))

    def test_terraform_block_change_detected(self):
        base = {"main.tf": 'terraform {\n  required_version = ">= 1.5"\n}\nresource "aws_security_group" "a" {\n  name = "a"\n}\n'}
        changed = base["main.tf"].replace(">= 1.5", ">= 1.0")
        r = validate_candidate(cand({"main.tf": changed}), base, POLICY)
        self.assertFalse(r.ok)
        self.assertTrue(any("protected_blocks" in v for v in r.violations))

    def test_identical_content_and_too_many_files(self):
        r = validate_candidate(cand({"main.tf": BASE_MAIN}), BASELINE, POLICY)
        self.assertFalse(r.ok)
        many = {f"f{i}.tf": "x" for i in range(5)}
        self.assertFalse(validate_candidate(cand(many), {**BASELINE, **many}, POLICY).ok)

    def test_non_patch_status_is_noop(self):
        self.assertTrue(validate_candidate(cand({}, status="INSUFFICIENT_INFO"), BASELINE, POLICY).ok)

    def test_block_extractor(self):
        blocks = extract_top_level_blocks(BASE_PROVIDER)
        self.assertEqual([h.split()[0] for h in (b[0] for b in blocks)], ["terraform", "provider"])


class RiskTests(unittest.TestCase):
    def _v5(self, base, cand_case, rename=None):
        b, c = load_case_plan(base), load_case_plan(cand_case)
        if rename:
            for r in c["planned_values"]["root_module"]["resources"]:
                if r["address"] == rename[0]:
                    r["address"] = rename[1]
        return v5_plan_diff(b, c, POLICY), c

    def test_simple_sg_change_is_low(self):
        v5, cplan = self._v5("00-baseline", "00b-baseline-fixed")
        world = build_world(cplan, load_case_sources("00b-baseline-fixed"))
        r = score_risk(RUBRIC, v5.details, world, {"added_lines": 2, "removed_lines": 2, "files": 1})
        self.assertEqual(r.risk_level, RiskLevel.LOW)
        self.assertEqual(r.autonomy_cap, AutonomyLevel.HIGH)

    def test_delete_is_hard_high(self):
        v5, cplan = self._v5("00-baseline", "14-target-deleted")
        r = score_risk(RUBRIC, v5.details, build_world(cplan, {}), {"added_lines": 1, "removed_lines": 10, "files": 1})
        self.assertEqual(r.risk_level, RiskLevel.HIGH)
        self.assertTrue(any(f["factor"] == "resource_deleted" for f in r.factors))

    def test_iam_touched_is_at_least_medium_and_trust_policy_is_high(self):
        """risk-v2 (D-6): IAM 리소스 변경은 최소 MEDIUM(사람 승인 필수). 신뢰 정책(assume_role_policy) 변경은 hard HIGH."""
        details = {"removed": [], "added": [], "changed": {"aws_iam_policy.x": ["policy"]}, "plan_actions_delete": [], "plan_actions_replace": [], "provider_config_diff": []}
        r = score_risk(RUBRIC, details, None, {"added_lines": 5, "removed_lines": 1, "files": 1})
        self.assertEqual(r.risk_level, RiskLevel.MEDIUM)
        self.assertTrue(any(f["factor"] == "iam_resource_touched" for f in r.factors))
        details2 = {"removed": [], "added": [], "changed": {"aws_iam_role.x": ["assume_role_policy"]}, "plan_actions_delete": [], "plan_actions_replace": [], "provider_config_diff": []}
        r2 = score_risk(RUBRIC, details2, None, {"added_lines": 1, "removed_lines": 1, "files": 1})
        self.assertEqual(r2.risk_level, RiskLevel.HIGH)
        self.assertEqual(r2.autonomy_cap, AutonomyLevel.LOW)
        self.assertTrue(any(f["factor"] == "iam_trust_policy_changed" for f in r2.factors))

    def test_attachment_blast_radius_raises_score(self):
        cplan = load_case_plan("08-second-sg")
        world = build_world(cplan, load_case_sources("08-second-sg"))
        details = {"removed": [], "added": [], "changed": {"aws_security_group.app": ["ingress"]}, "plan_actions_delete": [], "plan_actions_replace": [], "provider_config_diff": []}
        r = score_risk(RUBRIC, details, world, {"added_lines": 1, "removed_lines": 1, "files": 1})
        self.assertGreaterEqual(r.score, 1)
        self.assertTrue(any(f["factor"] == "attachment_points" and f["points"] >= 1 for f in r.factors))


class GateTests(unittest.TestCase):
    def _validity(self, v):
        return ValidityReport("pre_deploy", [LayerResult("V6", "x", Verdict.PASS if v == Validity.PASS else Verdict.FAIL, "")], v, "s")

    def _risk(self, level):
        from iacpatch.models import RISK_TO_AUTONOMY_CAP, RiskDecision
        return RiskDecision(level, RISK_TO_AUTONOMY_CAP[level], 0, [], "t")

    def test_policy_violation_blocks_regardless(self):
        g = decide(self._validity(Validity.PASS), PolicyResult(False, ["x"], [], "p"), self._risk(RiskLevel.LOW))
        self.assertEqual(g.action, GateAction.BLOCK)

    def test_verification_fail_blocks_even_low_risk(self):
        g = decide(self._validity(Validity.FAIL), PolicyResult(True, [], [], "p"), self._risk(RiskLevel.LOW))
        self.assertEqual(g.action, GateAction.BLOCK)

    def test_incomplete_holds(self):
        g = decide(self._validity(Validity.INCOMPLETE), PolicyResult(True, [], [], "p"), self._risk(RiskLevel.LOW))
        self.assertEqual(g.action, GateAction.HOLD_FOR_HUMAN)

    def test_pass_maps_by_risk(self):
        ok = PolicyResult(True, [], [], "p")
        self.assertEqual(decide(self._validity(Validity.PASS), ok, self._risk(RiskLevel.LOW)).action, GateAction.CREATE_PR_AUTO)
        self.assertEqual(decide(self._validity(Validity.PASS), ok, self._risk(RiskLevel.MEDIUM)).action, GateAction.CREATE_PR_APPROVAL)
        self.assertEqual(decide(self._validity(Validity.PASS), ok, self._risk(RiskLevel.HIGH)).action, GateAction.REPORT_ONLY)

    def test_llm_can_only_lower(self):
        ok = PolicyResult(True, [], [], "p")
        g = decide(self._validity(Validity.PASS), ok, self._risk(RiskLevel.LOW), llm_proposed="LOW")
        self.assertEqual(g.final_autonomy, AutonomyLevel.LOW)
        self.assertEqual(g.action, GateAction.REPORT_ONLY)
        g = decide(self._validity(Validity.PASS), ok, self._risk(RiskLevel.MEDIUM), llm_proposed="HIGH")
        self.assertEqual(g.final_autonomy, AutonomyLevel.MEDIUM)
        self.assertTrue(any("ignored" in r for r in g.reasons))
        g = decide(self._validity(Validity.PASS), ok, self._risk(RiskLevel.LOW), llm_proposed="ULTRA")
        self.assertEqual(g.final_autonomy, AutonomyLevel.HIGH)

    def test_no_risk_decision_holds(self):
        g = decide(self._validity(Validity.PASS), PolicyResult(True, [], [], "p"), None)
        self.assertEqual(g.action, GateAction.HOLD_FOR_HUMAN)


if __name__ == "__main__":
    unittest.main()
