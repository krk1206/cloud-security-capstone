"""파이프라인 통합 테스트 — terraform(또는 tofu) + trivy 바이너리가 있을 때만 실행된다.

    TERRAFORM_BIN=... TRIVY_BIN=... python -m unittest tests/unit/test_pipeline_integration.py

각 케이스는 실제 Trivy 스캔 + 실제 plan 을 돌린다 (오프라인 plan). 한 케이스에 30~60초.
mock 응답은 tests/fixtures/mock_llm/ 의 canned(seeded) 파일이다 — LLM 이 생성한 것이 아니다.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT, tools_available

from iacpatch.config import load_settings
from iacpatch.models import GateAction, Validity, Verdict
from iacpatch.pipeline import run_predeploy

INTENT = "tests/fixtures/intents/sg-baseline.test.json"


def settings(fixture: str, generator_extra=None):
    ov = {"llm_provider": "mock", "llm_mock_fixture": fixture, "max_attempts": 1, "offline_plan": True,
          "tf_var_file": "terraform.tfvars.example", "data_dir": os.environ.get("IACPATCH_TEST_DATA_DIR") or tempfile.mkdtemp(prefix="iacpatch-test-runs-")}
    ov.update(generator_extra or {})
    return load_settings(str(ROOT), ov)


@unittest.skipUnless(tools_available(), "terraform/tofu and trivy binaries required (set TERRAFORM_BIN / TRIVY_BIN)")
class PipelineIntegrationTests(unittest.TestCase):
    def _layers(self, res):
        return {l.layer: l for l in res.validity.layers}

    def test_correct_patch_creates_pr_candidate(self):
        res = run_predeploy(settings("sg_baseline_ok"), "infrastructure/sg-baseline", INTENT, "it-ok")
        self.assertEqual(res.status, "DONE", res.note)
        self.assertEqual(res.validity.validity, Validity.PASS, res.validity.summary)
        self.assertEqual(res.gate.action, GateAction.CREATE_PR_AUTO)
        self.assertTrue((res.run_dir / "pr_body.md").exists())
        self.assertTrue((res.run_dir / "candidates" / "01" / "files" / "main.tf").exists())
        # 원본은 그대로
        self.assertIn('cidr_blocks = ["0.0.0.0/0"]', (ROOT / "infrastructure" / "sg-baseline" / "main.tf").read_text())
        run = json.loads((res.run_dir / "run.json").read_text())
        self.assertEqual(run["candidate"]["prompt_version"], "sg_v1")
        self.assertNotIn("api_key", json.dumps(run).lower().replace("api_key\": \"<redacted>", ""))

    def test_cidr_split_passes_scanner_but_blocked_by_oracle(self):
        res = run_predeploy(settings("sg_baseline_cidr_split"), "infrastructure/sg-baseline", INTENT, "it-split")
        L = self._layers(res)
        self.assertEqual(L["V1"].verdict, Verdict.PASS)   # 스캐너는 조용하다
        self.assertEqual(L["V2"].verdict, Verdict.PASS)
        self.assertEqual(L["V5"].verdict, Verdict.PASS)
        self.assertEqual(L["V6"].verdict, Verdict.FAIL)   # 오라클이 잡는다
        self.assertEqual(res.gate.action, GateAction.BLOCK)
        self.assertEqual(res.gate.risk_level.value, "LOW")  # 위험도가 낮아도 차단

    def test_external_prefix_list_is_held_not_approved(self):
        res = run_predeploy(settings("sg_baseline_external_prefix_list"), "infrastructure/sg-baseline", INTENT, "it-pl")
        L = self._layers(res)
        self.assertEqual(L["V1"].verdict, Verdict.PASS)
        self.assertEqual(L["V6"].verdict, Verdict.UNKNOWN)
        self.assertEqual(res.validity.validity, Validity.INCOMPLETE)
        self.assertEqual(res.gate.action, GateAction.HOLD_FOR_HUMAN)

    def test_two_groups_same_instance(self):
        s = settings("sg_two_groups_fix_app_only")
        s.tf_var_file = ""
        res = run_predeploy(s, "scenarios/eval/sg-two-groups", "tests/fixtures/intents/sg-two-groups.test.json", "it-two", target_resource="aws_security_group.app")
        L = self._layers(res)
        self.assertEqual(L["V1"].verdict, Verdict.PASS)
        self.assertEqual(L["V2"].verdict, Verdict.PASS)   # legacy 의 finding 은 기존 것
        self.assertEqual(L["V6"].verdict, Verdict.FAIL)
        self.assertIn("aws_instance.app", L["V6"].summary)
        self.assertEqual(res.gate.action, GateAction.BLOCK)

    def test_truncated_response_never_becomes_patch(self):
        res = run_predeploy(settings("sg_baseline_truncated"), "infrastructure/sg-baseline", INTENT, "it-trunc")
        self.assertEqual(res.status, "GENERATION_FAILED")
        self.assertFalse((res.run_dir / "candidates" / "01" / "files").exists())

    def test_draft_intent_stops_before_generation(self):
        res = run_predeploy(settings("sg_baseline_ok"), "infrastructure/sg-baseline", "policy/intent/sg-baseline.example.json", "it-draft")
        self.assertEqual(res.status, "INSUFFICIENT_INFO")
        self.assertFalse((res.run_dir / "candidates").exists())

    def test_rule_based_baseline(self):
        res = run_predeploy(settings("sg_baseline_ok"), "infrastructure/sg-baseline", INTENT, "it-rule", generator_kind="rule_based")
        self.assertEqual(res.validity.validity, Validity.PASS, res.validity.summary)
        self.assertEqual(res.candidate.origin, "rule_based")


if __name__ == "__main__":
    unittest.main()
