"""LLM 응답 파싱(잘림/오류), mock provider, Rule-based baseline 테스트."""
import json
import unittest

from helpers import ROOT, load_case_trivy, load_case_sources, intent_for

from iacpatch.evidence import build_bundle
from iacpatch.generator.base import GenerationError, LLMResponse, extract_json_object, parse_llm_output
from iacpatch.generator.llm_generator import LLMPatchGenerator, load_prompt
from iacpatch.generator.llm_providers import MockProvider, make_provider
from iacpatch.generator.rule_based import RuleBasedGenerator

POLICY = json.loads((ROOT / "policy" / "patch_policy.json").read_text(encoding="utf-8"))


def resp(text, truncated=False, stop="end_turn", error=""):
    return LLMResponse(text, "m", "mock", truncated=truncated, stop_reason=stop, error=error)


class ParseTests(unittest.TestCase):
    def test_plain_json(self):
        p = parse_llm_output(resp('{"status":"PATCH","files":[{"path":"main.tf","content":"x"}],"rationale":"r","proposed_autonomy":"low"}'), ["main.tf"])
        self.assertEqual(p["status"], "PATCH")
        self.assertEqual(p["files"], {"main.tf": "x"})
        self.assertEqual(p["proposed_autonomy"], "LOW")

    def test_fenced_and_prose(self):
        text = 'Here you go:\n```json\n{"status": "ABSTAIN", "rationale": "no"}\n```\nThanks!'
        self.assertEqual(parse_llm_output(resp(text), [])["status"], "ABSTAIN")

    def test_truncated_flag_refuses_even_if_parsable(self):
        with self.assertRaises(GenerationError) as cm:
            parse_llm_output(resp('{"status":"ABSTAIN"}', truncated=True, stop="max_tokens"), [])
        self.assertIn("truncated", str(cm.exception))

    def test_cut_json(self):
        with self.assertRaises(GenerationError):
            parse_llm_output(resp('{"status":"PATCH","files":[{"path":"main.tf","content":"resource \\"a'), ["main.tf"])

    def test_garbage_and_empty(self):
        with self.assertRaises(GenerationError):
            parse_llm_output(resp("I cannot help with that."), [])
        with self.assertRaises(GenerationError):
            parse_llm_output(resp(""), [])
        with self.assertRaises(GenerationError):
            parse_llm_output(resp("", error="HTTP 500"), [])

    def test_schema_violations(self):
        with self.assertRaises(GenerationError):
            parse_llm_output(resp('{"status":"FIXED"}'), [])
        with self.assertRaises(GenerationError):
            parse_llm_output(resp('{"status":"PATCH","files":[]}'), [])
        with self.assertRaises(GenerationError):
            parse_llm_output(resp('{"status":"PATCH","files":[{"path":1,"content":"x"}]}'), [])
        with self.assertRaises(GenerationError):
            parse_llm_output(resp('{"status":"PATCH","files":[{"path":"a.tf","content":"x"},{"path":"a.tf","content":"y"}]}'), [])

    def test_invalid_autonomy_becomes_none(self):
        p = parse_llm_output(resp('{"status":"ABSTAIN","proposed_autonomy":"MAXIMUM"}'), [])
        self.assertIsNone(p["proposed_autonomy"])

    def test_extract_first_object_with_nested_braces_in_strings(self):
        obj = extract_json_object('x {"a": "}{", "b": {"c": 1}} y {"d": 2}')
        self.assertEqual(obj, {"a": "}{", "b": {"c": 1}})


class MockProviderTests(unittest.TestCase):
    def test_fixture_roundtrip_and_metadata(self):
        gen = LLMPatchGenerator(MockProvider("sg_baseline_ok"))
        bundle = _bundle_for_sg_baseline()
        c = gen.generate(bundle)
        self.assertEqual(c.status, "PATCH")
        self.assertEqual(c.origin, "mock")
        self.assertEqual(c.prompt_version, "sg_v1")
        self.assertEqual(len(c.prompt_sha256), 64)
        self.assertIn("main.tf", c.files)

    def test_truncated_fixture(self):
        c = LLMPatchGenerator(MockProvider("sg_baseline_truncated")).generate(_bundle_for_sg_baseline())
        self.assertEqual(c.status, "GENERATION_FAILED")
        self.assertIn("truncated", c.error)

    def test_missing_fixture_is_generation_failed(self):
        c = LLMPatchGenerator(MockProvider("does_not_exist")).generate(_bundle_for_sg_baseline())
        self.assertEqual(c.status, "GENERATION_FAILED")

    def test_factory(self):
        self.assertEqual(make_provider("mock").name, "mock")
        self.assertEqual(make_provider("anthropic").name, "anthropic")
        self.assertEqual(make_provider("openai").name, "openai")
        with self.assertRaises(ValueError):
            make_provider("nope")

    def test_real_provider_without_key_returns_error_not_exception(self):
        import os
        for k in ("LLM_API_KEY", "ANTHROPIC_API_KEY"):
            os.environ.pop(k, None)
        r = make_provider("anthropic").complete("s", "u", 10, 0.0)
        self.assertTrue(r.error)
        self.assertIn("API key not set", r.error)

    def test_prompt_has_sections(self):
        s, u = load_prompt("sg_v1")
        self.assertIn("INSUFFICIENT_INFO", s)
        self.assertIn("{{BUNDLE_JSON}}", u)


def _bundle_for_sg_baseline():
    scan = load_case_trivy("00-baseline")
    files = {"main.tf": (ROOT / "infrastructure" / "sg-baseline" / "main.tf").read_text(encoding="utf-8")}
    target = next(f for f in scan.findings if f.rule_id == "AVD-AWS-0107")
    # 00-baseline 스캔의 finding 은 main.tf:14 를 가리키지만 sg-baseline/main.tf 에서는 11 행이다 → 위치를 맞춘다
    target.start_line = 11
    target.resource = "aws_security_group.vulnerable_ssh"
    intent = intent_for("aws_security_group.vulnerable_ssh", v4=["203.0.113.0/24"],
                        required=[{"label": "a", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "source_cidr": "203.0.113.0/24"}])
    return build_bundle("t", "infrastructure/sg-baseline", target, scan.findings, files, intent.to_dict(), POLICY, {}, {"trivy": "0.74.0"})


class RuleBasedTests(unittest.TestCase):
    def _bundle(self, case, target_addr, v4=None, required=None):
        scan = load_case_trivy(case)
        files = load_case_sources(case)
        target = next(f for f in scan.findings if f.rule_id == "AVD-AWS-0107")
        intent = intent_for(target_addr, v4=v4, required=required)
        return build_bundle(case, f"tests/fixtures/src/{case}", target, scan.findings, files, intent.to_dict(), POLICY, {}, {})

    def test_literal_replacement(self):
        c = RuleBasedGenerator().generate(self._bundle("00-baseline", "aws_security_group.baseline"))
        self.assertEqual(c.status, "PATCH", c.error)
        self.assertIn('cidr_blocks = ["10.0.0.0/8"]', c.files["main.tf"])
        self.assertNotIn("0.0.0.0/0", c.files["main.tf"])
        self.assertEqual(c.origin, "rule_based")

    def test_variable_not_supported(self):
        c = RuleBasedGenerator().generate(self._bundle("02-var-default", "aws_security_group.var_default"))
        self.assertEqual(c.status, "NOT_SUPPORTED")

    def test_dynamic_not_supported(self):
        c = RuleBasedGenerator().generate(self._bundle("04-dynamic", "aws_security_group.dynamic_rules"))
        self.assertEqual(c.status, "NOT_SUPPORTED")

    def test_separate_rule_single_value(self):
        c = RuleBasedGenerator().generate(self._bundle("05-separate", "aws_security_group.clean"))
        self.assertEqual(c.status, "PATCH", c.error)
        self.assertIn('cidr_ipv4         = "10.0.0.0/8"', c.files["main.tf"])
        c2 = RuleBasedGenerator().generate(self._bundle("05-separate", "aws_security_group.clean", v4=["10.0.0.0/8", "172.16.0.0/12"]))
        self.assertEqual(c2.status, "NOT_SUPPORTED")

    def test_ipv6_also_fixed_in_same_block(self):
        c = RuleBasedGenerator().generate(self._bundle("07-ipv6-only", "aws_security_group.ipv6_only"))
        self.assertEqual(c.status, "PATCH", c.error)
        self.assertIn("ipv6_cidr_blocks = []", c.files["main.tf"])

    def test_no_intent_is_insufficient(self):
        b = self._bundle("00-baseline", "aws_security_group.baseline")
        b.intent = {}
        self.assertEqual(RuleBasedGenerator().generate(b).status, "INSUFFICIENT_INFO")


if __name__ == "__main__":
    unittest.main()
