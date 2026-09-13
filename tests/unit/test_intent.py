import copy
import unittest

from helpers import INTENT_TEMPLATE

from iacpatch.intent import IntentError, parse_intent


class IntentTests(unittest.TestCase):
    def _d(self):
        d = copy.deepcopy(INTENT_TEMPLATE)
        d["targets"]["security_groups"] = ["aws_security_group.x"]
        return d

    def test_valid(self):
        spec = parse_intent(self._d())
        self.assertEqual(spec.intent_id, "unit-test")
        self.assertEqual(len(spec.guarded_services), 2)
        self.assertEqual(spec.required_access[0].source_cidr, "10.0.0.0/8")

    def test_placeholder_rejected(self):
        d = self._d()
        d["guarded_services"][0]["approved_sources"]["cidrs_v4"] = ["__FILL_ME__/32"]
        with self.assertRaises(IntentError) as cm:
            parse_intent(d)
        self.assertIn("placeholder", str(cm.exception))

    def test_placeholder_in_description_is_ignored(self):
        d = self._d()
        d["description"] = "replace __FILL_ME__ with the real value"
        parse_intent(d)  # 자유 텍스트는 검사 대상이 아니다

    def test_draft_rejected(self):
        d = self._d()
        d["status"] = "draft"
        with self.assertRaises(IntentError):
            parse_intent(d)

    def test_whole_internet_approval_rejected(self):
        d = self._d()
        d["guarded_services"][0]["approved_sources"]["cidrs_v4"] = ["0.0.0.0/1", "128.0.0.0/1"]
        with self.assertRaises(IntentError) as cm:
            parse_intent(d)
        self.assertIn("entire internet", str(cm.exception))

    def test_bad_cidr_and_version_mismatch(self):
        d = self._d()
        d["guarded_services"][0]["approved_sources"]["cidrs_v4"] = ["10.0.0.1/8"]
        with self.assertRaises(IntentError):
            parse_intent(d)
        d = self._d()
        d["guarded_services"][0]["approved_sources"]["cidrs_v6"] = ["10.0.0.0/8"]
        with self.assertRaises(IntentError):
            parse_intent(d)

    def test_missing_targets_or_services(self):
        d = self._d()
        d["targets"]["security_groups"] = []
        with self.assertRaises(IntentError):
            parse_intent(d)
        d = self._d()
        d["guarded_services"] = []
        with self.assertRaises(IntentError):
            parse_intent(d)


if __name__ == "__main__":
    unittest.main()
