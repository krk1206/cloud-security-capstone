"""4주차 데모 계산(iacpatch.rubric_demo) — 도구·네트워크 없이. 팀 완료 기준: '목업 데이터로 High/Medium/Low 가 올바르게 분류되고, 상한 강제가 동작한다'."""
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch import rubric_demo as rd
from iacpatch.models import AUTONOMY_ORDER, AutonomyLevel


class RubricViewTests(unittest.TestCase):
    def test_view_matches_policy_file(self):
        v = rd.rubric_view()
        self.assertTrue(v["version"].startswith("risk-v2"))
        self.assertEqual(v["thresholds"], {"low_max": 2, "medium_max": 5})
        keys = {p["key"] for p in v["points"]}
        self.assertIn("attachment_points_2_or_more", keys)
        self.assertTrue(all(p["label"] != p["key"] for p in v["points"]), "점수 항목마다 한국어 설명이 있어야 한다")
        self.assertEqual(v["autonomy_cap"], {"LOW": "HIGH", "MEDIUM": "MEDIUM", "HIGH": "LOW"})


class CalculatorTests(unittest.TestCase):
    def test_mock_inputs_reach_all_three_levels(self):
        self.assertEqual(rd.calc_risk({"target_kind": "SG"})["level"], "LOW")
        mid = rd.calc_risk({"target_kind": "SG", "attachment_points": 2, "external_sg": True})
        self.assertEqual(mid["level"], "MEDIUM"); self.assertEqual(mid["score"], 4)
        self.assertEqual(rd.calc_risk({"target_kind": "SG", "deleted": True})["level"], "HIGH")          # hard
        self.assertEqual(rd.calc_risk({"target_kind": "IAM"})["level"], "MEDIUM")                        # floor
        self.assertEqual(rd.calc_risk({"target_kind": "IAM", "trust_policy": True})["level"], "HIGH")   # hard
        high = rd.calc_risk({"target_kind": "SG", "resources_touched": 5, "new_resources": 3, "attachment_points": 2, "external_sg": True})
        self.assertEqual(high["level"], "HIGH"); self.assertGreater(high["score"], 5)


class CapEnforcementTests(unittest.TestCase):
    def test_exhaustive_72_combinations_have_no_violation(self):
        c = rd.cap_enforcement_check()
        self.assertEqual(c["total"], 72)
        self.assertEqual(c["violations"], [])

    def test_llm_proposal_above_cap_is_forced_down_and_recorded(self):
        g = rd.gate_demo("MEDIUM", "HIGH")
        self.assertEqual(g["final"], "MEDIUM"); self.assertEqual(g["action"], "CREATE_PR_APPROVAL")
        self.assertTrue(any("ignored" in r for r in g["reasons"]))
        self.assertTrue(g["forced_down"])
        g2 = rd.gate_demo("LOW", "LOW")     # 낮추는 제안은 반영
        self.assertEqual(g2["final"], "LOW"); self.assertEqual(g2["action"], "REPORT_ONLY")
        g3 = rd.gate_demo("LOW", "HIGH", validity="FAIL")
        self.assertEqual(g3["action"], "BLOCK"); self.assertIsNone(g3["final"])


class LabeledMatrixTests(unittest.TestCase):
    def test_25_labels_replayed_without_tools_agree_with_code(self):
        with tempfile.TemporaryDirectory() as td:
            m = rd.labeled_matrix(ROOT, Path(td))
        self.assertEqual(m["total"], 25)
        self.assertEqual(m["judged"], 25, [r for r in m["rows"] if not r.get("actual")])
        self.assertEqual(m["agree"], 25, [r for r in m["rows"] if not r.get("agree")])
        self.assertEqual(m["distribution"], {"LOW": 12, "MEDIUM": 12, "HIGH": 1})
        # V6 는 plan 쌍으로 계산된다 (기만 후보는 FAIL, 정상은 PASS) — 도구 없이도 오라클이 돈다는 증거
        by = {r["scenario"]: r for r in m["rows"]}
        self.assertEqual(by["eval-seeded-sg/deceptive-cidr-split"]["v6"], "FAIL")
        self.assertEqual(by["eval-seeded-sg/correct-approved"]["v6"], "PASS")
        self.assertEqual(by["eval-seeded-iam/unapproved-trust-policy-open"]["actual"], "HIGH")
        # 사람 검산 수는 정직하게 (manifest 에 verified_by 가 없으면 0)
        self.assertIn("human_verified", m)
        for r in m["rows"]:
            self.assertTrue(all(f["label"] for f in r["factors"]))


if __name__ == "__main__":
    unittest.main()
