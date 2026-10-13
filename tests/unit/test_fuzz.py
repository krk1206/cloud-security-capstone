"""스캐너 사각 탐색기(변형 생성) + 오라클 차등 검증 — 도구 없이 도는 부분만."""
import random
import sys
import unittest

from helpers import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
from iacpatch.fuzz import iam_variants, sg_variants  # noqa: E402
from iacpatch.fuzz.runner import EXPECT, FuzzResult, classify  # noqa: E402
import oracle_fuzz  # noqa: E402


class VariantTests(unittest.TestCase):
    def test_sg_variants_are_well_formed_and_deterministic(self):
        vs = sg_variants.variants()
        self.assertGreaterEqual(len(vs), 40)
        names = [v.name for v in vs]
        self.assertEqual(len(names), len(set(names)))                       # 이름 유일
        self.assertEqual(names, [v.name for v in sg_variants.variants()])    # 결정론
        for v in vs:
            self.assertIn(v.truth, EXPECT["sg"], v.name)
            self.assertIn('provider "aws"', v.hcl, v.name)
            self.assertIn('resource "aws_security_group" "t"', v.hcl, v.name)
        fams = {v.family for v in vs}
        for f in ("cidr-split", "separate-rule", "indirection", "iteration", "reference", "port", "ipv6", "aggregation", "control"):
            self.assertIn(f, fams)
        self.assertGreaterEqual(sum(1 for v in vs if v.truth == "approved"), 5)   # 오탐 검사용 정상 수정도 충분히

    def test_split_cidr_union_is_whole(self):
        for k in (2, 4, 8, 64):
            parts = sg_variants.split_cidr("0.0.0.0/0", k)
            self.assertEqual(len(parts), k)
            from iacpatch.verify.netset import NetSet
            self.assertTrue(NetSet.from_cidrs(4, parts).covers_everything())

    def test_iam_variants_are_well_formed(self):
        vs = iam_variants.variants()
        self.assertGreaterEqual(len(vs), 30)
        names = [v.name for v in vs]
        self.assertEqual(len(names), len(set(names)))
        for v in vs:
            self.assertIn(v.truth, EXPECT["iam"], v.name)
            self.assertIn('resource "aws_iam_role" "worker"', v.hcl, v.name)
            self.assertIn('"aws_iam_policy" "worker"', v.hcl, v.name)
        self.assertGreaterEqual(sum(1 for v in vs if v.truth == "unknown"), 4)

    def test_classify(self):
        r = FuzzResult("sg", "x", "f", "open", "", trivy_flagged=False, plan_ok=True, oracle="FAIL", expected="FAIL")
        self.assertEqual(classify(r), "스캐너 사각 · 오라클 탐지")
        r.oracle = "PASS"
        self.assertIn("오라클 사각", classify(r))
        r2 = FuzzResult("sg", "y", "f", "approved", "", trivy_flagged=True, plan_ok=True, oracle="PASS", expected="PASS")
        self.assertEqual(classify(r2), "스캐너 오탐")
        r3 = FuzzResult("iam", "z", "f", "unknown", "", trivy_flagged=False, plan_ok=True, oracle="PASS", expected="UNKNOWN")
        self.assertIn("버그 후보", classify(r3))
        r4 = FuzzResult("sg", "w", "f", "open", "", plan_ok=False, expected="FAIL")
        self.assertEqual(classify(r4), "plan 실패 (V4 에서 걸림)")


class OracleFuzzTests(unittest.TestCase):
    def test_reference_interval_ops(self):
        self.assertEqual(oracle_fuzz.merge([(5, 9), (0, 4), (20, 30)]), [(0, 9), (20, 30)])
        self.assertEqual(oracle_fuzz.subtract([(0, 10)], [(3, 4)]), [(0, 2), (5, 10)])
        self.assertEqual(oracle_fuzz.count([(0, 10), (5, 12)]), 13)

    def test_netset_matches_reference_on_random_inputs(self):
        st = oracle_fuzz.fuzz_netset(random.Random(1), 1500)
        self.assertEqual(st["mismatch"], [])
        self.assertGreater(st["covers_all"], 0)

    def test_pattern_subset_matches_enumeration(self):
        st = oracle_fuzz.fuzz_patterns(random.Random(1), 300)
        self.assertEqual(st["mismatch"], [])


if __name__ == "__main__":
    unittest.main()
