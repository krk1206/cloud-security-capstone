"""오라클 실험 스크립트(scripts/oracle_experiment.py) — 실제 커밋 plan 으로 E2 표를 만든다."""
import sys
import unittest
from pathlib import Path

from helpers import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import oracle_experiment as ox  # noqa: E402


class OracleExperimentTests(unittest.TestCase):
    def test_scanner_column_uses_normalized_loader(self):
        # 00-baseline 은 Trivy 가 잡고(FAIL), 01-cidr-split / 06-prefix-list 는 통과(PASS=우회)
        self.assertEqual(ox.scanner_0107("00-baseline"), "FAIL")
        self.assertEqual(ox.scanner_0107("01-cidr-split"), "PASS")
        self.assertEqual(ox.scanner_0107("06-prefix-list"), "PASS")

    def test_oracle_matches_expected_on_all_committed_plans(self):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ox.main()
        self.assertEqual(rc, 0)
        out = (ROOT / "experiments" / "ORACLE_RESULTS.md").read_text(encoding="utf-8")
        # 스캐너 통과 ∧ 오라클 실패가 최소 2건(01,06 은 확실) — 프로젝트 핵심 주장
        import re
        m = re.search(r"오라클이 잡은\(FAIL\) 케이스: (\d+)건", out)
        self.assertIsNotNone(m)
        self.assertGreaterEqual(int(m.group(1)), 2)
        self.assertNotIn("**X**", out)   # 전부 기대대로 판정 (불일치 없음)


if __name__ == "__main__":
    unittest.main()
