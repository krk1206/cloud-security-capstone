"""textio.write_text_lf — 후보 .tf 줄바꿈 CRLF 버그(10-04 실측, PR #5 준비 중 파일 전체 diff) 회귀 테스트.

Linux 에서는 open("w") 가 줄바꿈을 바꾸지 않아 버그가 재현되지 않으므로, 입력에 CRLF 를 섞어 넣고
바이트 단위로 LF 만 남는지 본다 (OS 와 무관하게 같은 바이트가 나와야 한다).
"""
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch.config import load_settings
from iacpatch.review.flow import ReviewOptions, run_review
from iacpatch.textio import normalize_lf, write_text_lf


class TextIoTests(unittest.TestCase):
    def test_write_text_lf_bytes_are_lf_only_and_utf8_without_bom(self):
        tmp = Path(tempfile.mkdtemp())
        p = write_text_lf(tmp / "sub" / "a.tf", 'resource "x" "y" {\r\n  a = "한글"\r\n}\r\n')
        raw = p.read_bytes()
        self.assertNotIn(b"\r", raw)
        self.assertEqual(raw, 'resource "x" "y" {\n  a = "한글"\n}\n'.encode("utf-8"))
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))      # BOM 없음 (Terraform 은 BOM 을 못 읽는다)

    def test_normalize_lf_handles_crlf_and_cr(self):
        self.assertEqual(normalize_lf("a\r\nb\rc\n"), "a\nb\nc\n")
        self.assertEqual(normalize_lf("no newline"), "no newline")

    def test_review_candidate_and_diff_files_have_no_cr(self):
        """검토 기록의 candidate/*.tf·original/*.tf·candidate.diff 는 어느 OS 에서나 LF 바이트여야 한다."""
        out = Path(tempfile.mkdtemp(prefix="iacpatch-textio-"))
        res = run_review(load_settings(str(ROOT)), ReviewOptions(tf_dir="infrastructure/sg-baseline", trivy_json="infrastructure/sg-baseline/baseline-scan.json",
                                                                 candidate="mock:sg_baseline_ok", scenario="t", rule="AVD-AWS-0107", out_dir=str(out)))
        for rel in ("candidate/main.tf", "original/main.tf", "candidate.diff", "pr_body.md"):
            raw = (res.run_dir / rel).read_bytes()
            self.assertNotIn(b"\r", raw, rel)
            self.assertTrue(raw.endswith(b"\n") or rel == "pr_body.md", rel)


if __name__ == "__main__":
    unittest.main()
