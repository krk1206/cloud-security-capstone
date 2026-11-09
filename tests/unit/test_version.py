"""프로그램 · 소스 · 정책 판 묶음 (version.py, D-37): git 없이 커밋을 읽고, 소스 지문은 내용이 바뀌면 바뀌고 줄바꿈 차이에는 안 바뀐다.
검사 기록 · AI 실행 기록 · /api/app 에 같은 묶음이 들어간다."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch import version as V


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="iacpatch-ver-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "src" / "iacpatch").mkdir(parents=True)
        (self.tmp / "policy").mkdir()
        (self.tmp / "src" / "iacpatch" / "a.py").write_text("x = 1\n", encoding="utf-8")
        (self.tmp / "policy" / "patch_policy.json").write_text(json.dumps({"policy_version": "p-1"}), encoding="utf-8")
        (self.tmp / "policy" / "risk_rubric.json").write_text(json.dumps({"rubric_version": "r-1"}), encoding="utf-8")

    def test_fingerprint_changes_with_content_not_with_line_endings(self):
        fp1 = V.source_fingerprint(self.tmp)
        self.assertEqual(len(fp1), 12)
        (self.tmp / "src" / "iacpatch" / "a.py").write_bytes(b"x = 1\r\n")          # CRLF — 같은 내용
        self.assertEqual(V.source_fingerprint(self.tmp), fp1)
        (self.tmp / "src" / "iacpatch" / "a.py").write_text("x = 2\n", encoding="utf-8")
        self.assertNotEqual(V.source_fingerprint(self.tmp), fp1)
        (self.tmp / "src" / "iacpatch" / "a.py").write_text("x = 1\n", encoding="utf-8")
        (self.tmp / "policy" / "patch_policy.json").write_text(json.dumps({"policy_version": "p-2"}), encoding="utf-8")   # 정책도 지문에 든다
        self.assertNotEqual(V.source_fingerprint(self.tmp), fp1)
        (self.tmp / "src" / "iacpatch" / "build_info.json").write_text("{}", encoding="utf-8")                           # 빌드 정보는 지문에 안 든다
        (self.tmp / "policy" / "patch_policy.json").write_text(json.dumps({"policy_version": "p-1"}), encoding="utf-8")
        self.assertEqual(V.source_fingerprint(self.tmp), fp1)

    def test_git_head_without_git_binary(self):
        g = self.tmp / ".git"
        (g / "refs" / "heads").mkdir(parents=True)
        (g / "HEAD").write_text("ref: refs/heads/work\n", encoding="utf-8")
        (g / "refs" / "heads" / "work").write_text("a" * 40 + "\n", encoding="utf-8")
        self.assertEqual(V.git_head(self.tmp), {"sha": "a" * 40, "branch": "work"})
        (g / "refs" / "heads" / "work").unlink()                                   # packed-refs 에만 있는 경우
        (g / "packed-refs").write_text("# pack-refs\n" + "b" * 40 + " refs/heads/work\n", encoding="utf-8")
        self.assertEqual(V.git_head(self.tmp)["sha"], "b" * 40)
        (g / "HEAD").write_text("c" * 40 + "\n", encoding="utf-8")                   # detached
        self.assertEqual(V.git_head(self.tmp), {"sha": "c" * 40, "branch": None})
        self.assertEqual(V.git_head(self.tmp / "nowhere"), {"sha": None, "branch": None})

    def test_provenance_bundle_and_short_line(self):
        p = V.provenance(self.tmp)
        self.assertEqual(p["program_version"], V.PROGRAM_VERSION)
        self.assertEqual((p["policy_version"], p["rubric_version"]), ("p-1", "r-1"))
        self.assertEqual(p["src_fingerprint"], V.source_fingerprint(self.tmp))
        self.assertFalse(p["stale_exe"])
        self.assertEqual(p["git_head"], {"sha": None, "branch": None})            # 그 폴더엔 .git 이 없다 (build 의 커밋은 '돌고 있는 프로그램' 것)
        line = V.short(p)
        self.assertIn(f"v{V.PROGRAM_VERSION}", line)
        self.assertIn("소스 지문", line)
        self.assertIn("커밋", line)
        self.assertIn("커밋 없음", V.short({"program_version": "0", "build": {}, "git_head": {}}))

    def test_repo_provenance_has_policy_and_prompt_versions(self):
        p = V.provenance(ROOT)
        self.assertTrue(p["policy_version"])
        self.assertTrue(p["rubric_version"])
        self.assertEqual(p["prompt_version"], "llmfix-v1")
        self.assertEqual(len(p["src_fingerprint"]), 12)
        from iacpatch import __version__
        self.assertEqual(__version__, V.PROGRAM_VERSION)


if __name__ == "__main__":
    unittest.main()
