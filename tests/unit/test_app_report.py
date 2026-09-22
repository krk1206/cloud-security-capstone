"""한 번 클릭 실행기(iacpatch.app) + HTML 리포트(iacpatch.report_html) — 모델 호출·AWS·네트워크 없음."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch import app, report_html


class ReportHtmlTests(unittest.TestCase):
    def test_build_with_no_reviews_still_writes_a_page(self):
        with tempfile.TemporaryDirectory() as td:
            out = report_html.build(Path(td) / "r" / "index.html", reviews_root=Path(td) / "empty-reviews")
            self.assertTrue(out.exists())
            html = out.read_text(encoding="utf-8")
            self.assertIn("<html", html)
            self.assertIn("실행 기록 없음", html)                # 세트 기록이 없으면 없다고 적는다 (숫자를 만들지 않음)
            self.assertNotIn("<script src=", html)             # 외부 스크립트 없음 (파일 하나로 열림)
            self.assertNotIn('rel="stylesheet" href="http', html)

    def test_md_tables_to_html_keeps_numbers(self):
        md = "# 제목\n\n| a | b |\n|---|---|\n| 12 | PASS |\n\n- 항목 3/4\n"
        out = report_html.md_tables_to_html(md)
        self.assertIn("<table", out)
        self.assertIn("12", out)
        self.assertIn("PASS", out)
        self.assertIn("3/4", out)

    def test_badges_never_carry_meaning_by_color_alone(self):
        for v in ("PASS", "FAIL", "UNKNOWN", "ERROR", "NOT_RUN"):
            b = report_html.badge(v)
            self.assertIn(v, b)                                # 색 + 글자 (아이콘/글자 없이 색만으로 뜻을 주지 않는다)


class AppTests(unittest.TestCase):
    def test_root_is_repo(self):
        self.assertEqual(app.ROOT, ROOT)
        self.assertTrue((app.ROOT / "policy" / "patch_policy.json").exists())

    def test_steps_follow_run_experiments_order_and_never_call_llm_or_aws(self):
        s = app.steps(include_cc=False)
        titles = [t for t, _ in s]
        self.assertTrue(titles[0].startswith("0/8"))
        self.assertTrue(titles[-1].startswith("8/8"))
        self.assertIn("eval-a-probe-rule", titles[2]); self.assertIn("eval-seeded-sg", titles[3])
        self.assertIn("eval-iam-rule", titles[4]); self.assertIn("eval-seeded-iam", titles[5])
        self.assertIsNone(s[6][1])                             # 후보 0건이면 건너뜀 (실행하지 않음)
        cmds = [" ".join(c) for _, c in s if c]
        for banned in ("aws ", "apply", "claude", "curl", "git push", "openai", "anthropic"):
            self.assertFalse(any(banned in c for c in cmds), banned)
        self.assertEqual(len(app.steps(include_cc=True)), len(s))

    def test_exec_runs_repo_script_in_process(self):
        # exe 모드에서 쓰는 자기 재실행 경로. 여기서는 python 으로 같은 진입점을 호출한다.
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONIOENCODING="utf-8")
        r = subprocess.run([sys.executable, "-m", "iacpatch.app", "--exec", "scripts/cc_prompt.py", "--help"],
                           cwd=str(ROOT), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("usage", r.stdout)
        r2 = subprocess.run([sys.executable, "-m", "iacpatch.app", "--exec", "scripts/does-not-exist.py"],
                            cwd=str(ROOT), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        self.assertEqual(r2.returncode, 2)

    def test_launcher_bat_is_ascii_crlf_and_sets_pythonpath(self):
        raw = (ROOT / "IaCPatch.bat").read_bytes()
        raw.decode("ascii")                                     # 한글 없음 (cmd 코드페이지 문제 회피)
        self.assertIn(b"\r\n", raw)
        self.assertIn(b"PYTHONPATH=%~dp0src", raw)
        self.assertIn(b"-m iacpatch.app", raw)


if __name__ == "__main__":
    unittest.main()
