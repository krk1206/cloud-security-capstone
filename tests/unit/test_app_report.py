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
        self.assertTrue(any("fuzz_scanner" in " ".join(c) for _, c in s if c))
        self.assertTrue(any("oracle_fuzz" in " ".join(c) for _, c in s if c))
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


class FingerprintTests(unittest.TestCase):
    def test_code_digest_ignores_runner_and_report_modules(self):
        from iacpatch import fingerprint
        d1 = fingerprint.code_digest(ROOT)
        # 실행기/리포트 모듈은 판정과 무관 → 지문에 포함되지 않는다 (같은 트리를 두 번 읽어도 같은 값)
        self.assertEqual(d1, fingerprint.code_digest(ROOT))
        self.assertEqual(len(d1), 64)
        self.assertIn("app.py", fingerprint._NON_JUDGING)
        self.assertIn("report_html.py", fingerprint._NON_JUDGING)

    def test_tree_digest_changes_with_content_and_ignores_terraform_dir(self):
        from iacpatch import fingerprint
        with tempfile.TemporaryDirectory() as td:
            d = Path(td); (d / "main.tf").write_text("a", encoding="utf-8")
            h1 = fingerprint.tree_digest(d)
            (d / ".terraform").mkdir(); (d / ".terraform" / "x").write_text("junk", encoding="utf-8")
            (d / "plan.json").write_text("{}", encoding="utf-8")
            self.assertEqual(h1, fingerprint.tree_digest(d))           # .terraform/, plan.json 무시
            (d / "main.tf").write_text("b", encoding="utf-8")
            self.assertNotEqual(h1, fingerprint.tree_digest(d))        # 내용이 바뀌면 다른 지문

    def test_provider_template_restore_uses_links_and_keeps_lock(self):
        from iacpatch.tools.terraform import TerraformAdapter
        with tempfile.TemporaryDirectory() as td:
            t = Path(td) / "tpl"; (t / ".terraform" / "providers" / "r" / "h" / "aws" / "1.0" / "os_arch").mkdir(parents=True)
            (t / ".terraform" / "providers" / "r" / "h" / "aws" / "1.0" / "os_arch" / "terraform-provider-aws").write_bytes(b"bin")
            (t / ".terraform.lock.hcl").write_text("lock", encoding="utf-8")
            tf = TerraformAdapter("terraform-not-needed", template_dir=t)
            wd = Path(td) / "wd"; wd.mkdir()
            self.assertTrue(tf.restore_provider_template(wd))
            prov = wd / ".terraform" / "providers" / "r" / "h" / "aws" / "1.0" / "os_arch" / "terraform-provider-aws"
            self.assertEqual(prov.read_bytes(), b"bin")
            self.assertEqual((wd / ".terraform.lock.hcl").read_text(encoding="utf-8"), "lock")
            self.assertEqual(tf.last_template_action, "restored")
            # 템플릿이 없으면 False (init 이 평소대로)
            tf2 = TerraformAdapter("terraform-not-needed", template_dir=Path(td) / "none")
            self.assertFalse(tf2.restore_provider_template(wd))
            # 같은 lock 이면 다시 저장하지 않는다
            self.assertFalse(tf.save_provider_template(wd))
            (wd / ".terraform.lock.hcl").write_text("lock2", encoding="utf-8")
            self.assertTrue(tf.save_provider_template(wd))
            self.assertEqual((t / ".terraform.lock.hcl").read_text(encoding="utf-8"), "lock2")


class SelfcheckTests(unittest.TestCase):
    def test_selfcheck_passes_on_this_tree_and_launcher_checks_python_version(self):
        from iacpatch import app
        self.assertEqual(app.selfcheck(), [])
        raw = (ROOT / "IaCPatch.bat").read_bytes().decode("ascii")
        self.assertIn("pyver.py", raw)                       # 3.10+ 파이썬을 골라 쓴다 (py -3 가 3.7 을 가리킨 사례)
        self.assertIn("py -3.14", raw)
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "pyver.py")])
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
