"""혼자 실험 키트 — 프롬프트 생성·응답 등록·요약 스크립트 (모델 호출 없음)."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import cc_add  # noqa: E402
import cc_prompt  # noqa: E402


class SoloKitTests(unittest.TestCase):
    def test_prompt_has_finding_and_approved_source_only(self):
        prompt, status = cc_prompt.build("00-baseline")
        self.assertEqual(status, "ok")
        self.assertIn("AVD-AWS-0107", prompt)
        self.assertIn("aws_security_group.baseline", prompt)
        self.assertIn("10.0.0.0/8", prompt)                 # 팀 결정값 (D-2)
        self.assertIn('cidr_blocks = ["0.0.0.0/0"]', prompt)  # 원본 파일 전체 포함
        for leak in ("V6", "Intent Oracle", "오라클", "기만", "deceptive"):
            self.assertNotIn(leak, prompt)                  # 검증 방식은 알려주지 않는다 (E1 공정성)

    def test_prompt_not_triggered_for_scanner_blind_cases(self):
        for case in ("01-cidr-split", "06-prefix-list"):
            prompt, status = cc_prompt.build(case)
            self.assertEqual(status, "not_triggered", case)
            self.assertEqual(prompt, "")

    def test_extract_tf_from_markdown_response(self):
        md = "설명\n\n```hcl\nresource \"a\" \"b\" {}\n```\n\n짧은 블록:\n```\nx\n```\n"
        self.assertEqual(cc_add.extract_tf(md), 'resource "a" "b" {}\n')
        self.assertEqual(cc_add.extract_tf("plain tf text"), "plain tf text")

    def test_cc_add_registers_and_refuses_duplicate(self):
        set_dir = ROOT / "experiments/candidate-sets/eval-claude-code"
        man = set_dir / "manifest.json"
        backup = man.read_text(encoding="utf-8")
        tmp = Path(tempfile.mkdtemp())
        resp = tmp / "resp.md"
        resp.write_text("```hcl\n" + (ROOT / "scenarios/eval/a-probe/00-baseline/main.tf").read_text(encoding="utf-8").replace("0.0.0.0/0", "10.0.0.0/8") + "```\n", encoding="utf-8")
        cid = "cc-00-baseline-r999"
        try:
            r = subprocess.run([sys.executable, str(ROOT / "scripts/cc_add.py"), "00-baseline", str(resp), "--rep", "999", "--expected", "correct",
                                "--note", "unit test", "--yes"], cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue((set_dir / "candidates" / f"{cid}.tf").exists())
            m = json.loads(man.read_text(encoding="utf-8"))
            self.assertEqual(m["candidates"][-1]["id"], cid)
            self.assertEqual(m["candidates"][-1]["source"], "claude-code")
            r2 = subprocess.run([sys.executable, str(ROOT / "scripts/cc_add.py"), "00-baseline", str(resp), "--rep", "999", "--expected", "correct", "--yes"],
                                cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertNotEqual(r2.returncode, 0)        # 같은 이름은 덮어쓰지 않는다
        finally:
            man.write_text(backup, encoding="utf-8")
            (set_dir / "candidates" / f"{cid}.tf").unlink(missing_ok=True)
            (set_dir / "responses" / f"{cid}.md").unlink(missing_ok=True)
            shutil.rmtree(tmp, ignore_errors=True)

    def test_summarize_runs_without_records(self):
        out = Path(tempfile.mkdtemp())
        r = subprocess.run([sys.executable, str(ROOT / "scripts/summarize_experiments.py"), "--out", str(out), "--write", str(out / "summary.md")],
                           cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(r.returncode, 0, r.stderr)
        text = (out / "summary.md").read_text(encoding="utf-8")
        self.assertIn("실행 기록이 없다", text)
        self.assertIn("| claude-code | 0 | 0 | 0 |", text)
        shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
