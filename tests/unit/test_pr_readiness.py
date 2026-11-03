"""PR 준비 확인(tools/github.pr_readiness, D-31) — 임시 git 저장소에서 읽기만 하는 확인이 맞게 막는지.

PR 은 '원본에서 바뀐 부분' 만 올려야 한다: 프로젝트 폴더가 커밋돼 있고, 기준 브랜치(origin/<base>)의 원본 = 검사한 원본일 때만 통과.
fetch · commit · push 는 하지 않는다 (원격은 로컬 참조 refs/remotes/origin/main 로 흉내).
"""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT  # noqa: F401  (sys.path 설정)

from iacpatch.config import Settings
from iacpatch.tools.github import pr_readiness, public_name

TF = "scenarios/demo"
ORIG = 'resource "aws_security_group" "web" {\n  name = "web"\n}\n'
FIXED = 'resource "aws_security_group" "web" {\n  name = "web"\n  description = "fixed"\n}\n'


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


@unittest.skipIf(shutil.which("git") is None, "git 없음")
class PrReadinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="iacpatch-prready-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "repo"
        (self.repo / TF).mkdir(parents=True)
        (self.repo / TF / "main.tf").write_text(ORIG, encoding="utf-8")
        git(self.repo, "init", "-q", "-b", "work")
        git(self.repo, "-c", "user.email=t@example.com", "-c", "user.name=t", "add", ".")
        git(self.repo, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "orig")
        git(self.repo, "remote", "add", "origin", "https://github.com/example/demo.git")
        git(self.repo, "update-ref", "refs/remotes/origin/main", "HEAD")      # 원격 main = 원본이 있는 커밋
        self.rec = self.tmp / "rec-1"
        for sub, text in (("candidate", FIXED), ("original", ORIG)):
            (self.rec / sub).mkdir(parents=True)
            (self.rec / sub / "main.tf").write_text(text, encoding="utf-8")
        (self.rec / "input").mkdir()
        (self.rec / "input" / "selected_finding.json").write_text(json.dumps({"rule_id": "AVD-AWS-0107", "resource": "aws_security_group.web"}), encoding="utf-8")
        (self.rec / "state.json").write_text(json.dumps({"review_level": "FULL_REVIEW", "state": "REVIEW_REQUIRED", "tf_dir": TF,
                                                         "scenario": "ui/demo-set/correct-design"}), encoding="utf-8")
        self.settings = Settings(repo_root=str(self.repo))

    def check(self, base="main"):
        r = pr_readiness(self.settings, str(self.rec), base_branch=base)
        return r, {c["name"]: c for c in r["checks"]}

    def test_ready_when_base_has_same_original(self):
        r, c = self.check()
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["slug"], "example/demo")
        self.assertEqual(r["branch"], "iacpatch/demo-set-rec-1")             # 후보 id(correct-design) 를 브랜치에 쓰지 않음
        self.assertEqual(public_name("ui/demo-set/correct-design"), "demo-set")
        self.assertEqual(git(self.repo, "rev-parse", "--abbrev-ref", "HEAD").strip(), "work")   # 읽기만 — 브랜치 그대로

    def test_untracked_project_folder_blocks(self):
        (self.repo / TF / "extra.tf").write_text("# new\n", encoding="utf-8")
        r, c = self.check()
        self.assertFalse(r["ok"])
        self.assertFalse(c["프로젝트 폴더가 커밋된 상태"]["ok"])
        self.assertIn("원본 코드를 먼저 커밋", c["프로젝트 폴더가 커밋된 상태"]["todo"])

    def test_base_without_project_folder_blocks(self):
        git(self.repo, "checkout", "-q", "--orphan", "other")             # 프로젝트 폴더가 없는 브랜치
        git(self.repo, "rm", "-rq", "--cached", ".")
        git(self.repo, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "empty")
        git(self.repo, "update-ref", "refs/remotes/origin/bare", "HEAD")
        git(self.repo, "checkout", "-q", "-f", "work")
        r, c = self.check("bare")
        self.assertFalse(r["ok"])
        name = "기준 브랜치 origin/bare 의 원본 = 검사한 원본"
        self.assertIn("프로젝트 폴더", c[name]["detail"])

    def test_base_with_different_original_blocks(self):
        (self.rec / "original" / "main.tf").write_text(ORIG + "# 검사 때 원본은 달랐음\n", encoding="utf-8")
        r, c = self.check()
        self.assertFalse(r["ok"])
        self.assertIn("검사한 원본과 다름", c["기준 브랜치 origin/main 의 원본 = 검사한 원본"]["detail"])

    def test_unknown_base_branch(self):
        r, c = self.check("no-such")
        self.assertFalse(r["ok"])
        self.assertIn("모름", c["기준 브랜치 origin/no-such 의 원본 = 검사한 원본"]["detail"])

    def test_not_reviewable_record_refused(self):
        st = json.loads((self.rec / "state.json").read_text(encoding="utf-8"))
        st["review_level"] = "BLOCKED"
        (self.rec / "state.json").write_text(json.dumps(st), encoding="utf-8")
        r, _ = self.check()
        self.assertFalse(r["ok"])
        self.assertEqual(r["checks"][0]["name"], "검사 결과")


if __name__ == "__main__":
    unittest.main()
