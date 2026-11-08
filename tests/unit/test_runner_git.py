"""PATH 에 git 이 없는 Windows PC 에서 GitHub Desktop 내장 git · Git for Windows 기본 위치를 찾는다 (9차, 2026-11-02).

팀 PC 실측: GitHub Desktop 만 설치돼 있어 ⑧ PR 준비 확인이 'git 없음' 으로 막혔다. 프로그램은 PATH → GitHub Desktop(app-* 최신 판) →
Git for Windows 기본 위치 순으로 찾고, 찾은 경로로 실행하되 기록(CmdResult.argv)에는 부른 이름('git')을 남긴다.

지켜야 하는 것
  - Windows 가 아니면 찾아보는 자리가 없다 (PATH 만)
  - Windows 에서 PATH 에 없으면 GitHub Desktop 의 최신 app-* 폴더의 git.exe 를 고른다
  - git 이 아닌 도구(terraform 등)는 이 대체를 쓰지 않는다
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import ROOT  # noqa: F401  (sys.path 준비)

from iacpatch.tools import runner


class GitFallbackTests(unittest.TestCase):
    def test_non_windows_has_no_fallbacks(self):
        with mock.patch.object(os, "name", "posix"):
            self.assertEqual(runner._git_fallbacks(), [])

    def test_windows_github_desktop_latest_app(self):
        with tempfile.TemporaryDirectory() as td:
            la = Path(td) / "Local"
            for ver in ("app-3.4.9", "app-3.5.1"):
                d = la / "GitHubDesktop" / ver / "resources" / "app" / "git" / "cmd"
                d.mkdir(parents=True)
                (d / "git.exe").write_text("", encoding="utf-8")
            env = {"LOCALAPPDATA": str(la), "ProgramFiles": str(Path(td) / "PF")}
            with mock.patch.object(os, "name", "nt"), mock.patch.dict(os.environ, env, clear=False), \
                    mock.patch.object(runner.shutil, "which", lambda b: None):
                cands = runner._git_fallbacks()
                self.assertTrue(cands[0].endswith(os.path.join("app-3.5.1", "resources", "app", "git", "cmd", "git.exe")), cands)
                self.assertTrue(any("Programs" in c for c in cands))
                self.assertTrue(any(os.path.join("PF", "Git", "cmd", "git.exe") in c for c in cands))
                hit = runner.which("git")
                self.assertEqual(hit, cands[0])
                self.assertIsNone(runner.which("terraform"))         # git 만 대체한다
                self.assertEqual(runner._call_argv(["git", "status"], hit), [hit, "status"])
                self.assertEqual(runner._call_argv(["terraform", "plan"], None), ["terraform", "plan"])

    def test_path_git_wins(self):
        with mock.patch.object(runner.shutil, "which", lambda b: "C:\\\\Git\\\\cmd\\\\git.exe" if b == "git" else None):
            self.assertEqual(runner.which("git"), "C:\\\\Git\\\\cmd\\\\git.exe")
            self.assertEqual(runner._call_argv(["git", "status"], "C:\\\\Git\\\\cmd\\\\git.exe"), ["C:\\\\Git\\\\cmd\\\\git.exe", "status"])


if __name__ == "__main__":
    unittest.main()
