"""새 빌드 받기(iacpatch.update) — 네트워크 없이 가짜 fetch 와 가짜 zip 으로. 실행(새 exe 띄우기)은 하지 않는다 (launch=False)."""
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from helpers import ROOT

from iacpatch import update as up


def _portable_zip(sha: str, backslash: bool = False) -> bytes:
    buf = io.BytesIO()
    sep = "\\" if backslash else "/"
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"policy{sep}patch_policy.json", json.dumps({"schema": "test", "sha": sha}))
        z.writestr(f"scripts{sep}pyver.py", "import sys\n")
        z.writestr("README.md", "# portable\n")
        z.writestr("IaCPatch.exe", b"MZ-not-really")
    return buf.getvalue()


def _fake_fetch(latest_sha: str, zip_bytes: bytes, sha256: str = None):
    latest = {"sha": latest_sha, "built_at": "2026-09-29T12:00:00Z", "zip": "IaCPatch-portable.zip",
              "sha256": sha256 if sha256 is not None else hashlib.sha256(zip_bytes).hexdigest()}
    calls = []

    def fetch(url: str) -> bytes:
        calls.append(url)
        if url.endswith("latest.json"):
            return json.dumps(latest).encode("utf-8")
        if url.endswith("IaCPatch-portable.zip"):
            return zip_bytes
        raise AssertionError(url)
    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self._orig = up.build_info
        up.build_info = lambda: {"sha": "0000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "built_at": None, "source": "test"}

    def tearDown(self):
        up.build_info = self._orig

    def test_check_reports_newer_and_network_errors_without_raising(self):
        z = _portable_zip("1111111bbbb")
        r = up.check("https://example.invalid/rel", _fake_fetch("1111111bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", z))
        self.assertTrue(r["newer"]); self.assertIsNone(r["error"])
        same = up.check("https://example.invalid/rel", _fake_fetch("0000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", z))
        self.assertFalse(same["newer"])

        def broken(url):
            raise OSError("no network")
        r2 = up.check("https://example.invalid/rel", broken)
        self.assertIsNotNone(r2["error"]); self.assertFalse(r2["newer"])

    def test_install_unpacks_next_to_root_copies_tools_and_data_and_skips_provider_template(self):
        z = _portable_zip("2222222")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "IaCPatch-old"
            (root / "tools").mkdir(parents=True); (root / "tools" / "trivy.exe").write_bytes(b"x")
            (root / "data" / "reviews" / "r1").mkdir(parents=True); (root / "data" / "reviews" / "r1" / "state.json").write_text("{}")
            (root / "data" / "cache" / "tf-template" / ".terraform").mkdir(parents=True); (root / "data" / "cache" / "tf-template" / "big.bin").write_bytes(b"0" * 10)
            (root / "data" / "cache" / "baseline" / "k1").mkdir(parents=True); (root / "data" / "cache" / "baseline" / "k1" / "plan_baseline.json").write_text("{}")
            logs = []
            res = up.install(root, "https://example.invalid/rel", log=logs.append, fetch=_fake_fetch("2222222cccccccccccccccccccccccccccccccccc", z), launch=False)
            dest = Path(res["dest"])
            self.assertEqual(dest.parent, root.parent)
            self.assertTrue(dest.name.startswith("IaCPatch-2222222"))
            self.assertTrue((dest / "policy" / "patch_policy.json").exists())
            self.assertTrue((dest / "IaCPatch.exe").exists())
            self.assertTrue((dest / "tools" / "trivy.exe").exists())
            self.assertTrue((dest / "data" / "reviews" / "r1" / "state.json").exists())
            self.assertTrue((dest / "data" / "cache" / "baseline" / "k1" / "plan_baseline.json").exists())
            self.assertFalse((dest / "data" / "cache" / "tf-template").exists())     # provider 템플릿은 크므로 안 가져감
            self.assertFalse((dest / "_portable.zip").exists())
            self.assertFalse(res["launched"])
            self.assertTrue((root / "policy").exists() is False)                      # 원래 폴더는 안 건드림 (policy 가 없던 그대로)
            # 같은 sha 를 또 받으면 -2 폴더
            res2 = up.install(root, "https://example.invalid/rel", log=logs.append, fetch=_fake_fetch("2222222cccccccccccccccccccccccccccccccccc", z), launch=False)
            self.assertTrue(Path(res2["dest"]).name.endswith("-2"))

    def test_install_refuses_zip_with_wrong_sha256(self):
        z = _portable_zip("3333333")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "old"; root.mkdir()
            with self.assertRaises(RuntimeError):
                up.install(root, "https://example.invalid/rel", log=lambda s: None,
                           fetch=_fake_fetch("3333333ddddddddddddddddddddddddddddddddd", z, sha256="0" * 64), launch=False)
            self.assertEqual([p.name for p in root.parent.iterdir() if p.name.startswith("IaCPatch-")], [])   # 대조 실패면 폴더도 안 만든다

    def test_install_handles_backslash_entries_and_nested_top_folder(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "old"; root.mkdir()
            z = _portable_zip("4444444", backslash=True)
            res = up.install(root, "https://example.invalid/rel", log=lambda s: None, fetch=_fake_fetch("4444444eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", z), launch=False)
            self.assertTrue((Path(res["dest"]) / "policy" / "patch_policy.json").exists())
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zz:
                zz.writestr("cloud-security-capstone/policy/patch_policy.json", "{}"); zz.writestr("cloud-security-capstone/IaCPatch.exe", b"MZ")
            res2 = up.install(root, "https://example.invalid/rel", log=lambda s: None, fetch=_fake_fetch("5555555fffffffffffffffffffffffffffffffff", buf.getvalue()), launch=False)
            self.assertTrue((Path(res2["dest"]) / "policy" / "patch_policy.json").exists())

    def test_up_to_date_does_nothing(self):
        z = _portable_zip("0000000")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "old"; root.mkdir()
            res = up.install(root, "https://example.invalid/rel", log=lambda s: None, fetch=_fake_fetch("0000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", z), launch=False)
            self.assertTrue(res["up_to_date"]); self.assertIsNone(res["dest"])
            self.assertEqual([p for p in root.parent.iterdir() if p.name.startswith("IaCPatch-")], [])

    def test_build_info_from_git_or_file(self):
        info = self._orig()
        self.assertIn("sha", info)
        self.assertIn(info["source"], ("git", "build_info.json", "unknown"))
        if (ROOT / ".git").exists():
            self.assertEqual(len(info["sha"] or ""), 40)


if __name__ == "__main__":
    unittest.main()
