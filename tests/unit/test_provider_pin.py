"""AWS provider 버전 고정 (D-13) — 팀 PC 실측(2026-09-29): 고정하지 않으면 원본 plan(5.100.0) 과 후보 plan(6.66.0) 의 provider 가 달라져
V5 가 6.x 의 `region` 속성을 '허용 목록 밖 변경' 으로 잡았다. terraform 없이 파일 내용만 검사한다."""
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch.config import Settings, load_settings
from iacpatch.review.local_verify import _baseline_key
from iacpatch.tools.terraform import DEFAULT_AWS_PROVIDER_VERSION, OFFLINE_OVERRIDE_FILENAME, TerraformAdapter


class ProviderPinTests(unittest.TestCase):
    def test_override_pins_the_provider_version_and_is_an_override_file(self):
        tf = TerraformAdapter("terraform-not-needed", provider_version="5.100.0")
        text = tf.offline_override_text()
        self.assertIn('source  = "hashicorp/aws"', text)
        self.assertIn('version = "5.100.0"', text)
        self.assertIn('provider "aws"', text)
        self.assertTrue(OFFLINE_OVERRIDE_FILENAME.endswith("_override.tf"))      # Terraform 이 덮어쓰기 파일로 인식하는 이름
        with tempfile.TemporaryDirectory() as td:
            p = tf.add_offline_override(td)
            self.assertEqual(p.read_text(encoding="utf-8"), text)

    def test_no_pin_when_disabled(self):
        text = TerraformAdapter("terraform-not-needed", provider_version=None).offline_override_text()
        self.assertNotIn("required_providers", text)

    def test_default_pin_matches_settings_and_team_lock_file(self):
        s = Settings(repo_root=str(ROOT))
        self.assertEqual(s.aws_provider_version, DEFAULT_AWS_PROVIDER_VERSION)
        self.assertEqual(load_settings(str(ROOT)).aws_provider_version, DEFAULT_AWS_PROVIDER_VERSION)
        lock = (ROOT / "infrastructure" / "sg-baseline" / ".terraform.lock.hcl").read_text(encoding="utf-8")
        self.assertIn(f'version     = "{DEFAULT_AWS_PROVIDER_VERSION}"', lock)   # 팀 PC 배포 경로의 lock 과 같은 버전

    def test_locked_provider_version_is_read_from_lock_file(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(TerraformAdapter.locked_provider_version(td))
            (Path(td) / ".terraform.lock.hcl").write_text(
                '# This file is maintained automatically by "terraform init".\n\nprovider "registry.terraform.io/hashicorp/aws" {\n'
                '  version = "6.66.0"\n  hashes = [\n    "h1:xxx",\n  ]\n}\n', encoding="utf-8")
            self.assertEqual(TerraformAdapter.locked_provider_version(td), "6.66.0")

    def test_baseline_cache_key_changes_with_provider_version(self):
        tf_dir = ROOT / "scenarios" / "eval" / "a-probe" / "00-baseline"
        k1 = _baseline_key(tf_dir, None, {"terraform": ("terraform", "1.16.1"), "aws_provider": "5.100.0"}, "ap-northeast-2")
        k2 = _baseline_key(tf_dir, None, {"terraform": ("terraform", "1.16.1"), "aws_provider": "6.66.0"}, "ap-northeast-2")
        self.assertNotEqual(k1, k2)


if __name__ == "__main__":
    unittest.main()
