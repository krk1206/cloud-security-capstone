"""내 Terraform 폴더 연결 (web/projects.py, 2026-11-01 갈아엎기 4차, D-32) — 연결 전 확인 · 연결 · 고칠 대상 · 지원 범위 밖 · 승인 · PR 대상.

도구(tofu · trivy)는 돌리지 않는다: 점검 결과(trivy.json · plan_baseline.json)는 손으로 만든 작은 파일로 대신한다.
기록 위치는 IACPATCH_PROJECTS_DIR 로 임시 폴더에 둔다 (data/ 에 쓰지 않음).
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT  # noqa: F401  (sys.path 설정)

from iacpatch.config import Settings
from iacpatch.report import unified_diff
from iacpatch.tools.github import public_name, repo_target
from iacpatch.web import cases, projects
from iacpatch.web.decision import can_approve
from iacpatch.web.explain import conclusion
from iacpatch.web.problems import unchecked

SG = '''resource "aws_security_group" "ops" {
  name = "ops"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
TRIVY = {"Results": [{"Target": "main.tf", "Misconfigurations": [
    {"ID": "AWS-0107", "AVDID": "AVD-AWS-0107", "Title": "Security groups should not allow unrestricted ingress to SSH or RDP from any IP address.",
     "Severity": "HIGH", "Status": "FAIL", "Message": "open", "CauseMetadata": {"Resource": "aws_security_group.ops", "StartLine": 7, "EndLine": 7}},
    {"ID": "AWS-0345", "AVDID": "AVD-AWS-0345", "Title": "Disallow unrestricted S3 IAM Policies", "Severity": "HIGH", "Status": "FAIL", "Message": "s3:*",
     "CauseMetadata": {"Resource": "aws_iam_policy.reports", "StartLine": 20, "EndLine": 20}},
]}]}


def ok_state(set_id, post=None):
    st = {"state": "REVIEW_REQUIRED", "review_level": "FULL_REVIEW", "verification_status": "COMPLETE", "scenario": f"ui/{set_id}/upload-1"}
    if post:
        st["post_deploy"] = post
    return st


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="iacpatch-projects-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ["IACPATCH_PROJECTS_DIR"] = str(self.tmp / "records")
        self.addCleanup(os.environ.pop, "IACPATCH_PROJECTS_DIR", None)
        self.folder = self.tmp / "orders-infra"
        self.folder.mkdir()
        (self.folder / "main.tf").write_text(SG, encoding="utf-8")

    def fake_scan(self, pid, plan=True):
        sc = projects.project_dir(pid) / "scan"
        (sc / "trivy.json").write_text(json.dumps(TRIVY), encoding="utf-8")
        if plan:
            (sc / "plan_baseline.json").write_text(json.dumps({"format_version": "1.2", "resource_changes": []}), encoding="utf-8")

    # ---------------------------------------------------------------- 연결 전 확인
    def test_inspect_rejects_relative_missing_and_empty(self):
        self.assertIn("전체 경로", projects.inspect_folder("infra/prod")["errors"][0])
        self.assertIn("폴더가 없음", projects.inspect_folder(str(self.tmp / "nope"))["errors"][0])
        empty = self.tmp / "empty"
        empty.mkdir()
        self.assertIn(".tf 파일이 없음", projects.inspect_folder(str(empty))["errors"][0])
        self.assertFalse(projects.inspect_folder("")["ok"])

    def test_inspect_refuses_program_folder(self):
        r = projects.inspect_folder(str(cases._root()))
        self.assertFalse(r["ok"])
        self.assertIn("프로그램 폴더", r["errors"][0])

    def test_inspect_notes_without_reading_state(self):
        (self.folder / "terraform.tfstate").write_text('{"secret": "x"}', encoding="utf-8")
        (self.folder / "modules" / "m").mkdir(parents=True)
        (self.folder / "modules" / "m" / "x.tf").write_text("# m\n", encoding="utf-8")
        r = projects.inspect_folder(f'  "{self.folder}"  ')         # 탐색기에서 복사한 따옴표 · 공백
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["tf_files"], ["main.tf"])
        notes = " ".join(r["notes"])
        self.assertIn("하위 폴더의 .tf 1개", notes)
        self.assertIn("tfstate 파일이 있음 — 프로그램은 읽지 않습니다", notes)

    # ---------------------------------------------------------------- 연결 · 끊기
    def test_create_is_deduplicated_and_id_follows_folder(self):
        r = projects.create("주문 서비스", str(self.folder))
        self.assertTrue(r["ok"], r)
        pid = r["project"]
        self.assertRegex(pid, r"^orders-infra-[0-9a-f]{6}$")
        again = projects.create("Other name", str(self.folder))
        self.assertTrue(again["existing"])
        self.assertEqual(again["project"], pid)                 # 이름을 바꿔도 같은 폴더면 같은 프로젝트
        c = cases.get_case(pid)
        self.assertEqual((c["kind"], c["name"], c["tf_dir"]), ("user", "주문 서비스", self.folder.resolve().as_posix()))
        self.assertEqual([s["set_id"] for s in c["sets"]], [f"{pid}.main"])
        man = json.loads(cases._manifest_path(f"{pid}.main").read_text(encoding="utf-8"))
        self.assertEqual((man["project"], man["candidates"]), (pid, []))
        self.assertEqual(cases.project_of_set(f"{pid}.main"), pid)
        self.assertEqual(cases.case_of_set(f"{pid}.main")["id"], pid)

    def test_remove_keeps_the_folder(self):
        pid = projects.create("", str(self.folder))["project"]
        self.assertTrue(projects.remove(pid)["ok"])
        self.assertIsNone(cases.get_case(pid))
        self.assertTrue((self.folder / "main.tf").exists())
        self.assertFalse(projects.remove(pid)["ok"])
        with self.assertRaises(ValueError):
            projects.remove("../x")

    # ---------------------------------------------------------------- ④ → ⑤ 고칠 대상
    def test_target_needs_scan_and_plan(self):
        pid = projects.create("", str(self.folder))["project"]
        self.assertIn("점검 결과 없음", projects.ensure_target(pid, "AVD-AWS-0107", "aws_security_group.ops")["error"])
        self.fake_scan(pid, plan=False)
        self.assertIn("원본 plan 이 없어", projects.ensure_target(pid, "AVD-AWS-0107", "aws_security_group.ops")["error"])
        self.fake_scan(pid)
        t1 = projects.ensure_target(pid, "AVD-AWS-0107", "aws_security_group.ops")
        self.assertTrue(t1["ok"], t1)
        self.assertRegex(t1["set_id"], rf"^{pid}\.t[0-9a-f]{{8}}$")
        self.assertEqual(projects.ensure_target(pid, "AVD-AWS-0107", "aws_security_group.ops")["set_id"], t1["set_id"])   # 다시 만들지 않음
        man = json.loads(cases._manifest_path(t1["set_id"]).read_text(encoding="utf-8"))
        self.assertEqual((man["rule"], man["resource"], man["file"], man["line"]), ("AVD-AWS-0107", "aws_security_group.ops", "main.tf", 7))
        self.assertIsNone(projects.set_problem(man))
        self.assertFalse(projects.ensure_target(pid, "AVD-AWS-0107", "aws_security_group.db")["ok"])   # 점검 결과에 없는 문제
        # IAM 은 고칠 대상으로 받지 않는다 (필요한 권한 = 요구사항을 정하는 기능이 없어 고친 뒤 판정 불가) — 탐지만
        iam = projects.ensure_target(pid, "AVD-AWS-0345", "aws_iam_policy.reports")
        self.assertFalse(iam["ok"])
        self.assertIn("보안 그룹 문제만", iam["error"])

    def test_set_problem_for_project_sets_only(self):
        self.assertIsNone(projects.set_problem({"set_id": "arch-3tier-sg"}))
        self.assertIn("Trivy", projects.set_problem({"project": "p-1", "trivy_json": str(self.tmp / "none.json")}))

    # ---------------------------------------------------------------- 지원 범위 밖: AWS 를 조회하는 data 소스
    def test_offline_blockers(self):
        (self.folder / "data.tf").write_text('''
# data "aws_vpc" "in_comment" {}
data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
data "aws_region" "current" {}
locals { s = "data \\"aws_ami\\" \\"x\\" {" }
data "aws_vpc" "default" {
  default = true
}
''', encoding="utf-8")
        self.assertEqual(projects.offline_blockers(self.folder), ["data.aws_vpc.default (data.tf)"])

    def test_why_texts(self):
        why = projects._why({"unsupported": ["data.aws_vpc.default (main.tf)"], "plan": {"status": "NOT_RUN"}, "scan": {"status": "PASS"}})
        self.assertEqual(len(why), 1)
        self.assertIn("data.aws_vpc.default", why[0])
        self.assertIn("지원 범위 밖", why[0])
        g = projects._why({"guard": {"ok": False, "violations": ["module 블록"]}})
        self.assertIn("실행 전 안전 점검에서 멈춤", g[0])
        p = projects._why({"plan": {"status": "FAIL", "steps": {"plan": {"ok": False, "error": "Error: No valid credential sources found"}}}})
        self.assertIn("data 소스", p[0])
        self.assertEqual(projects._why({"plan": {"status": "PASS"}, "scan": {"status": "PASS"}}), [])

    # ---------------------------------------------------------------- ⑧ 승인 (시험 환경 없는 프로젝트)
    def test_no_testbed_project_needs_ack(self):
        ok, why = can_approve(ok_state("orders-infra-abc123.t0000aaaa"))
        self.assertFalse(ok)
        self.assertIn("실제 AWS 미검증", why)
        ok, why = can_approve(ok_state("orders-infra-abc123.t0000aaaa"), ack_unverified=True)
        self.assertTrue(ok)
        self.assertIn("확인 표시", why)

    def test_testbed_set_still_needs_real_aws_even_with_ack(self):
        self.assertFalse(can_approve(ok_state("arch-3tier-sg"), ack_unverified=True)[0])
        self.assertTrue(can_approve(ok_state("arch-3tier-sg", {"status": "VERIFIED"}))[0])
        # 실제 AWS 에서 문제가 나온 기록은 확인 표시로도 승인 못 함
        self.assertFalse(can_approve(ok_state("orders-infra-abc123.t0000aaaa", {"status": "DEPLOY_FAILED"}), ack_unverified=True)[0])

    def test_unknown_set_stays_strict(self):
        st = ok_state("x")
        st.pop("scenario")                                       # 어느 묶음인지 모르는 기록 → 실제 AWS 통과 필요 (확인 표시로 대신 못 함)
        self.assertFalse(can_approve(st, ack_unverified=True)[0])

    def test_blocked_record_cannot_be_approved_with_ack(self):
        st = ok_state("orders-infra-abc123.t0000aaaa")
        st["state"] = "VALIDATION_FAILED"
        self.assertFalse(can_approve(st, ack_unverified=True)[0])

    def test_conclusion_and_unchecked_for_no_testbed(self):
        st = ok_state("x")
        ver = {"report": {"validity": "PASS", "layers": []}}
        c = conclusion(st, ver, {"decision": {"risk_level": "MEDIUM"}}, {"ok": True}, [], testbed=False)
        self.assertEqual(c["status"], "승인 판단 가능 · 실제 AWS 미검증")
        self.assertNotIn("시험 환경 반영", " ".join(c["next"]))
        self.assertEqual(conclusion(st, ver, {"decision": {}}, {"ok": True}, [], testbed=True)["status"], "다음: AWS 시험 환경 검사")
        self.assertTrue(any("시험 환경이 없어 확인하지 않음" in x for x in unchecked("topology", None, testbed=False)))
        self.assertTrue(any("V7 · V8) 전" in x for x in unchecked("topology", None)))

    # ---------------------------------------------------------------- PR 대상 · 이름
    def test_pr_names_and_diff_paths(self):
        self.assertEqual(public_name("ui/orders-infra-abc123.t0000aaaa/upload-1"), "orders-infra-abc123")
        self.assertEqual(public_name("ui/arch-3tier-sg/correct-design"), "arch-3tier-sg")
        d = unified_diff({"main.tf": "a\n"}, {"main.tf": "b\n"}, self.folder.as_posix())
        self.assertIn("--- a/main.tf", d)                       # 이 PC 의 절대 경로를 PR 에 쓰지 않는다
        self.assertNotIn(self.tmp.as_posix(), d)
        self.assertIn("--- a/scenarios/x/main.tf", unified_diff({"main.tf": "a\n"}, {"main.tf": "b\n"}, "scenarios/x"))

    @unittest.skipIf(shutil.which("git") is None, "git 없음")
    def test_repo_target_for_absolute_project_folder(self):
        repo = self.tmp / "repo"
        sub = repo / "infra" / "prod"
        sub.mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        top, rel, why = repo_target(Settings(repo_root=str(cases._root())), sub.as_posix())
        self.assertEqual((Path(top).resolve(), rel), (repo.resolve(), "infra/prod"))
        top2, rel2, why2 = repo_target(Settings(repo_root=str(cases._root())), self.folder.as_posix())   # git 저장소 아님
        self.assertIsNone(top2)
        self.assertTrue(why2)


if __name__ == "__main__":
    unittest.main()
