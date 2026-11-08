"""plan 확인 (2차 검사 전, 실제 시험 환경 상태 기준 terraform plan) 단위 테스트.

plan JSON 은 샌드박스에서 OpenTofu 1.10.6 + AWS provider 5.100.0 으로 만든 실제 출력이다 (tests/fixtures/plancheck/).
상태 파일에 원본 Bastion 보안 그룹 1개를 넣고 -refresh=false 로 계산했다:
  rule_desc  규칙 설명만 바꿈            → 제자리 수정 (update)
  cidr       SSH 출처를 허용 목록으로     → 제자리 수정
  sg_desc    보안 그룹 자체 설명을 바꿈   → 교체 (delete+create, replace_paths=description)
  name       보안 그룹 이름을 바꿈        → 교체 (replace_paths=name)
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from helpers import ROOT

from iacpatch import plancheck
from iacpatch.proof import postcards
from iacpatch.tools.runner import CmdResult

FIX = ROOT / "tests" / "fixtures" / "plancheck"
SCEN = ROOT / "scenarios" / "arch" / "webapp-3tier"


def _plan(name):
    return json.loads((FIX / f"{name}.json").read_text(encoding="utf-8"))


class SummarizeRealPlanTest(unittest.TestCase):
    def test_rule_changes_are_in_place(self):
        for name in ("rule_desc", "cidr"):
            s = plancheck.summarize_plan(_plan(name))
            self.assertEqual(s["verdict"], "CLEAN", name)
            self.assertEqual(s["counts"]["update"], 1)
            self.assertEqual(s["replaced"], [])
            self.assertIn("반영 가능", s["summary"])

    def test_sg_description_forces_replacement(self):
        s = plancheck.summarize_plan(_plan("sg_desc"))
        self.assertEqual(s["verdict"], "BLOCKED")
        self.assertEqual(s["replaced"], ["aws_security_group.bastion"])
        e = s["changes"][0]
        self.assertEqual(e["kind"], "replace")
        self.assertEqual(e["replace_paths"], ["description"])
        self.assertEqual(e["values"]["description"], ["Bastion host: SSH for administrators", "Bastion host: SSH from the admin allowlist only"])
        self.assertNotIn("id", e["changed"])            # 교체로 당연히 바뀌는 값(id·arn)은 '바뀌는 속성' 에 넣지 않는다
        self.assertIn("Bastion 보안 그룹 교체 (설명(description) 변경)", s["summary"])

    def test_sg_name_forces_replacement(self):
        s = plancheck.summarize_plan(_plan("name"))
        self.assertEqual(s["verdict"], "BLOCKED")
        self.assertEqual(s["changes"][0]["replace_paths"], ["name"])

    def test_other_shapes(self):
        rc = lambda addr, typ, acts: {"address": addr, "mode": "managed", "type": typ, "change": {"actions": acts, "before": {}, "after": {}}}
        self.assertEqual(plancheck.summarize_plan({"resource_changes": [rc("aws_vpc.main", "aws_vpc", ["no-op"])]})["verdict"], "NO_CHANGES")
        self.assertEqual(plancheck.summarize_plan({"resource_changes": [rc("aws_security_group.db", "aws_security_group", ["delete"])]})["verdict"], "BLOCKED")
        self.assertEqual(plancheck.summarize_plan({"resource_changes": [rc("aws_instance.web", "aws_instance", ["update"])]})["verdict"], "CHECK")
        chk = plancheck.summarize_plan({"resource_changes": [rc("aws_security_group_rule.x", "aws_security_group_rule", ["create"])]})
        self.assertEqual(chk["verdict"], "CHECK")
        self.assertIn("생성 1개", chk["summary"])
        data = {"address": "data.aws_ami.x", "mode": "data", "type": "aws_ami", "change": {"actions": ["read"]}}
        self.assertEqual(plancheck.summarize_plan({"resource_changes": [data]})["verdict"], "NO_CHANGES")

    def test_mask_and_errors(self):
        m = plancheck.mask("arn:aws:ec2:ap-northeast-2:111122223333:sg/x 3.35.10.179 0.0.0.0/0 203.0.113.0/24 10.0.1.5 128.0.0.0/1")
        self.assertNotIn("111122223333", m)
        self.assertNotIn("3.35.10.179", m)
        for keep in ("0.0.0.0/0", "203.0.113.0/24", "10.0.1.5", "128.0.0.0/1"):
            self.assertIn(keep, m)
        self.assertIn("aws login", plancheck.plan_error_ko("Error: failed to refresh cached credentials, the SSO session has expired"))
        self.assertIn("terraform init", plancheck.plan_error_ko('Error: Inconsistent dependency lock file ... run "terraform init"'))
        self.assertIn("상태 파일 사용 중", plancheck.plan_error_ko("Error: Error acquiring the state lock"))


class _Rec:
    """기록 폴더 + 시험 환경 폴더 (임시)."""

    def __init__(self, scenario="ui/arch-3tier-sg/sg-desc-replace", level="FULL_REVIEW"):
        self.tmp = Path(tempfile.mkdtemp())
        self.tb = self.tmp / "scenarios" / "arch" / "webapp-3tier-testbed"
        self.tb.mkdir(parents=True)
        (self.tmp / "scenarios" / "arch" / "webapp-3tier").mkdir(parents=True, exist_ok=True)
        shutil.copy(SCEN / "security_groups.tf", self.tmp / "scenarios" / "arch" / "webapp-3tier" / "security_groups.tf")
        self.rd = self.tmp / "data" / "reviews" / "20261026-100000-abcdef"
        (self.rd / "candidate").mkdir(parents=True)
        cand = ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "candidates" / "sg-desc-replace.tf"
        shutil.copy(cand, self.rd / "candidate" / "security_groups.tf")
        shutil.copy(cand, self.tb / "security_groups.tf")                     # 후보를 시험 환경에 넣은 상태
        (self.rd / "state.json").write_text(json.dumps({"scenario": scenario, "state": "REVIEW_REQUIRED", "review_level": level,
                                                        "verification_status": "COMPLETE"}), encoding="utf-8")
        st = self.tb / "terraform.tfstate"                                     # 원본으로 배포돼 있던 상태 (리소스 있음)
        st.write_text(json.dumps({"version": 4, "resources": [{"type": "aws_security_group"}] * 39}), encoding="utf-8")
        t0 = time.time() - 600
        os.utime(st, (t0, t0))                                                 # 상태 파일이 후보 파일보다 오래됨 = 후보는 아직 apply 전
        (self.tb / ".terraform").mkdir()

    def state(self):
        return json.loads((self.rd / "state.json").read_text(encoding="utf-8"))

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def fake_runner(plan_name, rc=0, stderr=""):
    calls = []

    def run(argv, cwd=None, env=None, timeout=600, input_text=None):
        calls.append({"argv": list(argv), "cwd": cwd, "env": dict(env or {})})
        if argv[1] == "plan":
            out = Path([a for a in argv if a.startswith("-out=")][0][5:])
            calls[-1]["out_dir_existed"] = out.parent.is_dir()
            txt = (FIX / "sg_desc_plan.txt").read_text(encoding="utf-8") if plan_name == "sg_desc" else "No changes. Your infrastructure matches the configuration.\n"
            if rc == 0:
                out.write_bytes(b"plan")
            return CmdResult(argv, rc, txt if rc == 0 else "", stderr, cwd or "")
        if argv[1] == "show":
            return CmdResult(argv, 0, json.dumps(_plan(plan_name)), "", cwd or "")
        raise AssertionError(argv)
    run.calls = calls
    return run


class RunPlanCheckTest(unittest.TestCase):
    def setUp(self):
        self.r = _Rec()

    def tearDown(self):
        self.r.close()

    def _run(self, runner, profile="capstone-tf"):
        return plancheck.run_plan_check(SimpleNamespace(terraform_bin="terraform"), testbed=self.r.tb, record_dir=self.r.rd, profile=profile,
                                        out_dir=self.r.rd / "plancheck" / "20261026-101500", log=lambda s: None, runner=runner)

    def test_blocked_records_second_stage_failure(self):
        run = fake_runner("sg_desc")
        doc = self._run(run)
        self.assertEqual(doc["verdict"], "BLOCKED")
        plan_call = run.calls[0]
        self.assertIn("-lock=false", plan_call["argv"])                       # 상태 파일을 잠그지 않는다
        self.assertEqual(plan_call["env"].get("AWS_PROFILE"), "capstone-tf")
        self.assertEqual(Path(plan_call["cwd"]), self.r.tb)
        out = Path([a for a in plan_call["argv"] if a.startswith("-out=")][0][5:])
        self.assertFalse(str(out).startswith(str(self.r.tb)))                  # plan 파일은 시험 환경 폴더 밖
        self.assertFalse(out.parent.exists())                                  # 임시 폴더는 지웠다
        self.assertNotIn("apply", " ".join(" ".join(c["argv"]) for c in run.calls))
        st = self.r.state()
        self.assertEqual(st["post_deploy"]["status"], "PLAN_BLOCKED")
        self.assertEqual(st["post_deploy"]["layers"], {"V7": "NOT_RUN", "V8": "NOT_RUN"})
        self.assertEqual(st["plan_check"]["verdict"], "BLOCKED")
        self.assertEqual(st["plan_check"]["replaced"], ["aws_security_group.bastion"])
        pdir = self.r.rd / "plancheck" / "20261026-101500"
        for n in ("plan_summary.json", "plan.txt", "plan_changes.json", "commands.json"):
            self.assertTrue((pdir / n).exists(), n)
        self.assertNotIn("111122223333", (pdir / "plan.txt").read_text(encoding="utf-8"))          # 계정 번호 가림
        self.assertNotIn("111122223333", (pdir / "plan_changes.json").read_text(encoding="utf-8"))
        man = json.loads((self.r.rd / "evidence" / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn("plancheck/20261026-101500/plan_summary.json", [f["path"] for f in man["files"]])
        self.assertTrue(plancheck.blocked_for(st, st["plan_check"]["candidate_sha256"]))

    def test_clean_does_not_touch_post_deploy(self):
        doc = self._run(fake_runner("rule_desc"))
        self.assertEqual(doc["verdict"], "CLEAN")
        st = self.r.state()
        self.assertNotIn("post_deploy", st)
        self.assertEqual(st["plan_check"]["verdict"], "CLEAN")

    def test_login_error_is_not_a_verdict_and_keeps_block(self):
        self._run(fake_runner("sg_desc"))
        doc = self._run(fake_runner("sg_desc", rc=1, stderr="Error: failed to refresh cached credentials, token has expired"))
        self.assertEqual(doc["verdict"], "ERROR")
        self.assertIn("aws login", doc["summary"])
        st = self.r.state()
        self.assertEqual(st["plan_check"]["verdict"], "ERROR")                # 가장 최근 시도는 오류로 남지만
        self.assertTrue(plancheck.blocked_for(st, st["plan_check"]["candidate_sha256"]))   # 막힘은 풀리지 않는다
        self.assertEqual(st["post_deploy"]["status"], "PLAN_BLOCKED")


class PlanCheckApiTest(unittest.TestCase):
    def setUp(self):
        from iacpatch.web import proof_api as pa
        self.pa = pa
        self.r = _Rec()
        self._root, self._reviews = pa._root, pa._reviews
        pa._root = lambda: self.r.tmp
        pa._reviews = lambda: self.r.tmp / "data" / "reviews"
        self.rid = self.r.rd.name

    def tearDown(self):
        self.pa._root, self.pa._reviews = self._root, self._reviews
        self.r.close()

    def _err(self, body):
        with self.assertRaises(ValueError) as e:
            self.pa.job_plan_check(body)
        return str(e.exception)

    def test_gates(self):
        self.assertTrue(callable(self.pa.job_plan_check({"record_id": self.rid, "profile": "capstone-tf"})))
        self.assertIn("프로필", self._err({"record_id": self.rid, "profile": "a b"}))
        (self.r.tb / ".terraform").rmdir()
        self.assertIn("terraform init", self._err({"record_id": self.rid}))
        (self.r.tb / ".terraform").mkdir()
        (self.r.tb / plancheck.OFFLINE_OVERRIDE).write_text("#", encoding="utf-8")
        self.assertIn("가짜 자격 증명", self._err({"record_id": self.rid}))
        (self.r.tb / plancheck.OFFLINE_OVERRIDE).unlink()
        st = self.r.tb / "terraform.tfstate"
        keep = st.read_text(encoding="utf-8")
        st.write_text(json.dumps({"version": 4, "resources": []}), encoding="utf-8")
        self.assertIn("시험 환경 미배포", self._err({"record_id": self.rid}))
        st.write_text(keep, encoding="utf-8")
        shutil.copy(SCEN / "security_groups.tf", self.r.tb / "security_groups.tf")
        self.assertIn("이 기록의 후보와 다름", self._err({"record_id": self.rid}))

    def test_blocked_or_other_case_records_refused(self):
        s = self.r.state()
        (self.r.rd / "state.json").write_text(json.dumps({**s, "review_level": "BLOCKED"}), encoding="utf-8")
        self.assertIn("배포 전 검사 통과 기록만", self._err({"record_id": self.rid}))
        (self.r.rd / "state.json").write_text(json.dumps({**s, "scenario": "ui/arch-webapp-sg/rule-based"}), encoding="utf-8")
        self.assertIn("3계층", self._err({"record_id": self.rid}))
        self.assertIn("기록", self._err({"record_id": ""}))

    def test_measure_refused_after_block_and_setup_says_so(self):
        plancheck.run_plan_check(SimpleNamespace(terraform_bin="terraform"), testbed=self.r.tb, record_dir=self.r.rd, profile="capstone-tf",
                                 out_dir=self.r.rd / "plancheck" / "20261026-101500", log=lambda s: None, runner=fake_runner("sg_desc"))
        m = self.pa.measure_setup(self.rid)
        self.assertTrue(m["plan_blocked"])
        self.assertTrue(m["tf_inited"])
        self.assertEqual(m["plan_check"]["verdict"], "BLOCKED")
        self.assertTrue(m["plan_check"]["current"])
        st = self.r.tb / "terraform.tfstate"
        now = time.time() - 300
        os.utime(self.r.tb / "security_groups.tf", (now - 10, now - 10))
        os.utime(st, (now, now))                                              # (사람이 막힌 후보를 apply 했다고 해도)
        with self.assertRaises(ValueError) as e:
            self.pa.job_measure({"record_id": self.rid, "profile": "capstone-tf", "region": "ap-northeast-2"})
        self.assertIn("plan 확인에서 교체", str(e.exception))


class PlanCardsTest(unittest.TestCase):
    def setUp(self):
        self.r = _Rec()

    def tearDown(self):
        self.r.close()

    def _check(self, name):
        plancheck.run_plan_check(SimpleNamespace(terraform_bin="terraform"), testbed=self.r.tb, record_dir=self.r.rd, profile="capstone-tf",
                                 out_dir=self.r.rd / "plancheck" / "20261026-101500", log=lambda s: None, runner=fake_runner(name))

    def test_blocked_cards(self):
        self._check("sg_desc")
        post = postcards.build_post_cards(self.r.rd, ROOT)
        c0, c7, c8 = post["cards"]
        self.assertEqual((c0["layer"], c0["verdict"], c0["verdict_ko"], c0["status"]), ("임시", "FAIL", "차단 (apply 미실행)", "done"))
        self.assertIn("Bastion 보안 그룹 교체 (설명(description) 변경)", c0["summary"])
        self.assertEqual([c7["skipped"], c8["skipped"]], ["plan", "plan"])
        self.assertIn("plan 확인에서 교체", c7["reason"])
        self.assertEqual(post["after"]["status"], "PLAN_BLOCKED")
        keys = [b["title"] for b in c0["evidence"] if b.get("key")]
        self.assertIn("plan 변경 대상 리소스", keys)
        why = next(b for b in c0["evidence"] if b["title"].startswith("교체 원인 값"))
        self.assertEqual(why["rows"], [["Bastion 보안 그룹 · 설명(description)", "'Bastion host: SSH for administrators' → 'Bastion host: SSH from the admin allowlist only'"]])
        code = next(b for b in c0["evidence"] if b["t"] == "code")
        self.assertTrue(any("forces replacement" in ln["text"] and ln["mark"] for ln in code["lines"]))
        self.assertTrue(any(s.get("doc", "").startswith("Terraform AWS provider") for s in c0["basis"]["standard"]))
        self.assertTrue(all(lf["path"].startswith("plancheck/") for lf in c0["leaves"]))
        from iacpatch.proof import report
        glance = report._glance({}, {}, [], post["cards"], True)              # 증거 보고서 맨 위 표
        self.assertIn("차단 (apply 미실행)", glance)
        self.assertIn("plan 확인에서 교체", glance)                             # V7·V8 은 '미검증' 이 아니라 막힌 이유
        self.assertNotIn("이 후보는 시험 환경 반영·측정 전", glance)

    def test_clean_before_measure(self):
        self._check("rule_desc")
        post = postcards.build_post_cards(self.r.rd, ROOT)
        c0 = post["cards"][0]
        self.assertEqual(c0.get("scope"), "plan")
        self.assertEqual(c0["verdict_ko"], "plan 확인 통과 · 측정 전")
        self.assertIn("반영 가능", c0["summary"])
        self.assertEqual(post["plan"]["verdict"], "CLEAN")

    def test_approval_refused(self):
        from iacpatch.web.decision import can_approve
        self._check("sg_desc")
        ok, why = can_approve(self.r.state())
        self.assertFalse(ok)
        self.assertIn("교체·삭제", why)


if __name__ == "__main__":
    unittest.main()
