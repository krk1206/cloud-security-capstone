"""시험 환경 apply · destroy 버튼 (testbed_ops.py, D-19) 단위 테스트.

지켜야 하는 것
  - plan 을 먼저 만들고, 실행은 그 plan 파일로만 한다 (terraform apply <plan 파일>)
  - 확인 값(apply/destroy)이 맞아야, plan 뒤에 시험 환경 파일·상태 파일이 그대로여야, 1시간 안이어야 실행한다
  - apply 는 교체·삭제 없는 plan 만, 후보는 plan 확인 CLEAN 만, destroy 는 삭제만 있는 plan 만
  - 한 번 쓴 plan 은 다시 못 쓴다, 모든 plan·실행은 data/testbed_ops.jsonl 에 남는다
  - destroy 가 끝나면 시험 환경 파일을 원본으로 되돌린다 / 후보 apply 는 그 기록에 'apply 방법' 을 남긴다
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from helpers import ROOT

from iacpatch import plancheck, testbed_ops
from iacpatch.config import Settings
from iacpatch.tools.runner import CmdResult, run_stream

SCEN = ROOT / "scenarios" / "arch" / "webapp-3tier"
CAND = ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "candidates"
FIX = ROOT / "tests" / "fixtures" / "plancheck"
TF = Settings(repo_root=str(ROOT), terraform_bin="terraform")


def _rc(addr, typ, acts):
    return {"address": addr, "mode": "managed", "type": typ, "change": {"actions": acts, "before": {}, "after": {}}}


CREATE_PLAN = {"format_version": "1.2", "resource_changes": [_rc("aws_vpc.main", "aws_vpc", ["create"]), _rc("aws_instance.web", "aws_instance", ["create"]),
                                                             _rc("aws_security_group.bastion", "aws_security_group", ["create"])]}
DESTROY_PLAN = {"format_version": "1.2", "resource_changes": [_rc("aws_vpc.main", "aws_vpc", ["delete"]), _rc("aws_instance.web", "aws_instance", ["delete"])]}


class Env:
    """저장소 루트 흉내 (임시 폴더): 원본 파일 · 시험 환경 폴더 · 상태 파일."""

    def __init__(self, deployed=False, testbed_file=None):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "scenarios" / "arch" / "webapp-3tier").mkdir(parents=True)
        shutil.copy(SCEN / "security_groups.tf", self.root / "scenarios" / "arch" / "webapp-3tier" / "security_groups.tf")
        self.tb = self.root / testbed_ops.TESTBED_REL
        self.tb.mkdir(parents=True)
        (self.tb / ".terraform").mkdir()
        shutil.copy(testbed_file or (SCEN / "security_groups.tf"), self.tb / "security_groups.tf")
        self.set_state(39 if deployed else 0, serial=5)

    def set_state(self, n, serial):
        (self.tb / "terraform.tfstate").write_text(json.dumps({"version": 4, "serial": serial, "resources": [{"type": "x"}] * n}), encoding="utf-8")

    def ops(self):
        p = self.root / "data" / "testbed_ops.jsonl"
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


def fake_plan_runner(plan_json):
    calls = []

    def run(argv, cwd=None, env=None, timeout=600, input_text=None):
        calls.append({"argv": list(argv), "cwd": cwd, "env": dict(env or {})})
        if argv[1] == "plan":
            Path([a for a in argv if a.startswith("-out=")][0][5:]).write_bytes(b"PLAN")
            return CmdResult(argv, 0, "Plan: ...\n", "", cwd or "")
        if argv[1] == "show":
            return CmdResult(argv, 0, json.dumps(plan_json), "", cwd or "")
        raise AssertionError(argv)
    run.calls = calls
    return run


def fake_apply(env: "Env", resources_after: int, ok=True):
    calls = []

    def run(argv, cwd=None, env_=None, timeout=1800, on_line=None, **kw):
        calls.append({"argv": list(argv), "cwd": cwd, "plan_exists": Path(argv[-1]).exists(), "plan_bytes": Path(argv[-1]).read_bytes()})
        for line in ("aws_vpc.main: Creating...", "Apply complete! Resources: 3 added, 0 changed, 0 destroyed."):
            on_line and on_line(line)
        if ok:
            st = json.loads((env.tb / "terraform.tfstate").read_text(encoding="utf-8"))
            env.set_state(resources_after, serial=int(st.get("serial") or 0) + 1)
        return CmdResult(argv, 0 if ok else 1, "Apply complete!\narn:aws:ec2:ap-northeast-2:111122223333:x\n", "", cwd or "")
    run.calls = calls

    def wrapper(argv, cwd=None, env=None, timeout=1800, on_line=None):
        return run(argv, cwd=cwd, env_=env, timeout=timeout, on_line=on_line)
    wrapper.calls = calls
    return wrapper


class RunStreamTest(unittest.TestCase):
    def test_lines_arrive_and_timeout_kills(self):
        got = []
        r = run_stream([sys.executable, "-c", "import sys,time\nfor i in range(3):\n    print('줄', i, flush=True)\nsys.exit(3)"], on_line=got.append, timeout=60)
        self.assertEqual(got, ["줄 0", "줄 1", "줄 2"])
        self.assertEqual(r.returncode, 3)
        self.assertFalse(r.ok)
        t0 = time.time()
        r2 = run_stream([sys.executable, "-c", "import time; print('시작', flush=True); time.sleep(30)"], timeout=2)
        self.assertTrue(r2.timed_out)
        self.assertLess(time.time() - t0, 20)
        self.assertIn("시작", r2.stdout)


class PrepareExecuteTest(unittest.TestCase):
    def tearDown(self):
        self.env.close()

    def test_original_apply_plan_then_execute_exact_plan(self):
        self.env = Env(deployed=False)
        meta = testbed_ops.prepare(TF, root=self.env.root, kind="apply_original", profile="capstone-tf", log=lambda s: None,
                                   runner=fake_plan_runner(CREATE_PLAN))
        self.assertTrue(meta["eligible"])
        self.assertEqual(meta["counts"]["create"], 3)
        self.assertIn("생성 3개", meta["summary"])
        pid = meta["plan_id"]
        slot = testbed_ops.slot_dir(pid)
        self.assertTrue((slot / "plan.bin").exists())
        self.assertFalse(str(slot).startswith(str(self.env.root)))           # plan 파일은 저장소 밖
        with self.assertRaises(ValueError):                                   # 확인 값이 다르면 실행 안 함
            testbed_ops.execute(TF, root=self.env.root, plan_id=pid, confirm="destroy", profile="x", log=lambda s: None, runner_stream=fake_apply(self.env, 3))
        ap = fake_apply(self.env, 3)
        lines = []
        entry = testbed_ops.execute(TF, root=self.env.root, plan_id=pid, confirm="apply", profile="capstone-tf", log=lines.append, runner_stream=ap)
        self.assertTrue(entry["ok"])
        self.assertEqual(ap.calls[0]["argv"][1], "apply")
        self.assertTrue(ap.calls[0]["plan_exists"])
        self.assertEqual(ap.calls[0]["plan_bytes"], b"PLAN")                  # 사람이 본 그 plan 파일
        self.assertEqual(entry["state_resources_after"], 3)
        self.assertTrue(any("Apply complete" in x for x in lines))            # 진행 줄이 화면 로그로
        self.assertFalse(slot.exists())                                       # 한 번 쓰면 지운다
        with self.assertRaises(ValueError):
            testbed_ops.execute(TF, root=self.env.root, plan_id=pid, confirm="apply", profile="x", log=lambda s: None, runner_stream=ap)
        out = (self.env.root / entry["dir"] / "apply.txt").read_text(encoding="utf-8")
        self.assertNotIn("111122223333", out)                                  # 계정 번호 가림
        ops = [e["op"] for e in self.env.ops()]
        self.assertEqual(ops, ["plan", "apply"])

    def test_cancelled_plan_is_replaced_by_new_plan_of_same_kind(self):
        """확인 창을 취소한 plan 은 같은 종류의 새 plan 을 만들 때 지운다 (임시 폴더에 1시간 남지 않게). 다른 종류 plan 은 그대로.
        plan 단계 문구는 '예정' — 10-27 실제 사례: destroy plan 의 '리소스 39개 삭제' 를 삭제 완료로 읽음."""
        self.env = Env(deployed=True)
        a = testbed_ops.prepare(TF, root=self.env.root, kind="apply_original", profile="p", log=lambda s: None, runner=fake_plan_runner(CREATE_PLAN))
        lines = []
        d1 = testbed_ops.prepare(TF, root=self.env.root, kind="destroy", profile="p", log=lines.append, runner=fake_plan_runner(DESTROY_PLAN))
        s1 = testbed_ops.slot_dir(d1["plan_id"])
        self.assertTrue(s1.exists())
        self.assertIn("삭제 예정", d1["summary"])
        self.assertIn("생성 3개 예정", a["summary"])
        self.assertTrue(any("아직 반영 안 함" in x for x in lines), lines)
        d2 = testbed_ops.prepare(TF, root=self.env.root, kind="destroy", profile="p", log=lambda s: None, runner=fake_plan_runner(DESTROY_PLAN))
        self.assertFalse(s1.exists())                                          # 취소된 이전 destroy plan 은 지움
        self.assertTrue(testbed_ops.slot_dir(d2["plan_id"]).exists())
        self.assertTrue(testbed_ops.slot_dir(a["plan_id"]).exists())           # 다른 종류(원본 반영) plan 은 그대로

    def test_stale_plan_is_refused(self):
        self.env = Env(deployed=True)
        meta = testbed_ops.prepare(TF, root=self.env.root, kind="destroy", profile="p", log=lambda s: None, runner=fake_plan_runner(DESTROY_PLAN))
        self.assertTrue(meta["eligible"])
        self.assertIn("리소스 2개 삭제", meta["summary"])
        self.env.set_state(39, serial=6)                                      # plan 뒤에 누가 apply 했다
        with self.assertRaises(ValueError) as e:
            testbed_ops.execute(TF, root=self.env.root, plan_id=meta["plan_id"], confirm="destroy", profile="p", log=lambda s: None,
                                runner_stream=fake_apply(self.env, 0))
        self.assertIn("상태 파일 변경됨", str(e.exception))
        meta2 = testbed_ops.prepare(TF, root=self.env.root, kind="destroy", profile="p", log=lambda s: None, runner=fake_plan_runner(DESTROY_PLAN))
        shutil.copy(CAND / "correct-design.tf", self.env.tb / "security_groups.tf")   # plan 뒤에 파일을 바꿨다
        with self.assertRaises(ValueError) as e:
            testbed_ops.execute(TF, root=self.env.root, plan_id=meta2["plan_id"], confirm="destroy", profile="p", log=lambda s: None,
                                runner_stream=fake_apply(self.env, 0))
        self.assertIn("security_groups.tf 변경됨", str(e.exception))

    def test_expired_and_ineligible(self):
        self.env = Env(deployed=True)
        meta = testbed_ops.prepare(TF, root=self.env.root, kind="destroy", profile="p", log=lambda s: None, runner=fake_plan_runner(DESTROY_PLAN))
        self.assertFalse(testbed_ops.fresh(meta, self.env.tb, now=time.time() + testbed_ops.PLAN_TTL_S + 5)[0])
        testbed_ops.drop(meta["plan_id"])
        bad = testbed_ops.prepare(TF, root=self.env.root, kind="destroy", profile="p", log=lambda s: None, runner=fake_plan_runner(CREATE_PLAN))
        self.assertFalse(bad["eligible"])                                     # destroy plan 에 '새로 만듦' 이 섞임
        self.assertIsNone(bad["plan_id"])
        ok, why = testbed_ops.eligible("apply_original", plancheck.summarize_plan(json.loads((FIX / "sg_desc.json").read_text(encoding="utf-8"))))
        self.assertFalse(ok)
        self.assertIn("교체", why)
        ok, why = testbed_ops.eligible("apply_candidate", {"verdict": "CHECK", "counts": {"create": 1}})
        self.assertFalse(ok)


class ApiTest(unittest.TestCase):
    """proof_api 의 문지기 + 작업 (실제 terraform 대신 가짜 실행기)."""

    def setUp(self):
        from iacpatch.web import proof_api as pa
        self.pa = pa
        self.env = Env(deployed=True, testbed_file=CAND / "pass-rule-desc.tf")
        self._root, self._reviews, self._env = pa._root, pa._reviews, pa._job_env
        pa._root = lambda: self.env.root
        pa._reviews = lambda: self.env.root / "data" / "reviews"
        pa._job_env = lambda: None
        self.rd = self.env.root / "data" / "reviews" / "20261026-090000-aaaaaa"
        (self.rd / "candidate").mkdir(parents=True)
        shutil.copy(CAND / "pass-rule-desc.tf", self.rd / "candidate" / "security_groups.tf")
        (self.rd / "state.json").write_text(json.dumps({"scenario": "ui/arch-3tier-sg/pass-rule-desc", "state": "REVIEW_REQUIRED",
                                                        "review_level": "FULL_REVIEW", "verification_status": "COMPLETE"}), encoding="utf-8")
        self._ls = None

    def tearDown(self):
        self.pa._root, self.pa._reviews, self.pa._job_env = self._root, self._reviews, self._env
        if self._ls is not None:
            import iacpatch.config as cfg
            cfg.load_settings = self._ls
        self.env.close()

    def _err(self, f, body):
        with self.assertRaises(ValueError) as e:
            f(body)
        return str(e.exception)

    def test_prepare_gates(self):
        self.assertIn("원본과 다름", self._err(self.pa.job_testbed_prepare, {"kind": "apply_original"}))
        self.assertIn("kind 값", self._err(self.pa.job_testbed_prepare, {"kind": "apply"}))
        self.assertTrue(callable(self.pa.job_testbed_prepare({"kind": "destroy"})))
        self.env.set_state(0, serial=9)
        self.assertIn("삭제 대상 없음", self._err(self.pa.job_testbed_prepare, {"kind": "destroy"}))
        (self.env.tb / ".terraform").rmdir()
        self.assertIn("terraform init", self._err(self.pa.job_testbed_prepare, {"kind": "destroy"}))

    def test_use_same_content_does_not_rewrite(self):
        dst = self.env.tb / "security_groups.tf"
        t = time.time() - 600
        os.utime(dst, (t, t))
        r = self.pa.testbed_use({"which": "candidate", "record_id": self.rd.name})    # 시험 환경 파일 = 이 기록의 후보 (같은 내용)
        self.assertTrue(r["ok"])
        self.assertFalse(r["changed"])
        self.assertAlmostEqual(dst.stat().st_mtime, t, delta=1)                        # 수정 시각 그대로
        self.assertFalse((self.env.root / "data" / "testbed_switch.jsonl").exists())    # 교체 기록도 남기지 않음
        r = self.pa.testbed_use({"which": "original"})                                 # 다른 내용이면 바꾸고 기록
        self.assertTrue(r["changed"])
        self.assertGreater(dst.stat().st_mtime, t + 1)
        self.assertTrue((self.env.root / "data" / "testbed_switch.jsonl").exists())

    def test_execute_gates(self):
        self.assertIn("plan 없음 또는 사용 완료", self._err(self.pa.job_testbed_execute, {"plan_id": "0123456789abcdef", "confirm": "apply"}))
        self.assertIn("plan 없음 또는 사용 완료", self._err(self.pa.job_testbed_execute, {"plan_id": "../x", "confirm": "apply"}))

    def test_stale_plan_is_dropped_by_api(self):
        self._patch_settings()
        fn = self.pa.job_testbed_prepare({"kind": "destroy"})
        orig = testbed_ops.run
        testbed_ops.run = fake_plan_runner(DESTROY_PLAN)
        try:
            pid = fn(lambda s: None, lambda i, n: None)["plan"]["plan_id"]
        finally:
            testbed_ops.run = orig
        self.assertIsNotNone(testbed_ops.load_meta(pid))
        self.env.set_state(39, serial=50)                                     # plan 뒤에 상태가 바뀜
        self.assertIn("상태 파일 변경됨", self._err(self.pa.job_testbed_execute, {"plan_id": pid, "confirm": "destroy"}))
        self.assertIsNone(testbed_ops.load_meta(pid))                         # 낡은 plan 은 지운다

    def _patch_settings(self):
        import iacpatch.config as cfg
        self._ls = cfg.load_settings
        cfg.load_settings = lambda root: TF

    def test_candidate_flow_plan_check_then_apply_writes_record(self):
        self._patch_settings()
        plancheck.run_plan_check(TF, testbed=self.env.tb, record_dir=self.rd, profile="capstone-tf", out_dir=self.rd / "plancheck" / "20261026-091000",
                                 log=lambda s: None, runner=fake_plan_runner(json.loads((FIX / "rule_desc.json").read_text(encoding="utf-8"))))
        m = self.pa.measure_setup(self.rd.name)
        self.assertIsNotNone(m["plan_ready"])                                 # [이 후보 apply] 가 켜진다
        pid = m["plan_ready"]["plan_id"]
        self.assertIn("제자리 수정 1개", m["plan_ready"]["summary"])
        self.assertIn("확인 값", self._err(self.pa.job_testbed_execute, {"plan_id": pid, "confirm": "destroy"}))
        fn = self.pa.job_testbed_execute({"plan_id": pid, "confirm": "apply", "profile": "capstone-tf"})
        orig = testbed_ops.run_stream
        testbed_ops.run_stream = fake_apply(self.env, 39)
        try:
            res = fn(lambda s: None, lambda i, n: None)
        finally:
            testbed_ops.run_stream = orig
        self.assertTrue(res["ok"])
        st = json.loads((self.rd / "state.json").read_text(encoding="utf-8"))
        self.assertTrue(st["testbed_apply"]["ok"])
        self.assertEqual(st["testbed_apply"]["plan_dir"], "plancheck/20261026-091000")
        m2 = self.pa.measure_setup(self.rd.name)
        self.assertIsNone(m2["plan_ready"])                                   # 한 번 쓴 plan 은 끝
        self.assertIsNotNone(m2["cand_applied"])                              # 화면: '이미 반영함'
        self.env.set_state(39, serial=99)                                     # 그 뒤 PowerShell 에서 누가 apply 했다
        self.assertIsNone(self.pa.measure_setup(self.rd.name)["cand_applied"])

    def test_blocked_candidate_never_gets_apply_plan(self):
        shutil.copy(CAND / "sg-desc-replace.tf", self.env.tb / "security_groups.tf")
        shutil.copy(CAND / "sg-desc-replace.tf", self.rd / "candidate" / "security_groups.tf")
        doc = plancheck.run_plan_check(TF, testbed=self.env.tb, record_dir=self.rd, profile="p", out_dir=self.rd / "plancheck" / "x",
                                       log=lambda s: None, runner=fake_plan_runner(json.loads((FIX / "sg_desc.json").read_text(encoding="utf-8"))))
        self.assertEqual(doc["verdict"], "BLOCKED")
        self.assertIsNone(doc["plan_id"])
        self.assertIsNone(self.pa.measure_setup(self.rd.name)["plan_ready"])

    def test_destroy_flow_reverts_testbed_file(self):
        self._patch_settings()
        fn = self.pa.job_testbed_prepare({"kind": "destroy", "profile": "capstone-tf"})
        orig = testbed_ops.run
        testbed_ops.run = fake_plan_runner(DESTROY_PLAN)
        try:
            res = fn(lambda s: None, lambda i, n: None)
        finally:
            testbed_ops.run = orig
        pid = res["plan"]["plan_id"]
        fn2 = self.pa.job_testbed_execute({"plan_id": pid, "confirm": "destroy", "profile": "capstone-tf"})
        orig2 = testbed_ops.run_stream
        testbed_ops.run_stream = fake_apply(self.env, 0)
        try:
            res2 = fn2(lambda s: None, lambda i, n: None)
        finally:
            testbed_ops.run_stream = orig2
        self.assertTrue(res2["ok"])
        self.assertTrue(res2["reverted"])
        self.assertEqual((self.env.tb / "security_groups.tf").read_bytes(), (SCEN / "security_groups.tf").read_bytes())
        sw = (self.env.root / "data" / "testbed_switch.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertIn("destroy 뒤 자동", json.loads(sw[-1])["by"])
        self.assertEqual([e["op"] for e in self.env.ops()], ["plan", "destroy"])
        self.assertEqual(self.pa.measure_setup("")["ops_last"]["op"], "destroy")


class ServerGuardTest(unittest.TestCase):
    """다른 웹 페이지가 이 PC 의 서버(버튼 API)를 부르지 못한다 — Host · Origin 검사."""

    @classmethod
    def setUpClass(cls):
        import threading
        from http.server import ThreadingHTTPServer
        from iacpatch.web import server as ws
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), ws.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _req(self, method, path, headers=None, body=None):
        import urllib.error
        import urllib.request
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method, headers=headers or {},
                                     data=json.dumps(body or {}).encode("utf-8") if method == "POST" else None)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")

    def test_cross_site_post_is_refused(self):
        body = {"plan_id": "0123456789abcdef", "confirm": "apply"}
        code, j = self._req("POST", "/api/testbed/execute", {"Origin": "http://evil.example", "Content-Type": "text/plain"}, body)
        self.assertEqual(code, 403)
        self.assertIn("다른 사이트", j["error"])
        code, j = self._req("POST", "/api/testbed/execute", {"Origin": "null"}, body)
        self.assertEqual(code, 403)
        code, _ = self._req("POST", "/api/testbed/execute", {"Origin": f"http://127.0.0.1:{self.port + 1}"}, body)
        self.assertEqual(code, 403)                                          # 같은 PC 의 다른 포트(다른 프로그램)도 거절

    def test_dns_rebinding_host_is_refused(self):
        code, _ = self._req("GET", "/api/measure/setup", {"Host": f"rebind.evil.example:{self.port}"})
        self.assertEqual(code, 403)
        code, _ = self._req("POST", "/api/testbed/prepare", {"Host": f"rebind.evil.example:{self.port}"}, {"kind": "destroy"})
        self.assertEqual(code, 403)

    def test_own_screen_and_local_programs_pass_the_guard(self):
        body = {"plan_id": "0123456789abcdef", "confirm": "apply"}
        for hdr in ({"Origin": f"http://127.0.0.1:{self.port}"}, {"Origin": f"http://localhost:{self.port}", "Host": f"localhost:{self.port}"}, {}):
            code, j = self._req("POST", "/api/testbed/execute", hdr, body)
            self.assertEqual(code, 400, hdr)                                  # 문지기는 통과 — plan 이 없어서 거절
            self.assertIn("plan 없음 또는 사용 완료", j["error"])


if __name__ == "__main__":
    unittest.main()
