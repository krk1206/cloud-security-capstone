"""2차 검사 진행 안내 (web/static/app/flow2.js) 단위 테스트 — node 로 순수 함수 stage2Plan 을 직접 부른다.

지켜야 하는 것
  - 상태마다 다음 작업이 하나로 정해진다: 원본 배포 → 수정 전 측정 → 후보 반영 → 수정 후 측정 → 시험 환경 삭제
  - 안내가 고르는 동작은 plan 계산·plan 확인·측정·확인 창 열기·화면 이동뿐이다. apply · destroy 실행(tb-exec)은 고르지 않는다 (D-19)
  - 측정 버튼은 apply 뒤 서버 기준(settle_s)이 지나기 전에는 꺼져 있다 · AWS CLI 가 없으면 꺼져 있다
  - 1차 미통과 · plan 차단 후보는 반영 단계로 가지 않는다
node 가 없으면 건너뛴다.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

JS = ROOT / "src" / "iacpatch" / "web" / "static" / "app" / "flow2.js"
NODE = shutil.which("node") or (shutil.which("/opt/node22/bin/node") if Path("/opt/node22/bin/node").exists() else None)
HARNESS = """
const F = await import(process.argv[2]);
const cases = JSON.parse(await new Promise((ok) => { let s = ""; process.stdin.on("data", (d) => { s += d; }); process.stdin.on("end", () => ok(s)); }));
const out = cases.map((c) => F.stage2Plan(c));
process.stdout.write(JSON.stringify({ out, consts: { STEPS: F.STEPS, WAIT_BEFORE_S: F.WAIT_BEFORE_S, WAIT_AFTER_S: F.WAIT_AFTER_S, ACTIONS: F.ACTIONS,
  mmss: [F.mmss(0), F.mmss(59.2), F.mmss(180), F.mmss(-5)] } }));
"""
NOW = 1_800_000_000_000
ISO_OLD = "2026-01-01T00:00:00+00:00"


def iso(ms: float) -> str:
    import datetime as dt
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).isoformat()


def M(**kw):
    base = {"exists": True, "tf_inited": True, "deployed_state_file": True, "applied_after_change": True, "since_apply_s": 1000, "settle_s": 120,
            "is_original": True, "is_record_candidate": False, "plan_blocked": False, "plan_ready": None, "destroyed": False, "aws_cli": True,
            "record_case_ok": True, "testbed": "scenarios/arch/webapp-3tier-testbed"}
    base.update(kw)
    return base


REC = {"id": "r1", "candidate_id": "pass-rule-desc"}


def C(m, rec=None, passed=False, post=None, running=None, fetched_ago_ms=0):
    return {"m": m, "rec": rec, "passed": passed, "post": post or {}, "running": running, "now": NOW, "fetchedAt": NOW - fetched_ago_ms}


@unittest.skipUnless(NODE, "node 없음")
class Flow2Test(unittest.TestCase):
    def run_cases(self, cases):
        with tempfile.TemporaryDirectory() as td:
            h = Path(td) / "h.mjs"
            h.write_text(HARNESS, encoding="utf-8")
            r = subprocess.run([NODE, str(h), JS.as_uri()], input=json.dumps(cases), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def plan(self, case):
        return self.run_cases([case])["out"][0]

    def act(self, p):
        return (p.get("primary") or {}).get("act")

    def test_constants(self):
        k = self.run_cases([])["consts"]
        self.assertEqual(k["STEPS"], ["원본 배포", "수정 전 측정", "후보 반영", "수정 후 측정", "시험 환경 삭제"])
        self.assertEqual((k["WAIT_BEFORE_S"], k["WAIT_AFTER_S"]), (180, 130))
        self.assertGreaterEqual(k["WAIT_AFTER_S"], 120)         # 서버 측정 하한(SETTLE_AFTER_APPLY_S)보다 짧으면 안 된다
        self.assertEqual(k["mmss"], ["0:00", "1:00", "3:00", "0:00"])
        self.assertNotIn("tb-exec", k["ACTIONS"])

    def test_not_ready_states(self):
        self.assertIsNone(self.plan(C(None))["primary"])
        p = self.plan(C({"error": "x"}))
        self.assertEqual((p["tone"], p["primary"]), ("bad", None))
        self.assertIsNone(self.plan(C(M(exists=False)))["primary"])
        p = self.plan(C(M(tf_inited=False)))
        self.assertEqual((p["cur"], p["primary"]), (1, None))
        self.assertIn("terraform init", p["title"])

    def test_order_full_pass(self):
        """원본 배포 → (대기) → 수정 전 측정 → 후보 반영 → 확인 창 → (대기) → 수정 후 측정 → 삭제 → 완료."""
        post_none = {"before": {}, "after": {}}
        p = self.plan(C(M(deployed_state_file=False, destroyed=True, since_apply_s=None), REC, True, post_none))
        self.assertEqual((p["cur"], self.act(p)), (1, "s2-deploy"))
        p = self.plan(C(M(since_apply_s=30), REC, True, {"before": {"at": ISO_OLD}, "after": {}}))
        self.assertEqual((p["cur"], self.act(p), p["primary"]["kind"], p["primary"]["disabled"]), (2, "s2-measure", "before", True))
        self.assertEqual(round(p["wait"]["left"]), 150)
        p = self.plan(C(M(since_apply_s=150), REC, True, {"before": {"at": ISO_OLD}, "after": {}}))
        self.assertEqual((p["primary"]["disabled"], round(p["wait"]["left"])), (False, 30))   # 120초 뒤부터 수동 측정 가능, 대기 표시는 180초까지
        p = self.plan(C(M(since_apply_s=200), REC, True, {"before": {"at": ISO_OLD}, "after": {}}))
        self.assertEqual((p["cur"], self.act(p), p["wait"]), (2, "s2-measure", None))
        measured = {"before": {"at": iso(NOW - 10_000), "dir": "b"}, "after": {}}
        p = self.plan(C(M(since_apply_s=200), REC, True, measured))
        self.assertEqual((p["cur"], self.act(p)), (3, "s2-cand"))
        p = self.plan(C(M(applied_after_change=False, is_original=False, is_record_candidate=True), REC, True, measured))
        self.assertEqual((p["cur"], self.act(p)), (3, "s2-cand"))
        p = self.plan(C(M(applied_after_change=False, is_original=False, is_record_candidate=True, plan_ready={"plan_id": "x"}), REC, True, measured))
        self.assertEqual((p["cur"], self.act(p)), (3, "s2-open-apply"))
        p = self.plan(C(M(since_apply_s=60, is_original=False, is_record_candidate=True), REC, True, measured))
        self.assertEqual((p["cur"], self.act(p), p["primary"]["kind"], p["primary"]["disabled"], round(p["wait"]["left"])), (4, "s2-measure", "after", True, 70))
        p = self.plan(C(M(since_apply_s=125, is_original=False, is_record_candidate=True), REC, True, measured))
        self.assertEqual((p["primary"]["disabled"], round(p["wait"]["left"])), (False, 5))
        after = {"before": measured["before"], "after": {"at": iso(NOW - 5_000), "dir": "a", "status": "VERIFIED"}}
        p = self.plan(C(M(since_apply_s=200, is_original=False, is_record_candidate=True), REC, True, after))
        self.assertEqual((p["cur"], self.act(p), p["tone"]), (5, "s2-destroy", "ok"))
        p = self.plan(C(M(deployed_state_file=False, destroyed=True, since_apply_s=None, is_original=True), REC, True, after))
        self.assertEqual((p["cur"], self.act(p), [b["act"] for b in p["secondary"]]), (6, "s2-decide", ["s2-deploy"]))

    def test_elapsed_time_since_fetch(self):
        """상태를 받은 뒤 흐른 시간도 대기 계산에 넣는다 (화면은 10초마다만 다시 읽는다)."""
        p = self.plan(C(M(since_apply_s=100), REC, True, {"before": {"at": ISO_OLD}}, fetched_ago_ms=50_000))
        self.assertEqual((round(p["wait"]["left"]), p["primary"]["disabled"]), (30, False))

    def test_blocked_and_not_passed(self):
        measured = {"before": {"at": iso(NOW - 10_000), "dir": "b"}, "after": {}}
        p = self.plan(C(M(applied_after_change=False, is_original=False, is_record_candidate=True, plan_blocked=True), REC, True, measured))
        self.assertEqual((p["cur"], self.act(p), p["tone"]), (5, "s2-destroy", "bad"))
        self.assertEqual(p["marks"], {"3": "bad", "4": "skip"})     # 차단된 반영·하지 않은 측정을 ✓ 로 그리지 않는다
        blocked_post = {"before": measured["before"], "after": {"at": iso(NOW - 1000), "dir": "p", "status": "PLAN_BLOCKED"}}
        p = self.plan(C(M(since_apply_s=300), REC, True, blocked_post))
        self.assertEqual((p["cur"], self.act(p), p["marks"]), (5, "s2-destroy", {"3": "bad", "4": "skip"}))
        p = self.plan(C(M(deployed_state_file=False, destroyed=True, since_apply_s=None), REC, True, blocked_post))
        self.assertEqual((p["cur"], self.act(p), p["marks"]), (6, "s2-pick", {"3": "bad", "4": "skip"}))
        p = self.plan(C(M(applied_after_change=False, is_original=False, is_record_candidate=True), REC, True, {"before": {"at": ISO_OLD}}))
        self.assertEqual((self.act(p), p["marks"]), ("s2-cand", {"2": "skip"}))   # 수정 전 측정 없이 후보로 바꾼 경우
        p = self.plan(C(M(since_apply_s=300), REC, False, measured))
        self.assertEqual((self.act(p), p["tone"]), ("s2-pick", "warn"))
        p = self.plan(C(M(since_apply_s=300), None, False, measured))
        self.assertEqual(self.act(p), "s2-pick")
        p = self.plan(C(M(since_apply_s=300), REC, True, measured | {"x": 1}) | {"m": M(since_apply_s=300, record_case_ok=False)})
        self.assertNotEqual(self.act(p), "s2-cand")                # 다른 사례(시험 환경 없음) 기록은 반영하지 않는다

    def test_other_file(self):
        measured = {"before": {"at": iso(NOW - 10_000), "dir": "b"}, "after": {}}
        # 다른 기록의 후보가 들어 있고 apply 전 — 이 기록이 1차 통과 후보면 이 후보로 교체해 반영 진행 (원본 재배포는 보조).
        # 10-27 실제 사례: 이때 원본 재배포만 안내해서, plan 이 '변경 없음' 이면 더 진행할 수 없었다
        p = self.plan(C(M(applied_after_change=False, is_original=False), REC, True, measured))
        self.assertEqual((p["cur"], self.act(p), [b["act"] for b in p["secondary"]]), (3, "s2-cand", ["s2-deploy"]))
        p = self.plan(C(M(applied_after_change=False, is_original=False), REC, False, measured))
        self.assertEqual((self.act(p), [b["act"] for b in p["secondary"]]), ("s2-deploy", ["s2-destroy"]))
        p = self.plan(C(M(applied_after_change=False, is_original=False), dict(REC, post_deploy={"status": "PLAN_BLOCKED"}), True, measured))
        self.assertEqual((p["cur"], self.act(p), p["marks"]), (5, "s2-destroy", {"3": "bad", "4": "skip"}))   # 차단 기록이 있는 후보는 다시 반영하지 않는다
        p = self.plan(C(M(since_apply_s=300, is_original=False), REC, True, measured))
        self.assertEqual(self.act(p), "s2-cand")
        p = self.plan(C(M(since_apply_s=300, is_original=False), REC, False, measured))
        self.assertEqual(self.act(p), "s2-destroy")

    def test_running_and_no_cli(self):
        p = self.plan(C(M(since_apply_s=300), REC, True, {"before": {"at": ISO_OLD}}, running={"kind": "measure", "label": "수정 전 측정"}))
        self.assertEqual((p["cur"], p["primary"], p["secondary"]), (2, None, []))
        self.assertIn("작업 실행 중", p["title"])
        p = self.plan(C(M(since_apply_s=300, aws_cli=False), REC, True, {"before": {"at": ISO_OLD}}))
        self.assertEqual((self.act(p), p["primary"]["disabled"]), ("s2-measure", True))
        self.assertIn("AWS CLI", p["primary"]["why"])

    def test_actions_are_limited(self):
        """어떤 상태에서도 안내는 허용 목록 밖의 동작(특히 apply·destroy 실행)을 고르지 않는다."""
        allowed = set(self.run_cases([])["consts"]["ACTIONS"])
        posts = [{}, {"before": {"at": iso(NOW - 1000), "dir": "b"}}, {"before": {"at": iso(NOW - 1000)}, "after": {"at": iso(NOW - 500), "dir": "a", "status": "DEPLOY_FAILED"}},
                 {"after": {"at": iso(NOW - 500), "dir": "a", "status": "PLAN_BLOCKED"}}]
        cases = []
        for dep in (True, False):
            for applied in (True, False):
                for orig, candf in ((True, False), (False, True), (False, False)):
                    for blocked in (True, False):
                        for ready in (None, {"plan_id": "p"}):
                            for since in (10, 125, 400):
                                for rec, passed in ((None, False), (REC, False), (REC, True)):
                                    for post in posts:
                                        cases.append(C(M(deployed_state_file=dep, destroyed=not dep, applied_after_change=applied, is_original=orig, is_record_candidate=candf,
                                                         plan_blocked=blocked, plan_ready=ready, since_apply_s=since), rec, passed, post))
        out = self.run_cases(cases)["out"]
        self.assertEqual(len(out), len(cases))
        for p in out:
            for b in [p.get("primary")] + list(p.get("secondary") or []):
                if b:
                    self.assertIn(b["act"], allowed, p)
            self.assertTrue(p["title"] and p["text"], p)
            self.assertIn(p["cur"], range(0, 7))


if __name__ == "__main__":
    unittest.main()
