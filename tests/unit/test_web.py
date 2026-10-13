"""브라우저 화면의 뒷단(iacpatch.web.server) — 서버를 스레드로 띄우고 API 를 부른다. 도구가 없으면 후보 실행은 NOT_RUN 이 남는 것까지 확인."""
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

from helpers import ROOT, tools_available

from iacpatch.web import server as ws


class _Srv:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), ws.Handler)
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        self.t.start()

    def get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=120) as r:
            return r.status, r.read()

    def post(self, path, body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(body or {}).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def wait_job(self, timeout=300):
        t0 = time.time()
        while time.time() - t0 < timeout:
            _, raw = self.get("/api/log?since=0")
            j = json.loads(raw)
            if not j["running"]:
                return j
            time.sleep(0.3)
        raise AssertionError("job did not finish")

    def close(self):
        self.httpd.shutdown()


class WebServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["IACPATCH_REVIEWS_DIR"] = cls.tmp.name      # 화면에서 돌린 기록은 임시 폴더에 (실험 기록 data/reviews 를 건드리지 않음)
        cls.s = _Srv()

    @classmethod
    def tearDownClass(cls):
        cls.s.close()
        os.environ.pop("IACPATCH_REVIEWS_DIR", None)
        cls.tmp.cleanup()

    def test_index_is_self_contained_html(self):
        st, raw = self.s.get("/")
        html = raw.decode("utf-8")
        self.assertEqual(st, 200)
        self.assertIn("<!doctype html>", html.lower())
        self.assertNotIn("<script src=", html)                 # 외부 스크립트 없음
        self.assertNotIn('rel="stylesheet" href="http', html)
        for tab in ("tab-w4", "tab-w5", "tab-exp", "tab-rep", "tab-tools"):
            self.assertIn(f'id="{tab}"', html)

    def test_state_and_week4_endpoints(self):
        st, raw = self.s.get("/api/state"); d = json.loads(raw)
        self.assertEqual(st, 200)
        self.assertEqual(d["root"], str(ROOT))
        self.assertIn("trivy", d["tools"]); self.assertIn("terraform", d["tools"])
        self.assertEqual(d["selfcheck"], [])
        self.assertTrue(any("8/8" in s for s in d["steps"]))
        st, raw = self.s.get("/api/week4/rubric"); self.assertEqual(st, 200); self.assertIn("points", json.loads(raw))
        st, raw = self.s.get("/api/week4/capcheck"); c = json.loads(raw)
        self.assertEqual(c["total"], 72); self.assertEqual(c["violations"], [])
        st, j = self.s.post("/api/week4/gate", {"risk_level": "MEDIUM", "proposal": "HIGH"})
        self.assertEqual(j["final"], "MEDIUM"); self.assertTrue(j["forced_down"])
        st, j = self.s.post("/api/week4/calc", {"target_kind": "SG", "deleted": True})
        self.assertEqual(j["level"], "HIGH")
        st, raw = self.s.get("/api/week4/labels"); lab = json.loads(raw)
        self.assertEqual(lab["replay"]["agree"], 25); self.assertEqual(lab["replay"]["judged"], 25)

    def test_week5_sets_and_records_listing(self):
        st, raw = self.s.get("/api/week5/sets"); d = json.loads(raw)
        ids = {s["set_id"] for s in d["sets"]}
        self.assertTrue({"eval-seeded-sg", "eval-seeded-iam", "eval-a-probe-rule", "eval-iam-rule"} <= ids)
        sg = next(s for s in d["sets"] if s["set_id"] == "eval-seeded-sg")
        self.assertEqual(len(sg["candidates"]), 11)
        st, raw = self.s.get("/api/week5/records"); self.assertEqual(st, 200)
        st, raw = self.s.get("/api/week5/record?id=../etc"); self.assertIn("error", json.loads(raw))
        st, j = self.s.post("/api/week5/pr_preview", {"record_id": "does-not-exist"})
        self.assertNotEqual(j.get("rc", 0), 0)                 # 없는 기록은 거부 (0 이 아님)

    def test_candidate_job_runs_review_flow_and_never_fakes_pass(self):
        st, j = self.s.post("/api/job/candidate", {"set_id": "eval-seeded-sg", "candidate_id": "deceptive-cidr-split"})
        self.assertTrue(j["started"], j)
        st2, j2 = self.s.post("/api/job/candidate", {"set_id": "eval-seeded-sg", "candidate_id": "correct-approved"})
        self.assertEqual(st2, 409)                              # 한 번에 하나만
        done = self.s.wait_job()
        self.assertFalse(done["error"], done)
        res = done["result"]
        self.assertTrue(res["record_id"])
        st, raw = self.s.get("/api/week5/records"); self.assertTrue(any(r["scenario"].startswith("ui/") for r in json.loads(raw)["records"]))
        st, raw = self.s.get("/api/week5/record?id=" + res["record_id"]); rec = json.loads(raw)
        layers = {l["layer"]: l["verdict"] for l in rec["verification"]["layers"]}
        # 기만 후보(0.0.0.0/1+128.0.0.0/1): plan 이 만들어졌으면 V6 는 반드시 FAIL, plan 을 못 만들었으면(도구/provider 없음) NOT_RUN — 절대 PASS 가 아니다
        self.assertNotEqual(layers["V6"], "PASS")
        if layers.get("V4") == "PASS":
            self.assertEqual(layers["V6"], "FAIL"); self.assertEqual(res["state"], "VALIDATION_FAILED")
        else:
            self.assertIn(layers["V6"], ("NOT_RUN", "SKIPPED"))
        if not tools_available():
            self.assertEqual(layers["V1"], "NOT_RUN")
        self.assertNotIn(res["level"], ("LIGHT_REVIEW", "FULL_REVIEW"))   # 통과로 격하되지 않는다
        st, j = self.s.post("/api/week5/pr_preview", {"record_id": res["record_id"]})
        self.assertIn("refusing", j["output"])                  # BLOCKED 는 PR 이 되지 않는다

    def test_paste_candidate_is_labeled_as_pasted(self):
        tf = (ROOT / "experiments" / "candidate-sets" / "eval-seeded-sg" / "candidates" / "correct-approved.tf").read_text(encoding="utf-8")
        st, j = self.s.post("/api/job/candidate", {"set_id": "eval-seeded-sg", "paste": tf})
        self.assertTrue(j["started"], j)
        done = self.s.wait_job()
        self.assertFalse(done["error"], done)
        st, raw = self.s.get("/api/week5/record?id=" + done["result"]["record_id"]); rec = json.loads(raw)
        self.assertIn("붙여넣", rec["candidate"]["provenance"])
        self.assertEqual(rec["candidate"]["origin"], "manual")

    def test_quit_and_heartbeat(self):
        st, j = self.s.post("/api/heartbeat"); self.assertTrue(j["ok"])


if __name__ == "__main__":
    unittest.main()
