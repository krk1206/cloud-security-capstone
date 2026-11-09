"""브라우저 화면의 뒷단(iacpatch.web.server) — 서버를 스레드로 띄우고 화면 API 를 부른다.

도구(trivy/terraform)가 없으면 후보 검토는 NOT_RUN → '판단 불가' 로 남는 것까지 확인한다 (가짜 PASS 없음).
사람의 결정: 통과하지 않은 기록의 승인은 서버가 거부한다.
"""
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

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

    def getj(self, path):
        st, raw = self.get(path)
        return st, json.loads(raw)

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
            _, j = self.getj("/api/log?since=0")
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
        os.environ["IACPATCH_REVIEWS_DIR"] = cls.tmp.name      # 화면에서 돌린 기록은 임시 폴더에 (data/reviews 를 건드리지 않음)
        cls.s = _Srv()

    @classmethod
    def tearDownClass(cls):
        cls.s.close()
        os.environ.pop("IACPATCH_REVIEWS_DIR", None)
        cls.tmp.cleanup()

    def test_structure_endpoints_refuse_bad_input(self):
        # 그림에서 바꾸기 (D-33): 없는 프로젝트 404, 바꾼 것 없는 저장 400 (설계도를 만들거나 바꾸지 않음)
        st, r = self.s.post("/api/p/structure/preview", {"project": "nope", "edits": []})
        self.assertEqual(st, 404)
        st, r = self.s.post("/api/p/structure/save", {"project": "nope", "edits": [{"op": "keep", "edges": ["e1"]}]})
        self.assertEqual(st, 404)
        st, r = self.s.post("/api/p/structure/save", {"project": "webapp-3tier", "edits": []})
        self.assertEqual(st, 400)
        self.assertFalse(r["ok"])

    def test_first_screen_is_the_demo_and_main_keeps_8_steps(self):
        # 첫 화면 = 시연 화면 4단계 (2026-11-10). 8단계 화면은 /main ('자세히 보기'), 이전 흐름 화면은 /story, 작업 화면은 /work. 모두 외부 스크립트 없음
        st, raw = self.s.get("/")
        demo = raw.decode("utf-8")
        self.assertEqual(st, 200)
        self.assertIn('src="/static/app/demo.js"', demo)
        self.assertIn('href="/main"', demo)
        self.assertNotIn('src="http', demo)
        for path in ("/static/app/demo.js", "/static/app/demo.css"):
            st, _ = self.s.get(path)
            self.assertEqual(st, 200, path)
        st, raw = self.s.get("/main")
        html = raw.decode("utf-8")
        self.assertEqual(st, 200)
        self.assertIn('src="/static/app/main.js"', html)
        self.assertNotIn('href="/work"', html)                  # 11차 (D-47): 전문가 화면 링크는 화면에서 뺐다 — 주소(/work)로는 그대로 열린다
        self.assertNotIn('src="http', html)
        for path in ("/static/app/main.js", "/static/app/m_core.js", "/static/app/m_one.js", "/static/app/m_two.js", "/static/app/m_struct.js",
                     "/static/app/m_map.js", "/static/app/m_req.js", "/static/app/archview.js", "/static/app/archlayout.js", "/static/app/flowview.js", "/static/app/aws/ecs.svg",
                     "/static/app/main.css", "/static/app/topolayout.js", "/static/app/story.js", "/static/app/story.css"):
            st, _ = self.s.get(path)
            self.assertEqual(st, 200, path)
        st, raw = self.s.get("/story")
        self.assertEqual(st, 200)
        self.assertIn('src="/static/app/story.js"', raw.decode("utf-8"))
        st, m = self.s.getj("/api/topology?case=webapp-3tier&set=arch-3tier-sg")
        self.assertTrue(m["ok"], m)
        self.assertEqual(len(m["flows"]), 9)
        st, pj = self.s.getj("/api/p/projects")
        # 11차 (D-47): 화면 목록 = 고객 제안서 예제 → 3계층. 2계층(IAM 예제)은 hidden — 목록에는 없지만 id 로는 열린다 (실험 · 시험용)
        # 13차 (D-49): 팀 3계층 → 3계층(AWS 시험 환경 실측), 게시판 · 2계층 숨김. 15차 (D-51): 팀 3계층에 같은 가상 고객의 요청 2 (S3) · 3 (IAM)
        self.assertEqual([p["id"] for p in pj["projects"]], ["three-tier-team", "three-tier-team-s3", "three-tier-team-iam", "webapp-3tier"])
        self.assertEqual({p["id"]: p["testbed"] for p in pj["projects"]}, {"webapp-3tier": True, "three-tier-team": False, "three-tier-team-s3": False, "three-tier-team-iam": False})
        self.assertEqual({p["id"]: p["proposal"] for p in pj["projects"]}, {"webapp-3tier": False, "three-tier-team": True, "three-tier-team-s3": False, "three-tier-team-iam": True})
        self.assertEqual({p["id"]: p["proposal_label"] for p in pj["projects"]}, {"webapp-3tier": "", "three-tier-team": "팀 설계 문서", "three-tier-team-s3": "", "three-tier-team-iam": "팀 설계 문서"})
        # 14차 (D-50): 예제마다 가상 고객 요청서 (제목 · 보낸 곳 · 조건 · 원문). 15차: 팀 3계층 요청 1 · 2 · 3 (조건 5 · 4 · 4), 요청 2 는 '사람에게 넘김'
        req = {p["id"]: p["request"] for p in pj["projects"]}
        self.assertTrue(all(r and r["fictional"] and "(가상)" in r["from"] and len(r["items"]) >= 4 and r["text"] for r in req.values()), req)
        self.assertEqual({k: (r["seq"], r["kind"], len(r["items"])) for k, r in req.items()},
                         {"three-tier-team": (1, "topology", 5), "three-tier-team-s3": (2, "handoff", 4), "three-tier-team-iam": (3, "iam", 4), "webapp-3tier": (None, "topology", 5)})
        self.assertEqual({p["id"]: p["fix_scope"] for p in pj["projects"]}["three-tier-team-s3"], "out_of_policy")
        self.assertEqual(req["three-tier-team"]["path"], "scenarios/requests/three-tier-team.md")
        from iacpatch.web import cases as _cs
        self.assertIsNotNone(_cs.get_case("webapp-2tier"))
        self.assertTrue(_cs.get_case("webapp-2tier").get("hidden"))
        st, m2 = self.s.getj("/api/p/design?id=webapp-2tier")
        self.assertEqual(st, 200)
        st, cov = self.s.getj("/api/p/coverage")
        self.assertEqual(cov["trivy_checks"], 168)            # Trivy 0.74.0 내장 AWS 체크 175개 중 사용 중지 7개 제외
        self.assertGreaterEqual(len(cov["rows"]), 15)
        st, bad = self.s.getj("/api/p/impact?id=../x")
        self.assertFalse(bad["ok"])

    def test_index_is_self_contained_and_has_no_dev_vocabulary(self):
        st, raw = self.s.get("/work")
        html = raw.decode("utf-8")
        self.assertEqual(st, 200)
        self.assertIn("<!doctype html>", html.lower())
        self.assertNotIn('src="http', html)                    # 외부 스크립트 없음 (화면 파일은 전부 /static/ 에서)
        self.assertIn('src="/static/app/app.js"', html)
        self.assertNotIn('rel="stylesheet" href="http', html)
        # 고친 흐름 (2026-10-20) · 사용자 관점 이름 (2026-10-31 교수 피드백): 고객 설계도 → 지금 코드의 문제 → 수정 코드 → 배포 전 검사(코드 V1~V6)
        # → 실제 AWS 검사(시험 환경 V7·V8) → 사람의 승인 결정
        for step in ("고객 설계도", "지금 코드의 문제", "수정 코드", "배포 전 검사", "AWS 시험 환경 검사", "승인 결정", "결과 요약"):
            self.assertIn(step, html)
        for banned in ("주차", "지도교수", "숙제", "종료</button>", "복구 절차", "배포(apply) 실패 기록"):
            self.assertNotIn(banned, html)

    def test_app_and_case_payloads(self):
        st, a = self.s.getj("/api/app"); self.assertEqual(st, 200)
        self.assertIn("tools", a); self.assertIn("does_not", a)
        st, c = self.s.getj("/api/cases"); self.assertTrue(c["cases"])
        self.assertIn("webapp-3tier", [x["id"] for x in c["cases"]])
        # 3계층 사례: 설계도 통신(keep) + '그 밖의 통신 차단'(limit) 요구사항. 점검 결과가 아직 없으면 그렇다고 말한다 (지어내지 않음)
        st, c3 = self.s.getj("/api/case?id=webapp-3tier")
        ids = [r["id"] for r in c3["requirements"]]
        self.assertIn("deny:other", ids)
        self.assertEqual(sum(1 for i in ids if i.startswith("flow:")), 9)
        self.assertTrue(c3["findings"]["ok"] or c3["findings"].get("need_scan"), c3["findings"])
        cid = "webapp-2tier"
        st, case = self.s.getj(f"/api/case?id={cid}")
        self.assertTrue(case["requirements"], case)
        kinds = {r["kind"] for r in case["requirements"]}
        self.assertEqual(kinds, {"limit", "keep"})
        f = case["findings"]
        self.assertTrue(f["ok"], f)
        self.assertGreater(len(f["out_of_scope"]), 0)          # 요구사항 없는 finding 은 '판단 안 함' 으로 분류되어 보인다
        self.assertTrue(all("why" in x for x in f["out_of_scope"]))
        st, cands = self.s.getj(f"/api/case/candidates?id={cid}")
        self.assertTrue(cands["sets"][0]["candidates"])
        self.assertTrue(all(c["origin"]["label"] for c in cands["sets"][0]["candidates"]))

    def test_current_state_without_plan_is_honest(self):
        # 테스트 환경에는 원본 plan 캐시가 없을 수 있다 → ok=False 와 이유를 돌려준다 (가짜 '충족' 없음)
        st, cur = self.s.getj("/api/case/current?id=webapp-2tier")
        self.assertEqual(st, 200)
        if cur.get("ok"):
            for s in cur["sets"]:
                for r in s["rows"]:
                    self.assertIn(r["verdict"], ("PASS", "FAIL", "UNKNOWN"))
        else:
            self.assertIn("reason", cur)

    def test_review_job_never_fakes_pass_and_blocked_cannot_be_approved(self):
        st, j = self.s.post("/api/review", {"case_id": "webapp-2tier", "set_id": "arch-webapp-sg", "candidate_id": "deceptive-cidr-split"})
        self.assertTrue(j["started"], j)
        st2, j2 = self.s.post("/api/review", {"case_id": "webapp-2tier", "set_id": "arch-webapp-sg", "candidate_id": "correct-approved"})
        self.assertEqual(st2, 409)                              # 한 번에 하나만
        done = self.s.wait_job()
        self.assertFalse(done["error"], done)
        rid = done["result"]["record_id"]
        st, rec = self.s.getj("/api/record?id=" + rid)
        layers = {l["layer"]: l["verdict"] for l in rec["layers"]}
        self.assertNotEqual(layers["V6"], "PASS")
        if layers.get("V4") == "PASS":
            self.assertEqual(layers["V6"], "FAIL"); self.assertEqual(rec["state"]["code"], "VALIDATION_FAILED")
            self.assertEqual(rec["conclusion"]["tone"], "bad")
        else:
            self.assertIn(layers["V6"], ("NOT_RUN", "SKIPPED"))
            self.assertEqual(rec["conclusion"]["tone"], "warn")  # 판단 불가 — 통과로 격하되지 않는다
        if not tools_available():
            self.assertEqual(layers["V1"], "NOT_RUN")
        self.assertFalse(rec["conclusion"]["can_approve"])
        st, pg = self.s.getj("/api/job/progress")              # 진행 표시는 기록 폴더에 실제로 생긴 파일로만
        self.assertEqual(pg["record_id"], rid)
        done_keys = {s["key"]: s["done"] for s in pg["stages"]}
        self.assertTrue(done_keys["prepare"]); self.assertTrue(done_keys["verify"])
        if not tools_available():
            self.assertFalse(done_keys["trivy_after"]); self.assertFalse(done_keys["plan_candidate"])
        st, d = self.s.post("/api/decision", {"record_id": rid, "decision": "APPROVED", "by": "test"})
        self.assertEqual(st, 403, d)                            # 승인이 검증을 덮지 못한다
        st, d = self.s.post("/api/decision", {"record_id": rid, "decision": "DISCARDED", "reason": "test", "by": "test"})
        self.assertEqual(st, 200, d)
        st, rec = self.s.getj("/api/record?id=" + rid)
        self.assertEqual(rec["decision"]["decision"], "DISCARDED")
        st, lst = self.s.getj("/api/records"); self.assertTrue(any(r["id"] == rid for r in lst["records"]))

    def test_prefetch_analyzes_featured_candidates_without_records(self):
        """⑤ 미리 분석 (D-47): 보이는 수정안(featured) 중 지금 기준 기록이 없는 것만 차례로 검사 — 초안 설계도면 거절. 두 번째 호출은 할 일 0."""
        from iacpatch.web import server as srv
        # 초안(고객 제안서 예제는 확정 전) → 400
        st, j = self.s.post("/api/review/prefetch", {"case_id": "board-saas", "set_id": "board-saas-sg"})
        self.assertEqual(st, 400); self.assertIn("초안", j["error"])
        # 없는 묶음 → 400
        st, j = self.s.post("/api/review/prefetch", {"case_id": "webapp-3tier", "set_id": "nope"})
        self.assertEqual(st, 400)
        # needs_analysis 규칙 (기록 없음 · 설계도 지문 다름 · 초안 기준 기록인데 지금은 확정)
        st0 = {"design_sha256": "abc", "design_confirmation": {"confirmed": True, "basis": "human"}}
        self.assertTrue(srv.needs_analysis({"latest": None}, st0))
        self.assertTrue(srv.needs_analysis({"latest": {"design": {"sha256": "zzz", "confirmed": True}}}, st0))
        self.assertTrue(srv.needs_analysis({"latest": {"design": {"sha256": "abc", "confirmed": False}}}, st0))
        self.assertFalse(srv.needs_analysis({"latest": {"design": {"sha256": "abc", "confirmed": True}}}, st0))
        self.assertFalse(srv.needs_analysis({"latest": {"design": {"sha256": "abc", "confirmed": None}}}, {"design_sha256": "abc", "design_confirmation": {"confirmed": True, "basis": "manifest"}}))
        # 3계층(팀 작성 평가 기준 = 확정) — 임시 기록 폴더라 4개 모두 분석 대상. 실제로 돈다 (도구 없으면 V1~V4 NOT_RUN 으로 끝남)
        st, j = self.s.post("/api/review/prefetch", {"case_id": "webapp-3tier", "set_id": "arch-3tier-sg"})
        self.assertTrue(j["started"], j)
        self.assertEqual(j["job"]["name"], "prefetch")
        st2, j2 = self.s.post("/api/review", {"case_id": "webapp-3tier", "set_id": "arch-3tier-sg", "candidate_id": "correct-design"})
        self.assertEqual(st2, 409)                              # 미리 분석 중에는 다른 검사 못 시작
        done = self.s.wait_job(timeout=900)
        self.assertFalse(done["error"], done)
        res = done["result"]
        self.assertEqual(res["n"], 4)
        self.assertEqual([r["id"] for r in res["results"]], ["flagged-only-fix", "bastion-cidr-split", "correct-design", "redis-from-web"])
        self.assertTrue(all(r.get("record_id") for r in res["results"]), res)
        st, c = self.s.getj("/api/case/candidates?id=webapp-3tier")
        s3 = next(x for x in c["sets"] if x["set_id"] == "arch-3tier-sg")
        feat = [x for x in s3["candidates"] if x["featured"]]
        self.assertEqual({x["id"]: x["label"] for x in feat}, {"flagged-only-fix": "수정안 1", "bastion-cidr-split": "수정안 2", "correct-design": "수정안 3", "redis-from-web": "수정안 4"})
        self.assertEqual(s3["featured"], ["flagged-only-fix", "bastion-cidr-split", "correct-design", "redis-from-web"])
        self.assertTrue(all(x["latest"] for x in feat))
        self.assertFalse(any(srv.needs_analysis(x, s3) for x in feat))
        if tools_available():                                   # 설계도대로 고친 것(3번)만 통과, 지목된 줄만 고친 것(1번)은 설계 위반이 남아 막힘
            tone = {x["id"]: x["latest"]["classification"]["tone"] for x in feat}
            self.assertEqual(tone["correct-design"], "good", tone)
            self.assertEqual(tone["flagged-only-fix"], "bad", tone)
        # 두 번째: 할 일 없음 (기록이 다 있음)
        st, j = self.s.post("/api/review/prefetch", {"case_id": "webapp-3tier", "set_id": "arch-3tier-sg"})
        self.assertTrue(j["started"], j)
        done = self.s.wait_job(timeout=120)
        self.assertEqual(done["result"]["n"], 0)

    def test_paste_candidate_is_labeled_as_pasted(self):
        tf = (ROOT / "experiments" / "candidate-sets" / "arch-webapp-sg" / "candidates" / "correct-approved.tf").read_text(encoding="utf-8")
        st, j = self.s.post("/api/review", {"case_id": "webapp-2tier", "set_id": "arch-webapp-sg", "paste": tf})
        self.assertTrue(j["started"], j)
        done = self.s.wait_job()
        self.assertFalse(done["error"], done)
        st, rec = self.s.getj("/api/record?id=" + done["result"]["record_id"])
        self.assertEqual(rec["candidate"]["origin"]["code"], "paste")
        self.assertTrue(rec["candidate_label"].startswith("직접 제출"), rec["candidate_label"])
        # 작성 메모(provenance) · 후보 파일 이름(generator)은 화면으로 보내지 않는다 (2026-10-31, 피드백 7) — 기록 파일(candidate.json)에는 남는다
        self.assertNotIn("provenance", rec["candidate"])
        self.assertNotIn("generator", rec["candidate"])

    def test_new_screen_files_are_local_and_static_route_is_contained(self):
        for name, ctype in (("app/app.js", "text/javascript"), ("app/engine.js", "text/javascript"), ("app/scene.js", "text/javascript"), ("app/app.css", "text/css")):
            with urllib.request.urlopen(f"http://127.0.0.1:{self.s.port}/static/{name}", timeout=30) as r:
                self.assertEqual(r.status, 200)
                self.assertTrue(r.headers.get("Content-Type", "").startswith(ctype), r.headers.get("Content-Type"))
                body = r.read().decode("utf-8")
            self.assertNotRegex(body, r"https?://")             # 외부 주소 없음 — 네트워크 없이 그려진다
        for bad in ("../server.py", "..%2f..%2fserver.py", "app/../../server.py", "%2e%2e/server.py", ".hidden", "app/missing.js", "app/app.py"):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                self.s.get("/static/" + bad)
            self.assertEqual(cm.exception.code, 404, bad)

    def test_classic_screen_is_kept_with_way_back(self):
        st, raw = self.s.get("/classic")
        self.assertEqual(st, 200)
        html = raw.decode("utf-8")
        self.assertIn("<!doctype html>", html.lower())
        self.assertIn('href="/"', html)

    def test_candidate_source_preview_reads_only_registered_set_files(self):
        st, src = self.s.getj("/api/candidate/source?set_id=arch-webapp-sg&id=deceptive-cidr-split")
        self.assertEqual(src.get("file"), "security_groups.tf", src)
        self.assertIn("0.0.0.0/0", src["original"])
        self.assertIn("0.0.0.0/1", src["candidate"]); self.assertIn("128.0.0.0/1", src["candidate"])
        st, src = self.s.getj("/api/candidate/source?set_id=arch-webapp-sg")
        self.assertIsNone(src["candidate"]); self.assertTrue(src["original"])
        st, src = self.s.getj("/api/candidate/source?set_id=arch-webapp-iam&id=rule-based")
        self.assertTrue(src["generated_at_run"]); self.assertIsNone(src["candidate"])   # 규칙 기반은 실행할 때 만든다 — 미리 지어내지 않음
        for q in ("set_id=../../etc", "set_id=arch-webapp-sg&id=nope"):
            st, src = self.s.getj("/api/candidate/source?" + q)
            self.assertIn("error", src, q)

    def test_job_progress_shape(self):
        st, pg = self.s.getj("/api/job/progress")
        self.assertEqual(st, 200)
        self.assertEqual([s["key"] for s in pg["stages"]], ["prepare", "trivy_before", "trivy_after", "plan_baseline", "plan_candidate", "verify"])
        for s in pg["stages"]:
            if s["done"]:
                self.assertIsNotNone(pg["record_id"])          # 끝났다고 표시한 단계에는 실제 기록 폴더가 있다

    def test_legacy_endpoints_still_answer(self):
        st, d = self.s.getj("/api/state"); self.assertEqual(st, 200); self.assertIn("tools", d)
        st, d = self.s.getj("/api/week5/sets"); self.assertTrue(d["sets"])
        st, d = self.s.getj("/api/week5/record?id=../etc"); self.assertIn("error", d)
        st, j = self.s.post("/api/heartbeat"); self.assertTrue(j["ok"])


class ExplainTests(unittest.TestCase):
    def test_classify_and_conclusion_from_fixture_like_dicts(self):
        from iacpatch.web import explain
        st = {"state": "VALIDATION_FAILED", "review_level": "BLOCKED", "verification_status": "FAILED"}
        ver = {"report": {"validity": "FAIL", "summary": "FAIL at V6", "layers": [
            {"layer": "V1", "verdict": "PASS", "summary": ""},
            {"layer": "V6", "verdict": "FAIL", "summary": "EXCESS", "details": {"targets": [{"target": "aws_security_group.web", "scopes": [
                {"scope_id": "aws_instance.web", "services": [{"label": "ssh", "verdict": "FAIL", "excess_v4": ["128.0.0.0/1"], "covers_entire_internet_v4": True}], "required": []}]}]}}]}}
        cls = explain.classify_candidate(st, ver, {"ok": True})
        self.assertEqual(cls["code"], "excess")
        rows = [{"id": "limit:ssh", "kind": "limit", "label": "ssh", "text": "SSH 제한", "verdict": "FAIL", "reasons": ["x"]}]
        c = explain.conclusion(st, ver, None, {"ok": True}, rows)
        self.assertEqual(c["tone"], "bad"); self.assertFalse(c["can_approve"]); self.assertIn("Trivy", c["reason"])
        ok = explain.conclusion({"state": "REVIEW_REQUIRED", "review_level": "LIGHT_REVIEW", "verification_status": "COMPLETE"},
                                {"report": {"validity": "PASS", "layers": []}}, {"decision": {"risk_level": "LOW", "score": 1}}, {"ok": True}, [])
        self.assertTrue(ok["can_approve"])
        pend = explain.conclusion({"state": "REVIEW_REQUIRED", "review_level": "PENDING"}, {"report": {"validity": "INCOMPLETE", "layers": [{"layer": "V1", "verdict": "NOT_RUN"}]}}, None, {"ok": True}, [])
        self.assertEqual(pend["tone"], "warn"); self.assertFalse(pend["can_approve"])

    def test_conclusion_after_second_check(self):
        """2차 결과가 있으면 '다음 단계: 2차 검사' 대신 그 결과를 적는다 (10-27 PC 확인: 2차 통과 뒤에도 2차가 다음 단계로 보였음).
        승인 가능 여부(can_approve)·톤은 그대로 — APPLY 요청 조건은 서버의 결정 처리에서 따로 확인한다."""
        from iacpatch.web import explain
        base = {"state": "REVIEW_REQUIRED", "review_level": "FULL_REVIEW", "verification_status": "COMPLETE"}
        ver = {"report": {"validity": "PASS", "layers": []}}
        risk = {"decision": {"risk_level": "MEDIUM", "score": 3}}
        none = explain.conclusion(dict(base), ver, risk, {"ok": True}, [])
        self.assertIn("다음: AWS 시험 환경 검사 (시험 환경 반영 → V7 → V8)", none["reason"])
        self.assertEqual((none["title"], none["status"]), ("배포 전 검사를 모두 통과했습니다", "다음: AWS 시험 환경 검사"))
        ok = explain.conclusion(dict(base, post_deploy={"status": "VERIFIED"}), ver, risk, {"ok": True}, [])
        self.assertIn("AWS 시험 환경 검사(V7 · V8) 통과 — 시험 환경(샌드박스)에서 확인한 것이지 운영 반영 후 확인이 아님. 다음: 사람이 승인 결정", ok["reason"])
        self.assertNotIn("다음: AWS 시험 환경 검사", ok["reason"])
        for st, word in (("DEPLOY_FAILED", "AWS 시험 환경 검사 실패"), ("PLAN_BLOCKED", "AWS 시험 환경 검사 차단"), ("UNVERIFIED", "AWS 시험 환경 검사 판정 불가")):
            c = explain.conclusion(dict(base, post_deploy={"status": st}), ver, risk, {"ok": True}, [])
            self.assertIn(f"{word} — 적용 승인 불가", c["reason"])
        for c in (none, ok):
            self.assertEqual((c["tone"], c["headline"], c["can_approve"]), ("good", "배포 전 검사 통과", True))

    def test_conclusion_names_every_stage_that_caught_it(self):
        """V2(Trivy 새 지적)도 걸렸으면 'V6 만 잡았다'로 읽히지 않게 걸린 단계를 모두 적는다."""
        from iacpatch.web import explain
        st = {"state": "VALIDATION_FAILED", "review_level": "BLOCKED"}
        ver = {"report": {"validity": "FAIL", "layers": [{"layer": "V1", "verdict": "PASS"}, {"layer": "V2", "verdict": "FAIL"}, {"layer": "V6", "verdict": "FAIL"}]}}
        rows = [{"id": "x", "label": "x", "text": "x", "verdict": "FAIL", "reasons": ["인터넷 → 웹 서버 3389"]}]
        c = explain.conclusion(st, ver, None, {"ok": True}, rows)
        self.assertIn("새 보안 문제(V2) · 고객 설계 일치(V6)에서 차단", c["reason"])
        self.assertEqual(c["title"], "수정하면서 새로운 보안 문제가 생겼습니다")      # 맨 위 한 문장: 먼저 걸린 질문

    def test_terraform_error_reason_in_plain_words(self):
        from iacpatch.web import explain
        st = {"state": "VALIDATION_FAILED", "review_level": "BLOCKED"}
        ver = {"report": {"validity": "FAIL", "layers": [{"layer": "V4", "verdict": "FAIL",
                                                          "summary": 'Error: No value for required variable\n\n  on x.tf line 4:\n   4: variable "admin_cidrs" {'}]}}
        c = explain.conclusion(st, ver, None, {"ok": True}, [])
        self.assertIn("기본값 없는 변수에 값 미지정 (admin_cidrs)", c["reason"])
        self.assertNotIn("Error:", c["reason"])


class NoConsoleWindowTests(unittest.TestCase):
    """창 없는 exe 가 trivy·terraform 을 부를 때 터미널 창이 뜨지 않게 하는 인자 (팀 PC 실측 2026-10-19)."""

    def test_flag_only_on_windows(self):
        from unittest import mock
        from iacpatch.tools import runner
        with mock.patch.object(runner.os, "name", "nt"):
            self.assertEqual(runner.no_console_window(), {"creationflags": 0x08000000})
        with mock.patch.object(runner.os, "name", "posix"):
            self.assertEqual(runner.no_console_window(), {})

    def test_all_tool_calls_use_it(self):
        # 도구를 부르는 곳이 전부 이 인자를 쓰는지 (새 호출이 생기면 여기서 걸린다)
        src = ROOT / "src" / "iacpatch"
        for rel in ("tools/runner.py", "app.py", "web/server.py"):
            text = (src / rel).read_text(encoding="utf-8")
            calls = text.count("subprocess.run(") + text.count("subprocess.Popen(")
            if rel == "app.py":
                calls -= text.count("subprocess.run([\"py\"") + text.count("subprocess.run([cand") + text.count("subprocess.Popen([edge")
            self.assertGreater(text.count("no_console_window()"), 0, rel)
            self.assertGreaterEqual(text.count("**no_console_window()"), calls, rel)



class ApprovalGateTests(unittest.TestCase):
    """고친 흐름 (2026-10-20): 1차(V1~V6) 와 2차(임시 환경 V7·V8) 를 모두 통과한 후보만 APPLY 를 요청할 수 있다."""

    BASE = {"state": "REVIEW_REQUIRED", "review_level": "LIGHT_REVIEW", "verification_status": "COMPLETE"}

    def test_first_stage_only_is_not_enough(self):
        from iacpatch.web.decision import can_approve
        ok, why = can_approve(dict(self.BASE))
        self.assertFalse(ok)
        self.assertIn("AWS 시험 환경 검사", why)

    def test_failed_second_stage_blocks(self):
        from iacpatch.web.decision import can_approve
        ok, why = can_approve({**self.BASE, "post_deploy": {"status": "BEHAVIOR_FAILED"}})
        self.assertFalse(ok)
        self.assertIn("BEHAVIOR_FAILED", why)

    def test_both_stages_pass(self):
        from iacpatch.web.decision import can_approve
        ok, why = can_approve({**self.BASE, "post_deploy": {"status": "VERIFIED"}})
        self.assertTrue(ok, why)

    def test_second_stage_cannot_rescue_blocked_candidate(self):
        from iacpatch.web.decision import can_approve
        ok, _ = can_approve({"state": "VALIDATION_FAILED", "review_level": "BLOCKED", "verification_status": "FAILED",
                             "post_deploy": {"status": "VERIFIED"}})
        self.assertFalse(ok)


class ProgressCachedTests(unittest.TestCase):
    """진행 단계: 캐시에서 복사한 파일(원래 시각 유지)은 '이전 결과 재사용' 으로 표시한다."""

    def test_cached_flag_from_mtime(self):
        import os, tempfile, time
        from unittest import mock
        from iacpatch.web import server
        with tempfile.TemporaryDirectory() as td:
            rr = Path(td)
            now = time.time()
            rid = time.strftime("%Y%m%d-%H%M%S", time.localtime(now)) + "-abcdef"
            d = rr / rid
            (d / "local_verify").mkdir(parents=True)
            old = d / "local_verify" / "plan_baseline.json"; old.write_text("{}")
            os.utime(old, (now - 3600, now - 3600))           # 한 시간 전 캐시 → 재사용
            new = d / "local_verify" / "trivy_after.json"; new.write_text("{}")
            os.utime(new, (now + 5, now + 5))                  # 이번에 만든 파일
            job = server.JOB
            with mock.patch.object(server, "reviews_root", return_value=rr), \
                 mock.patch.multiple(job, running=True, name="review", started=now - 0.5, finished=None, result=None):
                pg = server.job_progress()
        st = {s["key"]: s for s in pg["stages"]}
        self.assertEqual(pg["record_id"], rid)
        self.assertTrue(st["plan_baseline"]["done"]); self.assertTrue(st["plan_baseline"]["cached"])
        self.assertTrue(st["trivy_after"]["done"]); self.assertFalse(st["trivy_after"]["cached"])
        self.assertFalse(st["verify"]["done"])


if __name__ == "__main__":
    unittest.main()
