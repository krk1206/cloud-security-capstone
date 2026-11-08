"""가상 고객 요청서 (D-50, 2026-11-06) — web/request.py · scenarios/requests/*.md.

지켜야 하는 것
  - 요청서(scenarios/requests/*.md)와 조건 목록(REQUESTS)이 서로 맞는다: 조건 문장이 요청서에 그대로 있고, 조건이 가리키는 설계도 통신 · 계층이 그 예제 설계도에 있다
  - 요청서 · 고객은 '가상' 으로 표시된다 (화면 · PR 본문)
  - 조건 결과는 기록 값을 모을 뿐이다: V6 가 찾은 위반은 조건 하나에만 들어가고, V6 가 FAIL 이면 반드시 어떤 조건 하나는 '어김'
  - CIDR 쪼개기처럼 Trivy 는 통과했지만 설계도를 어긴 수정안은 조건 1 이 '어김' 이고, 근거에 'Trivy 지적 없어짐' 도 같이 보인다
  - 설계도가 초안이면 설계도로 정하는 조건은 '지킴' 이 아니라 '초안 기준' (D-38)
  - 승인 전에는 '승인한 뒤에 반영' 이 '아직', 승인하면 '지킴' — 이 프로그램은 반영(apply)하지 않는다
"""
from __future__ import annotations

import json
import re
import unittest
from unittest import mock

from helpers import ROOT

from iacpatch.web import cases, inbox, request

TEAM = "three-tier-team"
WEB3 = "webapp-3tier"


def _flow(fid, src, dst, port, status="ok"):
    return {"id": fid, "src": src, "dst": dst, "ports": str(port), "status": status, "src_label": src, "dst_label": dst}


TEAM_FLOWS = [_flow("internet-alb-80", "internet", "alb", 80), _flow("alb-web-80", "alb", "web", 80), _flow("admin-bastion-22", "admin", "bastion", 22),
              _flow("web-db-3306", "web", "db", 3306), _flow("bastion-db-3306", "bastion", "db", 3306)]


def _ctx(v6="PASS", flows=None, excess=None, v1="PASS", scope="good", new="good", decision=None, post=None, draft=False, basis=None):
    qs = [{"key": "scope", "question": "관련 없는 설정까지 바꿨나요?", "tone": scope, "answer": "아니오, 허용 범위 안" if scope == "good" else "예, 정책 위반", "problems": []},
          {"key": "new", "question": "새로운 문제가 생겼나요?", "tone": new, "answer": "아니오, 새 문제 없음" if new == "good" else "예, 새 문제 있음", "problems": []}]
    return {"v1": v1, "v6": {"verdict": v6, "summary": "", "details": {"flows": flows if flows is not None else [dict(f) for f in TEAM_FLOWS], "excess": excess or []}},
            "rule": "AVD-AWS-0107", "questions": qs, "decision": decision or {}, "decision_ko": None, "post": post or {}, "draft": draft, "basis": basis}


def _tones(res):
    return [x["tone"] for x in res["items"]]


class RequestDocumentTests(unittest.TestCase):
    def test_each_example_request_matches_its_document_and_design(self):
        for cid, spec in request.REQUESTS.items():
            case = cases.get_case(cid)
            self.assertIsNotNone(case, cid)
            text = (ROOT / spec["path"]).read_text(encoding="utf-8")
            self.assertIn("가상", text.splitlines()[0])                       # 제목 줄에 '가상'
            self.assertIn("(가상)", spec["from"])
            if cid in inbox.IDS:            # 16차 (D-52): 팀 3계층 요청은 받은 시각을 요청함이 정한다 — 요청서에는 날짜 줄이 없고 보낸 사람 줄이 있다
                self.assertNotIn("- 날짜:", text)
                self.assertIn("- 보낸 사람: (가상) ", text)
                self.assertIn("- 보낸 곳: (가상) 3계층 웹 서비스 운영팀", text)
                self.assertIn(f"요청 {spec['seq']}", text.splitlines()[0])
            else:
                self.assertIn(f"- 날짜: {spec['date']}", text)
            for n, it in enumerate(spec["items"], 1):
                self.assertIn(f"{n}. {it['text']}", text, (cid, n))           # 조건 문장 = 요청서 문장 그대로
            if spec.get("handoff"):        # 요청 2 (S3, 15차): 고칠 묶음이 없다 — 조건 키도 없다 (사람에게 넘김)
                self.assertEqual(case["sets"], [])
                self.assertEqual(case.get("fix_scope"), "out_of_policy")
                self.assertFalse(any(k in it for it in spec["items"] for k in ("trivy_fixed", "flows_ok", "iam_limit", "approved")))
                continue
            set_id = case["sets"][0]["set_id"]
            if request._kind(spec) == "iam":    # 요청 3 (IAM, 15차): 조건 키가 IAM 세 가지를 모두 덮는다 (V6 IAM FAIL 이면 어느 조건이든 어김)
                self.assertEqual({k for it in spec["items"] for k in ("iam_limit", "iam_required", "iam_trust") if it.get(k)}, {"iam_limit", "iam_required", "iam_trust"})
                self.assertEqual(request.case_for_set(set_id), cid)
                continue
            # 조건이 가리키는 통신 · 계층이 그 예제 설계도에 있다
            man = json.loads((ROOT / "experiments" / "candidate-sets" / set_id / "manifest.json").read_text(encoding="utf-8"))
            intent = json.loads((ROOT / man["intent"]).read_text(encoding="utf-8"))
            fids, tiers = {f["id"] for f in intent["flows"]}, {t["id"] for t in intent["tiers"]}
            for it in spec["items"]:
                self.assertTrue(set(it.get("flows_ok") or []) <= fids, (cid, it.get("flows_ok")))
                self.assertTrue({t for t, _ in it.get("no_extra_to") or []} <= tiers, (cid, it.get("no_extra_to")))
            self.assertEqual(request.case_for_set(set_id), cid)
            self.assertEqual(sum(1 for it in spec["items"] if it.get("design_rest")), 1)   # '그 밖' 조건은 하나 — V6 위반이 빠짐없이 한 번씩 들어가게

    def test_meta_for_screen_and_none_for_others(self):
        m = request.meta(TEAM)
        self.assertEqual((m["label"], m["fictional"], len(m["items"])), ("고객 요청서", True, 5))
        self.assertIn("Bastion 서버 SSH(22)는 운영자 IP(203.0.113.10)에서만", m["text"])
        self.assertEqual([i["n"] for i in m["items"]], [1, 2, 3, 4, 5])
        self.assertIsNone(request.meta("board-saas"))
        self.assertIsNone(request.case_for_set("board-saas-sg"))
        self.assertIsNone(request.case_for_set("my-proj-1a2b3c.sg"))


class RequestCheckTests(unittest.TestCase):
    def test_passing_fix_before_approval(self):
        res = request.check(TEAM, _ctx())
        self.assertEqual(_tones(res), ["good", "good", "good", "good", "wait"])
        self.assertEqual(res["line"], "고객 요청 조건 5개 — 지킴 4 · 아직 1")
        self.assertIn("아직 — ⑧ 에서 담당자가 승인하기 전", res["items"][4]["why"][0])
        self.assertEqual(res["note"], "")
        self.assertTrue(res["fictional"])

    def test_split_cidr_passes_trivy_but_breaks_condition_1_only(self):
        ex = [{"src": "internet", "dst": "bastion", "ports": "22", "src_label": "인터넷 (허용 목록 밖)", "dst_label": "점프 서버 (Bastion)", "kind": "outside_approved"}]
        res = request.check(TEAM, _ctx(v6="FAIL", excess=ex))
        self.assertEqual(_tones(res), ["bad", "good", "good", "good", "wait"])        # '그 밖' 조건(4)은 조건 1 이 가져간 위반을 다시 세지 않는다
        lines = res["items"][0]["lines"]
        self.assertEqual(lines[0]["tone"], "bad")                                       # 어긴 근거가 먼저
        self.assertIn("요청에 없는 통신", lines[0]["text"])
        self.assertIn({"tone": "good", "text": "Trivy 다시 검사: AVD-AWS-0107 지적이 없어짐"}, lines)   # Trivy 통과 ≠ 요청 충족

    def test_db_opened_breaks_condition_3(self):
        ex = [{"src": "internet", "dst": "db", "ports": "3306", "kind": "not_designed"}]
        self.assertEqual(_tones(request.check(TEAM, _ctx(v6="FAIL", excess=ex))), ["good", "good", "bad", "good", "wait"])

    def test_wrong_cidr_blocks_operator_and_opens_other(self):
        flows = [dict(f) for f in TEAM_FLOWS]
        flows[2]["status"] = "broken"
        ex = [{"src": "x", "dst": "bastion", "ports": "22", "kind": "outside_approved"}]
        res = request.check(TEAM, _ctx(v6="FAIL", flows=flows, excess=ex))
        self.assertEqual(_tones(res), ["bad", "good", "good", "good", "wait"])
        self.assertTrue(any("허용 규칙 없음 (요청한 통신이 막힘)" in w for w in res["items"][0]["why"]))

    def test_violation_outside_named_conditions_goes_to_rest(self):
        ex = [{"src": "internet", "dst": "web", "ports": "22", "kind": "not_designed"}]
        self.assertEqual(_tones(request.check(TEAM, _ctx(v6="FAIL", excess=ex))), ["good", "good", "good", "bad", "wait"])
        flows = [{"id": "api-redis", "src": "api", "dst": "redis", "ports": "6379", "status": "broken"}, _flow("admin-bastion", "admin", "bastion", 22),
                 _flow("user-alb", "internet", "alb", 443), _flow("alb-web", "alb", "web", 80), _flow("api-db", "api", "db", 3306)]
        res = request.check(WEB3, _ctx(v6="FAIL", flows=flows))
        self.assertEqual(_tones(res)[:4], ["good", "good", "good", "bad"])
        self.assertIn("설계도에 있는 통신이 막힘", res["items"][3]["why"][0])

    def test_any_v6_violation_breaks_some_condition(self):
        """V6 FAIL 의 원인(설계도에 없는 통신 · 막힌 통신) 하나하나가 어떤 조건이든 '어김' 을 만든다 — 조건 결과가 V6 와 어긋나지 않음."""
        for t in ("alb", "web", "bastion", "db", "res:aws_instance.x"):
            for port in ("22", "80", "3306", "TCP 전체 포트"):
                ex = [{"src": "internet", "dst": t, "ports": port, "kind": "not_designed"}]
                self.assertIn("bad", _tones(request.check(TEAM, _ctx(v6="FAIL", excess=ex))), (t, port))
        for i in range(len(TEAM_FLOWS)):
            flows = [dict(f) for f in TEAM_FLOWS]
            flows[i]["status"] = "broken"
            self.assertIn("bad", _tones(request.check(TEAM, _ctx(v6="FAIL", flows=flows))), flows[i]["id"])

    def test_draft_design_is_not_kept(self):
        res = request.check(TEAM, _ctx(draft=True))
        self.assertEqual(_tones(res), ["unknown", "unknown", "unknown", "unknown", "wait"])
        self.assertEqual([x["word"] for x in res["items"][:4]], ["지킴 — 초안 기준"] * 4)
        bad = request.check(TEAM, _ctx(draft=True, v6="FAIL", excess=[{"src": "internet", "dst": "db", "ports": "3306"}]))
        self.assertEqual(_tones(bad)[2], "bad")                                          # 어긴 것은 초안이어도 '어김'
        self.assertIn("초안", res["note"])
        self.assertNotIn("지킴 4", res["line"])

    def test_policy_blocked_before_plan(self):
        res = request.check(TEAM, _ctx(v6="SKIPPED", v1="NOT_RUN", scope="bad", new="skip"))
        self.assertEqual(_tones(res), ["unknown", "unknown", "unknown", "bad", "wait"])
        self.assertIn("설계도 비교(V6)를 하지 못함", res["items"][1]["why"][0])

    def test_approval_and_testbed(self):
        dec = {"decision": "APPROVED", "by": "김담당", "at": "2026-11-06T10:00:00Z"}
        res = request.check(TEAM, _ctx(decision=dec))
        self.assertEqual(res["items"][4]["tone"], "good")
        self.assertIn("김담당 승인 · 2026-11-06 10:00", res["items"][4]["why"][0])
        self.assertIn("반영(apply)은 이 프로그램이 하지 않음", res["items"][4]["why"][0])
        self.assertEqual(request.check(TEAM, _ctx(decision={"decision": "DISCARDED"}))["items"][4]["tone"], "dim")
        web_flows = [_flow("admin-bastion", "admin", "bastion", 22), _flow("user-alb", "internet", "alb", 443), _flow("alb-web", "alb", "web", 80), _flow("api-db", "api", "db", 3306)]
        self.assertEqual(request.check(WEB3, _ctx(flows=web_flows, decision=dec))["items"][4]["tone"], "wait")          # 시험 환경 검사 전
        self.assertEqual(request.check(WEB3, _ctx(flows=web_flows, decision=dec, post={"status": "VERIFIED"}))["items"][4]["tone"], "good")
        self.assertEqual(request.check(WEB3, _ctx(flows=web_flows, decision=dec, post={"status": "DEPLOY_FAILED"}))["items"][4]["tone"], "bad")
        self.assertIn("팀이 작성한 평가 기준", request.check(WEB3, _ctx(flows=web_flows, basis="manifest"))["note"])

    def test_port_matching(self):
        self.assertTrue(request._port_hit("22", "0-1023"))
        self.assertTrue(request._port_hit("22", "TCP 전체 포트"))
        self.assertTrue(request._port_hit("22", "모든 프로토콜·포트"))
        self.assertTrue(request._port_hit("", "80"))
        self.assertFalse(request._port_hit("22", "80"))
        self.assertFalse(request._port_hit("22", "220-230"))

    def test_markdown_for_pr_body(self):
        md = request.markdown(request.check(TEAM, _ctx()))
        self.assertTrue(md.startswith("## 고객 요청 (가상 · 예제) — Bastion SSH 전체 공개 — 점검 지적 조치 요청"))
        # 16차 (D-52): 날짜 = 요청함이 받은 시각 (시험은 임시 요청함 = 실제 날짜 기준 → 요청 1 은 정해 둔 11-05 09:10)
        self.assertIn("(가상) 3계층 웹 서비스 운영팀 · 2026-11-05 09:10 · 요청서 `scenarios/requests/three-tier-team.md`", md)
        self.assertRegex(md, re.compile(r"^1\. Bastion 서버 SSH\(22\).* — \*\*지킴\*\* \(V1 Trivy 다시 검사 · V6 설계도 비교\)", re.M))
        self.assertRegex(md, re.compile(r"^5\. .* — \*\*아직\*\* \(⑧ 사람 승인\)", re.M))
        self.assertEqual(request.markdown(None), "")

    def test_closing_markdown_adds_request_section(self):
        from iacpatch.web import server
        fake = {"ok": True, "closing": {"checked": "확인", "decided": "승인", "left": []}, "request": request.check(TEAM, _ctx())}
        with mock.patch("iacpatch.web.product.final_view", return_value=fake):
            md = server.closing_markdown("r1")
        self.assertIn("## IaCPatch 기록 r1 — 끝맺음", md)
        self.assertGreater(md.index("## 고객 요청 (가상 · 예제)"), md.index("끝맺음"))
        with mock.patch("iacpatch.web.product.final_view", return_value={**fake, "request": None}):
            self.assertNotIn("고객 요청", server.closing_markdown("r1"))


if __name__ == "__main__":
    unittest.main()
