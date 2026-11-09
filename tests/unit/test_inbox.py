"""고객 요청함 (16차, D-52 — B 2026-11-06 "고객 요청을 실시간으로 들어오게 … 시간 지나면 진짜 새로 들어온 거마냥, 실제 기반처럼").
17차 (D-53, B 11-07 "발표용 타이머 같은 쓸데없는 내용 빼라" → 답: [요청 넣기]만 남기기): 타이머 · [지금 받기] · [처음부터] · 방식 고르기를 뺐다.

지켜야 하는 것
  - 요청 11건 = 가상 요청서 11건(REQUESTS · scenarios/requests) 과 같은 순서 · 같은 예제. 도착 시각은 차례대로이고 기능 동결(11-16) 전에 모두 온다
  - 정해 둔 날짜 기준: 정해 둔 시각이 지난 요청만 도착 (받은 시각 = 정해 둔 시각). 다음 요청이 언제 오는지는 보여 주지 않는다
  - 타이머 · 지금 받기 · 처음부터 는 없다 (함수 · 길 모두). 16차 상태 파일(mode · running · interval)은 무시하고 날짜 기준으로 이어진다
  - [고객 역할로 넣기] = 안 온 요청만 · 이름 필수 · 길이 제한 — 요청 내용은 그대로, 넣은 사람 · 메모만 기록
  - 안 온 요청은 ① 목록(projects)에 없다 (주소로 여는 것 · include_hidden 은 그대로)
  - 상태 줄은 기록(검토 기록 · ⑧ 결정)을 읽을 뿐이다 — 넘김 요청은 읽으면 '사람에게 넘김'
  - 상태 파일이 깨져도 기본값으로 연다 (요청함 때문에 프로그램이 멈추지 않게)
상태 파일은 IACPATCH_INBOX_FILE 로 테스트마다 임시 파일을 쓴다 (저장소 data/inbox 를 건드리지 않음).
'지금' 은 IACPATCH_INBOX_NOW 로 고정한다 (helpers: 요청 1 ~ 3 이 와 있는 11-06 21:00) — 실제 날짜가 지나도 결과가 같게.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401 — 경로 · 임시 폴더 설정

from iacpatch.web import cases, inbox, product, request

KST = inbox.KST
TEAM, S3, IAM, DBSG, DBPUB = "three-tier-team", "three-tier-team-s3", "three-tier-team-iam", "three-tier-team-dbsg", "three-tier-team-dbpublic"


def T(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s)


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iacpatch-inbox-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.dict(os.environ, {"IACPATCH_INBOX_FILE": str(Path(self.tmp) / "state.json"), "IACPATCH_REVIEWS_DIR": str(Path(self.tmp) / "reviews"),
                                         "IACPATCH_INBOX_NOW": "2026-11-05T12:00:00+09:00"})        # 요청 1 만 와 있는 때
        p.start()
        self.addCleanup(p.stop)

    def write(self, st):
        Path(os.environ["IACPATCH_INBOX_FILE"]).write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def ids(v):
        return [i["id"] for i in v["items"]]


class ScheduleTests(_Tmp):
    def test_schedule_matches_requests_and_cases(self):
        team = sorted((r["seq"], cid) for cid, r in request.REQUESTS.items() if cid.startswith("three-tier-team"))
        self.assertEqual([cid for _, cid in team], inbox.IDS)
        self.assertEqual([s for s, _ in team], list(range(1, 12)))
        ats = [T(x["at"]) for x in inbox.SCHEDULE]
        self.assertEqual(ats, sorted(ats))
        self.assertTrue(all(a.utcoffset() == dt.timedelta(hours=9) for a in ats))
        self.assertLess(ats[-1], T("2026-11-16T00:00:00+09:00"))           # 기능 동결 전에 모두 도착
        for x in inbox.SCHEDULE:
            c = cases.get_case(x["id"])
            self.assertIsNotNone(c, x["id"])
            self.assertFalse(c.get("hidden"), x["id"])
            self.assertIn(f"요청 {request.REQUESTS[x['id']]['seq']} —", c["name"])
            self.assertTrue(x["sender"] and x["channel"] and x["priority"] in ("긴급", "높음", "보통") and x["due"], x)


class DateModeTests(_Tmp):
    def test_arrivals_follow_the_calendar(self):
        v = inbox.view(T("2026-11-06T21:00:00+09:00"))
        self.assertEqual((v["fictional"], v["total"]), (True, 11))
        self.assertEqual(self.ids(v), [IAM, S3, TEAM])                    # 최근 것이 위
        self.assertEqual([i["at_text"] for i in v["items"]], ["2026-11-06 15:20", "2026-11-06 10:30", "2026-11-05 09:10"])
        self.assertEqual((v["pending_count"], v["unread"]), (8, 3))
        self.assertEqual([p["seq"] for p in v["pending"]], list(range(4, 12)))
        # 17차: 타이머 · 다음 도착 시각 · 받은 방식 글은 화면에 주지 않는다
        self.assertFalse({"mode", "running", "interval_sec", "intervals", "next"} & set(v), sorted(v))
        self.assertFalse({"how", "how_ko"} & set(v["items"][0]), sorted(v["items"][0]))
        v2 = inbox.view(T("2026-11-14T10:00:00+09:00"))
        self.assertEqual((len(v2["items"]), v2["pending_count"]), (11, 0))
        self.assertEqual(v2["items"][0]["seq"], 11)

    def test_now_comes_from_env_for_tests(self):
        """IACPATCH_INBOX_NOW (자동 시험용) — 날짜가 지나도 같은 결과. 없으면 실제 시계."""
        self.assertEqual(self.ids(inbox.view()), [TEAM])                 # setUp: 11-05 12:00
        with mock.patch.dict(os.environ, {"IACPATCH_INBOX_NOW": "2026-11-07T10:00:00+09:00"}):
            self.assertEqual(self.ids(inbox.view()), [DBSG, IAM, S3, TEAM])
        with mock.patch.dict(os.environ, {"IACPATCH_INBOX_NOW": "엉터리"}):
            self.assertGreater(inbox._now(), T("2026-11-01T00:00:00+09:00"))      # 읽을 수 없으면 실제 시계

    def test_items_carry_request_fields(self):
        v = inbox.view(T("2026-11-07T17:00:00+09:00"))
        it = {i["id"]: i for i in v["items"]}
        self.assertEqual((it[DBSG]["seq"], it[DBSG]["kind"], it[DBSG]["auto"], it[DBSG]["priority"]), (4, "topology", True, "긴급"))
        self.assertEqual((it[DBPUB]["kind"], it[DBPUB]["auto"], it[DBPUB]["sender"]), ("handoff", False, "개발팀 리드"))
        self.assertEqual(it[IAM]["kind"], "iam")
        self.assertEqual(it[TEAM]["from"], "(가상) 3계층 웹 서비스 운영팀")
        self.assertTrue(all(i["title"] == request.REQUESTS[i["id"]]["title"] for i in v["items"]))


class NoTimerTests(_Tmp):
    """17차: 발표용 타이머 · [지금 받기] · [처음부터] 는 없다. 16차 때 저장한 '발표용 타이머 · 처음부터' 상태도 날짜 기준으로 이어진다."""

    def test_no_timer_functions(self):
        for name in ("control", "MODES", "INTERVALS", "MIN_INTERVAL", "HOW_KO"):
            self.assertFalse(hasattr(inbox, name), name)

    def test_old_demo_state_continues_by_date(self):
        self.write({"mode": "demo", "running": True, "interval_sec": 5, "timer_base": "2026-11-06T20:00:00+09:00",
                    "arrived": {TEAM: {"at": "2026-11-06T20:00:00+09:00", "how": "reset"}}, "read": [TEAM]})
        v = inbox.view(T("2026-11-07T10:00:00+09:00"))
        self.assertEqual(self.ids(v), [DBSG, TEAM, IAM, S3])            # 날짜가 지난 요청 2 · 3 · 4 가 들어옴 (타이머로 더 오지 않음) — 받은 시각 순
        self.assertEqual(v["items"][1]["at_text"], "2026-11-06 20:00")      # 이미 받은 요청의 받은 시각은 그대로
        st = json.loads(Path(os.environ["IACPATCH_INBOX_FILE"]).read_text(encoding="utf-8"))
        self.assertEqual(sorted(st), ["arrived", "read", "ver"])           # 저장할 때 타이머 칸은 남기지 않음


class ManualTests(_Tmp):
    def test_insert_rules(self):
        now = T("2026-11-05T14:00:00+09:00")
        self.write({"arrived": {TEAM: {"at": "2026-11-05T09:10:00+09:00", "how": "date"}}})
        bad = [{"id": "board-saas", "by": "김판종"}, {"id": DBSG, "by": "  "}, {"id": DBSG, "by": "가" * 31},
               {"id": DBSG, "by": "김판종", "memo": "메" * 201}, {"id": TEAM, "by": "김판종"}]
        for b in bad:
            with self.assertRaises(inbox.InboxError, msg=b):
                inbox.insert(b, now)
        v = inbox.insert({"id": "three-tier-team-flowlog", "by": "  김판종 ", "memo": "발표 중   질문 받고 넣음"}, now)
        top = v["items"][0]
        self.assertEqual((top["id"], top["by"], top["memo"], top["seq"], top["at_text"]), ("three-tier-team-flowlog", "김판종", "발표 중 질문 받고 넣음", 10, "2026-11-05 14:00"))
        self.assertEqual(top["title"], request.REQUESTS["three-tier-team-flowlog"]["title"])      # 요청 내용은 정해 둔 그대로
        self.assertNotIn("three-tier-team-flowlog", [p["id"] for p in v["pending"]])
        rec = json.loads(Path(os.environ["IACPATCH_INBOX_FILE"]).read_text(encoding="utf-8"))["arrived"]["three-tier-team-flowlog"]
        self.assertEqual(rec["how"], "manual")                         # 기록에는 남김 (화면에는 '고객 역할로 넣은 사람' 줄로만)


class VisibilityTests(_Tmp):
    def test_unarrived_requests_are_not_listed(self):
        self.write({"arrived": {TEAM: {"at": "2026-11-05T09:10:00+09:00", "how": "date"}, S3: {"at": "2026-11-05T11:00:00+09:00", "how": "manual", "by": "김판종"}}})
        self.assertTrue(inbox.is_arrived(TEAM))
        self.assertFalse(inbox.is_arrived(IAM))
        self.assertTrue(inbox.is_arrived("webapp-3tier"))              # 요청함 밖 예제는 늘 보임
        self.assertEqual([p["id"] for p in product.projects()["projects"] if p["kind"] == "example"], [TEAM, S3, "webapp-3tier"])
        allp = [p["id"] for p in product.projects(include_hidden=True)["projects"]]
        self.assertTrue(set(inbox.IDS) <= set(allp))                   # 주소로 직접 여는 것은 그대로
        self.assertIsNotNone(cases.get_case(IAM))

    def test_request_meta_uses_arrival(self):
        self.write({"arrived": {TEAM: {"at": "2026-11-05T11:05:00+09:00", "how": "manual", "by": "김판종", "memo": "질문"}}})
        m = request.meta(TEAM)
        self.assertEqual((m["date"], m["arrival"]["by"], m["arrival"]["memo"]), ("2026-11-05 11:05", "김판종", "질문"))
        self.assertNotIn("how_ko", m["arrival"])
        self.assertEqual((m["arrival"]["sender"], m["arrival"]["priority"]), ("운영팀 보안 담당", "긴급"))
        m2 = request.meta(DBSG)                                         # 아직 안 옴: 받은 시각 없음
        self.assertEqual(m2["date"], "")
        self.assertNotIn("at", m2["arrival"])
        self.assertIsNone(inbox.arrival("webapp-3tier"))


class StatusTests(_Tmp):
    def test_read_and_handoff(self):
        now = T("2026-11-05T12:00:00+09:00")
        self.write({"arrived": {TEAM: {"at": "2026-11-05T09:10:00+09:00", "how": "date"}, DBPUB: {"at": "2026-11-05T11:00:00+09:00", "how": "manual", "by": "김"}}, "read": [TEAM]})
        v = inbox.view(now)
        self.assertEqual((v["items"][0]["id"], v["items"][0]["unread"], v["items"][0]["status"]["word"], v["unread"]), (DBPUB, True, "새 요청", 1))
        inbox.mark_read(DBPUB)
        v = inbox.view(now)
        self.assertEqual((v["items"][0]["unread"], v["items"][0]["status"]["word"], v["unread"]), (False, "사람에게 넘김", 0))

    def test_status_reads_records_only(self):
        now = T("2026-11-05T12:00:00+09:00")
        self.write({"arrived": {TEAM: {"at": "2026-11-05T09:10:00+09:00", "how": "date"}}, "read": [TEAM]})
        rec = Path(self.tmp) / "rec1"
        rec.mkdir()
        with mock.patch("iacpatch.web.cases._records_for", return_value=[]):
            self.assertEqual(inbox.view(now)["items"][0]["status"]["word"], "확인함")
        with mock.patch("iacpatch.web.cases._records_for", return_value=[("r1", {}, rec)]):
            self.assertEqual(inbox.view(now)["items"][0]["status"]["word"], "처리 중 · 검토 1건")
            (rec / "decision.json").write_text(json.dumps({"decision": "APPROVED"}), encoding="utf-8")
            self.assertEqual(inbox.view(now)["items"][0]["status"]["word"], "승인됨")


class RouteTests(_Tmp):
    """화면이 부르는 길: GET /api/inbox · POST insert · read (잘못된 요청은 400 + 이유). 17차: POST /api/inbox/control 은 없음."""

    def test_routes(self):
        from test_web import _Srv
        srv = _Srv()
        self.addCleanup(srv.httpd.server_close)
        self.addCleanup(srv.close)
        st, v = srv.getj("/api/inbox")
        self.assertEqual((st, v["total"], [i["id"] for i in v["items"]]), (200, 11, [TEAM]))
        st, r = srv.post("/api/inbox/control", {"action": "next"})
        self.assertNotEqual(st, 200)                                     # 지금 받기 · 처음부터 · 타이머 길은 뺐다
        st, r = srv.post("/api/inbox/insert", {"id": S3, "by": "김판종"})
        self.assertEqual((st, [i["id"] for i in r["items"]]), (200, [S3, TEAM]))
        st, r = srv.post("/api/inbox/insert", {"id": DBPUB, "by": ""})
        self.assertEqual((st, r["ok"]), (400, False))
        self.assertIn("이름", " ".join(r["errors"]))
        st, r = srv.post("/api/inbox/insert", {"id": DBPUB, "by": "김판종", "memo": "질문"})
        self.assertEqual((st, r["items"][0]["id"], r["items"][0]["by"]), (200, DBPUB, "김판종"))
        st, r = srv.post("/api/inbox/read", {"id": DBPUB})
        self.assertEqual((st, r["ok"]), (200, True))
        st, v = srv.getj("/api/inbox")
        self.assertEqual(next(i for i in v["items"] if i["id"] == DBPUB)["status"]["word"], "사람에게 넘김")
        st, pr = srv.getj("/api/p/projects")
        self.assertEqual([p["id"] for p in pr["projects"] if p["kind"] == "example"], [TEAM, S3, DBPUB, "webapp-3tier"])


class LoadTests(_Tmp):
    def test_broken_or_odd_state_opens_with_defaults(self):
        Path(os.environ["IACPATCH_INBOX_FILE"]).write_text("{깨짐", encoding="utf-8")
        self.assertEqual(inbox.load(), inbox._default())
        self.write({"mode": "fast", "interval_sec": 1, "running": True, "arrived": {"nope": {"at": "2026-11-05T09:10:00+09:00"}, TEAM: {"at": "어제"},
                                                                                      S3: {"at": "2026-11-06T10:30:00+09:00", "how": "date"}}, "read": ["nope", S3]})
        st = inbox.load()
        self.assertEqual(st, {"ver": 2, "arrived": {S3: {"at": "2026-11-06T10:30:00+09:00", "how": "date"}}, "read": [S3]})


if __name__ == "__main__":
    unittest.main()
