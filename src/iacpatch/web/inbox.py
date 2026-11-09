"""고객 요청함 (16차, D-52 — B 2026-11-06 "고객 요청을 실시간으로 들어오게 … 시간 지나면 진짜 새로 들어온 거마냥 들어올 수 있게, 실제 기반처럼").

가상 고객 '(가상) 3계층 웹 서비스 운영팀' 의 요청 11건(팀 3계층 요청 1 ~ 11)이 시간이 지나면 하나씩 '도착' 한다.
도착하기 전 요청은 ① 목록에 나오지 않는다 (주소로 직접 여는 것은 됨 — 숨긴 예제와 같음).

도착: 요청마다 정해 둔 도착 시각(SCHEDULE, 한국 시각)이 지나면 도착 — 다른 날 열면 그동안 온 요청이 쌓여 있다.
  11-05 ~ 11-14 에 걸쳐 들어오므로 기능 동결(11-16) 전에 모두 와 있다.
[고객 역할로 요청 넣기]: 팀원이 아직 안 온 요청 하나를 골라 이름 · 메모와 함께 바로 도착시킨다 (새 문제를 만들어 내지는 않음).
17차 (D-53, B 11-07 "발표용 타이머 같은 쓸데없는 내용 빼라" → 답: [요청 넣기]만 남기기): 발표용 타이머 · [다음 요청 지금 받기] ·
  [처음부터] · 방식 고르기를 뺐다. 예전 상태 파일의 mode · running · interval 칸은 읽지 않는다 (날짜 기준으로 이어진다).

판정 · 요청 내용 · 조건은 바꾸지 않는다 — 언제 보이는지 · 받은 시각 · 누가 넣었는지 · 읽었는지만 기록한다 (data/inbox/state.json, git 에 안 올림).
요청 · 고객 · 보낸 사람 · 사연은 예제를 위해 만든 가상이다 (화면에 '가상' 을 같이 적는다).
상태 줄(새 요청 · 확인함 · 처리 중 · 승인됨 · 사람에게 넘김)은 이미 있는 기록(검토 기록 · ⑧ 결정)을 읽어 보여 줄 뿐이다.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

CUSTOMER = "(가상) 3계층 웹 서비스 운영팀"
KST = _dt.timezone(_dt.timedelta(hours=9))
# 요청 순서 = 번호 순서. at = 날짜 기준 도착 시각(한국). sender · channel · priority · due 는 가상 요청표의 칸
SCHEDULE: List[Dict[str, str]] = [
    {"id": "three-tier-team", "at": "2026-11-05T09:10:00+09:00", "sender": "운영팀 보안 담당", "channel": "이메일 · 외부 점검 결과", "priority": "긴급", "due": "오늘 안"},
    {"id": "three-tier-team-s3", "at": "2026-11-06T10:30:00+09:00", "sender": "운영팀 보안 담당", "channel": "이메일", "priority": "높음", "due": "3일 안"},
    {"id": "three-tier-team-iam", "at": "2026-11-06T15:20:00+09:00", "sender": "운영팀 보안 담당", "channel": "이메일 · 점검 지적", "priority": "높음", "due": "3일 안"},
    {"id": "three-tier-team-dbsg", "at": "2026-11-07T09:40:00+09:00", "sender": "운영팀 보안 담당", "channel": "점검 도구 알림", "priority": "긴급", "due": "오늘 안"},
    {"id": "three-tier-team-dbpublic", "at": "2026-11-07T16:10:00+09:00", "sender": "개발팀 리드", "channel": "메신저", "priority": "높음", "due": "내일까지"},
    {"id": "three-tier-team-upload", "at": "2026-11-09T10:20:00+09:00", "sender": "개발팀 리드", "channel": "이메일 · 점검 지적", "priority": "높음", "due": "3일 안"},
    {"id": "three-tier-team-imds", "at": "2026-11-10T11:00:00+09:00", "sender": "운영팀 보안 담당", "channel": "이메일", "priority": "보통", "due": "이번 주 안"},
    {"id": "three-tier-team-dbenc", "at": "2026-11-11T14:30:00+09:00", "sender": "운영팀장", "channel": "이메일 · 개인정보 점검", "priority": "높음", "due": "날짜 협의"},
    {"id": "three-tier-team-deletion", "at": "2026-11-12T10:05:00+09:00", "sender": "운영팀장", "channel": "이메일", "priority": "보통", "due": "운영 전환 전"},
    {"id": "three-tier-team-flowlog", "at": "2026-11-13T16:40:00+09:00", "sender": "내부 감사 담당", "channel": "감사 지적서", "priority": "보통", "due": "다음 감사 전"},
    {"id": "three-tier-team-backup", "at": "2026-11-14T09:50:00+09:00", "sender": "운영팀 보안 담당", "channel": "점검 도구 알림", "priority": "보통", "due": "이번 주 안"},
]
IDS = [x["id"] for x in SCHEDULE]
_LOCK = threading.RLock()


class InboxError(ValueError):
    pass


def _root() -> Path:
    from .. import app as _app
    return _app.ROOT


def state_path() -> Path:
    """data/inbox/state.json (시험은 IACPATCH_INBOX_FILE 로 바꾼다 — 저장소 data 를 건드리지 않게)."""
    env = os.environ.get("IACPATCH_INBOX_FILE")
    return Path(env) if env else _root() / "data" / "inbox" / "state.json"


_T0 = _dt.datetime.now(_dt.timezone.utc)      # 프로그램이 켜진 시각 (시험용 시각에 흐른 시간을 더할 때)


def _now() -> _dt.datetime:
    """지금 시각. 자동 시험은 IACPATCH_INBOX_NOW(예: 2026-11-06T21:00:00+09:00)에서 시작해 프로그램이 켜진 뒤 흐른 만큼만 간다
    — 날짜가 지나도 시험 결과가 같고, 시험 중에 차례로 넣은 요청의 받은 시각 순서는 그대로 남는다."""
    t = _parse(os.environ.get("IACPATCH_INBOX_NOW")) if os.environ.get("IACPATCH_INBOX_NOW") else None
    real = _dt.datetime.now(_dt.timezone.utc)
    return (t + (real - _T0)).astimezone(_dt.timezone.utc) if t else real


def _iso(t: _dt.datetime) -> str:
    return t.astimezone(KST).isoformat(timespec="seconds")


def _parse(s: Any) -> Optional[_dt.datetime]:
    try:
        t = _dt.datetime.fromisoformat(str(s))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=KST)


def _default() -> Dict[str, Any]:
    return {"ver": 2, "arrived": {}, "read": []}


def load() -> Dict[str, Any]:
    p = state_path()
    try:
        st = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _default()
    out = _default()
    if isinstance(st, dict):          # 16차 파일의 mode · running · interval_sec · timer_base 는 버린다 (17차: 날짜 기준만)
        arr = st.get("arrived") if isinstance(st.get("arrived"), dict) else {}
        out["arrived"] = {k: v for k, v in arr.items() if k in IDS and isinstance(v, dict) and _parse(v.get("at"))}
        out["read"] = [x for x in st.get("read") or [] if x in out["arrived"]]
    return out


def save(st: Dict[str, Any]) -> None:
    p = state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, p)


def pending(st: Dict[str, Any]) -> List[Dict[str, str]]:
    return [x for x in SCHEDULE if x["id"] not in st["arrived"]]


def _deliver(st: Dict[str, Any], rid: str, at: _dt.datetime, how: str, by: str = "", memo: str = "") -> None:
    rec: Dict[str, Any] = {"at": _iso(at), "how": how}
    if by:
        rec["by"] = by
    if memo:
        rec["memo"] = memo
    st["arrived"][rid] = rec


def tick(st: Dict[str, Any], now: Optional[_dt.datetime] = None) -> List[str]:
    """정해 둔 도착 시각이 지난 요청을 도착시킨다. 새로 도착한 id 목록."""
    now = now or _now()
    new: List[str] = []
    for x in SCHEDULE:
        t = _parse(x["at"])
        if x["id"] not in st["arrived"] and t is not None and t <= now:
            _deliver(st, x["id"], t, "date")
            new.append(x["id"])
    return new


def _sync(now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """불러오기 + 도착 처리 + (바뀌었으면) 저장."""
    with _LOCK:
        st = load()
        before = json.dumps(st, sort_keys=True)
        tick(st, now)
        if json.dumps(st, sort_keys=True) != before:
            save(st)
        return st


def is_arrived(case_id: str, now: Optional[_dt.datetime] = None) -> bool:
    """요청함에 속한 예제가 아니면 언제나 True (3계층 실측 · 숨긴 예제 · 내 프로젝트)."""
    if case_id not in IDS:
        return True
    return case_id in _sync(now)["arrived"]


def arrival(case_id: str) -> Optional[Dict[str, Any]]:
    """받은 시각 · (고객 역할로 넣었으면) 넣은 사람 · 메모 + 요청표 칸. 요청함 밖이면 None."""
    if case_id not in IDS:
        return None
    st = _sync()
    a = st["arrived"].get(case_id)
    sch = next(x for x in SCHEDULE if x["id"] == case_id)
    out = {"sender": sch["sender"], "channel": sch["channel"], "priority": sch["priority"], "due": sch["due"], "customer": CUSTOMER}
    if a:
        out.update({"at": a["at"], "at_text": _short(a["at"]), "by": a.get("by") or "", "memo": a.get("memo") or ""})
    return out


def _short(iso: str) -> str:
    t = _parse(iso)
    return t.astimezone(KST).strftime("%Y-%m-%d %H:%M") if t else str(iso)


def insert(body: Dict[str, Any], now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """팀원이 고객 역할로 아직 안 온 요청 하나를 바로 도착시킨다 (이름 필수 · 메모 선택). 요청 내용은 정해 둔 그대로."""
    rid = str(body.get("id") or "")
    by = " ".join(str(body.get("by") or "").split())
    memo = " ".join(str(body.get("memo") or "").split())
    if rid not in IDS:
        raise InboxError(f"요청함에 없는 요청: {rid}")
    if not by:
        raise InboxError("고객 역할을 하는 사람 이름을 적어 주세요")
    if len(by) > 30:
        raise InboxError("이름은 30자까지")
    if len(memo) > 200:
        raise InboxError("메모는 200자까지")
    now = now or _now()
    with _LOCK:
        st = load()
        tick(st, now)
        if rid in st["arrived"]:
            raise InboxError("이미 도착한 요청")
        _deliver(st, rid, now, "manual", by, memo)
        save(st)
    return view(now)


def mark_read(case_id: str) -> Dict[str, Any]:
    with _LOCK:
        st = load()
        tick(st)
        if case_id in st["arrived"] and case_id not in st["read"]:
            st["read"].append(case_id)
            save(st)
    return {"ok": True}


def _status(case_id: str, kind: str, read: bool) -> Dict[str, str]:
    """요청표의 상태 칸 — 이미 있는 기록만 읽는다 (새 판정 없음)."""
    if kind == "handoff":
        return {"word": "사람에게 넘김", "tone": "warn"} if read else {"word": "새 요청", "tone": "new"}
    try:
        from . import cases as cs
        c = cs.get_case(case_id) or {}
        recs = cs._records_for(str(c.get("tf_dir") or "")) if c else []
    except Exception:  # noqa: BLE001
        recs = []
    decs = []
    for _rid, _st, d in recs:
        try:
            decs.append(str((json.loads((d / "decision.json").read_text(encoding="utf-8")) or {}).get("decision") or ""))
        except (OSError, ValueError):
            pass
    if "APPROVED" in decs:
        return {"word": "승인됨", "tone": "good"}
    if recs:
        return {"word": f"처리 중 · 검토 {len(recs)}건", "tone": "run"}
    return {"word": "확인함", "tone": "dim"} if read else {"word": "새 요청", "tone": "new"}


def view(now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """① 요청함 · 모든 화면의 새 요청 알림용."""
    from . import request as rq
    now = now or _now()
    st = _sync(now)
    items = []
    for x in SCHEDULE:
        a = st["arrived"].get(x["id"])
        if not a:
            continue
        r = rq.REQUESTS.get(x["id"]) or {}
        kind = rq._kind(r) if r else "topology"
        read = x["id"] in st["read"]
        items.append({"id": x["id"], "seq": r.get("seq"), "title": r.get("title"), "summary": r.get("summary"), "from": CUSTOMER,
                      "sender": x["sender"], "channel": x["channel"], "priority": x["priority"], "due": x["due"],
                      "at": a["at"], "at_text": _short(a["at"]), "by": a.get("by") or "", "memo": a.get("memo") or "", "unread": not read,
                      "kind": kind, "auto": kind != "handoff", "status": _status(x["id"], kind, read)})
    items.sort(key=lambda i: (_parse(i["at"]) or now, i["seq"] or 0), reverse=True)
    pend = pending(st)
    # 17차: 다음 요청이 언제 오는지는 보여 주지 않는다 (실제 요청함은 모른다). pending 은 [고객 역할로 요청 넣기] 창의 고르기 목록
    return {"customer": CUSTOMER, "fictional": True, "now": _iso(now), "items": items, "unread": sum(1 for i in items if i["unread"]),
            "total": len(SCHEDULE), "pending_count": len(pend),
            "pending": [{"id": x["id"], "seq": (rq.REQUESTS.get(x["id"]) or {}).get("seq"), "title": (rq.REQUESTS.get(x["id"]) or {}).get("title"),
                         "kind": rq._kind(rq.REQUESTS.get(x["id"]) or {}), "sender": x["sender"]} for x in pend]}
