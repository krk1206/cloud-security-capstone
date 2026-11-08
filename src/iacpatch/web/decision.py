"""사람의 결정 기록 — 승인 / 수정 요청 / 후보 재생성 / 폐기 / 배포(apply) 실패.

기록 폴더(data/reviews/<id>/)에 decision.json 을 쓰고 state.json 의 human_decision 을 갱신한다.
승인은 검증을 덮지 못한다: 상태가 REVIEW_REQUIRED 이고 검토 수준이 LIGHT_REVIEW / FULL_REVIEW 이며,
실제 AWS 검사(시험 환경 V7·V8)가 VERIFIED 일 때만 받는다 (화면 버튼과 별개로 여기서 한 번 더 거른다).
예외 (2026-11-01, D-32): 실제 AWS 시험 환경이 없는 프로젝트(연결한 프로젝트 · 2계층 예제)는 실제 AWS 검사를 할 수 없다.
이때는 사람이 '실제 AWS 에서 확인하지 않았다' 는 것을 확인 표시(ack_unverified)해야만 승인을 받고, 그 사실을 결정 기록 · PR 제목 · 본문에 남긴다.
시험 환경이 있는 프로젝트(3계층)는 지금처럼 VERIFIED 가 필요하고, 실제 AWS 검사에서 통과하지 못한 기록은 확인 표시로도 승인할 수 없다.
승인하면 PR 초안(브랜치 이름·제목·본문·명령)을 만든다 — tools/github.prepare_pr(execute=False). push·PR 생성·병합은 하지 않는다.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import io
import json
from pathlib import Path
from typing import Any, Dict, Optional

DECISIONS = ("APPROVED", "CHANGES_REQUESTED", "REGENERATE", "DISCARDED", "APPLY_FAILED")
APPROVABLE_LEVELS = ("LIGHT_REVIEW", "FULL_REVIEW")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def _read(p: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def load_decision(record_dir: Path) -> Optional[Dict[str, Any]]:
    return _read(record_dir / "decision.json")


def _set_of(state: Dict[str, Any]) -> str:
    parts = str(state.get("scenario") or "").split("/")
    if parts and parts[0] == "ui":
        parts = parts[1:]
    return parts[0] if parts else ""


def can_approve(state: Dict[str, Any], ack_unverified: bool = False) -> tuple[bool, str]:
    from .explain import LEVEL_KO, STATE_KO
    st = str(state.get("state") or "")
    lv = str(state.get("review_level") or "")
    if st in ("VALIDATION_FAILED", "POLICY_BLOCKED"):
        return False, f"{STATE_KO.get(st, st)} — 차단된 수정안은 승인 불가 (사람의 승인으로 검증 실패를 대체할 수 없음)"
    if st != "REVIEW_REQUIRED":
        return False, f"{STATE_KO.get(st, st)} — 검토 자료가 준비된 수정안만 승인 가능"
    if lv not in APPROVABLE_LEVELS:
        return False, f"{LEVEL_KO.get(lv, lv)} — 검증 통과 수정안만 승인 가능"
    if str(state.get("verification_status")) != "COMPLETE":
        return False, "결과가 없는 검증이 있어 승인 불가"
    # 설계도 확정 (D-38): 초안(자동 기준 · 확정 전)으로 검사한 결과는 '고객 요구 충족' 이 아니다 — 담당자가 ③ 에서 확정한 뒤 다시 검사해야 승인 가능.
    # 확정 정보가 없는 예전 기록(11-02 전)은 이 조건을 적용하지 않는다 (당시 기준으로 해석)
    des = state.get("design") if isinstance(state.get("design"), dict) else {}
    conf = des.get("confirmation") if isinstance(des.get("confirmation"), dict) else None
    if conf is not None and not conf.get("confirmed"):
        w = "IAM 요구사항" if str(conf.get("kind") or "") == "iam" else "설계도"
        return False, (f"{w} v{des.get('intent_version') or conf.get('version') or '?'} 는 초안(확정 전) — 이 검사는 초안 기준이라 '고객 요구 충족' 이 아님. "
                       "③ 원하는 구조에서 담당자가 확정한 뒤 다시 검사해야 승인 가능")
    # 실제 AWS 검사(2026-10-20 고친 흐름): 배포 전 검사(V1~V6)를 통과한 후보를 시험 환경에 반영해 V7·V8 을 재고 시험 환경을 지운다.
    # 두 단계를 모두 통과한 후보만 실제 환경 APPLY 를 요청할 수 있다.
    post = state.get("post_deploy") or {}
    if str(post.get("status") or "") == "PLAN_BLOCKED":
        return False, ("AWS 시험 환경 검사 차단 — 시험 환경 상태 기준 plan 에 교체·삭제 포함, apply 미실행. "
                       "배포 전 검사 · AWS 시험 환경 검사를 모두 통과해야 적용 승인 가능")
    if str(post.get("status") or "") != "VERIFIED":
        from .explain import POST_KO
        from .product import has_testbed
        st_ko = POST_KO.get(str(post.get("status")), str(post.get("status")))
        sid = _set_of(state)
        if not post.get("status") and sid and not has_testbed(sid):
            # 시험 환경이 없는 프로젝트 (D-32): 실제 AWS 검사를 할 수 없음 → 사람이 '미검증' 을 알고 승인할 때만.
            # 어느 묶음인지 모르는 기록(scenario 없음)은 이 길로 보내지 않는다 — 실제 AWS 통과가 필요한 쪽(엄격)으로 둔다
            if not ack_unverified:
                return False, ("실제 AWS 미검증 — 이 프로젝트는 AWS 시험 환경이 없어 반영해 재지 않음. '실제 AWS 에서 확인하지 않은 것을 알고 승인' 을 "
                               "표시해야 승인할 수 있고, 그 사실이 결정 기록 · PR 에 남음")
            return True, "실제 AWS 미검증 상태로 승인 (사람이 확인 표시함)"
        why = "결과 없음 (미검증)" if not post else f"결과 '{st_ko}'"
        return False, f"AWS 시험 환경 검사(시험 환경 반영 → V7 적용 규칙 조회 · V8 통신 시험 → 삭제) {why} — 배포 전 검사 · AWS 시험 환경 검사를 모두 통과해야 적용 승인 가능"
    return True, ""


def record_decision(settings: Any, record_dir: Path, decision: str, reason: str = "", by: str = "", base_branch: str = "main",
                    ack_unverified: bool = False) -> Dict[str, Any]:
    decision = str(decision or "").upper()
    if decision not in DECISIONS:
        return {"error": f"알 수 없는 결정 값: {decision}"}
    state = _read(record_dir / "state.json")
    if state is None:
        return {"error": "기록 없음"}
    prev = load_decision(record_dir) or {"history": []}
    unverified_ack = False
    if decision == "APPROVED":
        ok, why = can_approve(state, ack_unverified)
        if not ok:
            return {"error": why, "refused": True}
        unverified_ack = bool(ack_unverified) and str((state.get("post_deploy") or {}).get("status") or "") != "VERIFIED"
    if decision == "APPLY_FAILED" and prev.get("decision") != "APPROVED":
        return {"error": "승인된 수정안에만 배포 실패 기록 가능", "refused": True}
    entry = {"decision": decision, "reason": reason or "", "by": by or "", "at": _now()}
    if unverified_ack:
        entry["aws_unverified_ack"] = True
    doc = {"decision": decision, "reason": reason or "", "by": by or "", "at": entry["at"], "history": list(prev.get("history") or []) + [entry]}
    if unverified_ack:
        doc["aws_unverified_ack"] = True
    pr: Dict[str, Any] = {}
    if decision == "APPROVED":
        # PR 초안이 결정(미검증 확인 여부)을 읽을 수 있게 먼저 쓴다
        (record_dir / "decision.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        from ..tools.github import prepare_pr
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = prepare_pr(settings, None, execute=False, review_id=str(record_dir), base_branch=base_branch)
        pr = {"rc": rc, "output": buf.getvalue()}
        for name in ("pr_commands.sh", "pr_body.md", "commit_message.txt"):
            p = record_dir / name
            if p.exists():
                pr[name.replace(".", "_")] = p.read_text(encoding="utf-8")
        doc["pr_draft"] = {"rc": rc, "base_branch": base_branch, "created_at": entry["at"]}
    (record_dir / "decision.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    state["human_decision"] = {"decision": decision, "at": entry["at"], "by": by or "", "reason": reason or ""}
    if unverified_ack:
        state["human_decision"]["aws_unverified_ack"] = True
    (record_dir / "state.json").write_text(json.dumps(state, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return {"ok": True, "decision": doc, "pr": pr}
