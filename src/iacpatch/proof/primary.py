"""카드에서 처음부터 펼쳐 보여 줄 증거(key)를 고른다.

화면에는 질문 · 결과 요약 한 줄 · 핵심 그림(또는 표) 하나만 둔다. 나머지(확인 방법·순서·실행한 명령·다른 증거·기준·한계·파일)는 '자세히' 안에 접어 둔다.
판정·값은 바꾸지 않는다 — 어떤 블록을 먼저 보여 줄지만 정한다. 모든 블록은 그대로 남아 있다.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

# 단계별로 먼저 보여 줄 증거 블록 제목(앞부분). 비어 있으면 답 한 줄(과 그림)만 보인다.
KEY_TITLES: Dict[str, Tuple[str, ...]] = {
    "V1": ("변경 행",),
    "V2": ("신규 탐지",),
    "V3": ("오류 내용",),
    "V4": (),
    "V5": ("규칙 변경 내용", "정책 위반"),
    "V6": ("설계 외 허용 경로", "서비스별 허용 출발지", "필수 통신"),   # 뒤의 둘은 요구사항 목록 방식(2계층 사례)
    "임시": (),
    "V7": ("수정 전 → 수정 후", "설계 외 허용 경로"),
    "V8": ("요약", "기대 결과와 다른 시험", "수정 전 → 수정 후 결과 변화"),
}
# 실패한 카드는 실패 이유가 보이는 블록을 더 앞에 둔다
KEY_TITLES_FAIL: Dict[str, Tuple[str, ...]] = {
    "임시": ("plan 변경 대상 리소스", "교체 원인 값", "terraform plan 출력"),   # plan 확인에서 교체·삭제가 나와 apply 하지 않은 후보
    "V1": ("변경 행", "수정 후 결과"),
    "V4": ("terraform 오류 출력", "실행 계획"),
    "V5": ("변경 위치", "정책 위반"),        # 무엇을 몇 개 바꿨나 (리소스 수 초과·허용되지 않은 속성)
}


def _broken_rows(b: Dict[str, Any]) -> bool:
    """표의 마지막 칸이 '허용 규칙 없음'(필수 통신) — 예전 화면 말 '누락' · '끊김' 도 같은 뜻 (2026-10-31 문구 변경: V6 는 규칙만 본다)."""
    return any(str(r[-1]) in ("허용 규칙 없음", "누락", "끊김") for r in b.get("rows") or [] if r)


def _empty_table(b: Dict[str, Any]) -> bool:
    """행이 없는 표('없음')는 앞에 두지 않는다 — 요약 한 줄이 같은 내용을 이미 표시한다."""
    return b.get("t") == "table" and not b.get("rows")


def _said(b: Dict[str, Any], summary: str) -> bool:
    """한 줄짜리 표인데 그 내용이 요약 한 줄에 이미 있으면 앞에 두지 않는다 (같은 문장을 두 번 보이지 않음)."""
    rows = b.get("rows") or []
    if b.get("t") != "table" or len(rows) != 1 or not summary:
        return False
    cells = [str(x).strip() for x in rows[0] if str(x).strip()]
    return bool(cells) and all(x in summary for x in cells)


def mark(card: Dict[str, Any]) -> Dict[str, Any]:
    """card['evidence'] 의 각 블록에 key=True/False 를 단다."""
    ev = [b for b in card.get("evidence") or [] if isinstance(b, dict)]
    layer = str(card.get("layer"))
    summary = str(card.get("summary") or "")
    pre = KEY_TITLES_FAIL.get(layer) if card.get("verdict") == "FAIL" and layer in KEY_TITLES_FAIL else KEY_TITLES.get(layer, ())
    for b in ev:
        t = str(b.get("title") or "")
        b["key"] = bool(t) and any(t.startswith(p) for p in pre) and not _empty_table(b) and not _said(b, summary)
        # V6 의 설계 기준 경로 표는 허용 규칙 없는 필수 통신이 있을 때만 앞에 (없으면 그림이 같은 내용을 보여 줌)
        if layer == "V6" and t.startswith(("설계 기준 경로", "설계도 통신")) and _broken_rows(b):
            b["key"] = True
    return card
