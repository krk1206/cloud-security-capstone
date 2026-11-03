"""증거 보고서 (HTML 한 파일). 화면의 단계별 카드와 같은 내용을 인쇄·보관용으로 묶는다. 외부 파일·네트워크 없이 열린다."""
from __future__ import annotations

import html
from typing import Any, Dict, List

from . import plain

VCLS = {"PASS": "ok", "FAIL": "bad", "WARN": "warn", "UNKNOWN": "warn", "ERROR": "bad", "NOT_RUN": "dim", "SKIPPED": "dim"}

CSS = """
:root{--fg:#1d2433;--mut:#5b6474;--line:#d9dee7;--bg:#fff;--ok:#0f7a3d;--bad:#b42318;--warn:#a15c00;--code:#f6f7f9}
*{box-sizing:border-box}body{margin:0;font:13px/1.55 "Pretendard","Malgun Gothic","Apple SD Gothic Neo",system-ui,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:1000px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;padding-top:14px;border-top:2px solid var(--fg)}h3{font-size:13px;margin:14px 0 6px}
.mut{color:var(--mut)}.mono,code,pre{font-family:"D2Coding","Consolas",ui-monospace,monospace}
table{border-collapse:collapse;width:100%;margin:4px 0 8px}th,td{border:1px solid var(--line);padding:4px 7px;text-align:left;vertical-align:top}th{background:#f2f4f7;font-weight:600}
.v{display:inline-block;padding:1px 8px;border-radius:3px;font-weight:700;border:1px solid}.v.ok{color:var(--ok)}.v.bad{color:var(--bad)}.v.warn{color:var(--warn)}.v.dim{color:var(--mut)}
tr.ok td:first-child,tr.good td:first-child{border-left:3px solid var(--ok)}tr.bad td:first-child{border-left:3px solid var(--bad)}tr.warn td:first-child{border-left:3px solid var(--warn)}
pre{background:var(--code);border:1px solid var(--line);padding:6px 8px;overflow-x:auto;margin:4px 0;font-size:12px}
.code{background:var(--code);border:1px solid var(--line);font:12px/1.5 "D2Coding","Consolas",monospace;margin:4px 0}
.code div{white-space:pre;padding:0 8px}.code .n{display:inline-block;width:36px;color:var(--mut)}.code .m{background:#fff3c4}
.grid{display:grid;grid-template-columns:150px 1fr;gap:2px 12px}.k{color:var(--mut)}
.glance td:nth-child(1){width:44px;font-weight:700}.glance td:nth-child(3){width:96px;white-space:nowrap}.glance a{color:inherit}
@media print{h2{break-before:page}}
"""


def _e(x: Any) -> str:
    return html.escape("" if x is None else str(x))


def _sid(layer: Any) -> str:
    """보고서 안 이동용 id (단계 이름 → s-V1, s-tmp 등)."""
    t = str(layer or "")
    return "s-tmp" if t == "임시" else "s-" + ("".join(ch for ch in t if ch.isascii() and ch.isalnum()) or "x")


def _tag(layer: Any) -> str:
    """단계 표시 이름 — 기록의 단계 키(임시)는 그대로 두고 보고서에서만 '반영'(시험 환경 반영)으로 보여 준다."""
    t = str(layer or "")
    return "반영" if t == "임시" else t


def _n(x: Any) -> str:
    """숫자는 천 단위 쉼표 (2000 → 2,000). 숫자가 아니면 그대로."""
    return f"{x:,}" if isinstance(x, int) and not isinstance(x, bool) else _e(x)


def cal_ok(cal: Dict[str, Any]) -> bool:
    """화면의 검증 도구 사전 점검 '통과' 와 같은 기준: Trivy 정답 시료를 실제로 돌려 모두 맞고, 대역 계산 불일치 0, validate 시료를 잡음."""
    s = (cal or {}).get("summary") or {}
    return bool(s.get("trivy_total")) and s.get("trivy_correct") == s.get("trivy_total") and s.get("cidr_mismatches") == 0 and bool(s.get("validate_ok"))


def _own_post(c: Dict[str, Any]) -> bool:
    """이 기록의 후보를 직접 잰 2차 카드인가 (수정 전·원본 측정을 대신 보여 주는 카드는 아니다)."""
    return c.get("status") == "done" and c.get("scope") != "before"


def _glance(cal: Dict[str, Any], blocked: Dict[str, Any], cards: List[Dict[str, Any]], post: List[Dict[str, Any]], first_ok: bool) -> str:
    """맨 위 요약 — 단계마다 판정과 한 줄 근거. 자세한 증거는 아래 각 절."""
    rows: List[str] = []

    def row(no: str, name: str, verdict: str, tone: str, line: str, sid: str = "") -> None:
        nm = f'<a href="#{sid}">{_e(name)}</a>' if sid else _e(name)
        rows.append(f'<tr class="{tone}"><td>{_e(no)}</td><td>{nm}</td><td><span class="v {tone}">{_e(verdict)}</span></td><td>{_e(line)}</td></tr>')

    if cal:
        s = cal.get("summary") or {}
        d = (cal.get("cidr") or {}).get("differential") or {}
        ok = cal_ok(cal)
        row("0", "검증 도구 사전 점검", "통과" if ok else "경고", "ok" if ok else "warn",
            f"Trivy 점검 시료 검증 결과 {s.get('trivy_correct')}/{s.get('trivy_total')} 일치" + (" + 알려진 미탐지 사례 1건 재현" if s.get("known_limit_reproduced") else "")
            + f" · IP 대역 계산 {_n(d.get('cases'))}회 교차 검증, 결과 불일치 {_n(d.get('mismatches'))}건 · 잘못된 Terraform 구성 {'탐지' if s.get('validate_ok') else '미탐지'}"
            + " (시료 기준 동작 확인 — 전체 탐지 정확도 보장 아님)", "s-0")
    else:
        row("0", "검증 도구 사전 점검", "기록 없음", "dim", "이 기록에 사전 점검 결과 없음", "s-0")
    if blocked:
        row("정책", str(blocked.get("stage") or "정책 확인 (검사 전)"), "차단", "bad", "; ".join((blocked.get("violations_ko") or blocked.get("violations") or [])[:2]) or "policy.json 참고", "s-policy")
    if blocked and cards and all(c.get("status") != "done" for c in cards):
        row("V1~V6", "코드 검사 6개", "미실행", "dim", "정책 확인에서 차단되어 검사 미실행")
    else:
        for c in cards:
            v = str(c.get("verdict") or "")
            done = c.get("status") == "done"
            row(_tag(c.get("layer")), str(c.get("name") or ""), str(c.get("verdict_ko") or "기록 없음") if done else "기록 없음",
                VCLS.get(v, "dim") if done else "dim", str(c.get("summary") or c.get("reason") or "") if done else str(c.get("reason") or ""),
                _sid(c.get("layer")) if done else "")
    for c in post:
        v = str(c.get("verdict") or "")
        if _own_post(c):
            row(_tag(c.get("layer")), str(c.get("name") or ""), str(c.get("verdict_ko") or ""), VCLS.get(v, "dim"),
                str(c.get("summary") or c.get("reason") or ""), _sid(c.get("layer")))
        elif c.get("skipped"):
            # 앞 단계(plan 확인)에서 막혔거나, 시험 환경이 없는 사례 — 이유를 그대로
            row(_tag(c.get("layer")), str(c.get("name") or ""), "해당 없음" if c.get("skipped") == "case" else "미실행", "dim",
                str(c.get("reason") or ""))
        elif first_ok:
            row(_tag(c.get("layer")), str(c.get("name") or ""), "미검증", "dim", "이 후보는 시험 환경 반영·측정 전")
        else:
            row(_tag(c.get("layer")), str(c.get("name") or ""), "대상 아님", "dim", "배포 전 검사 통과 후보만 실제 AWS 검사(시험 환경) 진행")
    return ("<h2>요약</h2><p class=mut>단계별 판정과 근거 한 줄. 단계 이름을 누르면 해당 단계의 명령·증거·기준·한계로 이동.</p>"
            '<table class="glance"><thead><tr><th>단계</th><th>이름</th><th>판정</th><th>근거</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table>")


def _blocked(b: Dict[str, Any]) -> str:
    if not b:
        return ""
    return ('<section id="s-policy"><h2>정책 · 정책 확인 (검사 전) <span class="v bad">차단</span></h2>'
            "<p><b>수정 내용이 팀 정책 허용 범위 안인가</b><br><span class=mut>V1~V6 시작 전 차단 — 확신도·위험도와 무관하게 정책 위반이면 검사하지 않음</span></p>"
            "<h3>위반 항목 · 기록 폴더 policy.json</h3><ul>" + "".join(f"<li>{_e(v)}</li>" for v in b.get("violations_ko") or b.get("violations") or []) + "</ul>"
            + "<p class=mut>원문: " + "; ".join(_e(v) for v in b.get("violations") or []) + "</p></section>")


def _block(b: Dict[str, Any]) -> str:
    t = b.get("t")
    title = f"<h3>{_e(b.get('title'))}</h3>" if b.get("title") else ""
    if t == "kv":
        return title + '<div class="grid">' + "".join(f'<div class="k">{_e(k)}</div><div>{_e(v)}</div>' for k, v in b.get("rows") or []) + "</div>"
    if t == "table":
        rows = b.get("rows") or []
        if not rows:
            return title + f'<p class="mut">{_e(b.get("empty") or "없음")}</p>'
        tones = b.get("tones") or []
        head = "".join(f"<th>{_e(h)}</th>" for h in b.get("head") or [])
        body = "".join(f'<tr class="{_e(tones[i] if i < len(tones) else "")}">' + "".join(f"<td>{_e(c)}</td>" for c in r) + "</tr>" for i, r in enumerate(rows))
        return title + f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
    if t == "code":
        lines = "".join(f'<div class="{"m" if l.get("mark") else ""}"><span class="n">{_e(l.get("n"))}</span>{_e(l.get("text"))}</div>' for l in b.get("lines") or [])
        return f"<h3>{_e(b.get('title'))} <span class=\"mut mono\">{_e(b.get('file'))}</span></h3><div class=\"code\">{lines}</div>"
    if t == "note":
        return f'<p class="mut">{_e(b.get("text"))}</p>'
    if t == "stats":
        return title + "<p>" + " · ".join(f"<b>{_e(x.get('label'))}</b> {_e(x.get('value'))}" for x in b.get("items") or []) + "</p>"
    if t == "diffline":
        rows = [("수정 전", l) for l in b.get("old") or []] + [("수정 후", l) for l in b.get("new") or []]
        return (f"<h3>{_e(b.get('title'))} <span class=\"mut mono\">{_e(b.get('file'))}</span></h3><div class=\"code\">"
                + "".join(f'<div class="{"m" if k == "수정 전" else ""}"><span class="n">{_e(l.get("n"))}</span>{_e(k)}: {_e(str(l.get("text") or "").strip())}</div>' for k, l in rows) + "</div>")
    return ""


def _card(c: Dict[str, Any]) -> str:
    v = c.get("verdict")
    out = [f'<h2>{_e(_tag(c.get("layer")))} · {_e(c.get("name"))} <span class="v {VCLS.get(str(v), "dim")}">{_e(c.get("verdict_ko") or "기록 없음")}</span></h2>',
           f'<p><b>{_e(c.get("question"))}</b><br>{_e(c.get("summary"))}</p>'
           + (f'<p class=mut>확인 방법 — {_e(c.get("how"))}</p>' if c.get("how") else "")]
    m = c.get("method") or {}
    out.append("<h3>검사 순서</h3><ol>" + "".join(f"<li>{_e(s)}</li>" for s in m.get("steps") or []) + "</ol>")
    cmds = [x for x in m.get("commands") or [] if x.get("cmd")]
    if cmds:
        out.append("<h3>실행 명령 (기록 commands.json)</h3><table><thead><tr><th>단계</th><th>명령</th><th>시작</th><th>소요 시간</th><th>종료 코드</th></tr></thead><tbody>"
                   + "".join(f"<tr><td class=mono>{_e(x.get('step'))}</td><td class=mono>{_e(x.get('cmd'))}</td><td>{_e(x.get('started_at'))}</td>"
                             f"<td>{_e(x.get('elapsed_s'))}s</td><td>{_e(x.get('returncode'))}</td></tr>" for x in cmds) + "</tbody></table>")
    for x in m.get("commands") or []:
        if x.get("cached"):
            out.append(f'<p class="mut">{_e(x.get("step"))}: {_e(x.get("note"))} (최초 생성 시각 {_e(x.get("cache_created_at"))})</p>')
        elif not x.get("cmd") and x.get("note"):
            out.append(f'<p class="mut">{_e(x.get("note"))}</p>')
    out.append("".join(_block(b) for b in c.get("evidence") or []))
    bs = c.get("basis") or {}
    if bs.get("standard"):
        out.append("<h3>외부 기준 (확인 상태 표시)</h3><table><thead><tr><th>기관</th><th>문서 · 항목</th><th>내용</th><th>확인</th></tr></thead><tbody>"
                   + "".join(f"<tr><td>{_e(s.get('org'))}</td><td>{_e(s.get('doc'))}<br><b>{_e(s.get('item'))}</b></td><td>{_e(s.get('text'))}<br>"
                             f"<span class=mut>{_e(s.get('detail'))}</span><br><span class=\"mut mono\">{_e(s.get('url'))}</span></td>"
                             f"<td>{_e(s.get('status'))}<br><span class=mut>{_e(s.get('checked'))}</span></td></tr>" for s in bs["standard"]) + "</tbody></table>")
    for key, ttl in (("team", "팀 요구사항 (외부 기준 아님)"), ("tool", "도구"), ("cross", "교차 확인 (다른 방식으로 재계산)")):
        if bs.get(key):
            out.append(f"<h3>{ttl}</h3><div class=grid>" + "".join(f'<div class="k">{_e(x.get("k"))}</div><div>{_e(x.get("v"))}</div>' for x in bs[key]) + "</div>")
    out.append(f"<h3>판정 근거</h3><p>{_e(c.get('reason'))}</p>")
    if c.get("limits"):
        out.append("<h3>검사 한계</h3><ul>" + "".join(f"<li>{_e(x)}</li>" for x in c["limits"]) + "</ul>")
    if c.get("leaves"):
        out.append("<h3>근거 파일</h3><table><tbody>" + "".join(f"<tr><td class=mono>{_e(x.get('path'))}</td><td class=mono>{_e((x.get('sha256') or '')[:16])}</td></tr>"
                                                             for x in c["leaves"]) + "</tbody></table>")
    return f'<section id="{_sid(c.get("layer"))}">' + "".join(out) + "</section>"


def _calibration(cal: Dict[str, Any]) -> str:
    if not cal:
        return '<section id="s-0"><h2>0 · 검증 도구 사전 점검</h2><p class=mut>이 기록에 사전 점검 결과 없음.</p></section>'
    s = cal.get("summary") or {}
    rows: List[str] = []
    for r in cal.get("trivy") or []:
        rows.append(f"<tr><td>{_e(r.get('label'))}</td><td>{'위험' if r.get('risky') else '안전'}</td><td>{_e(plain.cal_result(r.get('result')))}</td><td>{_e(plain.cal_verdict(r.get('verdict')))}</td></tr>")
    d = ((cal.get("cidr") or {}).get("differential") or {})
    v = cal.get("validate") or {}
    pr = cal.get("probe") or []
    return ('<section id="s-0"><h2>0 · 검증 도구 사전 점검 — 기대 결과가 고정된 점검 시료로 도구 동작 확인</h2>'
            f"<p class=mut>점검 {_e(cal.get('id'))} · {_e(cal.get('started_at'))} · {'이전 점검 재사용' if cal.get('reused') else '이번 검사 직전 실행'}"
            " · 시료 기준 동작 확인이며 전체 탐지 정확도를 보장하지 않음</p>"
            "<h3>Trivy 점검 시료</h3><table><thead><tr><th>시료</th><th>기대 결과</th><th>Trivy</th><th>판정</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
            f"<h3>IP 대역 계산 교차 검증 (독립 구현 2개)</h3><p>무작위 대역 목록 {_n(d.get('cases'))}건 · 결과 불일치 {_n(d.get('mismatches'))}건 (seed {_e(d.get('seed'))})</p>"
            f"<h3>잘못된 Terraform 구성 탐지 (terraform validate)</h3><p>{_e(plain.legacy(v.get('sample') or v.get('reason')))} → 결과 {_e(v.get('result'))} · 판정 {_e(plain.cal_verdict(v.get('verdict')))}</p>"
            + (f"<pre>{_e((v.get('diagnostic') or {}).get('severity'))}: {_e((v.get('diagnostic') or {}).get('summary'))} — {_e((v.get('diagnostic') or {}).get('detail'))}</pre>" if isinstance(v.get('diagnostic'), dict) else "")
            + "<h3>통신 시험 판정 규칙 시료</h3><ul>" + "".join(f"<li>{_e(p.get('what') or p.get('label'))} <span class=mono>{_e(p.get('target'))}</span>: 기대 {_e(p.get('expect'))} · 결과 {_e(p.get('result'))} → {_e(plain.cal_verdict(p.get('verdict')))}</li>" for p in pr) + "</ul>"
            f"<p class=mut>요약: Trivy 검증 결과 {_e(s.get('trivy_correct'))}/{_e(s.get('trivy_total'))} 일치 · 알려진 미탐지 사례 재현 {'예' if s.get('known_limit_reproduced') else '아니오'} · IP 대역 계산 결과 불일치 {_n(s.get('cidr_mismatches'))}건</p></section>")


def _design_line(des: Any) -> str:
    """이 검사가 쓴 설계 기준 (2026-10-31 부터 기록). 없으면 그 사실을 적는다."""
    if not isinstance(des, dict) or not des.get("sha256"):
        return "<p class=mut>설계 기준: 기록 없음 (2026-10-31 이전 기록은 설계도 버전을 저장하지 않음)</p>"
    return (f"<p class=mut>설계 기준: {_e(des.get('intent_id'))} v{_e(des.get('intent_version'))} · sha256 {_e(str(des.get('sha256'))[:16])}…"
            f" · 사본 {_e(des.get('copy'))}</p>")


def render_report(view: Dict[str, Any]) -> str:
    cards = view.get("cards") or []
    post = (view.get("post") or {}).get("cards") or []
    man = view.get("manifest_files") or []
    head = (f"<h1>검증 증거 보고서 · {_e(view.get('record'))}</h1>"
            f"<p class=mut>{_e(view.get('candidate_label') or '')} · 후보 sha256 {_e((view.get('candidate_sha256') or '')[:16])}… · 시작 {_e(view.get('started_at'))} · 끝 {_e(view.get('finished_at'))}"
            f" · 검토 수준 {_e(view.get('level'))}</p>"
            + _design_line(view.get("design"))
            + "<p class=mut>판정 값은 기록 폴더의 verification.json · measure.json 값 그대로. 외부 기준의 '확인' 칸이 '대조 전'인 항목은 원문 대조 미완료.</p>")
    cal = view.get("calibration") or {}
    blocked = view.get("blocked_before") or {}
    first_ok = str(view.get("level") or "") in ("LIGHT_REVIEW", "FULL_REVIEW")
    # 자세한 절은 실제로 실행된 단계만 — 이 후보를 직접 재지 않은 2차 카드(수정 전 원본 측정)는 넣지 않는다
    body = (_glance(cal, blocked, cards, post, first_ok) + _calibration(cal) + _blocked(blocked)
            + "".join(_card(c) for c in cards if c.get("status") == "done") + "".join(_card(c) for c in post if _own_post(c)))
    mtab = ("<h2>근거 파일 · 기록 폴더 파일 목록 (evidence/manifest.json)</h2><table><thead><tr><th>파일</th><th>크기</th><th>sha256</th></tr></thead><tbody>"
            + "".join(f"<tr><td class=mono>{_e(f.get('path'))}</td><td>{_e(f.get('bytes'))}</td><td class=mono>{_e(f.get('sha256'))}</td></tr>" for f in man)
            + "</tbody></table>")
    return (f"<!doctype html><html lang=ko><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>검증 증거 · {_e(view.get('record'))}</title><style>{CSS}</style></head><body><main>{head}{body}{mtab}</main></body></html>")
