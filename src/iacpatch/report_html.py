"""한 장짜리 HTML 리포트 (외부 의존성 없음, CSS/JS 인라인, 브라우저에서 바로 열림).

    python -m iacpatch.report_html [--out report/index.html]

입력은 전부 저장소 안의 실측 기록이다 — 숫자를 만들어내지 않는다:
  data/reviews/<id>/           후보별 기록 (state/verification/risk/diff)
  experiments/candidate-sets/<set>/manifest.json   expected 라벨·출처
  experiments/ORACLE_RESULTS.md, WHY_THIS_GATE.md, RESULTS_SUMMARY.md, run_experiments.log
색: dataviz 검증 팔레트 (series 파랑/주황, 상태 4색은 아이콘+글자와 함께만).
"""
from __future__ import annotations

import datetime as _dt
import html
import json
import platform
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from .metrics import collect

ROOT = Path(__file__).resolve().parents[2]
SETS = ["eval-a-probe-rule", "eval-seeded-sg", "eval-iam-rule", "eval-seeded-iam", "eval-claude-code"]
SET_TITLES = {"eval-a-probe-rule": "규칙 기반 baseline — SG (A 의 우회 케이스 9)", "eval-seeded-sg": "오라클 유무 (E2) — SG seeded 11",
              "eval-iam-rule": "규칙 기반 baseline — IAM (probe 5)", "eval-seeded-iam": "오라클 유무 (E2) — IAM seeded 13",
              "eval-claude-code": "LLM 축 — Claude Code 후보"}
LEVEL_KO = {"LIGHT_REVIEW": "경량 검토(PR 자동)", "FULL_REVIEW": "정식 검토(승인 필수)", "REPORT_ONLY": "리포트만", "BLOCKED": "차단", "PENDING": "검증 대기", "None": "-", None: "-"}
STATE_KO = {"REVIEW_REQUIRED": "검토 자료 생성", "VALIDATION_FAILED": "검증 실패(차단)", "POLICY_BLOCKED": "정책 위반(차단)", "CANDIDATE_INVALID": "후보 무효",
            "INFO_INSUFFICIENT": "정보 부족(후보 없음)", "NO_FINDING": "탐지 없음", "AMBIGUOUS_FINDING": "finding 모호", "INPUT_ERROR": "입력 오류"}


def esc(x: Any) -> str:
    return html.escape("" if x is None else str(x))


def badge(v: Any) -> str:
    v = "-" if v in (None, "", "-") else str(v)
    cls = {"PASS": "good", "FAIL": "critical", "UNKNOWN": "warning", "ERROR": "serious", "NOT_RUN": "muted", "SKIPPED": "muted", "WARN": "warning"}.get(v, "muted")
    icon = {"PASS": "✔", "FAIL": "✖", "UNKNOWN": "?", "ERROR": "!", "NOT_RUN": "·", "SKIPPED": "·", "WARN": "△"}.get(v, "")
    return f'<span class="badge {cls}" title="{esc(v)}">{icon} {esc(v)}</span>'


def level_badge(level: Any) -> str:
    l = str(level) if level else "None"
    cls = {"LIGHT_REVIEW": "good", "FULL_REVIEW": "warning", "REPORT_ONLY": "serious", "BLOCKED": "critical", "PENDING": "muted"}.get(l, "muted")
    return f'<span class="badge {cls}">{esc(LEVEL_KO.get(l, l))}</span>'


def md_tables_to_html(md: str) -> str:
    """마크다운의 '# 제목', 표(| ... |), 목록(- ), 문단을 최소한으로 HTML 로. 숫자·문구는 손대지 않는다."""
    out: List[str] = []
    lines = md.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(lines[i]); i += 1
            cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows if not re.match(r"^\|\s*-{3,}", r)]
            if cells:
                out.append("<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells[0]) + "</tr></thead><tbody>")
                for r in cells[1:]:
                    out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>")
                out.append("</tbody></table>")
            continue
        m = re.match(r"^(#{1,6})\s+(.*)", line)
        if m:
            h = min(len(m.group(1)) + 2, 5)
            out.append(f"<h{h}>{inline(m.group(2))}</h{h}>")
        elif line.startswith("- "):
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(lines[i][2:]); i += 1
            out.append("<ul>" + "".join(f"<li>{inline(x)}</li>" for x in items) + "</ul>")
            continue
        elif line.startswith("> "):
            out.append(f"<blockquote>{inline(line[2:])}</blockquote>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
        i += 1
    return "\n".join(out)


def inline(s: str) -> str:
    s = esc(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


def _load(p: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _labels(set_id: str) -> Dict[str, Dict[str, str]]:
    m = _load(ROOT / "experiments" / "candidate-sets" / set_id / "manifest.json") or {}
    return {f"{set_id}/{c['id']}": {"expected": c.get("expected", ""), "source": c.get("source", ""), "expected_risk": c.get("expected_risk", ""),
                                    "reason": c.get("expected_reason", "")} for c in m.get("candidates", [])}


def _latest_rows(rows: List[Dict[str, Any]], set_id: str) -> List[Dict[str, Any]]:
    by: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        scn = str(r.get("scenario") or "")
        if scn.startswith(set_id + "/") and (scn not in by or str(r["run_id"]) > str(by[scn]["run_id"])):
            by[scn] = r
    return sorted(by.values(), key=lambda r: str(r["scenario"]))


def _detail(run_id: str, reviews_root: Path) -> Dict[str, Any]:
    d = reviews_root / run_id
    diff = ""
    try:
        diff = (d / "candidate.diff").read_text(encoding="utf-8")
    except OSError:
        pass
    ver = _load(d / "verification.json") or {}
    layers = ((ver.get("report") or {}).get("layers") or [])
    risk = ((_load(d / "risk.json") or {}).get("decision") or {})
    st = _load(d / "state.json") or {}
    return {"diff": diff, "layers": layers, "risk": risk, "state": st, "dir": str(d)}


def _label_ok(exp: str, r: Dict[str, Any]) -> Optional[bool]:
    if not exp:
        return None
    st, v6, lvl = str(r.get("state")), r["layers"].get("V6"), str(r.get("review_level"))
    if exp == "correct":
        return r.get("verification_status") in ("COMPLETE", "PASS") and st not in ("VALIDATION_FAILED", "BLOCKED")
    if exp in ("deceptive", "breaks_required", "unapproved"):
        return v6 == "FAIL" or st == "VALIDATION_FAILED" or lvl in ("BLOCKED", "BLOCK")
    if exp == "unknown":
        return v6 == "UNKNOWN" or lvl in ("PENDING", "HOLD_FOR_HUMAN")
    if exp == "invalid":
        return st in ("CANDIDATE_INVALID", "INFO_INSUFFICIENT", "POLICY_BLOCKED", "GENERATION_FAILED", "INSUFFICIENT_INFO")
    if exp == "not_triggered":
        return st == "NO_FINDING"
    if exp == "unsupported":
        return st in ("INFO_INSUFFICIENT", "CANDIDATE_INVALID") and str(r.get("candidate_status")) in ("NOT_SUPPORTED", "INSUFFICIENT_INFO", "ABSTAIN")
    return None


CSS = """
:root{color-scheme:light;--bg:#fcfcfb;--panel:#ffffff;--line:#e6e5e1;--ink:#0b0b0b;--ink2:#52514e;--ink3:#8a8985;--s1:#2a78d6;--s2:#eb6834;
--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b;--muted:#a9a8a3;--code:#f3f2ee;--accent:#2a78d6}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#1a1a19;--panel:#222221;--line:#3a3a37;--ink:#fff;--ink2:#c3c2b7;--ink3:#8f8e88;--s1:#3987e5;--s2:#d95926;--code:#2a2a28;--accent:#3987e5}}
:root[data-theme=dark]{color-scheme:dark;--bg:#1a1a19;--panel:#222221;--line:#3a3a37;--ink:#fff;--ink2:#c3c2b7;--ink3:#8f8e88;--s1:#3987e5;--s2:#d95926;--code:#2a2a28;--accent:#3987e5}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,"Segoe UI","Malgun Gothic","Apple SD Gothic Neo",Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:24px 16px 80px}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:baseline;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:20px}
h1{font-size:22px;margin:0}h2{font-size:18px;margin:36px 0 12px;padding-top:8px;border-top:1px solid var(--line)}h3{font-size:16px;margin:20px 0 8px}h4,h5{margin:14px 0 6px}
.sub{color:var(--ink2);font-size:13px}.muted{color:var(--ink3)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile .n{font-size:30px;font-weight:700;letter-spacing:-.02em}.tile .l{color:var(--ink2);font-size:13px}.tile .m{color:var(--ink3);font-size:12px;margin-top:4px}
.banner{border:1px solid var(--line);border-left:4px solid var(--warning);background:var(--panel);padding:12px 14px;border-radius:8px;margin:12px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:8px 0 14px;background:var(--panel)}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--code);font-weight:600;color:var(--ink2)}
tr.row{cursor:pointer}tr.row:hover td{background:color-mix(in srgb,var(--accent) 8%,var(--panel))}tr.det td{background:var(--code)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid transparent;white-space:nowrap}
.badge.good{color:var(--good);border-color:var(--good)}.badge.critical{color:var(--critical);border-color:var(--critical)}.badge.warning{color:#8a5b00;border-color:var(--warning)}
:root[data-theme=dark] .badge.warning,:root:not([data-theme=light]) .badge.warning{color:var(--warning)}
.badge.serious{color:var(--serious);border-color:var(--serious)}.badge.muted{color:var(--ink3);border-color:var(--line)}
.ok{color:var(--good);font-weight:700;white-space:nowrap}.ng{color:var(--critical);font-weight:700;white-space:nowrap}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow:auto;font:12.5px/1.45 ui-monospace,Consolas,"D2Coding",monospace;max-height:420px}
code{background:var(--code);padding:0 4px;border-radius:4px;font-size:.92em}
.bars{display:grid;gap:10px;margin:10px 0 6px}.bar{display:grid;grid-template-columns:200px 1fr;gap:10px;align-items:center}
.bar .lbl{font-size:13px;color:var(--ink2)}.bar .tr{display:grid;gap:4px;max-width:calc(100% - 96px)}.bar .seg{height:14px;border-radius:0 4px 4px 0;position:relative;min-width:2px}
.bar .seg span{position:absolute;left:calc(100% + 6px);top:-3px;font-size:12px;color:var(--ink2);white-space:nowrap}
.legend{display:flex;gap:16px;font-size:12.5px;color:var(--ink2);margin:6px 0}.legend i{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.tabs{display:flex;flex-wrap:wrap;gap:6px;position:sticky;top:0;background:var(--bg);padding:8px 0;z-index:2;border-bottom:1px solid var(--line)}.tabs a{color:var(--ink2);text-decoration:none;border:1px solid var(--line);border-radius:999px;padding:3px 11px;font-size:13px;background:var(--panel)}.tabs a:hover{color:var(--accent);border-color:var(--accent)}
button.tg{border:1px solid var(--line);background:var(--panel);color:var(--ink2);border-radius:999px;padding:3px 10px;cursor:pointer;font-size:12px}
.diff{white-space:pre}.diff .a{color:var(--good)}.diff .d{color:var(--critical)}.diff .h{color:var(--ink3)}
details summary{cursor:pointer;color:var(--ink2)}
.tw{overflow-x:auto;max-width:100%}.tw table{min-width:520px}
@media (max-width:640px){.bar{grid-template-columns:1fr}.tiles{grid-template-columns:repeat(2,1fr)}h1{font-size:18px}}
"""

JS = """
function tg(){var r=document.documentElement;var cur=r.getAttribute('data-theme');var dark=cur?cur==='dark':matchMedia('(prefers-color-scheme: dark)').matches;r.setAttribute('data-theme',dark?'light':'dark')}
document.addEventListener('click',function(e){var tr=e.target.closest('tr.row');if(!tr)return;var d=document.getElementById(tr.dataset.det);if(d)d.style.display=d.style.display==='table-row'?'none':'table-row'});
"""


def _diff_html(diff: str) -> str:
    out = []
    for line in diff.splitlines():
        cls = "a" if line.startswith("+") and not line.startswith("+++") else "d" if line.startswith("-") and not line.startswith("---") else "h" if line.startswith(("@@", "+++", "---")) else ""
        out.append(f'<span class="{cls}">{esc(line)}</span>' if cls else esc(line))
    return "\n".join(out)


def build(out_path: Path, reviews_root: Optional[Path] = None) -> Path:
    reviews_root = reviews_root or ROOT / "data" / "reviews"
    rows = collect([reviews_root])
    now = _dt.datetime.now().isoformat(timespec="seconds")
    env_line = ""
    tools = None
    for r in sorted(rows, key=lambda x: str(x["run_id"]), reverse=True):
        t = _load(reviews_root / str(r["run_id"]) / "local_verify" / "tools.json")
        if t:
            tools = t; break
    if tools:
        bits = []
        for k, v in tools.items():
            if isinstance(v, dict):
                bits.append(f"{v.get('kind') or k} {v.get('version') or '없음'}" + (" (offline plan)" if v.get("offline_plan") else ""))
            elif isinstance(v, str):
                bits.append(f"{k}={v}")
        env_line = ", ".join(bits)[:200]

    # ---- 세트별 집계
    set_blocks: List[str] = []
    bars: List[Dict[str, Any]] = []
    total_not_run = 0
    total_rows = 0
    label_agree = label_total = 0
    spof_total = 0
    for set_id in SETS:
        labels = _labels(set_id)
        srows = _latest_rows(rows, set_id)
        title = SET_TITLES.get(set_id, set_id)
        if not srows:
            note = "후보 0건 — 아직 채우지 않음 (scripts/cc_prompt.py → Claude Code 새 세션 → scripts/cc_add.py)" if set_id == "eval-claude-code" else "실행 기록 없음"
            set_blocks.append(f'<h2 id="{set_id}">{esc(title)}</h2><p class="muted">{esc(note)}</p>')
            continue
        v1_only = sum(1 for r in srows if r["layers"].get("V1") == "PASS")
        v1_v6 = sum(1 for r in srows if r["layers"].get("V1") == "PASS" and r["layers"].get("V6") == "PASS")
        spof = sum(1 for r in srows if r["layers"].get("V1") == "PASS" and r["layers"].get("V6") == "FAIL")
        spof_total += spof
        nr = sum(1 for r in srows for k in ("V1", "V2", "V3", "V4", "V5", "V6") if r["layers"].get(k) in ("NOT_RUN", "ERROR", "SKIPPED"))
        total_not_run += nr
        total_rows += len(srows)
        agree = 0; labeled = 0
        trs: List[str] = []
        for i, r in enumerate(srows):
            lab = labels.get(str(r["scenario"]), {})
            ok = _label_ok(lab.get("expected", ""), r)
            if ok is not None:
                labeled += 1; agree += int(ok)
            det = _detail(str(r["run_id"]), reviews_root)
            did = f"det-{set_id}-{i}"
            layers = "".join(f"<td>{badge(r['layers'].get(k, '-'))}</td>" for k in ("V1", "V2", "V3", "V4", "V5", "V6"))
            okc = '<span class="ok">일치</span>' if ok else ('<span class="ng">불일치</span>' if ok is False else "-")
            trs.append(f'<tr class="row" data-det="{did}"><td>{esc(str(r["scenario"]).split("/", 1)[1])}</td><td>{esc(lab.get("source") or r["origin"])}</td>'
                       f'<td>{esc(STATE_KO.get(str(r["state"]), r["state"]))}</td><td>{level_badge(r["review_level"])}</td><td>{esc(r["risk"] or "-")}</td>{layers}'
                       f'<td>{esc(lab.get("expected", ""))}</td><td>{okc}</td><td>{esc(r.get("duration_s") if r.get("duration_s") is not None else "-")}</td></tr>')
            lay_rows = "".join(f"<tr><td>{esc(l.get('layer'))}</td><td>{badge(l.get('verdict'))}</td><td>{esc(l.get('summary', ''))[:300]}</td><td class='muted'>{esc(l.get('tool', ''))}</td></tr>" for l in det["layers"])
            fac = "".join(f"<li>{esc(f.get('factor'))}: {esc(f.get('value'))} <b>(+{esc(f.get('points', 0))})</b> <span class='muted'>{esc(f.get('note', ''))}</span></li>"
                          for f in det["risk"].get("factors", []) if f.get("points") or f.get("factor") in ("iam_resource_touched", "iam_trust_policy_changed", "resource_deleted", "resource_replaced"))
            trs.append(f'<tr class="det" id="{did}" style="display:none"><td colspan="15">'
                       f'<div class="sub">기대 라벨 근거: {esc(lab.get("reason", "") or "-")} · 기록: <code>{esc(det["dir"])}</code></div>'
                       f'<h4>검증 계층</h4><table><thead><tr><th>계층</th><th>판정</th><th>요약</th><th>도구</th></tr></thead><tbody>{lay_rows or "<tr><td colspan=4 class=muted>검증 기록 없음</td></tr>"}</tbody></table>'
                       f'<h4>위험도 {esc(det["risk"].get("risk_level", "-"))} (점수 {esc(det["risk"].get("score", "-"))}, {esc(det["risk"].get("rubric_version", ""))})</h4><ul>{fac or "<li class=muted>가산 요인 없음</li>"}</ul>'
                       f'<h4>diff</h4><pre class="diff">{_diff_html(det["diff"]) or "(diff 없음)"}</pre></td></tr>')
        label_agree += agree; label_total += labeled
        bars.append({"set": title.split(" — ")[0] + " · " + set_id, "v1": v1_only, "gate": v1_v6, "n": len(srows)})
        set_blocks.append(
            f'<h2 id="{set_id}">{esc(title)}</h2>'
            f'<div class="tiles"><div class="tile"><div class="n">{len(srows)}</div><div class="l">후보</div></div>'
            f'<div class="tile"><div class="n">{v1_only} → {v1_v6}</div><div class="l">재스캔(V1)만 통과 → 게이트(V1+V6) 통과</div><div class="m">차이 = V6 가 FAIL 또는 UNKNOWN(사람 검토)으로 돌린 수</div></div>'
            f'<div class="tile"><div class="n">{spof}</div><div class="l">스캐너 PASS ∧ 오라클 FAIL</div><div class="m">스캐너만 믿었으면 통과했을 기만/필수깨짐</div></div>'
            f'<div class="tile"><div class="n">{agree}/{labeled}</div><div class="l">기대 라벨 일치</div></div>'
            f'<div class="tile"><div class="n">{nr}</div><div class="l">미검증 계층(NOT_RUN/ERROR)</div><div class="m">{"0 이어야 결과가 완전" if nr else "완전"}</div></div></div>'
            f'<table><thead><tr><th>후보</th><th>출처</th><th>상태</th><th>검토 수준</th><th>위험도</th><th>V1</th><th>V2</th><th>V3</th><th>V4</th><th>V5</th><th>V6</th><th>기대</th><th>일치</th><th>소요(s)</th></tr></thead>'
            f'<tbody>{"".join(trs)}</tbody></table><p class="muted">행을 누르면 검증 계층·위험도 요인·diff 가 펼쳐진다.</p>')

    # ---- 바 차트 (세트별 V1만 vs 게이트)
    maxn = max([b["n"] for b in bars] + [1])
    bar_html = ""
    if bars:
        segs = []
        for b in bars:
            w1 = 100 * b["v1"] / maxn; w2 = 100 * b["gate"] / maxn
            segs.append(f'<div class="bar"><div class="lbl">{esc(b["set"])}</div><div class="tr">'
                        f'<div class="seg" style="width:{w1:.1f}%;background:var(--s1)"><span>재스캔만 {b["v1"]}</span></div>'
                        f'<div class="seg" style="width:{w2:.1f}%;background:var(--s2)"><span>게이트 {b["gate"]}</span></div></div></div>')
        bar_html = ('<div class="legend"><span><i style="background:var(--s1)"></i>재스캔(V1)만 믿었을 때 통과</span><span><i style="background:var(--s2)"></i>게이트(V1+V6) 통과</span></div>'
                    f'<div class="bars">{"".join(segs)}</div><p class="muted">막대 길이는 후보 수 기준(최대 {maxn}). 값은 표의 숫자와 같다.</p>')

    cc = _load(ROOT / "experiments/candidate-sets/eval-claude-code/manifest.json") or {}
    n_llm = len(cc.get("candidates") or [])
    aws_runs = sum(1 for r in rows if r.get("post_deploy", "-") not in ("-", None))
    oracle_md = (ROOT / "experiments" / "ORACLE_RESULTS.md").read_text(encoding="utf-8") if (ROOT / "experiments" / "ORACLE_RESULTS.md").exists() else ""
    why_md = (ROOT / "experiments" / "WHY_THIS_GATE.md").read_text(encoding="utf-8") if (ROOT / "experiments" / "WHY_THIS_GATE.md").exists() else ""
    summ_md = (ROOT / "experiments" / "RESULTS_SUMMARY.md").read_text(encoding="utf-8") if (ROOT / "experiments" / "RESULTS_SUMMARY.md").exists() else ""
    e1 = summ_md[summ_md.find("## E1"):] if "## E1" in summ_md else ""
    log_tail = ""
    lp = ROOT / "experiments" / "run_experiments.log"
    if lp.exists():
        log_tail = "\n".join(lp.read_text(encoding="utf-8", errors="replace").splitlines()[-80:])
    sg_blind = re.search(r"Security Group: 실제 plan (\d+)개 중 \*\*(\d+)개\*\*", why_md)
    iam_blind = re.search(r"IAM \(Tier 1\): 실제 plan (\d+)개 중 \*\*(\d+)개\*\*", why_md)

    parts = [f"<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>IaCPatch 실행 리포트</title><style>{CSS}</style></head><body><div class='wrap'>",
             f"<header><div><h1>AI가 생성한 테라폼 보안패치의 실효성 검증 자동화 — 실행 리포트</h1>"
             f"<div class='sub'>생성 {esc(now)} · {esc(platform.node())} · {esc(env_line) or '도구 기록 없음'} · 기록 {len(rows)}건 (세트별 최신 실행만 집계)</div></div>"
             f"<div><button class='tg' onclick='tg()'>라이트/다크</button></div></header>",
             "<nav class='tabs'>" + "".join(f"<a href='#{s}'>{esc(SET_TITLES[s].split(' — ')[0])}</a>" for s in SETS) + "<a href='#oracle'>오라클 실험</a><a href='#why'>기업용 한 장</a><a href='#e1'>E1</a><a href='#log'>로그</a></nav>",
             "<div class='banner'><b>이 리포트가 말하지 않는 것</b> — "
             f"AWS 실제 반영·배포 후 검증(V7/V8) 실행 <b>{aws_runs}회</b> · Claude Code(LLM) 후보 <b>{n_llm}건</b> (0 이면 LLM 축은 미측정) · 미검증 계층(NOT_RUN/ERROR) <b>{total_not_run}</b> · "
             "seeded 후보는 알려진 우회 패턴(사람/AI 세션 작성)이지 LLM 이 실제로 내는 빈도가 아니다 · 오라클 UNKNOWN 은 통과가 아니라 사람 검토다.</div>",
             "<div class='tiles'>"
             f"<div class='tile'><div class='n'>{esc(sg_blind.group(2)) if sg_blind else '-'} / {esc(iam_blind.group(2)) if iam_blind else '-'}</div><div class='l'>스캐너 PASS ∧ 오라클 FAIL (SG / IAM, 실제 plan)</div><div class='m'>Trivy 가 통과시켰지만 실제 상태는 그대로인 패치를 오라클이 잡은 수</div></div>"
             f"<div class='tile'><div class='n'>{spof_total}</div><div class='l'>파이프라인 실행에서 재스캔 PASS ∧ V6 FAIL</div><div class='m'>UNKNOWN(사람 검토)은 제외</div></div>"
             f"<div class='tile'><div class='n'>{label_agree}/{label_total}</div><div class='l'>기대 라벨 일치 (라벨 있는 후보)</div></div>"
             f"<div class='tile'><div class='n'>{total_rows}</div><div class='l'>집계된 후보 실행</div></div>"
             f"<div class='tile'><div class='n'>{n_llm}</div><div class='l'>LLM(Claude Code) 후보</div><div class='m'>{'미측정' if n_llm == 0 else ''}</div></div>"
             f"<div class='tile'><div class='n'>{aws_runs}</div><div class='l'>AWS 배포 후 검증 실행</div><div class='m'>{'아직 0회' if aws_runs == 0 else ''}</div></div></div>",
             "<h2>세트별: 재스캔만 믿었을 때 vs 게이트</h2>" + (bar_html or "<p class='muted'>기록 없음</p>"),
             *set_blocks,
             "<h2 id='oracle'>오라클 실험 (스캐너 vs V6, 실제 plan)</h2><details open><summary>experiments/ORACLE_RESULTS.md</summary>" + md_tables_to_html(oracle_md) + "</details>",
             "<h2 id='why'>기업용 한 장 — 왜 스캐너만으로는 안 되나</h2><details open><summary>experiments/WHY_THIS_GATE.md</summary>" + md_tables_to_html(why_md) + "</details>",
             "<h2 id='e1'>E1 — 후보 출처별 (세트 합산)</h2>" + (md_tables_to_html(e1) if e1 else "<p class='muted'>RESULTS_SUMMARY.md 없음</p>"),
             f"<h2 id='log'>실행 로그 (마지막 80줄)</h2><pre>{esc(log_tail) or '(experiments/run_experiments.log 없음)'}</pre>",
             "<p class='muted'>생성기: <code>python -m iacpatch.report_html</code>. 모든 숫자는 <code>data/reviews/</code>, <code>experiments/</code> 의 기록에서 다시 계산한 것. 이 파일 하나로 열린다 (외부 의존성 없음).</p>",
             f"</div><script>{JS}</script></body></html>"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html_text = "\n".join(parts)
    # 표는 폰 폭에서 가로 스크롤 상자에 넣는다 (페이지 전체가 옆으로 밀리지 않게)
    html_text = html_text.replace("<table", "<div class='tw'><table").replace("</table>", "</table></div>")
    out_path.write_text(html_text, encoding="utf-8")
    return out_path


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="report/index.html")
    ap.add_argument("--reviews", default=None, help="기록 루트 (기본 data/reviews)")
    a = ap.parse_args(argv)
    p = build(ROOT / a.out if not Path(a.out).is_absolute() else Path(a.out), Path(a.reviews) if a.reviews else None)
    print(f"→ {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
