"""한 장짜리 HTML 리포트 (외부 의존성 없음, CSS/JS 인라인, 브라우저에서 바로 열림).

    python -m iacpatch.report_html [--out report/index.html]

입력은 전부 저장소 안의 실측 기록이다 — 숫자를 만들어내지 않는다:
  data/reviews/<id>/           후보별 기록 (state/verification/risk/diff)
  experiments/candidate-sets/<set>/manifest.json   expected 라벨·출처
  experiments/ORACLE_RESULTS.md, WHY_THIS_GATE.md, RESULTS_SUMMARY.md, run_experiments.log
구성: 머리(핵심 숫자) → 파이프라인 깔때기(후보가 어느 단계에서 걸러졌나) → 어느 계층이 잡았나 → 세트별 표(행을 누르면 근거)
      → 오라클 실험 · 기업용 한 장 · E1 · 로그.
색: dataviz 검증 팔레트 (series 파랑/주황, 상태 4색은 아이콘+글자와 함께만). summarize() 는 창(app.py)도 쓴다.
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
SET_SHORT = {"eval-a-probe-rule": "SG · 규칙 기반", "eval-seeded-sg": "SG · seeded", "eval-iam-rule": "IAM · 규칙 기반",
             "eval-seeded-iam": "IAM · seeded", "eval-claude-code": "LLM · Claude Code"}
LEVEL_KO = {"LIGHT_REVIEW": "경량 검토(PR 자동)", "FULL_REVIEW": "정식 검토(승인 필수)", "REPORT_ONLY": "리포트만", "BLOCKED": "차단", "PENDING": "검증 대기", "None": "-", None: "-"}
STATE_KO = {"REVIEW_REQUIRED": "검토 자료 생성", "VALIDATION_FAILED": "검증 실패(차단)", "POLICY_BLOCKED": "정책 위반(차단)", "CANDIDATE_INVALID": "후보 무효",
            "INFO_INSUFFICIENT": "정보 부족(후보 없음)", "NO_FINDING": "탐지 없음", "AMBIGUOUS_FINDING": "finding 모호", "INPUT_ERROR": "입력 오류"}
LAYERS = ("V1", "V2", "V3", "V4", "V5", "V6")
LAYER_KO = {"V1": "V1 대상 finding 제거", "V2": "V2 새 finding", "V3": "V3 validate", "V4": "V4 plan", "V5": "V5 plan 차이", "V6": "V6 실효 상태(오라클)"}
NOT_CHECKED = {"NO_FINDING", "INFO_INSUFFICIENT", "CANDIDATE_INVALID", "INPUT_ERROR", "AMBIGUOUS_FINDING"}


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
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            if len(rows) >= 2 and all(re.fullmatch(r":?-{2,}:?", c) for c in rows[1] if c):
                head = "".join(f"<th>{inline(c)}</th>" for c in rows[0])
                body = "".join("<tr>" + "".join(f"<td>{_cell(c)}</td>" for c in r) + "</tr>" for r in rows[2:])
                out.append(f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
            continue
        if line.startswith("#"):
            lvl = min(len(line) - len(line.lstrip("#")), 5) + 1
            out.append(f"<h{lvl}>{inline(line.lstrip('#').strip())}</h{lvl}>")
        elif line.startswith("- "):
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(f"<li>{inline(lines[i][2:])}</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue
        elif line.startswith(">"):
            out.append(f"<p class='muted'>{inline(line.lstrip('> '))}</p>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
        i += 1
    return "\n".join(out)


def _cell(c: str) -> str:
    """표 안의 PASS/FAIL/O/X 를 배지로 (색 + 글자, 글자는 그대로)."""
    if c in ("PASS", "FAIL", "UNKNOWN", "ERROR", "NOT_RUN"):
        return badge(c)
    if c == "O":
        return '<span class="ok">O</span>'
    if c == "X":
        return '<span class="ng">X</span>'
    return inline(c)


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


def first_stop(r: Dict[str, Any]) -> str:
    """후보가 어디서 걸렸나: '정책' | 'V1'..'V6' | 'V6 UNKNOWN' | '미검증' | '통과' | '검사 대상 아님'."""
    st = str(r.get("state"))
    if st in NOT_CHECKED:
        return "검사 대상 아님"
    if st == "POLICY_BLOCKED":
        return "정책"
    lay = r["layers"]
    for k in LAYERS:
        if lay.get(k) == "FAIL":
            return k
    if lay.get("V6") == "UNKNOWN":
        return "V6 UNKNOWN"
    if any(lay.get(k) in ("NOT_RUN", "ERROR", "SKIPPED", None, "-") for k in LAYERS):
        return "미검증"
    return "통과"


# --------------------------------------------------------------------------- 집계 (창과 리포트가 같이 쓴다)
def summarize(reviews_root: Optional[Path] = None) -> Dict[str, Any]:
    reviews_root = reviews_root or ROOT / "data" / "reviews"
    rows = collect([reviews_root])
    sets: List[Dict[str, Any]] = []
    all_latest: List[Dict[str, Any]] = []
    for set_id in SETS:
        labels = _labels(set_id)
        srows = _latest_rows(rows, set_id)
        info: Dict[str, Any] = {"id": set_id, "title": SET_TITLES[set_id], "short": SET_SHORT[set_id], "rows": srows, "labels": labels, "n": len(srows)}
        if srows:
            info["v1_only"] = sum(1 for r in srows if r["layers"].get("V1") == "PASS")
            info["gate"] = sum(1 for r in srows if r["layers"].get("V1") == "PASS" and r["layers"].get("V6") == "PASS")
            info["spof"] = sum(1 for r in srows if r["layers"].get("V1") == "PASS" and r["layers"].get("V6") == "FAIL")
            info["not_run"] = sum(1 for r in srows for k in LAYERS if r["layers"].get(k) in ("NOT_RUN", "ERROR", "SKIPPED"))
            oks = [(_label_ok(labels.get(str(r["scenario"]), {}).get("expected", ""), r)) for r in srows]
            info["labeled"] = sum(1 for o in oks if o is not None)
            info["agree"] = sum(1 for o in oks if o)
            info["oks"] = oks
            all_latest += srows
        sets.append(info)
    # 깔때기 (전 세트 합산, 세트별 최신 실행만)
    checked = [r for r in all_latest if str(r.get("state")) not in NOT_CHECKED]
    funnel = [("후보 실행", len(all_latest)), ("검사 대상 (finding 있고 후보 유효)", len(checked)),
              ("정책 통과", sum(1 for r in checked if str(r.get("state")) != "POLICY_BLOCKED"))]
    alive = [r for r in checked if str(r.get("state")) != "POLICY_BLOCKED"]
    for k in LAYERS:
        alive = [r for r in alive if r["layers"].get(k) == "PASS"]
        funnel.append((f"{k} 통과", len(alive)))
    stops = Counter(first_stop(r) for r in all_latest)
    levels = Counter(str(r.get("review_level") or "None") for r in checked)
    tools = None
    for r in sorted(rows, key=lambda x: str(x["run_id"]), reverse=True):
        t = _load(reviews_root / str(r["run_id"]) / "local_verify" / "tools.json")
        if t:
            tools = t; break
    env_bits = []
    for k, v in (tools or {}).items():
        if isinstance(v, dict):
            env_bits.append(f"{v.get('kind') or k} {v.get('version') or '없음'}" + (" (offline plan)" if v.get("offline_plan") else ""))
    cc = _load(ROOT / "experiments/candidate-sets/eval-claude-code/manifest.json") or {}
    fuzz_md = _read(ROOT / "experiments" / "FUZZ_RESULTS.md")
    fz = re.search(r"잡혀야 하는 변형 (\d+)개 중 Trivy 사각 \*\*(\d+)개\*\*, 그중 오라클 탐지 \*\*(\d+)개\*\* · UNKNOWN (\d+)개 · 오라클도 놓침 \*\*(\d+)개\*\*", fuzz_md)
    ofz_md = _read(ROOT / "experiments" / "ORACLE_FUZZ.md")
    ofz_cases = re.search(r"무작위 케이스 ([\d,]+)건", ofz_md)
    ofz_mism = re.findall(r"\*\*불일치: (\d+)건\*\*", ofz_md)
    why_md = _read(ROOT / "experiments" / "WHY_THIS_GATE.md")
    sg_blind = re.search(r"Security Group: 실제 plan (\d+)개 중 \*\*(\d+)개\*\*", why_md)
    iam_blind = re.search(r"IAM \(Tier 1\): 실제 plan (\d+)개 중 \*\*(\d+)개\*\*", why_md)
    return {
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"), "host": platform.node(), "env": ", ".join(env_bits),
        "rows_total": len(rows), "latest_total": len(all_latest), "sets": sets, "funnel": funnel, "stops": stops, "levels": levels,
        "spof_total": sum(s.get("spof", 0) for s in sets), "label_agree": sum(s.get("agree", 0) for s in sets), "label_total": sum(s.get("labeled", 0) for s in sets),
        "not_run_total": sum(s.get("not_run", 0) for s in sets), "n_llm": len(cc.get("candidates") or []),
        "aws_runs": sum(1 for r in rows if r.get("post_deploy", "-") not in ("-", None)),
        "blind_sg": (int(sg_blind.group(2)), int(sg_blind.group(1))) if sg_blind else None,
        "blind_iam": (int(iam_blind.group(2)), int(iam_blind.group(1))) if iam_blind else None,
        "fuzz": {"should": int(fz.group(1)), "trivy_blind": int(fz.group(2)), "oracle_caught": int(fz.group(3)), "unknown": int(fz.group(4)), "oracle_miss": int(fz.group(5))} if fz else None,
        "oracle_fuzz": {"cases": ofz_cases.group(1) if ofz_cases else None, "mismatch": sum(int(x) for x in ofz_mism) if ofz_mism else None},
        "reviews_root": reviews_root,
    }


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# --------------------------------------------------------------------------- 스타일
CSS = """
:root{color-scheme:light;--bg:#f6f5f1;--panel:#ffffff;--line:#e3e2dc;--ink:#0b0b0b;--ink2:#52514e;--ink3:#8a8985;--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;
--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b;--muted:#a9a8a3;--code:#f1f0ea;--accent:#2a78d6;--accent-soft:#e6f0fb;--hero:#0f2a4a;--hero-ink:#fff;--hero-sub:#b9cbe3;--shadow:0 1px 2px rgba(11,11,11,.06),0 8px 24px -12px rgba(11,11,11,.18)}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#151514;--panel:#1f1f1e;--line:#34342f;--ink:#fff;--ink2:#c3c2b7;--ink3:#8f8e88;--s1:#3987e5;--s2:#d95926;--s3:#199e70;--code:#2a2a28;--accent:#3987e5;--accent-soft:#1c2a3b;--hero:#0b1d33;--hero-sub:#9fb4d0;--shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px -12px rgba(0,0,0,.6)}}
:root[data-theme=dark]{color-scheme:dark;--bg:#151514;--panel:#1f1f1e;--line:#34342f;--ink:#fff;--ink2:#c3c2b7;--ink3:#8f8e88;--s1:#3987e5;--s2:#d95926;--s3:#199e70;--code:#2a2a28;--accent:#3987e5;--accent-soft:#1c2a3b;--hero:#0b1d33;--hero-sub:#9fb4d0;--shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px -12px rgba(0,0,0,.6)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,"Segoe UI","Malgun Gothic","Apple SD Gothic Neo",Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px 80px}
.hero{background:var(--hero);color:var(--hero-ink);margin:0 -16px;padding:34px 16px 30px}.hero .in{max-width:1180px;margin:0 auto;padding:0 16px;display:grid;grid-template-columns:1.4fr 1fr;gap:28px;align-items:center}
.hero .kicker{font-size:12.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--hero-sub);margin-bottom:8px}
.hero h1{font-size:28px;line-height:1.25;margin:0 0 10px;letter-spacing:-.01em}.hero p{color:var(--hero-sub);margin:0;font-size:14px}
.hero .big{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.14);border-radius:14px;padding:18px 20px}
.hero .big .n{font-size:56px;font-weight:800;line-height:1;letter-spacing:-.03em}.hero .big .l{font-size:14px;margin-top:8px;color:#fff}.hero .big .m{font-size:12.5px;color:var(--hero-sub);margin-top:6px}
.hero .meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}.chip{display:inline-block;border:1px solid rgba(255,255,255,.22);border-radius:999px;padding:2px 10px;font-size:12px;color:#fff}
.chip.ok{border-color:rgba(12,163,12,.7)}.chip.no{border-color:rgba(208,59,59,.8)}
.tabs{display:flex;flex-wrap:wrap;gap:6px;position:sticky;top:0;background:var(--bg);padding:10px 0;z-index:2;border-bottom:1px solid var(--line);margin:0 0 6px}.tabs a{color:var(--ink2);text-decoration:none;border:1px solid var(--line);border-radius:999px;padding:3px 11px;font-size:13px;background:var(--panel)}.tabs a:hover{color:var(--accent);border-color:var(--accent)}
.tabs .sp{flex:1}button.tg{border:1px solid var(--line);background:var(--panel);color:var(--ink2);border-radius:999px;padding:3px 10px;cursor:pointer;font-size:12px}
h2{font-size:20px;margin:40px 0 6px;letter-spacing:-.01em}h2 small{font-weight:400;color:var(--ink3);font-size:13px;margin-left:8px}h3{font-size:16px;margin:20px 0 8px}h4,h5{margin:14px 0 6px}
.lead{color:var(--ink2);margin:0 0 14px;font-size:14px}.sub{color:var(--ink2);font-size:13px}.muted{color:var(--ink3)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px;box-shadow:var(--shadow)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow);position:relative;overflow:hidden}.tile:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--s1)}
.tile.warn:before{background:var(--warning)}.tile.crit:before{background:var(--critical)}.tile.good:before{background:var(--good)}.tile.grey:before{background:var(--muted)}
.tile .n{font-size:30px;font-weight:800;letter-spacing:-.02em;line-height:1.1}.tile .l{color:var(--ink2);font-size:13px;margin-top:6px}.tile .m{color:var(--ink3);font-size:12px;margin-top:4px}
.banner{border:1px solid var(--line);border-left:4px solid var(--warning);background:var(--panel);padding:12px 14px;border-radius:10px;margin:18px 0;font-size:14px}
table{border-collapse:separate;border-spacing:0;width:100%;font-size:13.5px;margin:8px 0 14px;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{border-bottom:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}th{background:var(--code);font-weight:600;color:var(--ink2);position:sticky;top:46px;z-index:1}tr:last-child td{border-bottom:0}
tbody tr:nth-child(4n+3) td{background:color-mix(in srgb,var(--code) 55%,var(--panel))}
tr.row{cursor:pointer}tr.row:hover td{background:var(--accent-soft)}tr.det td{background:var(--code)}tr.det table{box-shadow:none}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid transparent;white-space:nowrap}
.badge.good{color:var(--good);border-color:var(--good)}.badge.critical{color:var(--critical);border-color:var(--critical)}.badge.warning{color:#8a5b00;border-color:var(--warning)}
:root[data-theme=dark] .badge.warning,:root:not([data-theme=light]) .badge.warning{color:var(--warning)}
.badge.serious{color:var(--serious);border-color:var(--serious)}.badge.muted{color:var(--ink3);border-color:var(--line)}
.ok{color:var(--good);font-weight:700;white-space:nowrap}.ng{color:var(--critical);font-weight:700;white-space:nowrap}
pre{background:var(--code);border:1px solid var(--line);border-radius:10px;padding:10px 12px;overflow:auto;font:12.5px/1.45 ui-monospace,Consolas,"D2Coding",monospace;max-height:420px}
code{background:var(--code);padding:0 4px;border-radius:4px;font-size:.92em}
.funnel{display:grid;gap:8px;margin:12px 0}.fstep{display:grid;grid-template-columns:260px 1fr 70px;gap:12px;align-items:center;font-size:13.5px}
.fstep .fl{color:var(--ink2)}.fstep .fb{height:22px;border-radius:0 6px 6px 0;background:var(--s1);min-width:2px;position:relative}.fstep .fb.last{background:var(--s3)}
.fstep .fn{font-weight:700;font-variant-numeric:tabular-nums;text-align:right}.fstep .drop{font-size:12px;color:var(--s2);margin-left:8px;font-weight:600}
.bars{display:grid;gap:10px;margin:10px 0 6px}.bar{display:grid;grid-template-columns:200px 1fr;gap:10px;align-items:center}
.bar .lbl{font-size:13px;color:var(--ink2)}.bar .tr{display:grid;gap:4px;max-width:calc(100% - 96px)}.bar .seg{height:14px;border-radius:0 4px 4px 0;position:relative;min-width:2px}
.bar .seg span{position:absolute;left:calc(100% + 6px);top:-3px;font-size:12px;color:var(--ink2);white-space:nowrap}
.stops{display:grid;gap:6px;margin:10px 0}.stop{display:grid;grid-template-columns:200px 1fr 40px;gap:10px;align-items:center;font-size:13.5px}.stop .sb{height:16px;border-radius:0 4px 4px 0;min-width:2px}
.stack{display:flex;height:26px;border-radius:8px;overflow:hidden;border:1px solid var(--line);margin:10px 0 6px}.stack div{display:flex;align-items:center;justify-content:center;font-size:12px;color:#fff;font-weight:700;min-width:0}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:12.5px;color:var(--ink2);margin:6px 0}.legend i{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.setgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
.diff{white-space:pre}.diff .a{color:var(--good)}.diff .d{color:var(--critical)}.diff .h{color:var(--ink3)}
details summary{cursor:pointer;color:var(--ink2)}
.tw{overflow-x:auto;max-width:100%}.tw table{min-width:520px}
footer{margin-top:40px;color:var(--ink3);font-size:12.5px;border-top:1px solid var(--line);padding-top:12px}
@media (max-width:760px){.hero .in{grid-template-columns:1fr}.hero h1{font-size:22px}.two{grid-template-columns:1fr}.fstep{grid-template-columns:1fr}.fstep .fn{text-align:left}.bar{grid-template-columns:1fr}.stop{grid-template-columns:1fr}.tiles{grid-template-columns:repeat(2,1fr)}th{position:static}}
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


def _funnel_html(funnel: List[tuple]) -> str:
    top = max([n for _, n in funnel] + [1])
    parts = []
    prev = None
    for i, (label, n) in enumerate(funnel):
        w = 100 * n / top
        drop = f'<span class="drop">−{prev - n}</span>' if prev is not None and prev > n else ""
        parts.append(f'<div class="fstep"><div class="fl">{esc(label)}</div><div><div class="fb{" last" if i == len(funnel) - 1 else ""}" style="width:{w:.1f}%"></div></div>'
                     f'<div class="fn">{n}{drop}</div></div>')
        prev = n
    return '<div class="funnel">' + "".join(parts) + "</div>"


def _stops_html(stops: Counter) -> str:
    order = ["정책", "V1", "V2", "V3", "V4", "V5", "V6", "V6 UNKNOWN", "미검증", "통과", "검사 대상 아님"]
    color = {"정책": "var(--critical)", "V1": "var(--s1)", "V2": "var(--s1)", "V3": "var(--s1)", "V4": "var(--s1)", "V5": "var(--s1)", "V6": "var(--s2)",
             "V6 UNKNOWN": "var(--warning)", "미검증": "var(--muted)", "통과": "var(--good)", "검사 대상 아님": "var(--muted)"}
    label = {"정책": "정책 검증 (범위 밖 변경)", "V6": "V6 오라클 (실효 상태)", "V6 UNKNOWN": "V6 판단 불가 → 사람", "미검증": "미검증 계층 있음", "통과": "전부 통과",
             "검사 대상 아님": "검사 대상 아님 (탐지 없음·후보 없음·무효)"}
    top = max(list(stops.values()) + [1])
    parts = []
    for k in order:
        n = stops.get(k, 0)
        if n == 0:
            continue
        parts.append(f'<div class="stop"><div class="fl sub">{esc(label.get(k, LAYER_KO.get(k, k)))}</div><div><div class="sb" style="width:{100 * n / top:.1f}%;background:{color[k]}"></div></div><div class="fn">{n}</div></div>')
    return '<div class="stops">' + "".join(parts) + "</div>"


def _levels_html(levels: Counter) -> str:
    order = [("LIGHT_REVIEW", "var(--good)"), ("FULL_REVIEW", "var(--warning)"), ("REPORT_ONLY", "var(--serious)"), ("PENDING", "var(--muted)"), ("BLOCKED", "var(--critical)")]
    total = sum(levels.get(k, 0) for k, _ in order) or 1
    segs = "".join(f'<div style="flex:{levels.get(k, 0)};background:{c}" title="{esc(LEVEL_KO[k])} {levels.get(k, 0)}">{levels.get(k, 0) if levels.get(k, 0) else ""}</div>' for k, c in order if levels.get(k, 0))
    leg = "".join(f'<span><i style="background:{c}"></i>{esc(LEVEL_KO[k])} {levels.get(k, 0)}</span>' for k, c in order)
    return f'<div class="stack">{segs}</div><div class="legend">{leg}</div><p class="muted">검사 대상 {total}건의 최종 검토 수준. 어느 수준이든 apply 는 사람이 한다.</p>'


def build(out_path: Path, reviews_root: Optional[Path] = None) -> Path:
    S = summarize(reviews_root)
    reviews_root = S["reviews_root"]
    set_blocks: List[str] = []
    bars: List[Dict[str, Any]] = []
    for info in S["sets"]:
        set_id, title, srows, labels = info["id"], info["title"], info["rows"], info["labels"]
        if not srows:
            note = "후보 0건 — 아직 채우지 않음 (scripts/cc_prompt.py → Claude Code 새 세션 → scripts/cc_add.py)" if set_id == "eval-claude-code" else "실행 기록 없음"
            set_blocks.append(f'<h2 id="{set_id}">{esc(title)}</h2><div class="card"><p class="muted" style="margin:0">{esc(note)}</p></div>')
            continue
        trs: List[str] = []
        for i, r in enumerate(srows):
            lab = labels.get(str(r["scenario"]), {})
            ok = info["oks"][i]
            det = _detail(str(r["run_id"]), reviews_root)
            did = f"det-{set_id}-{i}"
            layers = "".join(f"<td>{badge(r['layers'].get(k, '-'))}</td>" for k in LAYERS)
            okc = '<span class="ok">일치</span>' if ok else ('<span class="ng">불일치</span>' if ok is False else "-")
            stop = first_stop(r)
            trs.append(f'<tr class="row" data-det="{did}"><td><b>{esc(str(r["scenario"]).split("/", 1)[1])}</b></td><td>{esc(lab.get("source") or r["origin"])}</td>'
                       f'<td>{esc(STATE_KO.get(str(r["state"]), r["state"]))}</td><td>{level_badge(r["review_level"])}</td><td>{esc(r["risk"] or "-")}</td>{layers}'
                       f'<td>{esc(stop)}</td><td>{esc(lab.get("expected", ""))}</td><td>{okc}</td><td>{esc(r.get("duration_s") if r.get("duration_s") is not None else "-")}</td></tr>')
            lay_rows = "".join(f"<tr><td>{esc(l.get('layer'))}</td><td>{badge(l.get('verdict'))}</td><td>{esc(l.get('summary', ''))[:300]}</td><td class='muted'>{esc(l.get('tool', ''))}</td></tr>" for l in det["layers"])
            fac = "".join(f"<li>{esc(f.get('factor'))}: {esc(f.get('value'))} <b>(+{esc(f.get('points', 0))})</b> <span class='muted'>{esc(f.get('note', ''))}</span></li>"
                          for f in det["risk"].get("factors", []) if f.get("points") or f.get("factor") in ("iam_resource_touched", "iam_trust_policy_changed", "resource_deleted", "resource_replaced"))
            trs.append(f'<tr class="det" id="{did}" style="display:none"><td colspan="16">'
                       f'<div class="sub">기대 라벨 근거: {esc(lab.get("reason", "") or "-")} · 기록: <code>{esc(det["dir"])}</code></div>'
                       f'<h4>검증 계층</h4><table><thead><tr><th>계층</th><th>판정</th><th>요약</th><th>도구</th></tr></thead><tbody>{lay_rows or "<tr><td colspan=4 class=muted>검증 기록 없음</td></tr>"}</tbody></table>'
                       f'<h4>위험도 {esc(det["risk"].get("risk_level", "-"))} (점수 {esc(det["risk"].get("score", "-"))}, {esc(det["risk"].get("rubric_version", ""))})</h4><ul>{fac or "<li class=muted>가산 요인 없음</li>"}</ul>'
                       f'<h4>diff</h4><pre class="diff">{_diff_html(det["diff"]) or "(diff 없음)"}</pre></td></tr>')
        bars.append({"set": info["short"], "v1": info["v1_only"], "gate": info["gate"], "n": len(srows)})
        nr = info["not_run"]
        set_blocks.append(
            f'<h2 id="{set_id}">{esc(title)}</h2>'
            f'<div class="tiles"><div class="tile grey"><div class="n">{len(srows)}</div><div class="l">후보</div></div>'
            f'<div class="tile"><div class="n">{info["v1_only"]} → {info["gate"]}</div><div class="l">재스캔(V1)만 통과 → 게이트(V1+V6) 통과</div><div class="m">차이 = V6 가 FAIL 또는 UNKNOWN(사람 검토)으로 돌린 수</div></div>'
            f'<div class="tile crit"><div class="n">{info["spof"]}</div><div class="l">스캐너 PASS ∧ 오라클 FAIL</div><div class="m">스캐너만 믿었으면 통과했을 기만/필수깨짐</div></div>'
            f'<div class="tile good"><div class="n">{info["agree"]}/{info["labeled"]}</div><div class="l">기대 라벨 일치</div></div>'
            f'<div class="tile {"warn" if nr else "good"}"><div class="n">{nr}</div><div class="l">미검증 계층(NOT_RUN/ERROR)</div><div class="m">{"0 이어야 결과가 완전" if nr else "완전"}</div></div></div>'
            f'<table><thead><tr><th>후보</th><th>출처</th><th>상태</th><th>검토 수준</th><th>위험도</th>' + "".join(f"<th>{k}</th>" for k in LAYERS) +
            f'<th>걸린 곳</th><th>기대</th><th>일치</th><th>소요(s)</th></tr></thead>'
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

    oracle_md = _read(ROOT / "experiments" / "ORACLE_RESULTS.md")
    why_md = _read(ROOT / "experiments" / "WHY_THIS_GATE.md")
    summ_md = _read(ROOT / "experiments" / "RESULTS_SUMMARY.md")
    e1 = summ_md[summ_md.find("## E1"):] if "## E1" in summ_md else ""
    log_tail = ""
    lp = ROOT / "experiments" / "run_experiments.log"
    if lp.exists():
        log_tail = "\n".join(lp.read_text(encoding="utf-8", errors="replace").splitlines()[-80:])

    blind_n = (S["blind_sg"][0] if S["blind_sg"] else 0) + (S["blind_iam"][0] if S["blind_iam"] else 0)
    blind_d = (S["blind_sg"][1] if S["blind_sg"] else 0) + (S["blind_iam"][1] if S["blind_iam"] else 0)
    n_llm, aws_runs = S["n_llm"], S["aws_runs"]
    chips = (f'<span class="chip">{esc(S["generated_at"])}</span><span class="chip">{esc(S["host"])}</span>'
             + (f'<span class="chip ok">{esc(S["env"])}</span>' if S["env"] else '<span class="chip no">도구 기록 없음</span>')
             + f'<span class="chip">기록 {S["rows_total"]}건 · 세트별 최신 {S["latest_total"]}건 집계</span>'
             + (f'<span class="chip no">LLM 후보 0 (미측정)</span>' if n_llm == 0 else f'<span class="chip ok">LLM 후보 {n_llm}</span>')
             + (f'<span class="chip no">AWS 배포 후 검증 0회</span>' if aws_runs == 0 else f'<span class="chip ok">AWS 배포 후 검증 {aws_runs}회</span>'))

    parts = [f"<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>IaCPatch 실행 리포트</title><style>{CSS}</style></head><body><div class='wrap'>",
             "<div class='hero'><div class='in'><div><div class='kicker'>IaCPatch · 실행 리포트</div>"
             "<h1>AI가 생성한 테라폼 보안패치의 실효성 검증 자동화</h1>"
             "<p>Trivy 가 통과시킨 패치를 그대로 믿지 않는다. 8계층 검증(재스캔 → 새 finding → validate → plan → plan 차이 → 실효 상태 오라클 → 배포 후 상태 → 기능)과 위험도 기준표가 각 후보에 사람이 어떤 검토를 해야 하는지를 정한다. 아래 숫자는 전부 이 컴퓨터의 기록에서 다시 계산한 것이다.</p>"
             f"<div class='meta'>{chips}</div></div>"
             f"<div class='big'><div class='n'>{blind_n}<span style='font-size:22px;font-weight:600;color:var(--hero-sub)'> / {blind_d}</span></div>"
             "<div class='l'>스캐너는 통과시켰지만 실제 보안 상태는 그대로인 패치 — 오라클(V6)이 잡은 수 / 실제 plan 수</div>"
             f"<div class='m'>SG {S['blind_sg'][0] if S['blind_sg'] else '-'}/{S['blind_sg'][1] if S['blind_sg'] else '-'} · IAM {S['blind_iam'][0] if S['blind_iam'] else '-'}/{S['blind_iam'][1] if S['blind_iam'] else '-'} (experiments/ORACLE_RESULTS.md). "
             f"파이프라인 seeded 실행에서는 재스캔 PASS ∧ V6 FAIL {S['spof_total']}건.</div>"
             + (f"<div class='m' style='margin-top:10px;padding-top:10px;border-top:1px solid rgba(255,255,255,.14)'>자동 생성 변형 {S['fuzz']['should']}종(잡혀야 하는 것) 중 <b style='color:#fff'>Trivy 사각 {S['fuzz']['trivy_blind']}종</b> → 오라클 탐지 <b style='color:#fff'>{S['fuzz']['oracle_caught']}</b> · 사람에게 {S['fuzz']['unknown']} · 오라클도 놓침 <b style='color:#fff'>{S['fuzz']['oracle_miss']}</b> (experiments/FUZZ_RESULTS.md)</div>" if S.get("fuzz") else "")
             + (f"<div class='m'>오라클 차등 검증: 무작위 {S['oracle_fuzz']['cases']}건, 기준 구현과 불일치 <b style='color:#fff'>{S['oracle_fuzz']['mismatch']}</b>건 (experiments/ORACLE_FUZZ.md)</div>" if S.get("oracle_fuzz", {}).get("cases") else "")
             + "</div></div></div>",
             "<nav class='tabs'><a href='#funnel'>깔때기</a><a href='#stops'>어느 계층이 잡았나</a>" + "".join(f"<a href='#{s}'>{esc(SET_SHORT[s])}</a>" for s in SETS)
             + "<a href='#fuzz'>스캐너 사각 탐색</a><a href='#ofuzz'>오라클 차등 검증</a><a href='#oracle'>오라클 실험</a><a href='#why'>기업용 한 장</a><a href='#e1'>E1</a><a href='#log'>로그</a><span class='sp'></span><button class='tg' onclick='tg()'>라이트/다크</button></nav>",
             "<div class='banner'><b>이 리포트가 말하지 않는 것</b> — "
             f"AWS 실제 반영·배포 후 검증(V7/V8) 실행 <b>{aws_runs}회</b> · Claude Code(LLM) 후보 <b>{n_llm}건</b> (0 이면 LLM 축은 미측정) · 미검증 계층(NOT_RUN/ERROR) <b>{S['not_run_total']}</b> · "
             "seeded 후보는 알려진 우회 패턴(사람/AI 세션 작성)이지 LLM 이 실제로 내는 빈도가 아니다 · 오라클 UNKNOWN 은 통과가 아니라 사람 검토다.</div>",
             "<div class='tiles'>"
             f"<div class='tile crit'><div class='n'>{S['spof_total']}</div><div class='l'>파이프라인 실행에서 재스캔 PASS ∧ V6 FAIL</div><div class='m'>UNKNOWN(사람 검토)은 제외</div></div>"
             f"<div class='tile good'><div class='n'>{S['label_agree']}/{S['label_total']}</div><div class='l'>기대 라벨 일치 (라벨 있는 후보)</div><div class='m'>라벨은 실행 전에 적음</div></div>"
             f"<div class='tile grey'><div class='n'>{S['latest_total']}</div><div class='l'>집계된 후보 실행</div><div class='m'>세트별 최신 실행만</div></div>"
             f"<div class='tile {'warn' if S['not_run_total'] else 'good'}'><div class='n'>{S['not_run_total']}</div><div class='l'>미검증 계층</div><div class='m'>{'도구 없음/오류 — 결과 미완' if S['not_run_total'] else '전부 실행됨'}</div></div>"
             f"<div class='tile {'warn' if n_llm == 0 else ''}'><div class='n'>{n_llm}</div><div class='l'>LLM(Claude Code) 후보</div><div class='m'>{'미측정' if n_llm == 0 else ''}</div></div>"
             f"<div class='tile {'warn' if aws_runs == 0 else 'good'}'><div class='n'>{aws_runs}</div><div class='l'>AWS 배포 후 검증 실행</div><div class='m'>{'아직 0회' if aws_runs == 0 else ''}</div></div></div>",
             "<div class='two'>"
             "<div class='card' id='funnel'><h3 style='margin-top:0'>파이프라인 깔때기 <small class='muted'>후보가 어느 단계까지 살아남나 (전 세트 합산)</small></h3>"
             + _funnel_html(S["funnel"]) + "<p class='muted'>주황 −n 은 그 단계에서 걸러진 수. 계층은 전부 돌리고 전부 기록하되, 통과는 누적(앞 단계도 PASS)으로 센다.</p></div>"
             "<div class='card' id='stops'><h3 style='margin-top:0'>어느 계층이 잡았나 <small class='muted'>후보별 첫 FAIL 지점</small></h3>" + _stops_html(S["stops"])
             + "<h4>최종 검토 수준</h4>" + _levels_html(S["levels"]) + "</div></div>",
             "<h2>세트별: 재스캔만 믿었을 때 vs 게이트</h2><div class='card'>" + (bar_html or "<p class='muted'>기록 없음</p>") + "</div>",
             *set_blocks,
             "<h2 id='fuzz'>스캐너 사각 탐색 <small>겉모습만 다른 변형을 자동 생성해 Trivy 와 오라클에 나란히 — experiments/FUZZ_RESULTS.md</small></h2><div class='card'>" + (md_tables_to_html(_read(ROOT / "experiments" / "FUZZ_RESULTS.md")) or "<p class='muted'>아직 실행 전 (scripts/fuzz_scanner.py)</p>") + "</div>",
             "<h2 id='ofuzz'>오라클 차등 검증 <small>무작위 입력으로 기준 구현과 대조 — experiments/ORACLE_FUZZ.md</small></h2><div class='card'>" + (md_tables_to_html(_read(ROOT / "experiments" / "ORACLE_FUZZ.md")) or "<p class='muted'>아직 실행 전 (scripts/oracle_fuzz.py)</p>") + "</div>",
             "<h2 id='oracle'>오라클 실험 <small>스캐너 vs V6, 실제 plan — experiments/ORACLE_RESULTS.md</small></h2><div class='card'>" + md_tables_to_html(oracle_md) + "</div>",
             "<h2 id='why'>기업용 한 장 <small>왜 스캐너만으로는 안 되나 — experiments/WHY_THIS_GATE.md</small></h2><div class='card'>" + md_tables_to_html(why_md) + "</div>",
             "<h2 id='e1'>E1 <small>후보 출처별 (세트 합산)</small></h2><div class='card'>" + (md_tables_to_html(e1) if e1 else "<p class='muted'>RESULTS_SUMMARY.md 없음</p>") + "</div>",
             f"<h2 id='log'>실행 로그 <small>마지막 80줄</small></h2><pre>{esc(log_tail) or '(experiments/run_experiments.log 없음)'}</pre>",
             "<footer>생성기: <code>python -m iacpatch.report_html</code>. 모든 숫자는 <code>data/reviews/</code>, <code>experiments/</code> 의 기록에서 다시 계산한 것이며 만들어낸 값은 없다. 이 파일 하나로 열린다 (외부 의존성 없음). "
             "하지 않는 것: LLM API 호출, Claude Code 자동 호출, AWS 접속, terraform apply, git push.</footer>",
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
