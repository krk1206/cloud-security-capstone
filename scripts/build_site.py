#!/usr/bin/env python3
"""공유용 정적 사이트 만들기 — report/site.html (claude.ai Artifact 로 게시하는 조각: doctype/html/head/body 없이)
+ report/report-artifact.html (실행 리포트의 같은 형식 조각).

    python3 scripts/build_site.py [--report-url <게시된 리포트 URL>] [--repo-url ...]

들어가는 숫자는 전부 저장소 기록에서 계산한다:
  - 4주차: rubric_demo (기준표, 라벨 25건 재계산, 상한 강제 72 조합), 계산기는 scripts/site/calc.js (JS 이식) 를 무작위 입력으로 Python 과 대조한 뒤 넣는다
  - 5주차: data/reviews 의 실제 기록 3건 (V1~V6 표·diff·PR 미리보기)
  - 실험: report_html.summarize()
  - 문서: docs/*.md 를 HTML 로
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import argparse
import contextlib
import datetime as _dt
import html
import io
import json
import platform
import random
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_sys.path.insert(0, str(ROOT / "src"))
SITE = ROOT / "scripts" / "site"

from iacpatch import rubric_demo as rd  # noqa: E402
from iacpatch.report_html import summarize  # noqa: E402

esc = lambda x: html.escape("" if x is None else str(x))


# ----------------------------------------------------------------------------- markdown → html (작은 변환기: 제목·문단·목록·표·인용·코드·굵게·링크)
def _inline(s: str) -> str:
    s = esc(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"~~(.+?)~~", r"<s>\1</s>", s)
    s = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r'<a href="\2" target="_blank" rel="noopener">\1</a>', s)
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 <span class='small'>(\2)</span>", s)
    return s


def md_to_html(md: str) -> str:
    out = []
    lines = md.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            buf = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                buf.append(lines[i]); i += 1
            out.append(f"<pre>{esc(chr(10).join(buf))}</pre>")
            i += 1
            continue
        if line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")]); i += 1
            if len(rows) >= 2 and all(re.fullmatch(r":?-{2,}:?", c) for c in rows[1] if c):
                head = "".join(f"<th>{_inline(c)}</th>" for c in rows[0])
                body = "".join("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>" for r in rows[2:])
                out.append(f"<div class='tw'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>")
            continue
        m = re.match(r"^(#{1,6})\s+(.*)", line)
        if m:
            lvl = min(len(m.group(1)) + 1, 5)
            out.append(f"<h{lvl}>{_inline(m.group(2))}</h{lvl}>")
            i += 1; continue
        if re.match(r"^\s*[-*]\s+", line) or re.match(r"^\s*\d+\.\s+", line):
            ordered = bool(re.match(r"^\s*\d+\.\s+", line))
            items = []
            while i < len(lines) and (re.match(r"^\s*[-*]\s+", lines[i]) or re.match(r"^\s*\d+\.\s+", lines[i]) or (lines[i].startswith("   ") and items)):
                l = lines[i]
                if re.match(r"^\s*[-*]\s+", l) or re.match(r"^\s*\d+\.\s+", l):
                    items.append(re.sub(r"^\s*([-*]|\d+\.)\s+", "", l))
                else:
                    items[-1] += " " + l.strip()
                i += 1
            tag = "ol" if ordered else "ul"
            out.append(f"<{tag}>" + "".join(f"<li>{_inline(x)}</li>" for x in items) + f"</{tag}>")
            continue
        if line.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].startswith(">"):
                buf.append(lines[i].lstrip("> ").strip()); i += 1
            out.append(f"<blockquote>{_inline(' '.join(buf))}</blockquote>")
            continue
        if line.strip() in ("---", "***", "___"):
            out.append("<hr>"); i += 1; continue
        if line.strip():
            buf = [line.strip()]
            i += 1
            while i < len(lines) and lines[i].strip() and not re.match(r"^(#|\||>|```|\s*[-*]\s|\s*\d+\.\s|---)", lines[i]):
                buf.append(lines[i].strip()); i += 1
            out.append(f"<p>{_inline(' '.join(buf))}</p>")
            continue
        i += 1
    return "\n".join(out)


# ----------------------------------------------------------------------------- 데이터
def _examples() -> list:
    from iacpatch.config import load_settings
    from iacpatch.tools.github import prepare_pr
    reviews = ROOT / "data" / "reviews"
    latest = {}
    for d in sorted(reviews.iterdir()) if reviews.is_dir() else []:
        st = d / "state.json"
        if not st.exists():
            continue
        try:
            s = json.loads(st.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if s.get("state") == "INPUT_ERROR" or str(s.get("scenario", "")).startswith("ui/"):
            continue
        latest[s["scenario"]] = (d, s)
    want = [
        ("eval-seeded-sg/correct-approved", "정상 패치 (SG)", "0.0.0.0/0 을 승인 출처 10.0.0.0/8 로만 교체. V1~V6 전부 통과 → 위험도 LOW → 검토 수준 FULL_REVIEW(필수 정보 누락으로 경량 검토 대신 정식 검토). PR 미리보기까지 만들어진다. push 는 사람."),
        ("eval-seeded-sg/deceptive-cidr-split", "기만 패치 (SG, CIDR 분할)", "0.0.0.0/0 을 0.0.0.0/1 + 128.0.0.0/1 로 쪼갬. Trivy 재스캔(V1)은 통과시키지만 V6 오라클이 합집합 = 전체 인터넷임을 계산해 FAIL → BLOCKED. PR 은 거부된다."),
        ("eval-seeded-iam/deceptive-resource-star", "기만 패치 (IAM, Resource *)", "액션은 최소 권한으로 줄였지만 Resource:* 를 남김. 스캐너는 통과, IAM 오라클이 승인 집합 밖(EXCESS)으로 FAIL → BLOCKED. IAM 은 기준표 floor 로 최소 MEDIUM."),
    ]
    settings = load_settings(str(ROOT))
    out = []
    for scen, title, desc in want:
        if scen not in latest:
            continue
        d, s = latest[scen]
        ver = json.loads((d / "verification.json").read_text(encoding="utf-8")) if (d / "verification.json").exists() else {}
        rep = ver.get("report") or {}
        risk = (json.loads((d / "risk.json").read_text(encoding="utf-8")).get("decision") or {}) if (d / "risk.json").exists() else {}
        tools = {}
        if (d / "local_verify" / "tools.json").exists():
            tools = json.loads((d / "local_verify" / "tools.json").read_text(encoding="utf-8"))
        tool_line = ", ".join(f"{v.get('kind') or k} {v.get('version')}" for k, v in tools.items() if isinstance(v, dict))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            prepare_pr(settings, None, execute=False, review_id=d.name)
        pr_out = buf.getvalue().replace(str(ROOT), "<repo>")
        seen = set(); factors = []
        for f in risk.get("factors") or []:
            key = (f.get("factor"), f.get("points"))
            if key in seen or (not f.get("points") and not re.search(r"hard|floor", str(f.get("note", "")))):
                continue
            seen.add(key); factors.append({"factor": f.get("factor"), "points": f.get("points", 0), "note": ("무조건 HIGH" if "hard" in str(f.get("note", "")) else "최소 MEDIUM" if "floor" in str(f.get("note", "")) else "")})
        pr_body = (d / "pr_body.md").read_text(encoding="utf-8") if (d / "pr_body.md").exists() else ""
        out.append({
            "scenario": scen, "title": title, "desc": desc, "record": d.name, "state": s.get("state"), "level": s.get("review_level"),
            "verification_status": s.get("verification_status"), "risk": risk.get("risk_level"), "score": risk.get("score"), "cap": risk.get("autonomy_cap"),
            "rubric": str(risk.get("rubric_version", ""))[:34], "tools": tool_line or "도구 기록 없음",
            "layers": [{"layer": l.get("layer"), "name": l.get("name"), "verdict": l.get("verdict"), "summary": str(l.get("summary", ""))[:260]} for l in rep.get("layers") or []],
            "factors": factors, "history": [{"state": h.get("state"), "note": str(h.get("note", ""))[:200]} for h in s.get("history") or []],
            "diff": (d / "candidate.diff").read_text(encoding="utf-8") if (d / "candidate.diff").exists() else "", "pr_preview": pr_out.strip(), "pr_body": pr_body[:6000],
        })
    return out


def _js_differential(rubric: dict, n: int = 1500) -> dict:
    """calc.js 와 Python calc_risk / gate_demo 를 무작위 입력으로 대조. 페이지에 '일치 N/N' 으로 적는다."""
    rng = random.Random(20260928)
    cases = []
    for _ in range(n):
        kind = rng.choice(["SG", "IAM"])
        cases.append({"target_kind": kind, "changed_attrs": rng.choice(["ingress", "policy", "ingress,egress", "ingress,name", "policy,tags", "description", "ingress,vpc_id"]),
                      "resources_touched": rng.choice([1, 1, 2, 3, 4, 6]), "new_resources": rng.choice([0, 0, 1, 2, 3]), "deleted": rng.random() < .15, "replaced": rng.random() < .15,
                      "trust_policy": rng.random() < .15, "provider_changed": rng.random() < .1, "attachment_points": rng.choice([0, 0, 1, 2, 3]), "external_sg": rng.random() < .3,
                      "outside_family": rng.random() < .3, "oracle_partial": rng.random() < .3, "lines": rng.choice([0, 2, 10, 41, 80]), "files": rng.choice([1, 1, 2])})
    gates = [(rl, p, v, ok) for rl in ["LOW", "MEDIUM", "HIGH"] for p in [None, "LOW", "MEDIUM", "HIGH"] for v in ["PASS", "FAIL", "INCOMPLETE"] for ok in [True, False]]
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / "in.json"; inp.write_text(json.dumps({"rubric": rubric, "cases": cases, "gates": gates}), encoding="utf-8")
        runner = Path(td) / "run.js"
        runner.write_text("const fs=require('fs');const c=require(process.argv[3]);const d=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));"
                          "process.stdout.write(JSON.stringify({calc:d.cases.map(x=>c.calcRisk(x,d.rubric)),gates:d.gates.map(([r,p,v,o])=>c.gateDecide(r,p,v,o))}));", encoding="utf-8")
        r = subprocess.run(["node", str(runner), str(inp), str(SITE / "calc.js")], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return {"ok": False, "error": r.stderr[-500:], "n": n}
    js = json.loads(r.stdout)
    mism = 0
    for c, j in zip(cases, js["calc"]):
        p = rd.calc_risk(c, rubric)
        pf = sorted((f["factor"], f["points"]) for f in p["factors"]); jf = sorted((f["factor"], f["points"]) for f in j["factors"])
        if (p["level"], p["cap"], p["score"], pf) != (j["level"], j["cap"], j["score"], jf):
            mism += 1
    gm = 0
    for g, j in zip(gates, js["gates"]):
        p = rd.gate_demo(*g)
        if (p["final"], p["action"], p["cap"]) != (j["final"], j["action"], j["cap"]):
            gm += 1
    return {"ok": mism == 0 and gm == 0, "n": n, "mismatch": mism, "gates": len(gates), "gate_mismatch": gm}


def collect(report_url: str, repo_url: str) -> dict:
    policy, rubric = rd.load_policy_and_rubric(ROOT)
    labels = rd.labeled_matrix(ROOT, Path(tempfile.mkdtemp(prefix="site-rubric-")))
    labels.pop("tmp_dir", None)
    cap = rd.cap_enforcement_check()
    S = summarize()
    sets = []
    for s in S["sets"]:
        sets.append({"id": s["id"], "n": s.get("n", 0), "agree": s.get("agree", 0), "labeled": s.get("labeled", 0), "v1_only": s.get("v1_only", 0), "gate": s.get("gate", 0),
                     "spof": s.get("spof", 0), "not_run": s.get("not_run", 0), "note": "후보 0건 — Claude Code 출력을 사람이 넣어야 채워짐 (미측정)" if s["id"] == "eval-claude-code" else "실행 기록 없음"})
    summary = {"sets": sets, "funnel": S["funnel"], "stops": dict(S["stops"]), "levels": dict(S["levels"]), "spof_total": S["spof_total"], "label_agree": S["label_agree"],
               "label_total": S["label_total"], "not_run_total": S["not_run_total"], "n_llm": S["n_llm"], "aws_runs": S["aws_runs"], "blind_sg": S["blind_sg"], "blind_iam": S["blind_iam"],
               "fuzz": S["fuzz"], "oracle_fuzz": S["oracle_fuzz"], "env": S["env"], "host": S["host"], "latest_total": S["latest_total"], "rows_total": S["rows_total"]}
    docs = []
    for rel, title in (("docs/WEEKLY_REPORT_B_2026-09-29.md", "B 주간보고 초안"), ("docs/walkthroughs/B.md", "B 가 설명해야 하는 것 (공부용)"),
                       ("docs/WHITELIST_VS_POLICY.md", "화이트리스트 v0.2 ↔ 코드 대조표"), ("docs/WHY_8_LAYERS.md", "왜 8계층인가"), ("docs/DEPTH_OVER_SCALE.md", "깊이로 이기는 계획")):
        p = ROOT / rel
        if p.exists():
            docs.append({"title": title, "path": rel, "html": md_to_html(p.read_text(encoding="utf-8"))})
    diff = _js_differential(rubric)
    return {"generated": _dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "host": platform.node(), "report_url": report_url, "repo_url": repo_url,
            "rubric": rd.rubric_view(rubric), "rubric_raw": rubric, "factor_labels": {**rd.FACTOR_KO, **rd.HARD_KO}, "labels": labels, "cap": cap, "summary": summary,
            "examples": _examples(), "docs": docs, "js_check": diff}


# ----------------------------------------------------------------------------- 페이지
def render(D: dict) -> str:
    S = D["summary"]; L = D["labels"]; K = D["cap"]; J = D["js_check"]
    blind = (S["blind_sg"][0] if S["blind_sg"] else 0) + (S["blind_iam"][0] if S["blind_iam"] else 0)
    blind_d = (S["blind_sg"][1] if S["blind_sg"] else 0) + (S["blind_iam"][1] if S["blind_iam"] else 0)
    fz = S.get("fuzz") or {}
    ofz = S.get("oracle_fuzz") or {}
    css = (SITE / "site.css").read_text(encoding="utf-8")
    calc_js = (SITE / "calc.js").read_text(encoding="utf-8")
    site_js = (SITE / "site.js").read_text(encoding="utf-8")
    data_json = json.dumps(D, ensure_ascii=False).replace("</", "<\\/")
    report_link = f'<a href="{esc(D["report_url"])}" target="_blank" rel="noopener">실행 리포트 전체 (별도 페이지)</a>' if D["report_url"] else '<span class="small">실행 리포트 전체는 별도 게시 예정</span>'
    js_line = (f"JS 이식본을 Python 원본과 무작위 입력 {J['n']}건 + 게이트 {J['gates']} 조합으로 대조 → 불일치 {J['mismatch'] + J['gate_mismatch']}건 (빌드 시 자동)" if J.get("ok") is not None and "mismatch" in J
               else f"JS 대조 실패: {J.get('error', '')}")
    return f"""<title>IaCPatch 검증 현황</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+KR:wght@400;600;700&family=IBM+Plex+Mono:wght@400;600&display=swap">
<style>{css}</style>
<header class="head"><div class="wrap">
  <div class="kicker">사이버보안과 졸업작품 · 팀 놈3 · B 담당분 공유 페이지</div>
  <h1>AI가 생성한 테라폼 보안 패치의 실효성 검증 자동화 구현</h1>
  <p>Trivy 가 통과시킨 패치를 그대로 믿지 않는다. 검증 계층(재스캔 → 새 finding → validate → plan → plan 차이 → 실효 상태 오라클)과 위험도 기준표가 후보마다 '사람이 어떤 검토를 해야 하나' 를 정한다. 이 페이지의 숫자는 전부 저장소 기록에서 다시 계산한 것이고, 안 한 것은 안 했다고 적었다.</p>
  <div class="chips">
    <span class="chip">{esc(D['generated'])} 생성</span>
    <span class="chip ok">{esc(S['env'] or '도구 기록 없음')} · 샌드박스</span>
    <span class="chip ok">팀 PC Terraform 1.16.1 재현 38/38 (09-22)</span>
    <span class="chip">기록 {S['rows_total']}건 · 세트별 최신 {S['latest_total']}건 집계</span>
    <span class="chip no">LLM(Claude Code) 후보 {S['n_llm']} — 미측정</span>
    <span class="chip no">AWS 배포 후 검증(V7/V8) {S['aws_runs']}회</span>
    <span class="chip warn">GitHub push/PR 전 (B 브랜치 42 커밋)</span>
  </div>
  <div class="kpis">
    <div class="kpi crit"><div class="n">{blind}<small> / {blind_d}</small></div><div class="l">스캐너 통과 ∧ 오라클 FAIL</div><div class="m">실제 plan (SG {S['blind_sg'][0] if S['blind_sg'] else '-'}/{S['blind_sg'][1] if S['blind_sg'] else '-'} · IAM {S['blind_iam'][0] if S['blind_iam'] else '-'}/{S['blind_iam'][1] if S['blind_iam'] else '-'})</div></div>
    <div class="kpi good"><div class="n">{S['label_agree']}<small> / {S['label_total']}</small></div><div class="l">기대 라벨 일치</div><div class="m">후보 세트 4개, 실제 도구 실행</div></div>
    <div class="kpi good"><div class="n">{L['agree']}<small> / {L['judged']}</small></div><div class="l">위험도: 기대 등급 = 코드 등급</div><div class="m">도구 없이 재계산 · 사람 검산 {L['human_verified']}/{L['total']}</div></div>
    <div class="kpi good"><div class="n">{len(K['violations'])}<small> / {K['total']}</small></div><div class="l">상한 강제 위반</div><div class="m">위험도 × LLM 제안 × 검증 × 정책 전수</div></div>
    <div class="kpi good"><div class="n">{fz.get('oracle_caught', '–')}<small> / {fz.get('trivy_blind', '–')}</small></div><div class="l">스캐너 사각 중 오라클 탐지</div><div class="m">변형 자동 생성 {fz.get('should', '–')}종 · 놓침 {fz.get('oracle_miss', '–')}</div></div>
    <div class="kpi good"><div class="n">{esc(ofz.get('mismatch', '–'))}</div><div class="l">오라클 차등 검증 불일치</div><div class="m">무작위 {esc(ofz.get('cases', '–'))}건</div></div>
  </div>
</div></header>

<nav class="tabs"><div class="wrap">
  <button type="button" data-tab="w4"><span class="w">4주차</span>위험도 기준표 · 상한 강제</button>
  <button type="button" data-tab="w5"><span class="w">5주차</span>패치 → 검증 → PR</button>
  <button type="button" data-tab="exp"><span class="w">실험</span>결과 요약</button>
  <button type="button" data-tab="docs"><span class="w">문서</span>주간보고 · 근거</button>
</div></nav>

<main class="wrap">
<section class="tab" id="tab-w4">
  <div class="card">
    <h2>4주차 목표 — "목업 데이터로 High/Medium/Low 가 올바르게 분류되고, 상한 강제가 동작한다"</h2>
    <p class="sub">위험도는 <b>코드가 정한다</b>(plan 의 사실만 입력). LLM 은 등급을 <b>낮추는 제안</b>만 할 수 있고, 상한을 넘는 제안은 무시하고 기록한다. 아래 ①~③ 이 그 세 문장의 근거다.</p>
    <div class="note">정직 표기 — 라벨 25건(expected_risk)은 B 의 Claude 세션이 기준표를 읽고 적은 값이다. <b>사람 손 검산은 {L['human_verified']}/{L['total']}</b>. B 가 항목마다 직접 검산하면 그때부터 "사람 검산" 이라고 부른다.</div>
  </div>
  <div class="card">
    <h2>① 위험도 기준표 <span class="tag" id="rubric-ver"></span></h2>
    <p class="sub">원본은 <code>policy/risk_rubric.json</code> (사람이 고친다). 점수 합계 ≤ <b id="th-low"></b> → LOW(자율성 상한 HIGH), ≤ <b id="th-med"></b> → MEDIUM(상한 MEDIUM), 그 위 → HIGH(상한 LOW). '무조건 HIGH' 조건은 점수와 무관. "자율성 HIGH" 는 안전하다는 뜻이 아니라 PR 을 자동으로 열어도 되는 범위라는 뜻이고, apply 는 항상 사람이 한다.</p>
    <div class="two">
      <div><h3>점수 항목</h3><div class="tw"><table id="rubric-points"><thead><tr><th>항목</th><th>점수</th><th>키</th></tr></thead><tbody></tbody></table></div></div>
      <div><h3>무조건 HIGH (hard)</h3><ul id="rubric-hard" class="small"></ul><h3>최소 MEDIUM (floor)</h3><ul id="rubric-floor" class="small"></ul><h3>위험도 → 자율성 상한</h3><ul id="rubric-cap" class="small"></ul><h3>텍스트 근거만으로는 미확정</h3><ul id="rubric-undet" class="small"></ul></div>
    </div>
  </div>
  <div class="card">
    <h2>② 목업 plan 25건 분류 — 기대 등급 vs 코드 등급 <span class="tag">도구 없이, 커밋된 plan 쌍으로 재계산</span></h2>
    <p class="sub">후보 세트의 라벨을 <b>실제 검토 흐름</b>(run_review)으로 다시 돌려 코드 등급과 비교했다. V1~V4 는 도구가 없으면 NOT_RUN, V5·V6·위험도는 <code>tests/fixtures/plan-pairs</code> 의 plan 쌍으로 계산. 세 등급이 모두 나온다.</p>
    <p class="small" id="labels-status"></p>
    <div class="tw"><table id="labels-table"><thead><tr><th>후보</th><th>기대</th><th>코드</th><th>일치</th><th>점수</th><th>근거</th><th>V5</th><th>V6</th><th>상태</th><th>계산 근거</th></tr></thead><tbody></tbody></table></div>
  </div>
  <div class="card">
    <h2>③ 상한 강제 전수 검사 — 위험도 3 × LLM 제안 4 × 검증 3 × 정책 2 = 72 조합</h2>
    <p class="sub">불변식: 정책 위반/검증 실패 → 무조건 차단 · 검증 미완 → 보류 · 검증 통과 → 최종 자율성 = min(상한, 제안). 위반이 0 건이어야 한다.</p>
    <p id="cap-status"></p><ul id="cap-inv" class="small"></ul>
    <details><summary>72 조합 표 펼치기</summary><div class="tw"><table id="cap-table"><thead><tr><th>위험도</th><th>상한</th><th>LLM 제안</th><th>검증</th><th>정책</th><th>최종 자율성</th><th>동작</th><th>비고</th></tr></thead><tbody></tbody></table></div></details>
  </div>
  <div class="two">
    <div class="card">
      <h2>④ 게이트 데모 — LLM 제안이 상한을 넘으면?</h2>
      <p class="sub">코드가 정한 위험도와 LLM 제안을 넣으면 게이트가 최종 자율성과 동작을 정한다. 값을 바꾸면 바로 다시 판정한다.</p>
      <div class="form">
        <label for="g-risk">코드가 정한 위험도 <select id="g-risk"><option>LOW</option><option selected>MEDIUM</option><option>HIGH</option></select></label>
        <label for="g-prop">LLM 제안 자율성 <select id="g-prop"><option value="">없음</option><option selected>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label>
        <label for="g-val">검증 결과 <select id="g-val"><option>PASS</option><option>FAIL</option><option>INCOMPLETE</option></select></label>
        <label for="g-pol">정책 통과 <input type="checkbox" id="g-pol" checked></label>
      </div>
      <div id="gate-out" style="margin-top:10px"></div>
    </div>
    <div class="card">
      <h2>⑤ 기준표 계산기 (목업 입력)</h2>
      <p class="sub">체크·숫자를 바꾸면 기준표 계산이 다시 돈다. 이 페이지의 계산기는 Python 원본(<code>policy/risk.py</code>)을 JS 로 옮긴 것이다 — {esc(js_line)}.</p>
      <div class="form" id="calc-form"></div>
      <div id="calc-out" style="margin-top:10px"></div>
    </div>
  </div>
</section>

<section class="tab" id="tab-w5" hidden>
  <div class="card">
    <h2>5주차 목표 — 시나리오 → 패치 후보 → 검증(V1~V6) → 위험도 → 검토 수준 → PR 미리보기</h2>
    <p class="sub">한 후보가 흐름을 끝까지 지나가면 어떻게 되는지, 2026-09-22 샌드박스 실행 기록 3건으로 보여 준다. PR 은 <b>미리보기</b>까지다(브랜치·제목·명령). push/PR 생성/apply 는 사람이 한다.</p>
    <div class="flow">
      <span class="st">Trivy 스캔</span><span class="ar">→</span><span class="st">Evidence</span><span class="ar">→</span><span class="st">패치 후보 (규칙 기반 / Claude Code 출력)</span><span class="ar">→</span><span class="st">Policy Validator</span><span class="ar">→</span>
      <span class="st">V1 재스캔</span><span class="ar">→</span><span class="st">V2 새 finding</span><span class="ar">→</span><span class="st">V3 validate</span><span class="ar">→</span><span class="st">V4 plan</span><span class="ar">→</span><span class="st">V5 plan 차이</span><span class="ar">→</span><span class="st h">V6 실효 상태 오라클</span><span class="ar">→</span>
      <span class="st h">위험도 기준표</span><span class="ar">→</span><span class="st h">검토 수준 / 게이트</span><span class="ar">→</span><span class="st">PR 미리보기</span><span class="ar">→</span><span class="st">사람 승인 · apply(사람)</span><span class="ar">→</span><span class="st">V7 AWS 실측 · V8 기능 (0회)</span>
    </div>
  </div>
  <div class="card">
    <div class="docnav" id="ex-nav"></div>
    <div id="ex-meta"></div>
    <h3>검증 표</h3>
    <div class="tw"><table id="ex-layers"><thead><tr><th>계층</th><th>질문</th><th>판정</th><th>요약</th></tr></thead><tbody></tbody></table></div>
    <div class="two">
      <div><h3>위험도 요인</h3><ul id="ex-factors" style="padding-left:18px;margin:0"></ul></div>
      <div><h3>상태 전환 (state.json history)</h3><ul id="ex-history" class="small" style="padding-left:18px;margin:0"></ul></div>
    </div>
    <h3>패치 diff</h3><pre class="diff" id="ex-diff"></pre>
    <h3>PR 미리보기 (<code>iacpatch pr --review &lt;id&gt;</code>, execute 없음)</h3><pre id="ex-pr"></pre>
    <details><summary>pr_body.md 원문</summary><pre id="ex-prbody"></pre></details>
  </div>
</section>

<section class="tab" id="tab-exp" hidden>
  <div class="card">
    <h2>실험 결과 요약 <span class="tag">세트별 최신 실행만 집계</span></h2>
    <p class="sub">{report_link} · 아래는 그 리포트의 머리 숫자다. 실행 환경: {esc(S['env'] or '도구 기록 없음')} ({esc(S['host'])}).</p>
    <div class="tw"><table id="sets-table"><thead><tr><th>세트</th><th>후보</th><th>라벨 일치</th><th>재스캔(V1)만 통과</th><th>V1+V6 통과</th><th>스캐너 통과∧오라클 FAIL</th><th>미검증 계층</th></tr></thead><tbody></tbody></table></div>
    <div class="note info">"재스캔만 통과 → V1+V6 통과" 의 차이가 곧 <b>스캐너만 믿었으면 통과시켰을 패치</b> 다. seeded 후보는 알려진 우회 패턴을 사람/AI 세션이 만든 것이라 LLM 이 실제로 내는 빈도가 아니다. 오라클 UNKNOWN 은 통과가 아니라 사람 검토다.</div>
  </div>
  <div class="two">
    <div class="card"><h2>파이프라인 깔때기</h2><p class="sub">후보가 어느 단계까지 살아남나 (전 세트 합산, 누적 통과)</p><div class="funnel" id="funnel"></div></div>
    <div class="card"><h2>어느 계층이 잡았나</h2><p class="sub">후보별 첫 FAIL 지점</p><div class="stops" id="stops"></div><h3>최종 검토 수준</h3><ul id="levels" class="small" style="padding-left:18px"></ul></div>
  </div>
  <div class="card">
    <h2>오라클 실험 · 스캐너 사각 탐색 · 차등 검증</h2>
    <ul>
      <li>실제 plan {blind_d}개에서 스캐너 통과 ∧ V6 FAIL <b>{blind}</b> (SG {S['blind_sg'][0] if S['blind_sg'] else '-'}/{S['blind_sg'][1] if S['blind_sg'] else '-'}, IAM {S['blind_iam'][0] if S['blind_iam'] else '-'}/{S['blind_iam'][1] if S['blind_iam'] else '-'}) — <code>experiments/ORACLE_RESULTS.md</code></li>
      <li>겉모습만 다른 변형 자동 생성 {fz.get('should', '–')}종(잡혀야 하는 것) 중 Trivy 사각 <b>{fz.get('trivy_blind', '–')}</b> → 오라클 탐지 <b>{fz.get('oracle_caught', '–')}</b> · 사람에게(UNKNOWN) {fz.get('unknown', '–')} · 오라클도 놓침 <b>{fz.get('oracle_miss', '–')}</b> — <code>experiments/FUZZ_RESULTS.md</code></li>
      <li>오라클의 집합 연산을 따로 짠 기준 구현과 무작위 {esc(ofz.get('cases', '–'))}건 대조 → 불일치 <b>{esc(ofz.get('mismatch', '–'))}</b> — <code>experiments/ORACLE_FUZZ.md</code></li>
      <li>팀 PC(Windows, Terraform 1.16.1)에서 같은 4세트 38건을 다시 돌려 샌드박스(OpenTofu 1.10.6)와 판정 38/38 동일 — <code>results-history/*-DESKTOP-TSH8UUD.md</code></li>
    </ul>
    <div class="note">이 페이지가 말하지 않는 것 — AWS 실제 반영·배포 후 검증(V7/V8) <b>{S['aws_runs']}회</b> · Claude Code(LLM) 후보 <b>{S['n_llm']}건</b>(0 이면 LLM 축은 미측정) · 미검증 계층(NOT_RUN/ERROR) <b>{S['not_run_total']}</b>.</div>
  </div>
</section>

<section class="tab" id="tab-docs" hidden>
  <div class="card">
    <h2>문서</h2>
    <p class="sub">저장소의 마크다운을 그대로 옮긴 것. 원본: <code>docs/</code>.</p>
    <div class="docnav" id="docnav"></div>
    <div class="doc" id="doc-body"></div>
  </div>
</section>

<footer class="wrap">
  <div>코드: <a href="{esc(D['repo_url'])}" target="_blank" rel="noopener">{esc(D['repo_url'])}</a> (main 에는 아직 B 브랜치가 없다 — PR 뒤에 올라간다) · 생성: <code>python scripts/build_site.py</code> · 이 페이지는 서버 없이 동작하며 LLM API·AWS·GitHub 에 접속하지 않는다.</div>
  <div style="margin-top:6px">하지 않는 것: LLM API 호출, Claude Code 자동 호출, AWS 접속, terraform apply, git push. 검증 결과의 '표시' 이며 병합·반영 판단은 사람이 한다 (docs/DECISIONS.md D-5, D-11).</div>
</footer>
</main>
<script id="site-data" type="application/json">{data_json}</script>
<script>{calc_js}</script>
<script>{site_js}</script>
"""


def report_fragment() -> str:
    """report/index.html → Artifact 조각 (doctype/html/head/body 제거, title 유지)."""
    from iacpatch.report_html import build
    p = build(ROOT / "report" / "index.html")
    txt = p.read_text(encoding="utf-8")
    m = re.search(r"<style>(.*?)</style>", txt, re.S)
    body = re.search(r"<body>(.*)</body>", txt, re.S)
    css = m.group(1) if m else ""
    inner = body.group(1) if body else txt
    return f"<title>IaCPatch 실행 리포트</title>\n<style>{css}</style>\n{inner}\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report-url", default="")
    ap.add_argument("--repo-url", default="https://github.com/krk1206/cloud-security-capstone")
    ap.add_argument("--out", default="report/site.html")
    a = ap.parse_args()
    D = collect(a.report_url, a.repo_url)
    out = ROOT / a.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(D), encoding="utf-8")
    rep = ROOT / "report" / "report-artifact.html"
    rep.write_text(report_fragment(), encoding="utf-8")
    print(f"site: {out} ({out.stat().st_size // 1024} KB) · report fragment: {rep} ({rep.stat().st_size // 1024} KB)")
    print(f"labels {D['labels']['agree']}/{D['labels']['judged']} · cap violations {len(D['cap']['violations'])} · js check {D['js_check']}")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
