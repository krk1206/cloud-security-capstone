// 화면 ⑤ 수정안 · ⑥ 적용 판단 · ⑦ AWS 시험 환경 · ⑧ 최종 결정 (+ PR)
// 판정은 만들지 않는다 — 서버(web/product.py · 검사 기록)가 준 값을 그대로 보여 준다. 계산하지 못한 것은 '검사 못 함' 으로.
import { $, S, api, esc, escBrk, fmt, register, registerTodo, refreshTodo, guideCard, render, renderSide, chip, toast, modal, followJob, designVersion, designConf, go, onEnter, caseMode } from "./m_core.js";
import { mapBox, drawMap, mapView, MLEG, pop, nodeInfo, linkInfo } from "./m_map.js";
import { reqRow, reqCard } from "./m_req.js";
import { stage2Plan, mmss } from "./flow2.js";

// 실행 · 시도 상태 (서버 llmfix.STATUS_KO 와 같은 뜻 — D-36): 실패는 종류별로 다른 글자. 실행 오류 · 검증 불가는 AI 에게 다시 묻지 않은 것
const AI_ST = { PASSED: ["ok", "통과"], BLOCKED: ["bad", "막힘"], AI_ERROR: ["bad", "AI 오류"], GAVE_UP: ["bad", "3번 모두 막힘 — 사람이 직접 수정"],
  REPEATED: ["bad", "같은 수정안 반복 — 중단"], TOOL_ERROR: ["warn", "실행 오류 — 환경 복구 후 다시"], UNDECIDABLE: ["warn", "검증 불가 — 사람 검토"],
  RUNNING: ["run", "진행 중"], ASKING: ["run", "AI 답 기다리는 중"] };
const STAGES = [["trivy_after", "Trivy 다시 검사"], ["plan_candidate", "Terraform 유효성 · 변경 계산"], ["verify", "허용 범위 · 고객 설계 비교"]];
const SUB_ST = { changed: ["바뀐 파일 → 검사", "ok"], new: ["새 파일 → 검사", "warn"], same: ["원본과 같음 → 안 씀", "dim"], unused: ["검사에 안 씀", "dim"], rejected: ["거절", "bad"] };
const KIND_RULE = { topology: "고객 설계도", sg: "기존 요구사항 (보안 그룹)", iam: "IAM 요구사항" };
const isAiRun = (id) => /^ai-\d{8}-\d{6}-[0-9a-f]{6}-a\d+$/.test(String(id || ""));

// ------------------------------------------------------------------ 자료
// 고칠 대상이 있는 묶음만 (연결한 프로젝트의 '<id>.main' 은 설계도를 붙이는 기본 묶음 — 고칠 대상 없음)
export function sets() { return ((S.cands && S.cands.sets) || []).filter((s) => s.rule); }
export function curSet() { return sets().find((s) => s.set_id === S.target) || sets()[0] || {}; }
function activeSha() { return ((((S.design || {}).design || {}).versions || []).find((v) => v.active) || {}).sha256; }
const isRb = (id) => String(id) === "rule-based";      // ⑤ '설계도대로 자동 수정' 의 기록 (후보 id 없는 규칙 기반 생성, D-45)
// 화면에 보이는 수정안 = manifest 의 featured (D-47 "수정안 3~4개"). featured 가 없는 묶음(연결한 프로젝트)은 예전처럼 전부
function teamList() {
  const all = (curSet().candidates || []).filter((c) => !/^(paste|upload)/.test(String(c.id)) && !isAiRun(c.id) && !isRb(c.id));
  const feat = curSet().featured || [];
  if (feat.length) return feat.map((id) => all.find((c) => c.id === id)).filter(Boolean);
  return all.slice().sort((a, b) => String(a.label).localeCompare(String(b.label), "ko", { numeric: true }));
}
function directList() { return (curSet().candidates || []).filter((c) => /^(paste|upload)/.test(String(c.id))).slice(0, 6); }
function rbItem() { return (curSet().candidates || []).find((c) => isRb(c.id)) || null; }
// 설계도대로 자동 수정은 통신 구조 설계도(토폴로지)가 있는 고칠 문제에서만 — 요구사항 표(IAM 등)는 팀 평가용 수정안에 규칙 기반이 따로 있다
const rbOn = () => curSet().intent_kind === "topology" && !!(S.design && S.design.exists);
// 이전 기준 결과: 기록의 기준 파일 지문 ≠ 지금 기준 지문. 설계도(프로젝트)는 S.design 의 활성 버전, 요구사항(IAM 등)은 세트의 지금 기준 (D-40)
const curSha = () => curSet().intent_kind === "topology" ? activeSha() : curSet().design_sha256;
const stale = (c) => c && c.latest && c.latest.design && curSha() && c.latest.design.sha256 !== curSha();
const tone = (c) => { const l = c && c.latest; if (!l) return ["dim", "검사 전"]; const t = (l.classification || {}).tone; return t === "good" ? ["ok", "통과"] : t === "bad" ? ["bad", "막힘"] : ["warn", "판정 불가"]; };
const MARK = { ok: "✓", bad: "✕", warn: "?", dim: "–" };
const mark = (k, w) => `<em class="mk ${k}" aria-label="${esc(w)}">${MARK[k] || ""}</em>`;
const toneChip = (t) => (t === "good" ? "ok" : t === "bad" ? "bad" : "warn");
function curCand() { return teamList().concat(directList(), rbItem() ? [rbItem()] : []).find((x) => x.id === S.cand) || null; }

export async function loadRecord(rid) {
  if (S.rec !== rid) { S.dec = null; S.pr = null; }
  S.rec = rid; S.impact = null; S.verdict = null; S.final = null; S.picView = null;     // 다른 수정안을 고르면 그림은 다시 '적용 후' (D-48)
  render();
  const [im, vv] = await Promise.all([api.get(`/api/p/impact?id=${encodeURIComponent(rid)}`), api.get(`/api/p/verdict?id=${encodeURIComponent(rid)}`)]);
  if (S.rec !== rid) return;              // 그 사이 다른 수정안을 골랐음
  S.impact = im; S.verdict = vv; S.lastRec = { id: rid, label: (vv && vv.label) || (im && im.label) };
  render();
}

// ------------------------------------------------------------------ ⑤ 수정안
function targetInfo() {
  const s = curSet();
  const all = (S.issues && S.issues.issues) || [];
  // 고른 문제가 이 묶음으로 고치는 문제일 때만 그 이름을 쓴다 (S3 처럼 수정 묶음이 없는 문제를 고른 채로 오면 묶음의 대상 지적을 보여 준다)
  const iss = all.find((x) => x.id === S.issue && x.fix && x.fix.set_id === s.set_id) || all.find((x) => x.rule === s.rule && x.resource === s.resource);
  const swap = sets().length > 1 ? `<div class="seg">${sets().map((x) => `<button type="button" class="${x.set_id === S.target ? "on" : ""}" data-target="${esc(x.set_id)}">${esc(x.label)}</button>`).join("")}</div>` : "";
  const rc = s.design_confirmation || null;     // 요구사항 파일의 버전 · 상태 (D-40)
  const rst = rc ? (rc.basis === "manifest" ? "팀 작성 평가 기준" : rc.confirmed ? `${rc.by || ""} 확정` : "초안 — 확정 전") : "";
  const keep = s.intent_kind === "topology" ? `원하는 구조(고객 설계도) v${designVersion()}` : `${KIND_RULE[s.intent_kind] || "요구사항"} v${s.design_version || 1}${rst ? ` (${rst})` : ""}`;
  // Trivy 지적이 아닌 문제(설계 위반 · 자체 검사)는 같은 프로젝트의 Trivy 지적을 고치는 수정으로 함께 검사한다 (연결한 프로젝트, D-32)
  const via = iss && iss.fix && iss.fix.via ? all.find((x) => x.id === iss.fix.via) : null;
  const sub = via
    ? `Trivy 가 보는 문제가 아니라서, 같은 수정에서 <b>${esc(via.title)}</b> (<code>${esc(s.resource || "")}</code> · Trivy ${esc(s.rule || "")}) 와 함께 고치고 검사합니다 — 이 문제가 해결됐는지는 <b>${esc(keep)}</b> 비교로 확인`
    : `${s.resource ? `<code>${esc(s.resource)}</code> · ` : ""}${s.rule ? `Trivy ${esc(s.rule)} · ` : ""}수정 후에도 <b>${esc(keep)}</b> 를 지켜야 함`;
  return `<div class="target"><div><span class="kicker">고칠 문제${via ? "" : ` · ${esc(s.label || "")}`}</span><b>${esc(iss ? iss.title : (s.rule ? `${s.rule} · ${s.resource}` : s.label || ""))}</b>
      <small>${sub}</small></div>${swap}</div>`;
}

function aiState() {
  const st = S.llm.status;
  if (!st) return ["dim", "확인 중…"];
  if (!st.found) return ["bad", "Claude Code 없음"];
  if (st.logged_in === false) return ["warn", "로그인 필요"];
  return ["ok", `준비됨 · ${st.version || ""}`];
}

// 수정안 버튼 (6차 · D-34 — B: "수정안을 전부 합치면 어떡해, 각각 나눠서"): 합치지 않고 하나씩. AI 수정은 시도 하나 = 버튼 하나
// 7차 (D-35 — B 11-02 "쉽게"): 'AI 에게 고치게 하기' 를 맨 위 큰 버튼으로. 팀 평가용 수정안 25개는 한 줄 요약으로 접어 두고,
// 펼치면 수정안마다 '무엇을 바꿨는지'(줄 비교 요약 — 판정 아님) · 결과를 글자로. 정답 이름은 여전히 보이지 않는다 (교수 피드백 7)
const ATT = { PASSED: ["ok", "통과"], BLOCKED: ["bad", "막힘"], AI_ERROR: ["bad", "AI 오류"], REPEATED: ["bad", "반복"], TOOL_ERROR: ["warn", "실행 오류"], UNDECIDABLE: ["warn", "검증 불가"], ASKING: ["run", "진행 중"] };
function candBar() {
  const runs = (S.llm.runs || []).filter((r) => r.set_id === S.target).slice(0, 3);
  const team = teamList(), direct = directList();
  const [ak, aw] = aiState();
  const ai = runs.map((r) => {
    const atts = r.attempts || [];
    return `<span class="cgrp"><small>${esc(fmt(r.started_at))}</small>${atts.map((a) => {
      const [k, w] = ATT[a.status] || ["dim", a.status || ""];
      const on = (a.record_id && a.record_id === S.rec) || (S.aiPick === `${r.run_id}|${a.n}`);
      return `<button type="button" class="cchip ${on ? "on" : ""}" data-aiatt="${esc(r.run_id)}|${a.n}" title="${esc(`AI 수정 ${fmt(r.started_at)} · 시도 ${a.n} · ${w}${a.title ? ` — ${a.title}` : a.error ? ` — ${a.error}` : ""}`)}"><b>${a.n}차</b>${mark(k, w)}<span class="cw">${esc(w)}</span></button>`;
    }).join("") || `<span class="muted small">${esc((AI_ST[r.status] || ["", r.status || ""])[1])}</span>`}</span>`;
  }).join("");
  // 11차 (D-47): 수정안 1~4 를 큰 버튼으로 — 누르면 미리 분석해 둔 기록으로 아래 그림이 그 수정안을 적용한 모습으로 바로 바뀐다. '미리 분석 중' 이면 진행 표시
  const bg = S.bg && S.bg.set_id === S.target ? S.bg : null;
  const pending = team.filter((c) => needsAnalysis(c)).length;
  const bgTxt = bg ? `<span class="pfx run">미리 분석 중 ${bg.i}/${bg.n} — 끝난 수정안부터 누를 수 있음</span>`
    : pending && !prefetchOk() ? `<span class="pfx warn">③ 에서 설계도를 확정하면 ${pending}개를 미리 분석합니다</span>`
    : pending ? `<span class="pfx warn">${pending}개는 아직 분석 전 — 누르면 분석 시작</span>` : "";
  const trow = team.map((c, i) => { const [k, w] = tone(c); const na = needsAnalysis(c); return `<button type="button" class="cbig ${c.id === S.cand ? "on" : ""} ${na ? "na" : k}" data-cand="${esc(c.id)}" title="${esc(`${c.label} · ${c.summary || ""}`)}">
      <b>${i + 1}</b><span class="cb-t">${esc(c.summary || c.label)}</span><em class="tw ${na ? "dim" : k}">${na ? "분석 전" : `${MARK[k] || ""} ${w}`}${stale(c) ? " · 이전 설계도" : ""}</em></button>`; }).join("");
  // 설계도대로 자동 수정 (D-45): 규칙 기반 생성기 — ③ 설계도에서 외부 → 이 계층으로 그린 통신의 IP 대역을 그대로 허용 목록으로. AI 아님, 같은 8개 관문
  const rb = rbItem();
  const rbRow = rbOn() ? (() => { const [k, w] = rb && rb.latest && (rb.latest.classification || {}).code === "invalid" ? ["warn", "수정안 없음"] : tone(rb); return `<div class="cg rb"><b class="cg-l" title="③ 설계도에 그린 '밖에서 들어오는 통신' 의 IP 대역을 그대로 허용 목록으로 바꿔 씁니다 — 정해진 규칙, AI 아님. 결과는 다른 수정안과 똑같이 검사">설계도대로 자동 수정 <small class="muted">규칙 기반 · AI 아님</small></b>
        <div class="chips">${rb ? `<button type="button" class="cchip ${S.cand === rb.id ? "on" : ""}" data-cand="${esc(rb.id)}" title="${esc(`${rb.label} · ${w}${stale(rb) ? " · 이전 설계도 기준" : ""}`)}"><b>최근 결과</b>${mark(k, w)}<span class="cw">${esc(w)}${stale(rb) ? " · 이전 설계도 기준" : ""}</span></button>` : `<span class="muted small">아직 없음 — 설계도 v${designVersion()} 의 화살표대로 IP 목록만 바꿔 바로 검사</span>`}</div>
        <span class="cg-a"><button type="button" class="mbtn" data-act="run-rb" ${S.run ? "disabled" : ""}>설계도대로 자동 수정 ▶</button></span></div>`; })() : "";
  // 12차 (D-48): 수정안 번호 줄은 그림 바로 위에, AI · 설계도대로 자동 수정 · 직접 올린 파일은 '다른 방법' 으로 그림 아래에 — 번호와 그림이 붙어 있어야 '누르면 바뀐다' 가 보인다
  const teamBar = team.length ? `<div class="cands">
      <div class="cg team"><b class="cg-l" title="미리 만들어 둔 수정안 — 번호와 바꾼 곳만 보임, 결과는 검사가 정함">수정안 ${team.length}개 <small class="muted">누르면 아래 그림이 바뀜</small></b><div class="chips wrap">${bgTxt}</div></div><div class="tbig">${trow}</div></div>` : "";
  const otherBar = `<div class="cands other">
      <div class="cg ai"><b class="cg-l">AI 수정</b><div class="chips">${ai || `<span class="muted small">아직 없음</span>`}</div>
        <span class="cg-a"><button type="button" class="mbtn ${S.src === "ai" ? "on" : team.length ? "" : "primary"}" data-src="ai" title="${esc(aw)}">AI 에게 고치게 하기 ▾</button><small class="aist ${ak}">${esc(aw)}</small></span></div>
      ${rbRow}
      <div class="cg direct"><b class="cg-l">직접 올린 파일</b><div class="chips">${direct.slice(0, 6).map((c) => { const [k, w] = tone(c); return `<button type="button" class="cchip ${c.id === S.cand ? "on" : ""}" data-cand="${esc(c.id)}" title="${esc(`${c.label} · ${w}`)}"><b>${esc(String(c.label).replace("직접 제출 · ", ""))}</b>${mark(k, w)}</button>`; }).join("") || `<span class="muted small">아직 없음</span>`}</div>
        <span class="cg-a"><button type="button" class="mbtn sm ${S.src === "upload" ? "on" : ""}" data-src="upload">고친 파일 올리기 ▾</button></span></div>
    </div>`;
  return { teamBar, otherBar };
}

// 이 수정안을 지금 기준으로 (다시) 분석해야 하나 — 서버 needs_analysis 와 같은 판단 (기록 없음 · 설계도 파일 바뀜 · 초안 기준 기록인데 지금은 확정)
export function needsAnalysis(c) {
  const l = c && c.latest;
  if (!l) return true;
  if (stale(c)) return true;
  const conf = curSet().design_confirmation || {};
  return !!(conf.confirmed && l.design && l.design.confirmed === false);
}
// 미리 분석을 돌려도 되는 상태: 설계도가 확정됐거나(사람 · 팀 작성 기준) 설계도 확정 개념이 없는 묶음
export function prefetchOk() {
  const conf = curSet().design_confirmation;
  return !conf || !!conf.confirmed;
}

function aiPanel() {
  const st = S.llm.status;
  const [ak, aw] = aiState();
  return `<div class="mcard ai srcpanel"><h3>AI 에게 고치게 하기 <span class="aist ${ak}">${esc(aw)}</span></h3>
    <p class="small">AI(Claude Code, 구독)가 고친 코드를 냄 → 8개 관문 검사 → 막히면 <b>막힌 이유를 붙여 다시 요청</b> (최대 3번). AI 는 도구 없이 글만 씀 — 저장소 · AWS 접근 없음. 결과는 다른 수정안과 똑같이 검사합니다.</p>
    ${st && !st.found ? `<p class="small bad">${esc(st.note || "")}</p>` : st && st.logged_in === false ? `<p class="small warn">${esc(st.note || "")}</p>` : ""}
    ${(curSet().intent_kind === "topology" ? designConf().cls === "draft" : !!(curSet().design_confirmation && !curSet().design_confirmation.confirmed)) ? `<p class="small warn aidraft">${curSet().intent_kind === "topology" ? `설계도 v${designVersion()}` : `${KIND_RULE[curSet().intent_kind] || "요구사항"} v${curSet().design_version || 1}`} 는 아직 <b>초안</b>입니다 — 지금 돌리면 검사는 하지만 결과는 '검증 불가(확정 전 기준)' 로 남고 승인할 수 없습니다. 먼저 ③ 에서 담당자가 확정하는 것을 권합니다. <button type="button" class="linkbtn" data-go="3">③ 확정하러 가기</button></p>` : ""}
    <div class="aiopts"><span class="small muted">AI 에게 주는 자료</span><div class="seg"><button type="button" class="${S.llm.context === "trivy" || !(S.design && S.design.exists) ? "on" : ""}" data-ctx="trivy">Trivy 결과 + 원본 파일</button><button type="button" class="${S.llm.context === "design" && S.design && S.design.exists ? "on" : ""}" data-ctx="design" ${S.design && S.design.exists ? "" : "disabled title=\"고객 설계도가 없음\""}>+ 고객 설계도</button></div></div>
    <div class="mnav"><button type="button" class="mbtn primary" data-act="ai-run" ${st && st.found && !S.run ? "" : "disabled"}>AI 수정 시작 ▶</button><button type="button" class="mbtn" data-act="ai-refresh">상태 다시 확인</button></div></div>`;
}

function uploadPanel() {
  const u = S.upload || {};
  const chk = u.check;
  let body = "";
  if (u.reading) body = `<p class="muted small">파일 읽는 중…</p>`;
  else if (chk) {
    const rows = chk.files || [];
    body = `<ul class="inv">${rows.map((f) => { const st = SUB_ST[f.status] || [f.status, "dim"]; return `<li><code>${esc(f.path)}</code> ${chip(st[1], st[0])}<small>${esc(f.reason || "")}</small></li>`; }).join("")}</ul>
      ${chk.error ? `<p class="small bad">${esc(chk.error)}</p>` : ""}
      <div class="mnav"><button type="button" class="mbtn primary" data-act="run-upload" ${chk.ok && !S.run ? "" : "disabled"}>이 파일로 분석 시작 ▶</button></div>`;
  }
  return `<div class="mcard srcpanel"><h3>직접 고친 파일 올리기</h3><p class="small">원본 폴더에서 고친 .tf 파일(여러 개 · 폴더)을 고르면 원본과 비교해 <b>바뀐 파일만</b> 검사합니다. 원본 폴더 · AWS 는 바뀌지 않습니다.</p>
    <div class="mnav"><label class="mbtn">파일 고르기<input type="file" id="upFiles" multiple hidden></label><label class="mbtn">폴더 고르기<input type="file" id="upDir" webkitdirectory directory multiple hidden></label></div>${body}</div>`;
}

export function aiTimeline(run, live = false) {
  const atts = (run && run.attempts) || [];
  const n = (run && run.max_attempts) || 3;
  const rows = [];
  for (let i = 1; i <= n; i++) {
    const a = atts.find((x) => x.n === i);
    if (!a) { rows.push(`<li class="wait"><em>${i}</em><div><b>시도 ${i}</b><small>${live && run.status === "RUNNING" ? "대기" : "안 함"}</small></div></li>`); continue; }
    const st = a.status === "ASKING" ? (a.response_file ? ["run", "8개 관문 검사 중"] : ["run", "AI 답 기다리는 중"]) : (AI_ST[a.status] || ["", a.status]);
    rows.push(`<li class="${st[0]}"><em>${i}</em><div><b>시도 ${i} ${chip(st[0], st[1])}</b><small>${esc(a.title || a.error || "")}${a.seconds != null ? ` · AI 응답 ${a.seconds}초` : ""}</small>
      ${(a.problems || []).slice(0, 2).map((p) => `<span class="pr">${esc(p.what)}</span>`).join("")}
      <span class="lnk"><a href="#" data-prompt="${esc(run.run_id)}" data-n="${i}">AI 에게 보낸 요청</a>${a.record_id ? ` · <a href="#" data-rec="${esc(a.record_id)}">이 시도 결과</a>` : ""}</span></div></li>`);
  }
  const done = run && !live && run.status && run.status !== "RUNNING" ? (() => { const [k, w] = AI_ST[run.status] || ["", run.status]; return `<p class="airesult ${k}"><b>${esc(w)}</b>${run.status_ko ? ` — ${esc(run.status_ko)}` : ""}${run.run_error && run.status !== "PASSED" ? `<br><small>이유: ${esc(run.run_error)}</small>` : ""}${run.next ? `<br><small>다음: ${esc(run.next)}</small>` : ""}</p>`; })() : "";
  return `<ol class="aitl row">${rows.join("")}</ol>${done}`;
}

function runPanel() {
  const r = S.run || {};
  const sec = r.t0 ? ((Date.now() - r.t0) / 1000).toFixed(0) : "0";
  return `<div class="mcard run"><h3>${esc(r.label || "")} <small>${sec}초</small></h3>
    ${r.kind === "ai" ? `<div id="aiLive">${aiTimeline(S.llm.live || { attempts: [], max_attempts: 3, status: "RUNNING" }, true)}</div>` : `<ol class="stages row">${stagePills(r.stages)}</ol>`}
    <pre class="mlog" id="mlog">${esc(S.log.slice(-8).join("\n"))}</pre></div>`;
}
function stagePills(stages) {
  const done = new Set((stages || []).filter((x) => x.done).map((x) => x.key));
  let first = true;
  return STAGES.map(([k, w]) => { const d = done.has(k); const c = d ? "done" : first ? "run" : ""; if (!d) first = false; return `<li class="${c}">${esc(w)}</li>`; }).join("");
}

// 7차: 적용 후 그림을 못 그릴 때의 문장 — 쉬운 말이 먼저, 기술 이유(서버 값 그대로)는 작은 글씨로 아래에
const NO_AFTER = "이 수정안은 '적용 후' 그림을 그릴 수 없어요 — 검사가 실행 계획(plan)을 만들기 전에 멈춰서, 적용하면 어떻게 바뀌는지 계산하지 못했습니다. 멈춘 이유는 아래 결과에 있습니다.";

// ------------------------------------------------------------------ ⑤ 그림 하나 (12차 · D-48): 수정안 번호를 누르면 이 그림이 그 수정안을 적용한 모습으로 바뀐다
// B (11-04): "1번 누르면 김씨, 2번 누르면 이씨처럼 후보마다 설계도가 바뀌게" — 설계도와 적용 후를 나란히 두지 않고(6차 D-34) 한 그림을 바꾼다.
// 그림 = 흐름 그림 (출발지 · 보안 그룹 묶음 · 허용 포트). 설계도와 다른 곳만 빨강. [고객 설계도] 단추로 같은 자리에서 설계도만 볼 수 있다.
const rangeTxt = (rs) => [...new Set((rs || []).map((r) => (String(r[0]) === "-1" ? "전체" : +r[1] === +r[2] ? `${r[1]}` : `${r[1]}-${r[2]}`)))].join(", ");

// 적용 후 그림에 겹칠 것: 설계도와 다른 것만 (설계도에 없는 통신 = 빨강 ✕, 설계도에 있는데 막힘 = 빨간 점선).
// '원하는 구조의 통신인데 출발지가 코드와 다름(desired)' 은 그리지 않는다 — 그 통신은 [고객 설계도] 그림에 있고, 코드의 더 넓은 허용이 빨간 선으로 보인다
export function afterOpts(im) {
  const ov = im.overlay_after;
  if (!ov) return { overlay: null };
  const ge = (ov.ghost_edges || []).filter((g) => g.state !== "desired");
  const used = new Set(ge.flatMap((g) => [g.src, g.dst]));
  return { overlay: { ...ov, ghost_edges: ge, ghost_nodes: (ov.ghost_nodes || []).filter((n) => used.has(n.id)) } };
}
export function designDiffs(im) {
  const ov = im.overlay_after, A = im.arch_after;
  if (!ov || !A) return null;
  const nodes = Object.fromEntries([...(A.nodes || []), ...(ov.ghost_nodes || [])].map((n) => [n.id, n]));
  const nm = (id) => (nodes[id] || {}).label || id;
  const out = [];
  for (const e of A.edges || []) {
    const st = (ov.edges || {})[e.id];
    if (st && st.state === "excess") out.push({ cls: "risk", text: `${nm(e.src)} → ${nm(e.dst)} :${rangeTxt(st.ranges) || e.ports}`, why: "설계도에 없는 통신" });
  }
  for (const g of ov.ghost_edges || []) if (g.state === "missing") out.push({ cls: "miss", text: `${nm(g.src)} → ${nm(g.dst)} :${g.ports}`, why: "설계도에 있는데 막힘" });
  const seen = new Set();
  return out.filter((x) => (seen.has(x.text + x.why) ? false : seen.add(x.text + x.why)));
}
function onPick(id, ov) {
  return (p) => {
    const v = mapView(id);
    if (p.type === "node") pop(nodeInfo(v, p.node), p.x, p.y);
    else pop((p.links || [p.link]).map((l) => linkInfo(v, l, ov)).join("<hr>"), p.x, p.y);
  };
}
// '통신 관련만' 은 통신 구조(보안 그룹) 문제일 때만 — IAM 문제는 권한 그림 (15차, D-51: 역할 → 리소스 선만, 요구사항 비교 겹침)
const permOn = () => curSet().intent_kind === "iam";
const simpleOn = () => curSet().intent_kind === "topology";          // 흐름 그림 — IAM 요구사항 묶음은 권한 그림
export function drawAfter(id, im) {
  if (!im || !im.arch_after) return;
  const o = afterOpts(im);
  drawMap(id, im.arch_after, { ...o, simple: simpleOn(), perm: permOn() }, onPick(id, o.overlay));
}
// 권한 그림에서 요구사항과 다른 곳 (15차): 겹침의 '요구사항 밖' 선 · '꼭 필요한데 없음' 유령 선 · 신뢰 정책 상자 (판정은 V6 IAM 그대로)
function permDiffs(im) {
  const ov = im.overlay_after, A = im.arch_after;
  if (!ov || !A || ov.kind !== "iam") return null;
  const nodes = Object.fromEntries([...(A.nodes || []), ...(ov.ghost_nodes || [])].map((n) => [n.id, n]));
  const nm = (id) => (nodes[id] || {}).label || id;
  const out = [];
  for (const e of A.edges || []) {
    const st = (ov.edges || {})[e.id];
    const acts = [...new Set((e.pairs || []).map((x) => x[0]))].join(", ") || e.label;     // 선이 허용하는 동작 전부 (그림 글자는 줄여 씀)
    if (st && st.state === "excess") out.push({ cls: "risk", text: `${nm(e.src)} 역할 → ${nm(e.dst)} : ${acts}`, why: "요구사항 밖 권한" });
  }
  for (const g of ov.ghost_edges || []) if (g.state === "missing") out.push({ cls: "miss", text: `${nm(g.src)} 역할 → ${nm(g.dst)} : ${g.label}`, why: "꼭 필요한데 없음" });
  for (const [id, n] of Object.entries(ov.nodes || {})) if (n.state === "excess") out.push({ cls: "risk", text: `${nm(id)} 역할`, why: n.why || "신뢰 정책" });
  return out;
}
// 설계도 그림: 고른 기록이 설계도와 비교한 결과(빨강 표시)를 가지고 있으면 그 비교에 쓴 설계도, 아니면 지금 설계도
function designSide() {
  const im = S.rec ? S.impact : null;
  if (permOn()) {
    // IAM 요구사항 그림 (15차): 이 기록을 검사한 요구사항(input/design.json)으로 그린 것 — 없으면(검사 전) 비교 그림 없음
    const v = `v${((im || {}).design || {}).recorded ? (((im.design || {}).recorded || {}).intent_version || "?") : (curSet().design_version || 1)}`;
    return im && im.design_view ? { model: im.design_view, v, title: `IAM 요구사항 ${v} — 가져도 되는 권한`, perm: true } : { model: null, title: "IAM 요구사항", v, perm: true };
  }
  if (curSet().intent_kind !== "topology") return { model: null, title: "설계도", v: "" };
  if (im && im.overlay_after && im.design_view) {
    const des = (im.design || {}).recorded || {};
    const old = des.sha256 && activeSha() && des.sha256 !== activeSha();
    const v = `v${des.intent_version || designVersion()}`;
    return { model: im.design_view, v, title: `고객 설계도 ${v}${old ? ` — 이 수정안을 검사한 때의 설계도 (지금은 v${designVersion()})` : ""}` };
  }
  return { model: ((S.design || {}).compare || {}).view || null, v: `v${designVersion()}`, title: `고객 설계도 v${designVersion()}` };
}
// 그림에 무엇을 그리나: 고른 수정안의 적용 후 그림이 있으면 그것 (사람이 [고객 설계도] 를 눌렀으면 설계도), 없으면 설계도
function picView(D) {
  const im = S.rec ? S.impact : null;
  if (!(im && im.arch_after)) return "design";
  return S.picView === "design" && D.model ? "design" : "after";
}

function pictureHtml() {
  const im = S.rec ? S.impact : null;
  const c = curCand();
  const topo = curSet().intent_kind === "topology";
  const D = designSide();
  const hasAfter = !!(im && im.arch_after);
  const view = picView(D);
  const label = im ? (im.label || "수정안") : "";
  let title, legend = "", empty = "", foot = "";
  if (view === "after" && permOn()) {
    title = `${label} 적용 후 — 웹 서버 역할의 권한`;
    legend = MLEG.permNow;
    const d = permDiffs(im);
    foot = d ? `<div class="pdiff ${d.length ? "bad" : "ok"}">${d.length ? `<b>요구사항과 다른 곳 ${d.length}개</b><ul>${d.map((x) => `<li class="${x.cls}">${esc(x.text)} <small>${esc(x.why)}</small></li>`).join("")}</ul>` : `<b>요구사항과 같음</b> — 요구사항 밖 권한도, 빠진 꼭 필요한 권한도 없음`}</div>` : "";
  } else if (view === "after") {
    title = `${label} 적용 후 — 이렇게 됩니다`;
    legend = im.overlay_after ? MLEG.after : MLEG.afterCode;
    const d = designDiffs(im);
    foot = d ? `<div class="pdiff ${d.length ? "bad" : "ok"}">${d.length ? `<b>설계도와 다른 곳 ${d.length}개</b><ul>${d.map((x) => `<li class="${x.cls}">${esc(x.text)} <small>${esc(x.why)}</small></li>`).join("")}</ul>` : `<b>설계도와 같음</b> — 설계도에 없는 통신도, 막힌 필요한 통신도 없음`}</div>`
      : topo ? `<div class="pdiff warn">이 기록에는 설계도와 비교한 결과가 없음 (예전 기록) — 빨강은 자체 검사가 본 위험한 허용. ${S.cand ? `<button type="button" class="linkbtn" data-act="recheck">지금 설계도로 다시 분석</button>` : ""}</div>` : "";
  } else {
    title = D.title;
    legend = D.model ? (D.perm ? MLEG.permDesign : MLEG.design) : "";
    if (!D.model) empty = topo ? "설계도 그림 없음 — ③ 에서 확인" : hasAfter ? "" : permOn() ? "수정안 번호를 누르면 그 수정안을 적용한 뒤의 권한 그림이 나옵니다 (요구사항과 다른 곳만 빨강 ✕)" : "이 고칠 문제는 통신 구조 설계도가 아니라 요구사항 표(IAM 등)로 검사합니다 — 수정안을 누르면 적용 후 그림이 나옵니다";
  }
  // 전환 단추: 적용 후 그림이 있을 때만 (같은 자리에서 설계도 ↔ 적용 후)
  const seg = hasAfter && (D.model || !topo) ? `<div class="seg sm picseg"><button type="button" class="${view === "after" ? "on" : ""}" data-pv="after">${esc(label)} 적용 후</button>${D.model ? `<button type="button" class="${view === "design" ? "on" : ""}" data-pv="design">${D.perm ? "IAM 요구사항" : "고객 설계도"} ${esc(D.v)}</button>` : ""}</div>` : "";
  // 그림 아래 상태 글
  let note = "";
  if (!S.rec) {
    const ready = c && (!c.latest || stale(c)) && !S.run;
    note = ready ? `<div class="picnote"><b>${esc(c.label)}: ${c.latest ? "이전 설계도 기준 결과만 있음" : "아직 분석 전"}</b> — 분석하면 이 그림이 적용한 뒤 모습으로 바뀝니다 (AWS 접속 없음). <button type="button" class="mbtn primary sm" data-act="run-cand">${c.latest ? "지금 기준으로 다시 분석" : "분석 시작"} ▶</button></div>`
      : `<div class="picnote"><b>위에서 수정안 번호를 누르세요</b> — 이 그림이 그 수정안을 적용한 뒤 모습으로 바뀝니다. ${permOn() ? "요구사항과" : "설계도와"} 다른 곳만 빨강 ✕.</div>`;
  } else if (!im) note = `<div class="picnote">분석 결과 불러오는 중…</div>`;
  else if (!im.arch_after) note = `<div class="picnote warn"><b>${esc(label)}</b>: ${esc(NO_AFTER)}<br><small class="mc-why">${esc(im.reason || "수정안 plan 없음")}</small></div>`;
  return `<div class="pic1">${mapBox("tPic", title, legend, seg, empty, foot)}${note}</div>`;
}
function drawPicture() {
  const D = designSide();
  if (picView(D) === "after") { drawAfter("tPic", S.impact); return; }
  if (D.model) drawMap("tPic", D.model, { simple: simpleOn(), perm: !!D.perm }, onPick("tPic", null));
}

function resultHead() {
  const im = S.impact;
  if (!S.rec || !im) return "";
  const c = curCand();
  const cc = (S.verdict || {}).conclusion || {};
  const des = (im.design || {}).recorded || {};
  const staleRec = des.sha256 && activeSha() && des.sha256 !== activeSha();
  const post = c && c.post && c.post.id !== S.rec ? c.post : null;
  // 검사 당시 설계도 확정 상태 (D-38): 초안 기준 결과는 '고객 요구 충족' 이 아님 — 글자로 표시 (색만으로 구분하지 않음)
  const conf = des.confirmation && typeof des.confirmation === "object" ? des.confirmation : null;
  const W = permOn() ? "IAM 요구사항" : "설계도";
  const basis = conf && !conf.confirmed
    ? `<div class="mcard warn small basis">기준: <b>확정 전 기준</b> — ${W} v${esc(des.intent_version || conf.version || "?")} 는 검사 당시 초안이라 이 결과는 '고객 요구 충족' 이 아닙니다. ③ 에서 담당자가 확정한 뒤 다시 분석한 것만 승인할 수 있음. <button type="button" class="linkbtn" data-go="3">③ ${W} 확정</button></div>`
    : conf && conf.basis === "manifest" ? `<div class="mcard small basis">기준: 팀 작성 평가 기준 (실험 세트 ${W} — 고객이 확정한 ${W} 아님)</div>` : "";
  // 17차 (D-53): '고른 수정안' 칸(⑥ 가기 단추가 오른쪽 위와 겹침) · '기준: 설계도 v1 · 확정' 칸(머리말 오른쪽과 겹침)은 뺐다 — 결과 한 줄만
  return `<p class="cmp-line">${chip(toneChip(cc.tone), cc.status || cc.headline || "")}<b>${esc(im.label || "")}</b><span>${esc(cc.title || "")}</span></p>
    ${reqRow((S.verdict || {}).request)}
    ${basis}
    ${staleRec ? `<div class="mcard warn small">이 결과는 설계도 v${esc(des.intent_version)} 기준 — 지금 기준은 v${designVersion()}. <button type="button" class="linkbtn" data-act="recheck">지금 기준으로 다시 분석</button></div>` : ""}
    ${post ? `<div class="mcard small">이 수정안 파일로 AWS 시험 환경 검사까지 한 기록이 있습니다 (${esc(fmt(post.at))} · ${esc(post.status)}). <button type="button" class="linkbtn" data-rec="${esc(post.id)}">그 기록 보기</button></div>` : ""}`;
}

function detailsHtml() {
  const im = S.impact;
  if (!S.rec || !im) return "";
  const tr = im.trivy || {};
  const df = im.arch_diff || null;
  const added = df ? df.added_list : (im.added || []), removed = df ? df.removed_list : (im.removed || []);
  const ai = S.llm.view && (S.llm.view.attempts || []).some((a) => a.record_id === S.rec);
  const pd = im.perm_diff;
  const permCard = permOn() ? `<div class="mcard"><h4>이 수정안이 바꾼 권한 <small>적용 전 → 후, 역할 → 리소스 (허용 동작)</small></h4><ul class="flist">${(pd || []).map((x) => `<li class="${x.kind === "removed" ? "gone" : "add"}">${x.kind === "removed" ? "－" : x.kind === "added" ? "＋" : "～"} ${esc(x.who)} 역할 → ${esc(x.what)} <b>${esc(x.kind === "removed" ? x.before : x.after)}</b>${x.kind === "changed" ? ` <small>(전: ${esc(x.before)})</small>` : ""}</li>`).join("")}
        ${!(pd || []).length ? `<li class="muted">${pd ? "권한 변화 없음" : "계산 못 함"}</li>` : ""}</ul></div>` : "";
  return `<div class="cmp-grid">
      ${permCard || `<div class="mcard"><h4>이 수정안이 바꾼 통신 <small>적용 전 → 후, 보안 그룹 규칙 기준</small></h4><ul class="flist">${added.map((a) => `<li class="add">＋ ${esc(a.src)} → ${esc(a.dst)} <b>:${esc(a.port)}</b></li>`).join("")}${removed.map((a) => `<li class="gone">－ ${esc(a.src)} → ${esc(a.dst)} <b>:${esc(a.port)}</b></li>`).join("")}
        ${!added.length && !removed.length ? `<li class="muted">${im.arch_after || im.after ? "통신 변화 없음" : "계산 못 함"}</li>` : ""}</ul></div>`}
      <div class="mcard"><h4>해결 · 새로 생긴 문제</h4><ul class="flist">${(tr.resolved || []).map((x) => `<li class="add">해결 · Trivy: ${escBrk(x)}</li>`).join("")}${(im.sg_resolved || []).map((x) => `<li class="add">해결 · 자체 검사: ${esc(x.title)}</li>`).join("")}
        ${(tr.new || []).map((x) => `<li class="risk">새 문제 · Trivy: ${escBrk(x)}</li>`).join("")}${(im.sg_new || []).map((x) => `<li class="risk">새 문제 · 자체 검사: ${esc(x.title)} — ${esc(x.detail)}</li>`).join("")}
        ${(im.sg_remaining || []).map((x) => `<li>남음 · 자체 검사: ${esc(x.title)}</li>`).join("")}
        ${!(tr.resolved || []).length && !(tr.new || []).length && !(im.sg_resolved || []).length && !(im.sg_new || []).length && !(im.sg_remaining || []).length ? `<li class="muted">${tr.v1 ? "변화 없음" : "계산 못 함"}</li>` : ""}</ul></div>
    </div>
    ${ai ? `<div class="mcard ai small"><b>이 AI 수정의 시도 기록</b> <span class="muted">시도마다 위 'AI 수정' 버튼으로 따로 볼 수 있음</span>${aiTimeline(S.llm.view)}</div>` : ""}`;
}

// ⑤ 지금 상태 → 할 일 하나 (9차 D-43 · 11차 D-47): 수정안 1~4 는 미리 분석해 두므로 '누르면 바로 그림'. 세 길 = 수정안 번호 · AI · 내 파일 (+ 설계도대로 자동 수정)
function s5Now() {
  if (!S.cands || !S.target) return null;
  const [ak, aw] = aiState();
  const vv = S.verdict;
  const label = (S.impact && S.impact.label) || (vv && vv.label) || "이 수정안";
  const n = teamList().length;
  const aiBtn = (word) => `<button type="button" class="mbtn primary" data-srcopen="ai" ${ak === "ok" ? "" : `disabled title="${esc(aw)}"`}>${esc(word)}</button>`;
  const teamBtn = n ? `<button type="button" class="mbtn" data-jump=".tbig">수정안 1~${n} 중 하나 누르기</button>` : "";
  const upBtn = `<button type="button" class="mbtn" data-srcopen="upload">내가 고친 파일 올리기</button>`;
  const rbBtnCls = (cls) => (rbOn() ? `<button type="button" class="mbtn ${cls}" data-act="run-rb">설계도대로 자동 수정 (규칙 기반)</button>` : "");
  const rbBtn = rbBtnCls("");
  const rbWord = rbOn() ? " [설계도대로 자동 수정] 은 AI 없이 ③ 설계도의 화살표대로 IP 목록만 바꿉니다." : "";
  const bg = S.bg && S.bg.set_id === S.target ? S.bg : null;
  if (S.run) return { tone: "", title: `실행 중 — ${S.run.label || ""}`, text: "끝나면 결과가 아래에 나옵니다. 그동안 다른 버튼은 눌리지 않습니다.", btns: "", todo: `실행 중 — ${S.run.label || ""}. 끝날 때까지 기다리세요.` };
  if (S.rec && vv && vv.ok) {
    const c = vv.conclusion || {};
    if (c.tone === "good" && c.draft_design) return { keep: true, tone: "warn", title: `${label} — 관문은 통과했지만 확정 전 기준 (검증 불가)`, text: "설계도가 초안이라 '고객 요구 충족' 으로 볼 수 없고 승인할 수 없습니다. ③ 에서 확정한 뒤 이 수정안을 다시 검사하세요.", btns: `<button type="button" class="mbtn primary" data-go="3">③ 설계도 확정하러 가기</button><button type="button" class="mbtn" data-act="recheck">확정했으면 다시 검사</button>`, todo: "설계도가 초안이라 승인 불가 — ③ 에서 확정한 뒤 [다시 검사]." };
    if (c.tone === "good") return { tone: "ok", title: `${label} — 배포 전 검사 통과`, text: "아래 그림이 이 수정안을 적용한 뒤 모습입니다 (설계도와 다른 곳만 빨강 ✕). 다른 번호를 누르면 그림이 그 수정안으로 바뀝니다.", btns: `<button type="button" class="mbtn primary" data-go="6">다음 ▶ ⑥ 적용 판단</button>${teamBtn}`, todo: `${label} 은 배포 전 검사를 통과했습니다 — [다음 ▶ 적용 판단]. 다른 번호를 누르면 그 수정안으로 바뀝니다.` };
    return { tone: "bad", title: `${label} — 막힘: ${c.headline || c.title || ""}`, text: `막힌 이유는 아래 결과 칸에 있습니다 (그림의 빨간 선 ✕ = ${permOn() ? "요구사항과" : "설계도와"} 다른 곳). 다른 번호를 누르거나, AI 에게 고치게 하거나, 내가 고친 파일을 올리세요.${rbWord}`, btns: `${teamBtn}${aiBtn("AI 에게 고치게 하기")}${rbBtn}${upBtn}`, todo: `${label} 은 막혔습니다 (이유는 결과 칸) — 다른 번호를 누르거나 AI 에게 시키세요.` };
  }
  if (bg) return { tone: "", title: `수정안 미리 분석 중 ${bg.i}/${bg.n}`, text: "끝난 수정안부터 번호를 누르면 바로 그림이 바뀝니다. AI 수정 · 파일 올리기는 미리 분석이 끝난 뒤에.", btns: teamBtn, todo: `수정안 미리 분석 중 ${bg.i}/${bg.n} — 끝난 번호부터 눌러 보세요.` };
  if (S.llm.view && !S.rec) {
    const [, w] = AI_ST[S.llm.view.status] || ["", S.llm.view.status || ""];
    return { tone: "warn", title: `AI 수정 결과: ${w}`, text: `${S.llm.view.next || "검사할 수정안이 없습니다."}${rbWord}`, btns: `${teamBtn}${rbBtn}${upBtn}${aiBtn("AI 에게 다시 시키기")}`, todo: `AI 수정 결과: ${w} — 수정안 번호를 누르거나 ${rbOn() ? "[설계도대로 자동 수정] · " : ""}내가 고친 파일을 올리세요.` };
  }
  if (n && !prefetchOk()) return { keep: true, tone: "warn", title: "설계도가 초안이라 아직 미리 분석하지 않았습니다", text: "③ 에서 담당자가 확정하면 수정안을 미리 분석해 둡니다. 확정 전 기준으로 검사한 결과는 승인할 수 없습니다.", btns: `<button type="button" class="mbtn primary" data-go="3">③ 설계도 확정하러 가기</button>${teamBtn}`, todo: "③ 에서 설계도를 확정하세요 — 그러면 수정안을 미리 분석합니다." };
  if (n) return { tone: "", title: `수정안 1~${n} 중 하나를 누르세요`, text: `번호를 누르면 아래 그림이 그 수정안을 적용한 뒤 모습으로 바뀝니다 (설계도와 다른 곳만 빨강 ✕). AI 에게 새로 만들게 하거나(${ak === "ok" ? "준비됨" : aw}) 내가 고친 파일을 올릴 수도 있습니다.${rbWord}`, btns: `${teamBtn}${aiBtn("AI 에게 고치게 하기")}${rbBtn}${upBtn}`, todo: `수정안 1~${n} 중 번호 하나를 누르세요 — 그림이 바뀝니다. AI · 내 파일 · 설계도대로 자동 수정도 됩니다.` };
  if (ak === "ok") return { tone: "", title: "수정안을 하나 만드세요", text: `[AI 에게 고치게 하기] — AI 가 고친 코드를 내고 바로 8개 관문으로 검사합니다.${rbWord} 내가 고친 파일을 올려도 됩니다.`, btns: `${aiBtn("AI 에게 고치게 하기")}${rbBtn}${upBtn}`, todo: `[AI 에게 고치게 하기] 를 누르거나, ${rbOn() ? "[설계도대로 자동 수정] 을 누르거나, " : ""}고친 파일을 올리세요.` };
  return { tone: "warn", title: `수정안을 하나 만드세요 — AI 는 지금 쓸 수 없음`, text: `AI 상태: ${aw}.${rbWord} 내가 고친 파일을 올리세요. (AI 를 쓰려면 Claude Code 설치 · 로그인 뒤 '상태 다시 확인')`, btns: `${rbBtnCls("primary")}${upBtn}${aiBtn("AI 에게 고치게 하기")}`, todo: `AI 는 지금 쓸 수 없음 (${aw}) — ${rbOn() ? "[설계도대로 자동 수정] 을 누르거나 " : ""}고친 파일을 올리세요.` };
}
registerTodo(5, () => { if (caseMode() === "handoff") return "이 요청은 수정안을 만들지 않습니다 — ② '사람에게 넘김' 칸의 할 일대로 사람이 고칩니다."; const n = s5Now(); return n ? n.todo : ""; });
onEnter(5, () => { maybePrefetch(); });

register(5, () => {
  if (!S.cands) { $("#mbody").innerHTML = `<div class="mempty">불러오는 중…</div>`; return; }
  if (!sets().some((x) => x.set_id === S.target)) S.target = (sets().find((s) => s.intent_kind === "topology") || sets()[0] || {}).set_id;
  if (!S.target && caseMode() === "handoff") {
    // 요청 2 (S3, 15차 D-51): 팀 정책의 자동 수정 범위 밖 — 수정안 · AI 수정을 만들지 않는다 (사람에게 넘김)
    $("#mbody").innerHTML = `<div class="mempty"><b>이 요청은 수정안을 만들지 않습니다 — 자동 수정 범위 밖</b><p>팀 정책(policy/patch_policy.json)이 이 문제(S3 공개 차단)를 자동 수정 대상으로 두지 않았습니다.
      그래서 이 요청에는 수정안 · AI 수정 · 직접 올린 파일 검사가 없습니다. ② 의 '사람에게 넘김' 칸에 할 일과 고친 뒤 확인 방법이 있습니다.</p>
      <div class="mnav center"><button type="button" class="mbtn primary" data-go="2">◀ ② 사람에게 넘김 칸</button><button type="button" class="mbtn" data-go="4">④ 찾은 문제</button></div></div>`;
    return;
  }
  if (!S.target) {
    $("#mbody").innerHTML = `<div class="mempty"><b>먼저 ④ 에서 고칠 문제를 고르세요</b><p>④ 보안 문제 목록에서 문제를 누르고 '이 문제 고치기' 를 누르면, 그 문제가 여기의 '고칠 문제' 가 됩니다.<br>
      자동 수정 · 수정 검사는 보안 그룹(SSH · RDP 공개 등)과 IAM 일부 문제만 지원합니다 — 나머지는 탐지만.</p><div class="mnav center"><button type="button" class="mbtn primary" data-go="4">◀ ④ 보안 문제</button></div></div>`;
    return;
  }
  const noDesign = S.design && S.design.ok !== false && !S.design.exists && curSet().intent_kind !== "iam" && curSet().intent_kind !== "sg";
  const now = s5Now();
  const { teamBar, otherBar } = candBar();
  // 순서 (12차 D-48): 고칠 문제 → 다음 할 일 → (실행 중) → 수정안 번호 → 그림 (번호마다 바뀜) → 결과 → 다른 방법 (AI · 설계도대로 자동 수정 · 내 파일)
  // 17차 (D-53): '다음 할 일' 칸은 승인을 막는 경고(설계도가 초안)일 때만 — 나머지는 제목 밑 '할 일' 과 같은 말 · 아래에 있는 같은 단추라 뺐다
  $("#mbody").innerHTML = `${targetInfo()}${now && now.keep ? guideCard(now) : ""}${noDesign ? `<div class="mcard warn small dsgwarn">고객 설계도가 아직 없어서 '고객이 원하는 통신 구조를 지키나요?' (V6) 는 <b>판정 불가</b> — 이대로는 승인할 수 없습니다.
      <button type="button" class="mbtn" data-go="3">③ 에서 설계도 확정하기</button></div>` : ""}
    ${S.run ? runPanel() : ""}
    ${S.llm.view && !S.rec && !S.run ? `<div class="mcard ai small airun"><b>AI 수정 결과</b> <span class="muted">검사할 수정안이 없어 아래 그림은 바뀌지 않음</span>${aiTimeline(S.llm.view)}</div>` : ""}
    ${teamBar}
    <div class="cmpwrap">${pictureHtml()}${resultHead()}${detailsHtml()}</div>
    <h3 class="other-h">다른 방법으로 수정안 만들기 <small class="muted">결과는 위 수정안과 똑같이 검사 · 그림도 똑같이 바뀜</small></h3>
    ${otherBar}
    ${S.src === "ai" ? aiPanel() : ""}${S.src === "upload" ? uploadPanel() : ""}`;
  drawPicture();
});

// AI 수정 시도 하나 → 그 시도의 기록 (기록이 없으면 — AI 가 답하지 못함 — 실행 기록만)
export async function openAiAttempt(key) {
  const [runId, n] = String(key).split("|");
  const view = await api.get(`/api/llm/run?id=${encodeURIComponent(runId)}`);
  if (!view || view.error) { toast((view && view.error) || "기록을 읽지 못함"); return; }
  S.llm.view = view; S.cand = null; S.src = null; S.aiPick = key;
  const a = (view.attempts || []).find((x) => String(x.n) === String(n));
  if (a && a.record_id) await loadRecord(a.record_id);
  else { S.rec = null; S.impact = null; S.verdict = null; toast(`시도 ${n}: ${(a && (a.error || a.title)) || "기록 없음"} — 그릴 수정안이 없음`); render(); }
}

// ------------------------------------------------------------------ ⑥ 적용 판단
function verdictBanner(vv, sub) {
  const c = vv.conclusion || {};
  const t = c.tone === "good" ? "good" : c.tone === "bad" ? "bad" : "warn";
  return `<div class="verdict ${t}"><span>${esc(c.status || c.headline || "")}</span><h2>${esc(c.title || c.headline || "")}</h2><p>${esc(c.reason || "")}</p>
    <small>${esc(vv.label || "")} · ${esc(sub)}</small></div>`;
}

register(6, () => {
  const vv = S.verdict;
  if (!vv) { $("#mbody").innerHTML = `<div class="mempty">불러오는 중…</div>`; return; }
  if (!vv.ok) { $("#mbody").innerHTML = `<div class="mempty">${esc(vv.reason || "")}</div>`; return; }
  const q = vv.questions || [];
  // 17차 (D-53): 아래의 '수정안 적용 후' 그림은 뺐다 — ⑤ 에서 본 그림과 같다
  $("#mbody").innerHTML = `${verdictBanner(vv, "배포 전(코드만, AWS 접속 없음) 검사 결과")}${stageStrip(vv)}
    <div class="lay6 one"><div class="qcol">${reqCard(vv.request)}${q.map((x, i) => `<div class="qrow ${x.tone}"><div class="qh"><em>${i + 1}</em><b>${esc(x.question)}</b><span class="mchip ${x.tone === "good" ? "ok" : x.tone === "bad" ? "bad" : x.tone === "unknown" ? "warn" : "dim"}">${esc(x.answer)}</span></div>
        ${x.note ? `<p class="qnote">${esc(x.note)}</p>` : ""}
        ${(x.problems || []).slice(0, 3).map((p) => `<div class="qprob"><b>${esc(p.what)}</b><dl><dt>왜</dt><dd>${esc(p.why)}</dd><dt>어떻게</dt><dd>${esc(p.how)}</dd></dl></div>`).join("")}</div>`).join("")}
      <div class="mcard small"><b>이번 검사에서 확인하지 않은 것</b><ul>${(vv.unchecked || []).map((u) => `<li>${esc(u)}</li>`).join("")}</ul></div></div>
      </div>`;
});

// 세 단계 띠 (검토 문서 11-02 "8계층 통과 ≠ 배포 성공"): 배포 전(코드만) → AWS 시험 환경(샌드박스 반영 후) → 운영 반영(이 프로그램 밖). 글자로 — 색만으로 구분하지 않는다
export function stageStrip(vv) {
  if (!vv || !vv.ok) return "";
  const c = vv.conclusion || {};
  const post = vv.post_deploy || {};
  const pre = c.tone === "good" ? ["ok", "통과"] : c.tone === "bad" ? ["bad", "미통과"] : c.draft_design ? ["warn", "통과 · 확정 전 기준"] : ["warn", "판정 보류"];
  const tb = vv.testbed;
  const mid = !tb ? ["dim", "시험 환경 없음 → 미검증"]
    : post.status === "VERIFIED" ? ["ok", "통과 (샌드박스)"] : post.status === "DEPLOY_FAILED" ? ["bad", "적용 실패"] : post.status === "PLAN_BLOCKED" ? ["bad", "반영 전 차단"]
      : post.status === "UNVERIFIED" ? ["warn", "판정 불가"] : c.tone === "good" ? ["dim", "아직 안 함"] : ["dim", "대상 아님"];
  const row = (n, title, what, [k, w]) => `<li class="${k}"><em>${n}</em><div><b>${title}</b><small>${what}</small></div>${chip(k, w)}</li>`;
  return `<ol class="stages3">${row(1, "배포 전 검사", "V1~V6 · 코드만 (terraform plan · Trivy) — 배포 성공이 아님", pre)}
    ${row(2, "AWS 시험 환경 검사", "V7 · V8 · 샌드박스에 반영한 뒤 설정 읽기 · 연결 시험", mid)}
    ${row(3, "운영 반영", "이 프로그램 밖 — PR 병합 뒤 사람이 함. 여기서 확인하지 않음", ["dim", "확인 안 함"])}</ol>`;
}

// ------------------------------------------------------------------ ⑦ AWS 시험 환경 (9차, D-43 — 전문가 화면 5단계를 여기로)
// '다음 작업' 은 전문가 화면과 같은 순수 함수 stage2Plan(flow2.js)이 /api/p/testbed 의 상태로 정한다. 반영(apply · destroy)은 확인 창에서
// 사람이 plan 을 보고 체크 · [실행] 을 눌러야 한다 (D-19). 측정은 읽기 전용. AI · 자동 단계는 AWS 를 바꾸지 않는다.
const TB_STEPS = ["원본 반영", "수정 전 측정", "수정안 반영", "수정 후 측정", "시험 환경 삭제"];
const TB_STEP_WHO = ["사람 · 확인 창", "읽기만", "사람 · 확인 창", "읽기만", "사람 · 확인 창"];
const TB_WORD = { apply_original: "apply", apply_candidate: "apply", destroy: "destroy" };
const TB_RESULT = { VERIFIED: ["good", "AWS 시험 환경에서 확인됨 — 운영 반영 후 확인 아님"], DEPLOY_FAILED: ["warn", "AWS 시험 환경 적용 실패"], PLAN_BLOCKED: ["warn", "반영 전 차단 — plan 에 교체 · 삭제가 있어 반영하지 않음"], UNVERIFIED: ["warn", "AWS 시험 환경 판정 불가"] };
const TB_RW = { VERIFIED: "확인됨", DEPLOY_FAILED: "적용 실패", PLAN_BLOCKED: "차단", UNVERIFIED: "판정 불가" };
// stage2Plan 의 상황 key → 이 화면의 말 (수정안 · 반영 · 시험 환경, D-39). 없는 key 는 전문가 화면 문장을 그대로 쓴다
const TB_TEXT = {
  checking: ["시험 환경 상태 확인 중", "시험 환경 폴더와 상태 파일을 읽는 중입니다."],
  no_folder: ["시험 환경 폴더 없음", "시험 환경 폴더가 없어 AWS 시험 환경 검사를 할 수 없습니다."],
  need_init: ["terraform init 이 필요함", "시험 환경 폴더에서 terraform init 을 한 번 실행해야 합니다 (사람이 PowerShell 에서 — 아래 '직접 명령' 참고)."],
  deploy: ["1. 원본 반영 — 시험 환경에 원본 코드를 올립니다", "원본 보안 그룹 코드로 시험 환경을 만듭니다. 누르면 plan 을 계산해 확인 창을 띄우고, 사람이 내용을 보고 [apply 실행] 을 눌러야 실제로 반영됩니다."],
  cand_blocked: ["수정안 반영 차단 — plan 에 교체 · 삭제가 있음", "이 수정안은 시험 환경에 반영하지 않습니다 (시험 환경 결과: 차단). 시험 환경을 지우고 ⑤ 에서 다른 수정안을 고르세요."],
  cand_open_apply: ["3. 수정안 반영 — 사람 확인 대기", "plan 확인 결과 보안 그룹 제자리 수정만 있습니다. 확인 창에서 plan 을 보고 [apply 실행] 을 누르세요."],
  cand_start: ["3. 수정안 반영 — 먼저 계획(plan)을 확인합니다", "이 수정안 파일을 시험 환경에 넣고 실제 상태 기준 plan 을 계산합니다 (반영 없음). 보안 그룹 제자리 수정만 있으면 확인 창이 뜹니다."],
  rec_blocked: ["수정안 반영 차단 기록 있음", "이 수정안은 전에 plan 확인에서 교체 · 삭제가 나와 반영하지 않았습니다 (시험 환경 결과: 차단). 시험 환경을 지우고 다른 수정안을 고르세요."],
  file_differs: ["시험 환경 파일이 배포 상태와 다름", "시험 환경 폴더의 파일이 지금 배포된 것과 다릅니다 (반영 전). 원본을 다시 반영하거나 시험 환경을 지우세요."],
  measure_before_wait: ["2. 수정 전 측정 — 기다리는 중", "원본을 막 반영했습니다. 측정 지점 결과에 반영된 설정이 나타나도록 3분 기다립니다 (2분 뒤부터 직접 측정 가능). 시간이 되면 자동으로 잽니다 (읽기만)."],
  measure_before: ["2. 수정 전 측정", "원본 상태의 AWS 보안 그룹 규칙(V7)과 실제 연결(V8)을 잽니다. 설정은 바꾸지 않습니다."],
  pick_not_passed: ["이 수정안은 시험 환경 검사 대상이 아님", "배포 전 검사를 통과하지 못한 수정안은 시험 환경에 반영하지 않습니다. ⑤ 에서 다른 수정안을 고르거나 시험 환경을 지우세요."],
  pick: ["수정안을 골라야 함", "수정 전 측정은 끝났습니다. ⑤ 에서 배포 전 검사를 통과한 수정안을 고르면 '수정안 반영' 으로 이어집니다."],
  measure_after_wait: ["4. 수정 후 측정 — 기다리는 중", "수정안을 막 반영했습니다. 바뀐 보안 그룹이 측정 지점 결과에 나타나도록 기다립니다 (2분 뒤부터 직접 측정 가능). 시간이 되면 자동으로 잽니다 (읽기만)."],
  measure_after: ["4. 수정 후 측정", "수정안 반영 상태의 AWS 보안 그룹 규칙(V7)과 실제 연결(V8)을 잽니다. 설정은 바꾸지 않습니다."],
  other_file: ["다른 파일이 배포된 상태", "이 기록과 관계없는 파일이 배포돼 있습니다. 시험 환경을 지우거나 원본을 다시 반영하세요."],
};
function tbWords(pl) {
  const w = TB_RW[pl.result] || pl.result || "";
  if (pl.key === "done") return [`AWS 시험 환경 검사 끝 — ${w}${pl.result === "VERIFIED" ? " (운영 반영 후 확인 아님)" : ""}`, "시험 환경은 지워진 상태입니다. 다시 재려면 원본 반영부터 다시 합니다."];
  if (pl.key === "destroy") return ["5. 시험 환경 삭제", `수정 후 측정이 끝났습니다 (결과: ${w || "기록 없음"}). 비용이 생기지 않게 시험 환경을 지웁니다 — 확인 창에서 [destroy 실행].`];
  return TB_TEXT[pl.key] || [pl.title, pl.text];
}
function tbBtnLabel(b) {
  if (b.act === "s2-deploy") return /재/.test(b.label || "") ? "원본 다시 반영 (plan 확인 창)" : "원본 반영 (plan 확인 창)";
  return { "s2-cand": "수정안 반영 시작 (plan 확인)", "s2-open-apply": "확인 창 열기 (apply)", "s2-destroy": "시험 환경 삭제 (destroy)", "s2-pick": S.rec ? "⑤ 다른 수정안 고르기" : "⑤ 수정안 고르기", "s2-decide": "⑧ 결정으로 →" }[b.act] || b.label;
}
let tbTimer = null;

export async function loadTestbed() {
  const rid = S.rec || "";
  const d = await api.get(`/api/p/testbed?id=${encodeURIComponent(rid)}`);
  if (S.rec !== (rid || null) && S.rec !== rid) return;
  S.tb = { ...(S.tb || {}), data: d, at: Date.now(), rid };
  if (S.step === 7) render();
}

function tbPlan() {
  const t = S.tb && S.tb.rid === (S.rec || "") ? S.tb : null;
  if (!t || !t.data) return null;
  const d = t.data;
  if (!d.ok) return { cur: 0, title: "시험 환경 상태 조회 실패", text: d.reason || "", primary: null, secondary: [], marks: {}, tone: "bad" };
  return stage2Plan({ m: d.m, rec: S.rec ? { post_deploy: d.post_deploy } : null, passed: !!d.passed, post: d.post || {},
    running: S.run && S.run.kind === "testbed" ? { kind: "testbed", label: S.run.label } : null, now: Date.now(), fetchedAt: t.at });
}

function tbStepsHtml(pl) {
  return `<ol class="awsflow tbsteps">${TB_STEPS.map((t, i) => {
    const n = i + 1, mk = (pl.marks || {})[n];
    const cls = mk === "bad" ? "bad" : mk === "skip" ? "skip" : pl.cur === 6 || n < pl.cur ? "past" : n === pl.cur ? "cur" : "";
    const word = mk === "bad" ? "차단" : mk === "skip" ? "안 함" : pl.cur === 6 || n < pl.cur ? "끝" : n === pl.cur ? "지금" : "";
    return `<li class="${cls}"><b>${esc(t)}</b><span>${esc(word)}</span><i class="${i % 2 === 0 ? "human" : "ro"}">${esc(TB_STEP_WHO[i])}</i></li>`;
  }).join("")}</ol>`;
}

function tbGuideHtml(pl, d) {
  const m = (d && d.m) || {};
  const auto = !!(S.tb && S.tb.auto);
  const btn = (b, primary) => b ? `<button type="button" class="mbtn ${primary ? (b.danger ? "danger" : "primary") : ""}" data-tb="${esc(b.act)}" ${b.kind ? `data-kind="${esc(b.kind)}"` : ""} ${b.disabled || S.run ? "disabled" : ""} title="${esc(b.why || "")}">${esc(tbBtnLabel(b))}</button>` : "";
  const measuring = pl.primary && pl.primary.act === "s2-measure";
  const autoTxt = !measuring ? "" : auto ? ` · 시간이 되면 자동 측정 (읽기 전용) <button type="button" class="linkbtn" data-tb="tb-auto">끄기</button>` : ` · 자동 측정 끔 — 시간이 되면 버튼을 직접 누르세요 <button type="button" class="linkbtn" data-tb="tb-auto">켜기</button>`;
  const wait = pl.wait ? `<p class="tbwait">${pl.wait.left > 0 ? `측정까지 <b>${esc(mmss(pl.wait.left))}</b> 남음 — 반영한 설정이 측정 지점에 나타나는 시간` : "지금 측정할 수 있음"}${autoTxt}</p>` : measuring ? `<p class="tbwait">지금 측정할 수 있음${autoTxt}</p>` : "";
  const why = pl.primary && pl.primary.disabled && pl.primary.why ? `<p class="small bad">${esc(pl.primary.why)}</p>` : "";
  const file = m.is_original ? "원본" : m.is_record_candidate ? "이 수정안" : m.security_groups_sha256 ? "다른 파일" : "없음";
  const meta = !d || !d.ok || m.error ? "" : `<p class="small muted tbmeta">시험 환경 파일: <b>${esc(file)}</b> · 배포 리소스: <b>${m.state_resources == null ? "없음" : m.state_resources + "개"}</b> · AWS CLI: ${m.aws_cli ? "있음" : "<b>없음</b> (측정 불가)"} · 프로필 <input class="minput tbprof" id="tbProfile" value="${esc((S.tb && S.tb.profile) || m.profile || "")}" placeholder="AWS 프로필"></p>`;
  const [title, text] = tbWords(pl);
  return `<div class="mcard guide ${pl.tone || ""}"><div class="kicker">다음 할 일</div><h3>${esc(title)}</h3><p>${esc(text)}</p>${wait}${why}
    <div class="mnav">${btn(pl.primary, true)}${(pl.secondary || []).map((b) => btn(b, false)).join("")}</div>${meta}</div>`;
}

function tbResultHtml(vv) {
  const post = vv.post_deploy || {};
  if (!post.status) return "";
  const L = post.layers || {};
  const [tone, title] = TB_RESULT[post.status] || ["warn", post.status];
  const LW = { PASS: "예", FAIL: "아니오", NOT_RUN: "실행 안 함", UNKNOWN: "판정 불가", ERROR: "오류" };
  const q = (k, text, how) => `<li>${esc(text)} ${chip(L[k] === "PASS" ? "ok" : L[k] === "FAIL" ? "bad" : "warn", LW[L[k]] || L[k] || "미실행")}<small>${esc(how)}</small></li>`;
  return `<div class="mcard ${tone} tbresult"><h3>${esc(title)}</h3><ul class="flist">${q("V7", "AWS 시험 환경에 예상대로 적용됐나요?", "V7 — 시험 환경 AWS 계정에서 보안 그룹 규칙을 읽어 코드와 비교")}${q("V8", "시험 환경에서 실제 연결과 차단이 정상인가요?", "V8 — 시험 환경에서 실제로 연결해 봄 (허용할 것은 열리고, 막을 것은 막히는가)")}</ul>
</div>`;
}

function tbCommandsHtml(d) {
  const c = ((d && d.m) || {}).commands;
  if (!c) return "";
  return `<details class="mdetails tbcmd"><summary>직접 명령으로 하려면 (PowerShell · 사람)</summary><pre class="mlog">${esc([c.cd, c.profile, c.check, c.plan, c.apply, c.destroy].filter(Boolean).join("\n"))}</pre>
    <p class="small muted">이 프로그램이 하는 것: ${esc(((d.m || {}).does || []).join(" · "))}<br>하지 않는 것: ${esc(((d.m || {}).does_not || []).join(" · "))}</p></details>`;
}

// 17차 (D-53): 시험 환경이 없는 프로젝트에서 '버튼을 순서대로 누르세요' 가 나오던 것 — 할 것이 없으니 다음으로
registerTodo(7, () => (S.verdict && S.verdict.ok && !S.verdict.testbed ? "이 프로젝트는 AWS 시험 환경이 없어 여기서 할 것이 없습니다 — [다음 ▶ 최종 결정] 으로 가세요." : ""));
register(7, () => {
  const vv = S.verdict || {};
  const pass = (vv.conclusion || {}).tone === "good";
  const c = curCand();
  const other = c && c.post && c.post.id !== S.rec ? c.post : null;
  if (tbTimer) { clearInterval(tbTimer); tbTimer = null; }
  if (!vv.testbed) {
    // 17차 (D-53): 세 단계 띠는 ⑥ 과 같아서 뺐다 (여기서는 좁은 칸에 눌려 글자가 낱말 중간에서 끊겼다). 할 일 = 다음으로
    $("#mbody").innerHTML = `<div class="narrow"><div class="mcard warn"><h3>미검증 — 이 프로젝트는 AWS 시험 환경이 없습니다</h3><p>코드 검사(배포 전)만 했고, AWS 에 반영해서 설정 · 연결을 재지 않았습니다 (실제 AWS 미검증). 이 결과를 '전체 검증 성공' 으로 보지 않습니다.</p>
      <p>⑧ 에서 승인하려면 <b>'실제 AWS 에서 확인하지 않은 것을 알고 승인'</b> 을 표시해야 하고, 그 사실이 결정 기록 · PR 제목 · 본문에 남습니다.</p>
      <p class="small muted">AWS 시험 환경 검사(V7 규칙 조회 · V8 연결 측정)는 비용 · 시간 때문에 3계층 예제에만 시험 환경(샌드박스)을 만들어 두었습니다. 운영 환경에는 반영하지 않습니다.</p></div></div>`;
    return;
  }
  if (!S.tb || S.tb.rid !== (S.rec || "") || !S.tb.data) {
    $("#mbody").innerHTML = `<div class="narrow">${stageStrip(vv)}<div class="mempty">시험 환경 상태 확인 중…</div></div>`;
    loadTestbed();
    return;
  }
  const d = S.tb.data;
  const pl = tbPlan();
  const notPass = !pass && !(vv.post_deploy || {}).status;
  const head = notPass ? `<div class="mcard warn small">배포 전 검사를 통과하지 못한 수정안은 시험 환경에 반영하지 않습니다 — 먼저 ⑤ 에서 통과하는 수정안을 만드세요.${other ? ` 이 수정안 파일로 시험 환경 검사를 한 다른 기록: <button type="button" class="linkbtn" data-rec="${esc(other.id)}">그 기록 보기</button>` : ""}</div>` : "";
  $("#mbody").innerHTML = `<div class="narrow">${stageStrip(vv)}${tbStepsHtml(pl)}${head}${tbGuideHtml(pl, d)}${S.run && S.run.kind === "testbed" ? runPanel() : ""}${tbResultHtml(vv)}${tbCommandsHtml(d)}
    <p class="mnote">AI · 이 프로그램은 AWS 를 바꾸지 않습니다. 시험 환경 반영 · 삭제는 사람이 확인 창에서 plan 을 보고 눌러야 실행됩니다. 운영 환경 반영은 이 프로그램 밖(PR 병합 뒤 사람)입니다.</p></div>`;
  // 시간이 되면 자동 측정(읽기 전용) 한 번 — 화면에서 실행한 반영이 성공했을 때만 켜지고, 반영 한 번당 한 번 (전문가 화면과 같은 규칙)
  if (tbAutoMaybe(pl, d)) return;
  // 대기 중이거나 작업 중이면 남은 시간을 매초 고치고, 15초마다 상태를 다시 읽는다 (사람이 PowerShell 에서 바꿔도 따라가게)
  if (pl.wait || (pl.primary && pl.primary.act === "s2-measure") || (S.run && S.run.kind === "testbed")) {
    tbTimer = setInterval(async () => {
      if (S.step !== 7) { clearInterval(tbTimer); tbTimer = null; return; }
      const now = tbPlan();
      const w = $(".tbwait b"); if (w && now && now.wait) w.textContent = mmss(now.wait.left);
      if (now && now.wait && now.wait.left <= 0 && now.primary && !now.primary.disabled) { render(); return; }   // 대기 끝 → 버튼 켜기 (자동이면 render 에서 측정 시작)
      if (Date.now() - S.tb.at > 15000 && !S.run) await loadTestbed();
    }, 1000);
  }
});

function tbAutoMaybe(pl, d) {
  const m = (d && d.m) || {};
  if (!pl || S.run || !(S.tb && S.tb.auto) || !pl.primary || pl.primary.act !== "s2-measure" || pl.primary.disabled || (pl.wait && pl.wait.left > 0)) return false;
  const key = `${pl.primary.kind}|${(m.ops_last || {}).at || ""}|${(m.ops_last || {}).dir || ""}`;
  if (S.tb.autoKey === key) return false;
  S.tb.autoKey = key;
  toast(`대기 끝 — ${pl.primary.label} 자동 시작 (읽기 전용)`, "good");
  testbedAct("s2-measure", pl.primary.kind);
  return true;
}

function tbProfile() { const el = $("#tbProfile"); if (el) S.tb.profile = el.value.trim(); return (S.tb && S.tb.profile) || ""; }

// 확인 창 (D-19): plan 요약을 보고 체크 → [apply 실행] / [destroy 실행]. 서버는 plan_id · confirm 값이 맞을 때만, plan 이 낡지 않았을 때만 실행
const TB_KIND_KO = { apply_original: "원본 반영", apply_candidate: "수정안 반영", destroy: "시험 환경 삭제" };
function tbConfirmModal(meta) {
  const kind = meta.kind, word = TB_WORD[kind] || "apply", ko = TB_KIND_KO[kind] || meta.kind_ko || word;
  const cnt = meta.counts || {};
  const KW = { create: "생성", update: "변경 (제자리)", replace: "교체 (지우고 다시 만듦)", delete: "삭제" };
  const rows = (meta.changes || []).map((x) => `<tr><td><code>${esc(x.address)}</code></td><td>${esc(KW[x.kind] || x.kind || "")}${x.replace_paths && x.replace_paths.length ? ` <small>(${esc(x.replace_paths.join(", "))})</small>` : ""}</td></tr>`).join("");
  const summary = String(meta.summary || "").replace(/후보 반영/g, "수정안 반영").replace(/원본 배포/g, "원본 반영");   // 서버 요약은 전문가 화면 말 — 이 화면 말로 (D-39)
  const more = meta.n_changes > (meta.changes || []).length ? `<p class="small muted">… 외 ${meta.n_changes - meta.changes.length}개</p>` : "";
  // 10-27 실제 사례: plan 만 계산하고 창을 닫은 것을 '끝났다' 로 읽었다 — 제목 · 첫 줄에 '아직 반영 안 됨' 을 적고, 닫으면 '취소' 알림
  const m = modal(`${ko} — 실행 전 확인 (아직 반영 안 됨)`, `<p class="small warn tbpre"><b>아직 아무것도 바뀌지 않았습니다.</b> 아래는 실행하면 바뀔 ${kind === "destroy" ? "삭제 예정" : "변경 예정"} 목록(plan)입니다. 맨 아래 체크 → <b>[${word} 실행]</b> 을 눌러야 AWS 시험 환경에 반영됩니다. 닫으면 아무것도 바뀌지 않습니다.</p>
    <p>${esc(summary)}</p>
    <p class="small">생성 ${cnt.create ?? 0} · 변경 ${cnt.update ?? 0} · 교체 ${cnt.replace ?? 0} · 삭제 ${cnt.delete ?? 0}${meta.eligible === false ? ` — <b class="bad">실행 불가: ${esc(meta.why || "")}</b>` : ""}</p>
    <div class="tscroll"><table class="cov"><thead><tr><th>리소스</th><th>변경 방식</th></tr></thead><tbody>${rows || `<tr><td colspan="2">없음</td></tr>`}</tbody></table></div>${more}
    <p class="small muted">실행에 수 분 걸립니다 (원본 반영 실측 5~8분). 실행 뒤에는 화면의 진행 칸에서 끝날 때까지 기다리세요.</p>
    <label class="ack"><input type="checkbox" id="tbAck"> <span>plan 내용을 확인했고, AWS 시험 환경에 실제로 반영되는 것을 압니다${kind === "destroy" ? " — 시험 환경 리소스 전체 삭제" : ""}.</span></label>
    <div class="mnav"><button type="button" class="mbtn ${kind === "destroy" ? "danger" : "primary"}" id="tbExec" disabled>${word} 실행</button><button type="button" class="mbtn" data-close>취소 (반영 안 함)</button></div>`, true);
  const ack = m.querySelector("#tbAck"), ex = m.querySelector("#tbExec");
  let fired = false;
  m.addEventListener("click", (e) => { if (!fired && (e.target === m || e.target.closest("[data-close]"))) toast("취소 — 반영하지 않음 (plan 만 계산했고 AWS 는 그대로)", ""); });
  ack.addEventListener("change", () => { ex.disabled = !ack.checked || meta.eligible === false || !meta.plan_id; });
  ex.addEventListener("click", async () => {
    if (!ack.checked) return;
    fired = true;
    m.remove();
    await tbJob("/api/testbed/execute", { plan_id: meta.plan_id, confirm: word, profile: tbProfile() }, `${ko} · 사람 확인 후 실행 (${word})`, async (res) => {
      const out = res.result || {};
      if (res.error || out.ok === false) { toast(`${ko} 실패: ${res.error || out.error || ""}`, "bad"); return; }
      if (kind !== "destroy") S.tb.auto = true;      // 반영이 성공했을 때만 자동 측정을 켠다 (낡은 상태에서 화면만 열었을 때는 켜지 않음)
      toast(`${ko} 완료${out.state_resources_after != null ? ` · 배포 리소스 ${out.state_resources_after}개` : ""}${kind === "destroy" ? " · 시험 환경 파일은 원본으로 복원" : ""}`, "good");
    });
  });
}

async function tbJob(url, body, label, after) {
  await startRun("testbed", url, body, label, async (res) => {
    await after(res);
    if (S.rec) { S.tb = { ...(S.tb || {}), data: null }; await loadRecord(S.rec); }   // 측정 · 반영 뒤 기록(post_deploy)이 바뀐다
    await loadTestbed();
  });
}

export async function testbedAct(act, kind) {
  if (S.run) { toast("실행 중인 작업이 끝난 뒤 가능"); return; }
  const d = (S.tb && S.tb.data) || {}; const m = d.m || {};
  if (act === "tb-auto") { S.tb.auto = !S.tb.auto; render(); return; }
  if (act === "s2-pick") { go(5); return; }
  if (act === "s2-decide") { go(8); return; }
  if (act === "s2-deploy") {
    if (!m.is_original) {
      const r = await api.post("/api/testbed/use", { which: "original", record_id: S.rec || "" });
      if (!r || !r.ok) { toast((r && r.error) || "원본 파일로 바꾸지 못함", "bad"); return; }
      await loadTestbed();
      const mm = ((S.tb || {}).data || {}).m || {};
      if (mm.deployed_state_file && mm.applied_after_change && mm.is_original) { toast("원본 파일로 바꿈 — 배포 상태와 같아 반영할 것이 없음", "good"); return; }
    }
    await tbJob("/api/testbed/prepare", { kind: "apply_original", profile: tbProfile() }, "원본 반영 준비 · plan 계산 (반영 없음)", async (res) => {
      const meta = (res.result || {}).plan;
      if (res.error || !meta) { toast(`plan 계산 실패: ${res.error || ""}`, "bad"); return; }
      tbConfirmModal(meta);
    });
    return;
  }
  if (act === "s2-destroy") {
    await tbJob("/api/testbed/prepare", { kind: "destroy", profile: tbProfile() }, "시험 환경 삭제 준비 · plan -destroy (반영 없음)", async (res) => {
      const meta = (res.result || {}).plan;
      if (res.error || !meta) { toast(`plan 계산 실패: ${res.error || ""}`, "bad"); return; }
      tbConfirmModal(meta);
    });
    return;
  }
  if (act === "s2-cand") {
    if (!m.is_record_candidate) {
      const r = await api.post("/api/testbed/use", { which: "candidate", record_id: S.rec || "" });
      if (!r || !r.ok) { toast((r && r.error) || "수정안 파일을 넣지 못함", "bad"); return; }
    }
    await tbJob("/api/plan_check", { record_id: S.rec || "", profile: tbProfile() }, "수정안 계획 확인 · 실제 상태 기준 plan (반영 없음)", async (res) => {
      const out = res.result || {};
      if (res.error) { toast(`계획 확인 실패: ${res.error}`, "bad"); return; }
      if (out.verdict === "BLOCKED") toast("반영하지 않음 — plan 에 교체 · 삭제가 있음 (시험 환경 결과: 차단)", "bad");
      else toast(`계획 확인: ${out.summary || out.verdict || ""}`, "good");
    });
    const mm = ((S.tb || {}).data || {}).m || {};
    if (mm.plan_ready) tbConfirmModal(mm.plan_ready);
    return;
  }
  if (act === "s2-open-apply") { if (m.plan_ready) tbConfirmModal(m.plan_ready); else toast("준비된 plan 이 없음 — 수정안 계획 확인을 다시"); return; }
  if (act === "s2-measure") {
    await tbJob("/api/measure", { record_id: kind === "after" ? (S.rec || "") : "", profile: tbProfile() }, kind === "after" ? "수정 후 측정 (V7 · V8, 읽기 전용)" : "수정 전 측정 (원본 배포 상태, 읽기 전용)", async (res) => {
      const out = res.result || {};
      if (res.error) { toast(`측정 실패: ${res.error}`, "bad"); return; }
      toast(`${kind === "after" ? "수정 후" : "수정 전"} 측정 완료 · ${out.status || ""}`, out.status === "VERIFIED" ? "good" : "");
    });
  }
}

// ------------------------------------------------------------------ ⑧ 최종 결정 + PR
const DEC = [["APPROVED", "승인", "ok", "이 수정을 적용하기로 함 → PR 만들기"], ["CHANGES_REQUESTED", "수정 요청", "warn", "만든 사람에게 고쳐 달라고 돌려보냄"],
  ["REGENERATE", "재생성", "warn", "AI 에게 다시 만들게 함"], ["DISCARDED", "폐기", "bad", "이 수정안은 쓰지 않음"]];

// PR 카드: ① 기준 브랜치 · 준비 확인(읽기만) → ② 미리보기(실행 안 함) → ③ 사람이 확인 문구 입력 → PR 만들기
function prCard(pr) {
  const chk = pr.check;
  const ready = chk && chk.ok;
  const rows = chk ? `<ul class="prchk">${(chk.checks || []).map((c) => `<li class="${c.ok ? "ok" : "bad"}"><em>${c.ok ? "✓" : "✕"}</em><div><b>${esc(c.name)}</b><small>${esc(c.detail || "")}</small>${!c.ok && c.todo ? `<small class="todo">할 일: ${esc(c.todo)}</small>` : ""}</div></li>`).join("")}</ul>
      ${chk.error ? `<p class="small bad">${esc(chk.error)}</p>` : ""}${chk.note ? `<p class="small muted">${esc(chk.note)}</p>` : ""}` : "";
  return `<p class="small">승인한 수정 코드를 새 브랜치로 올리고 PR 을 만듭니다. <b>이 PC 의 git · GitHub 로그인</b>으로 실행되고, 병합(merge) · terraform apply 는 하지 않습니다.</p>
    <div class="prbase"><label>기준 브랜치 <small>(원본 코드가 GitHub 에 올라가 있는 브랜치)</small><input id="prBase" class="minput" value="${esc(pr.base || "main")}"></label>
      <button type="button" class="mbtn" data-act="pr-check">① PR 준비 확인</button></div>
    ${rows}
    ${ready ? (pr.preview ? `<details open><summary>② 'PR 만들기' 를 누르면 실행할 명령</summary><pre class="mlog">${esc(String(pr.preview.commands || pr.preview.output || pr.preview.error || "").split("\n").filter((l) => /^(git|gh|cp) /.test(l)).join("\n") || pr.preview.output || "")}</pre></details>
      ${pr.preview.pr_body ? `<details class="prbody"><summary>PR 본문 미리보기 — 맨 위 = 끝맺음 세 줄 (확인한 것 · 결정 · 남은 것)</summary><pre class="mlog tall">${esc(String(pr.preview.pr_body).slice(0, 6000))}</pre></details>` : ""}`
      : `<div class="mnav"><button type="button" class="mbtn" data-act="pr-preview">② PR 미리보기 (실행 안 함)</button></div>`) : ""}
    <div class="mnav"><button type="button" class="mbtn primary" data-act="pr-create" ${ready && pr.preview && !S.run ? "" : "disabled"} title="${ready ? "" : "① 준비 확인을 통과해야 함"}">③ PR 만들기 (확인 문구 입력)</button></div>
    ${S.run && S.run.kind === "pr" ? runPanel() : ""}
    ${pr.result ? `<pre class="mlog">${esc(pr.result)}</pre>${pr.url ? `<p><a href="${esc(pr.url)}" target="_blank" rel="noopener">GitHub 에서 열기 →</a></p>` : ""}` : ""}`;
}

// ⑧ 지금 상태 → 5칸 띠 + 할 일 하나 (9차, D-43 "결정 · PR 단계가 어려움"). PR 만들기는 여전히 사람이 확인 문구를 넣어야 실행된다
const DEC_STEPS = ["결정 고르기", "이유 · 이름 적기", "결정 기록하기", "PR 준비 확인 · 미리보기", "PR 만들기 (사람)"];
function s8Now(f) {
  const dec = (f && f.decision) || {};
  const ap = (f && f.approve) || { ok: false, why: "" };
  const pr = S.pr || {};
  const form = S.decForm || {};
  const jump = `<button type="button" class="mbtn primary" data-jump=".lay8">결정 칸으로 ▼</button>`;
  const prj = (w) => `<button type="button" class="mbtn primary" data-jump="#prcard">${esc(w)}</button>`;
  if (!dec.decision) {
    if (!S.dec) return { cur: 1, marks: {}, tone: !ap.ok && !ap.needs_ack ? "warn" : "", title: !ap.ok && !ap.needs_ack ? `승인 불가 — ${ap.why || ""}` : "1. 결정을 고르세요", text: !ap.ok && !ap.needs_ack ? "승인 조건을 어겨 승인은 누를 수 없습니다. 수정 요청 · 재생성 · 폐기 중 하나를 골라 이유와 함께 기록하세요." : "아래 정리(해결된 것 · 남은 것 · 새 문제 · 설계 위반 · AWS 시험 환경)와 맨 아래 '이 기록의 끝맺음'(확인한 것 · 결정 · 남은 것)을 보고, 승인 · 수정 요청 · 재생성 · 폐기 중 하나를 누르세요.", btns: jump,
      todo: !ap.ok && !ap.needs_ack ? `승인 불가 (${ap.why || ""}) — 수정 요청 · 재생성 · 폐기 중 하나를 골라 이유와 함께 기록하세요.` : "정리와 끝맺음을 읽고 승인 · 수정 요청 · 재생성 · 폐기 중 하나를 누르세요." };
    const w = (DEC.find((x) => x[0] === S.dec) || [])[1] || S.dec;
    const need = [!form.reason && "이유", !form.by && "결정한 사람"].filter(Boolean);
    if (need.length || (ap.needs_ack && S.dec === "APPROVED" && !form.ack)) return { cur: 2, marks: {}, tone: "", title: `2. '${w}' — ${need.length ? need.join(" · ") + " 을(를) 적으세요" : "미검증 확인 표시를 하세요"}`, text: `이유와 이름은 기록 · PR 본문에 남습니다.${ap.needs_ack && S.dec === "APPROVED" ? " 이 프로젝트는 시험 환경이 없어 '실제 AWS 미검증' 확인 표시가 필요합니다." : ""} 적은 뒤 [결정 기록하기].`, btns: jump, todo: `'${w}' 을 골랐습니다 — ${need.length ? need.join(" · ") + " 을 적고" : "미검증 확인 표시를 하고"} [결정 기록하기].` };
    return { cur: 3, marks: {}, tone: "", title: `3. '${w}' — [결정 기록하기] 를 누르세요`, text: "누르면 결정 · 이유 · 이름 · 시각이 기록에 남습니다. 승인이면 PR 칸이 열리고 준비 확인이 자동으로 돕니다 (읽기만).", btns: jump, todo: `'${w}' · 이유 · 이름을 적었습니다 — [결정 기록하기] 를 누르세요.` };
  }
  const w = f.decision_ko || dec.decision;
  if (dec.decision !== "APPROVED") return { cur: 6, marks: { 4: "skip", 5: "skip" }, tone: "ok", title: `결정 기록됨 — ${w}. PR 은 만들지 않습니다`, text: dec.decision === "REGENERATE" ? "AI 에게 다시 만들게 하려면 아래 버튼으로 ⑤ 로 갑니다." : "다른 수정안으로 하려면 ⑤ 에서 고르세요. 이 기록은 그대로 남습니다 (지우지 않음).", btns: dec.decision === "REGENERATE" ? `<button type="button" class="mbtn primary" data-act="regen">AI 에게 다시 만들게 하기 ▶ (⑤)</button>` : `<button type="button" class="mbtn primary" data-go="5">◀ ⑤ 다른 수정안</button>`, todo: `${w} 기록됨 — PR 은 만들지 않습니다. 다른 수정안은 ⑤ 에서.` };
  if (pr.url) return { cur: 6, marks: {}, tone: "ok", title: "PR 만들어짐 — GitHub 에서 검토 · 병합 (사람)", text: "병합과 운영 반영은 이 프로그램 밖입니다. PR 본문 맨 위에 끝맺음 세 줄(확인한 것 · 결정 · 남은 것)이 있습니다.", btns: `<a class="mbtn primary" href="${esc(pr.url)}" target="_blank" rel="noopener">GitHub 에서 열기 →</a>`, todo: "PR 을 만들었습니다 — GitHub 에서 검토 · 병합은 사람이 합니다." };
  const chk = pr.check;
  if (!chk || !chk.ok) {
    const bad = ((chk || {}).checks || []).find((c) => !c.ok);
    return { cur: 4, marks: {}, tone: bad ? "warn" : "", title: bad ? `4. PR 준비 확인에서 막힘 — ${bad.name}` : "4. 승인 기록됨 — PR 준비 확인", text: bad ? `${bad.detail || ""}${bad.todo ? ` 할 일: ${bad.todo}` : ""} 고친 뒤 [① PR 준비 확인] 을 다시 누르세요.` : chk ? (chk.note || "확인 중…") : "PR 칸의 기준 브랜치(원본 코드가 올라간 브랜치)를 확인하고 [① PR 준비 확인] 을 누르세요 (읽기만 — 이 PC 의 git · 기준 브랜치의 원본이 검사한 원본과 같은지).", btns: prj("PR 칸으로 ▼"), todo: bad ? `PR 준비 확인에서 막힘: ${bad.name}${bad.todo ? ` — 할 일: ${bad.todo}` : ""}.` : "승인 기록됨 — PR 칸에서 [① PR 준비 확인] 을 통과시키세요." };
  }
  if (!pr.preview) return { cur: 4, marks: {}, tone: "", title: "4. 준비 확인 통과 — [② PR 미리보기] 를 누르세요", text: "실행할 git 명령과 PR 본문을 보여 줄 뿐 아무것도 실행하지 않습니다.", btns: prj("PR 칸으로 ▼"), todo: "PR 준비 확인 통과 — [② PR 미리보기] 를 누르세요 (실행 안 함)." };
  return { cur: 5, marks: {}, tone: "", title: "5. [③ PR 만들기] — 확인 문구를 넣으면 이 PC 에서 push · PR 생성", text: "미리보기의 명령과 PR 본문(맨 위 끝맺음 세 줄)을 읽고 나서 누르세요. 병합 · terraform apply 는 하지 않습니다.", btns: prj("PR 칸으로 ▼"), todo: "미리보기를 읽고 [③ PR 만들기] — 확인 문구를 넣어야 실행됩니다. 병합은 GitHub 에서 사람이." };
}
function decStepsHtml(n) {
  return `<ol class="awsflow tbsteps dsteps">${DEC_STEPS.map((t, i) => {
    const k = i + 1, mk = (n.marks || {})[k];
    const cls = mk === "skip" ? "skip" : n.cur === 6 || k < n.cur ? "past" : k === n.cur ? "cur" : "";
    const word = mk === "skip" ? "안 함" : n.cur === 6 || k < n.cur ? "끝" : k === n.cur ? "지금" : "";
    return `<li class="${cls}"><b>${esc(t)}</b><span>${esc(word)}</span></li>`;
  }).join("")}</ol>`;
}
registerTodo(8, () => { const f = S.final; if (!f || !f.ok) return ""; const n = s8Now(f); return n ? n.todo : ""; });
// 이유 · 이름을 치는 동안 띠와 '다음 할 일' 만 제자리에서 바꾼다 (화면 전체를 다시 그리면 입력칸 초점이 사라짐)
export function refresh8() {
  const f = S.final;
  if (S.step !== 8 || !f || !f.ok) return;
  const n = s8Now(f);
  const a = $(".dsteps"), b = $(".mcard.guide");
  if (a) a.outerHTML = decStepsHtml(n);
  if (b) b.outerHTML = guideCard(n);
  refreshTodo();
}

register(8, () => {
  const f = S.final;
  if (!f) { $("#mbody").innerHTML = `<div class="mempty">정리하는 중…</div>`; loadFinal(); return; }
  if (!f.ok) { $("#mbody").innerHTML = `<div class="mempty">${esc(f.reason || "")}</div>`; return; }
  const now = s8Now(f);
  const form = S.decForm || {};
  const box = (title, items, cls, empty, extra = "") => `<div class="mcard sum ${cls}"><h4>${esc(title)} <b>${items == null ? "—" : items.length}</b></h4>
      <ul>${items == null ? `<li class="muted">검사 못 함</li>` : items.map((x) => `<li>${escBrk(x)}</li>`).join("") || `<li class="muted">${esc(empty)}</li>`}</ul>${extra}</div>`;
  const dec = f.decision || {};
  const pr = S.pr || {};
  const ap = f.approve || { ok: false, why: "" };
  const rest = f.remaining_other_trivy;
  // 17차 (D-53): 위의 결론 칸 · 세 단계 띠(⑥ 과 같음)와 '검증하지 못한 부분' 칸(맨 아래 끝맺음의 '남은 것' 과 같음)은 뺐다.
  // 결론 칸에 있던 '무엇을 결정하나'(수정안 이름)는 결정 칸 제목 옆 '대상:' 으로 옮겼다 — 승인 대상이 화면에서 사라지지 않게
  $("#mbody").innerHTML = `${decStepsHtml(now)}${guideCard(now)}
    ${reqCard(f.request, true)}
    <div class="final-grid">
      ${box("해결된 문제", f.resolved || [], "good", "없음")}
      ${box("남아 있는 문제", f.remaining || [], "warn", "이번 수정 대상 중 남은 것 없음", rest ? `<p class="small muted">그 밖에 이번 수정의 대상이 아닌 Trivy 지적 ${esc(rest)}개는 그대로입니다 (④ 보안 문제).</p>` : "")}
      ${box("새로 생긴 문제", f.new, "bad", "없음")}
      ${box("고객 설계 위반", f.design_violations, "bad", "없음")}
      <div class="mcard sum ${f.aws.status === "VERIFIED" ? "good" : "dim"}"><h4>AWS 시험 환경 검사 <small class="muted">V7 · V8 · 운영 아님</small></h4><p>${esc(f.aws.text)}</p></div></div>
    ${(f.opened || []).length || (f.closed || []).length ? `<div class="mcard flowchg"><b>통신 변화</b> <small class="muted">보안 그룹 규칙 기준 · 문제 여부는 위 칸</small>
      ${(f.opened || []).map((x) => `<span class="fc add">＋ ${esc(x)}</span>`).join("")}${(f.closed || []).map((x) => `<span class="fc gone">－ ${esc(x)}</span>`).join("")}</div>` : ""}
    <div class="lay8"><div class="mcard"><h3>결정 ${f.label ? `<small class="dec-target">대상: ${esc(f.label)}</small>` : ""} ${dec.decision ? chip("ok", `기록됨: ${f.decision_ko || dec.decision}`) : ""}</h3>
        <div class="decs">${DEC.map(([k, w, c, d]) => { const off = k === "APPROVED" && !ap.ok && !ap.needs_ack; return `<button type="button" class="dec ${c} ${S.dec === k ? "on" : ""}" data-dec="${k}" ${off ? `disabled title="${esc(ap.why)}"` : ""}><b>${esc(w)}</b><small>${esc(off ? "지금은 승인 불가 — 아래 이유" : k === "APPROVED" && ap.needs_ack ? "실제 AWS 미검증 확인 후 승인 → PR" : d)}</small></button>`; }).join("")}</div>
        ${!ap.ok && !ap.needs_ack ? `<p class="small warn">승인 불가: ${esc(ap.why)}</p>` : ""}
        ${ap.needs_ack && S.dec === "APPROVED" ? `<label class="ack"><input type="checkbox" id="decAck" ${form.ack ? "checked" : ""}> <span><b>실제 AWS 에서 확인하지 않은 것을 알고 승인합니다.</b> 이 프로젝트는 시험 환경이 없어 실제 적용 · 연결을 재지 못했습니다. 결정 기록 · PR 제목 · 본문에 '실제 AWS 미검증' 이 남습니다.</span></label>` : ""}
        <label class="ed-note">이유 (기록에 남음)<input id="decReason" value="${esc(form.reason || "")}" placeholder="예: 설계 일치 · 시험 환경 확인 끝"></label><label class="ed-note">결정한 사람<input id="decBy" value="${esc(form.by || "")}" placeholder="이름"></label>
        <div class="mnav"><button type="button" class="mbtn primary" data-act="decide" ${S.dec ? "" : "disabled"}>결정 기록하기</button></div>
        <p class="small muted">결정은 사람이 합니다. 프로그램은 승인 조건${f.testbed ? "(배포 전 검사 · AWS 시험 환경 검사 모두 통과)" : "(배포 전 검사 통과 + 실제 AWS 미검증 확인 표시 — 이 프로젝트는 시험 환경이 없음)"}을 어긴 승인을 거절합니다.</p></div>
      <div class="mcard prcard" id="prcard"><h3>PR (GitHub)</h3>
        ${dec.decision === "APPROVED" ? prCard(pr)
          : `<p class="muted">승인(APPROVED)을 기록하면 여기서 PR 을 만들 수 있습니다. 승인 전에는 만들지 않습니다.</p>`}</div></div>
    ${S.dec === "REGENERATE" || dec.decision === "REGENERATE" ? `<div class="mnav"><button type="button" class="mbtn primary" data-act="regen">AI 에게 다시 만들게 하기 ▶ (⑤ 수정안)</button></div>` : ""}
    ${closingCard(f.closing)}
`;      // 11차 (D-47): '이 판정의 버전' 카드는 화면에서 뺐다 — 값은 기록(state.json versions)에 그대로
});

// 끝맺음 세 줄 (검토 문서 11-02): 무엇을 확인했고 · 누가 어떤 결정을 했고 · 무엇이 남았는지 — 서버(product._closing)가 기록에서 문장으로 옮긴 것
function closingCard(c) {
  if (!c) return "";
  return `<div class="mcard closing"><h3>이 기록의 끝맺음</h3><dl class="kv3">
      <div><dt>확인한 것</dt><dd>${esc(c.checked || "")}</dd></div>
      <div><dt>결정</dt><dd>${esc(c.decided || "")}</dd></div>
      <div><dt>남은 것</dt><dd>${(c.left || []).length ? `<ul>${c.left.map((x) => `<li>${escBrk(x)}</li>`).join("")}</ul>` : "없음"}</dd></div></dl></div>`;
}

async function loadFinal() {
  if (!S.rec) return;
  const rid = S.rec;
  const f = await api.get(`/api/p/final?id=${encodeURIComponent(rid)}`);
  if (S.rec !== rid) return;
  S.final = f;
  if (S.step === 8) render();
}

// ------------------------------------------------------------------ 작업: 분석 · AI · 업로드 · 결정 · PR
async function startRun(kind, url, body, label, after) {
  if (S.run) return;
  if (S.bg) { toast(`수정안 미리 분석 중 (${S.bg.i}/${S.bg.n}) — 끝난 뒤에 할 수 있어요`); return; }
  const r = await api.post(url, body);
  if (!r || !r.started) { toast(r && r.error ? r.error : "시작하지 못함 (다른 작업이 진행 중일 수 있음)"); return; }
  S.run = { kind, t0: Date.now(), since: 0, label, stages: [] }; S.log = [];
  render();
  let runId = null;
  const res = await followJob(async (lg, pg) => {
    S.run.stages = (pg && pg.stages) || [];
    if (kind === "ai") {
      if (!runId) { const rs = await api.get(`/api/llm/runs?set=${encodeURIComponent(S.target)}`); const hit = ((rs && rs.runs) || []).find((x) => x.status === "RUNNING"); if (hit) runId = hit.run_id; }
      if (runId) { const live = await api.get(`/api/llm/run?id=${encodeURIComponent(runId)}`); if (live && !live.error) S.llm.live = live; }
    }
    const sec = $(".mcard.run small"); if (sec) sec.textContent = `${((Date.now() - S.run.t0) / 1000).toFixed(0)}초`;
    const lgEl = $("#mlog"); if (lgEl) { lgEl.textContent = S.log.slice(-8).join("\n"); lgEl.scrollTop = lgEl.scrollHeight; }
    const box = $("#aiLive"); if (box && S.llm.live) box.innerHTML = aiTimeline(S.llm.live, true);
    const st = $("ol.stages"); if (st) st.innerHTML = stagePills(S.run.stages);
  });
  S.run = null;
  await after(res, runId);
}

export async function runCandidate(cid) {
  const c = curCand() && curCand().id === cid ? curCand() : teamList().concat(directList()).find((x) => x.id === cid);
  if (!c) return;
  await startRun("review", "/api/review", { case_id: S.pid, set_id: S.target, candidate_id: c.id }, `${c.label} 분석 (배포 전 검사 6개)`, async (res) => {
    const rid = (res.result && res.result.record_id) || (res.pg && res.pg.record_id);
    if (res.error || !rid) { toast(`분석 실패: ${res.error || "기록 없음"}`); render(); return; }
    await refreshCands(); S.llm.view = null; await loadRecord(rid);
  });
}

// 설계도대로 자동 수정 (D-45): 규칙 기반 생성기가 지금 기준 설계도의 외부 → 이 계층 화살표를 허용 목록으로 써서 IP 목록만 바꾸고, 바로 8개 관문 검사
// 수정안 미리 분석 (D-47): 보이는 수정안 중 지금 기준 기록이 없는 것을 서버가 차례로 검사. 화면을 막지 않는 배경 작업 — 끝난 것부터 누를 수 있다
let bgPoll = null;
export async function maybePrefetch() {
  if (!S.cands || !S.target || S.run || S.bg) return;
  if (!(S.infra && S.infra.ok)) return;        // 원본 plan(② 점검)이 먼저 — 점검 작업과 겹치지 않게
  if (!teamList().some((c) => needsAnalysis(c)) || !prefetchOk()) return;
  const key = `${S.target}|${curSet().design_sha256 || ""}|${(curSet().design_confirmation || {}).confirmed}`;
  S.prefetched = S.prefetched || {};
  if (S.prefetched[key]) return;             // 같은 기준으로 한 번만 (실패해도 되풀이하지 않음)
  S.prefetched[key] = true;
  const r = await api.post("/api/review/prefetch", { case_id: S.pid, set_id: S.target });
  if (!r || !r.started) { if (r && r.error) toast(r.error); return; }
  S.bg = { kind: "prefetch", set_id: S.target, i: 0, n: teamList().filter((c) => needsAnalysis(c)).length, since: 0 };
  if (S.step === 5) render(); else renderSide();
  if (bgPoll) clearInterval(bgPoll);
  let last = -1;
  bgPoll = setInterval(async () => {
    const pg = await api.get("/api/job/progress");
    if (!pg || !S.bg) { clearInterval(bgPoll); bgPoll = null; return; }
    const [i, n] = pg.progress || [0, 0];
    if (n) { S.bg.i = i; S.bg.n = n; }
    const changed = i !== last; last = i;
    if (pg.running === false) {
      clearInterval(bgPoll); bgPoll = null;
      S.bg = null;
      await refreshCands();
      if (S.step === 5 && !S.run) { render(); toast(pg.error ? `미리 분석 중 오류: ${pg.error}` : `수정안 미리 분석 끝 — 번호를 누르면 바로 그림이 바뀝니다`, pg.error ? "bad" : "good"); } else renderSide();
      return;
    }
    if (changed) { await refreshCands(); if (S.step === 5 && !S.run) render(); else renderSide(); }
  }, 1500);
}

export async function runRuleBased() {
  if (!rbOn()) { toast("설계도가 있는 통신 구조 문제에서만 쓸 수 있음 — ③ 에서 설계도를 먼저"); return; }
  S.llm.view = null; S.aiPick = null; S.src = null;
  await startRun("review", "/api/review", { case_id: S.pid, set_id: S.target, generator: "rule_based" }, `설계도 v${designVersion()} 대로 자동 수정 (규칙 기반) + 배포 전 검사`, async (res) => {
    const rid = (res.result && res.result.record_id) || (res.pg && res.pg.record_id);
    if (res.error || !rid) { toast(`자동 수정 실패: ${res.error || "기록 없음"}`); render(); return; }
    await refreshCands(); S.cand = "rule-based"; await loadRecord(rid);
  });
}

export async function runUpload() {
  const u = S.upload || {};
  if (!u.check || !u.check.ok) return;
  await startRun("review", "/api/review", { case_id: S.pid, set_id: S.target, upload: { files: u.files, folder: !!u.folder } }, "직접 제출한 파일 분석", async (res) => {
    const rid = (res.result && res.result.record_id) || (res.pg && res.pg.record_id);
    if (res.error || !rid) { toast(`분석 실패: ${res.error || "기록 없음"}`); render(); return; }
    S.upload = null; S.src = null; await refreshCands(); S.cand = null; await loadRecord(rid);
  });
}

export async function runAi() {
  S.llm.live = null; S.llm.view = null; S.cand = null; S.rec = null; S.impact = null; S.verdict = null;
  const ctx = S.design && S.design.exists ? S.llm.context : "trivy";
  await startRun("ai", "/api/llm/fix", { set_id: S.target, context: ctx, max_attempts: 3 }, "AI 수정 (최대 3번)", async (res, runId) => {
    const out = res.result || {};
    const view = await api.get(`/api/llm/run?id=${encodeURIComponent(out.run_id || runId || "")}`);
    S.llm.view = view && !view.error ? view : null;
    const [st, runs] = await Promise.all([api.get("/api/llm/status"), api.get(`/api/llm/runs?set=${encodeURIComponent(S.target)}`)]);
    S.llm.status = st; S.llm.runs = (runs && runs.runs) || [];
    S.src = null;
    if (res.error && !out.run_id) { toast(`AI 수정 실패: ${res.error}`); render(); return; }
    await refreshCands();
    const rid = out.record_id || (S.llm.view && S.llm.view.final_record_id);
    if (rid) await loadRecord(rid); else { toast(`AI 가 수정안을 내지 못함: ${out.error || ""}`); render(); }
  });
}

export async function openAiRun(runId) {
  const view = await api.get(`/api/llm/run?id=${encodeURIComponent(runId)}`);
  if (!view || view.error) { toast((view && view.error) || "기록을 읽지 못함"); return; }
  S.llm.view = view; S.cand = null;
  if (view.final_record_id) await loadRecord(view.final_record_id); else { S.rec = null; S.impact = null; S.verdict = null; render(); }
}

export async function refreshCands() {
  S.cands = await api.get(`/api/case/candidates?id=${encodeURIComponent(S.pid)}`);
}

export async function readPicked(input, folder) {
  const all = Array.from(input.files || []);
  if (!all.length) return;
  S.upload = { reading: true, folder, files: [] }; render();
  const files = [], hidden = {};
  for (const f of all) {
    const path = folder ? (f.webkitRelativePath || f.name) : f.name;
    const parts = path.split("/");
    const inner = folder ? parts.slice(1) : parts;
    const h = inner.findIndex((x) => x.startsWith("."));
    if (folder && h >= 0 && h < inner.length - 1) { const k = inner.slice(0, h + 1).join("/"); hidden[k] = (hidden[k] || 0) + 1; continue; }
    const readIt = /\.tf$/i.test(path) && inner.length === 1 && f.size <= 1000000;
    let content = null;
    if (readIt) { try { content = await f.text(); } catch (e) { content = null; } }
    files.push({ path, content, size: f.size });
  }
  Object.entries(hidden).forEach(([k, n]) => files.push({ path: k + "/", content: null, aggregated: true, count: n }));
  const chk = await api.post("/api/submission/check", { set_id: S.target, files, folder });
  S.upload = { folder, files, check: chk };
  input.value = "";
  render();
}

export async function decide() {
  if (!S.dec || !S.rec) return;
  const r = await api.post("/api/decision", { record_id: S.rec, decision: S.dec, reason: ($("#decReason") || {}).value || "", by: ($("#decBy") || {}).value || "",
    ack_unverified: !!(($("#decAck") || {}).checked) });
  if (!r || !r.ok) { toast((r && (r.reason || r.error || (r.errors || []).join(" "))) || "결정을 기록하지 못함"); return; }
  toast("결정을 기록함", "good");
  const vv = await api.get(`/api/p/verdict?id=${encodeURIComponent(S.rec)}`);
  S.verdict = vv; S.final = null; S.decForm = null; render();
  if (S.dec === "APPROVED") await prCheck();     // 9차: 승인 뒤 PR 준비 확인(읽기만)을 바로 돈다 — 사용자가 ① 을 따로 찾지 않게. PR 만들기는 여전히 사람
}

function prBase() { const v = (($("#prBase") || {}).value || (S.pr || {}).base || "main").trim(); return v || "main"; }

let prSeq = 0;
export async function prCheck() {
  const base = prBase();
  const seq = ++prSeq;          // 승인 직후 자동 확인과 사람이 누른 확인이 겹치면 늦게 온 옛 결과는 버린다
  S.pr = { ...(S.pr || {}), base, check: { checks: [], note: "확인 중…" }, preview: null };
  render();
  const r = await api.get(`/api/p/pr_check?id=${encodeURIComponent(S.rec)}&base=${encodeURIComponent(base)}`);
  if (seq !== prSeq) return;
  S.pr = { ...(S.pr || {}), base, check: r };
  render();
}

export async function prPreview() {
  const r = await api.post("/api/week5/pr_preview", { record_id: S.rec, base_branch: prBase() });
  S.pr = { ...(S.pr || {}), preview: r }; render();
}

export function prCreate() {
  const m = modal("PR 만들기 — 확인", `<p>이 PC 에서 다음을 실행합니다: 새 브랜치 만들기 → 승인된 수정 파일 커밋 → GitHub 로 push → PR 만들기(토큰이 없으면 브라우저에서 만드는 주소 안내). 병합(merge)과 terraform apply 는 하지 않습니다.</p>
    <p>계속하려면 아래에 <b>PR 만들기</b> 를 그대로 입력하세요.</p><input id="prConfirm" class="minput" placeholder="PR 만들기">
    <div class="mnav"><button type="button" class="mbtn primary" id="prGo">실행</button><button type="button" class="mbtn" data-close>취소</button></div>`);
  m.querySelector("#prGo").addEventListener("click", async () => {
    const v = (m.querySelector("#prConfirm") || {}).value || "";
    if (v.trim() !== "PR 만들기") { toast("확인 문구가 다름"); return; }
    m.remove();
    await startRun("pr", "/api/p/pr", { record_id: S.rec, confirm: "PR 만들기", base_branch: (S.pr || {}).base || "main" }, "PR 만들기", async (res) => {
      const out = (res.result && res.result.output) || S.log.join("\n");
      const url = (out.match(/https:\/\/github\.com\/\S+/) || [])[0] || "";
      S.pr = { ...(S.pr || {}), result: res.error ? `실패: ${res.error}\n${S.log.slice(-12).join("\n")}` : out, url };
      render();
    });
  });
}

export function showPrompt(runId, n) {
  api.get(`/api/llm/text?id=${encodeURIComponent(runId)}&n=${n}&what=prompt`).then((r) => {
    modal(`시도 ${n} — AI 에게 보낸 요청 그대로`, `<p class="small muted">수정안 이름 · 기대 결과 같은 정답 정보는 들어가지 않습니다. 아래가 전부입니다 (지문 sha256 ${esc(String(r.sha256 || "").slice(0, 16))}…).</p><pre class="mlog tall">${esc(r.text || r.error || "")}</pre>`, true);
  });
}
