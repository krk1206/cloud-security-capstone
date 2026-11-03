// 화면 ⑤ 수정안 · ⑥ 적용 판단 · ⑦ AWS 시험 환경 · ⑧ 최종 결정 (+ PR)
// 판정은 만들지 않는다 — 서버(web/product.py · 검사 기록)가 준 값을 그대로 보여 준다. 계산하지 못한 것은 '검사 못 함' 으로.
import { $, S, api, esc, fmt, register, registerTodo, refreshTodo, guideCard, render, chip, toast, modal, followJob, designVersion, designConf, go } from "./m_core.js";
import { mapBox, drawMap, mapView, MLEG, pop, nodeInfo, linkInfo, fullToggle } from "./m_map.js";
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
function teamList() { return (curSet().candidates || []).filter((c) => !/^(paste|upload)/.test(String(c.id)) && !isAiRun(c.id)).slice().sort((a, b) => String(a.label).localeCompare(String(b.label), "ko", { numeric: true })); }
function directList() { return (curSet().candidates || []).filter((c) => /^(paste|upload)/.test(String(c.id))).slice(0, 6); }
// 이전 기준 결과: 기록의 기준 파일 지문 ≠ 지금 기준 지문. 설계도(프로젝트)는 S.design 의 활성 버전, 요구사항(IAM 등)은 세트의 지금 기준 (D-40)
const curSha = () => curSet().intent_kind === "topology" ? activeSha() : curSet().design_sha256;
const stale = (c) => c && c.latest && c.latest.design && curSha() && c.latest.design.sha256 !== curSha();
const tone = (c) => { const l = c && c.latest; if (!l) return ["dim", "검사 전"]; const t = (l.classification || {}).tone; return t === "good" ? ["ok", "통과"] : t === "bad" ? ["bad", "막힘"] : ["warn", "판정 불가"]; };
const MARK = { ok: "✓", bad: "✕", warn: "?", dim: "–" };
const mark = (k, w) => `<em class="mk ${k}" aria-label="${esc(w)}">${MARK[k] || ""}</em>`;
const toneChip = (t) => (t === "good" ? "ok" : t === "bad" ? "bad" : "warn");
function curCand() { return teamList().concat(directList()).find((x) => x.id === S.cand) || null; }

export async function loadRecord(rid) {
  if (S.rec !== rid) { S.dec = null; S.pr = null; }
  S.rec = rid; S.impact = null; S.verdict = null; S.final = null;
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
  const cnt = { ok: 0, bad: 0, warn: 0, dim: 0 };
  team.forEach((c) => { cnt[tone(c)[0]] += 1; });
  const picked = team.find((c) => c.id === S.cand);
  const open = !!S.teamOpen;
  return `<div class="cands">
      <div class="cg ai"><b class="cg-l">AI 수정</b><div class="chips">${ai || `<span class="muted small">아직 없음 — 오른쪽 버튼을 누르면 AI 가 고친 코드를 내고 바로 검사합니다</span>`}</div>
        <span class="cg-a"><button type="button" class="mbtn ${S.src === "ai" ? "on" : "primary"}" data-src="ai" title="${esc(aw)}">AI 에게 고치게 하기 ▾</button><small class="aist ${ak}">${esc(aw)}</small></span></div>
      ${team.length ? `<div class="cg team"><b class="cg-l" title="팀이 평가용으로 미리 만든 수정 — 번호와 바꾼 곳만 보임 (정답 · 오답은 검사해야 보임)">팀 평가용 수정안</b>
        <div class="tsum"><b>${team.length}개</b> — 검사함 ${team.length - cnt.dim}개 (${mark("ok", "통과")} 통과 ${cnt.ok} · ${mark("bad", "막힘")} 막힘 ${cnt.bad}${cnt.warn ? ` · ${mark("warn", "판정 불가")} 판정 불가 ${cnt.warn}` : ""}) · 검사 전 ${cnt.dim}개${picked ? ` · 고른 것: <b>${esc(picked.label)}</b>` : ""}</div>
        <span class="cg-a"><button type="button" class="mbtn sm" data-act="team-toggle" aria-expanded="${open}">${open ? "접기 ▴" : "수정안 펼치기 ▾"}</button></span></div>
        ${open ? `<div class="tlist">${team.map((c) => { const [k, w] = tone(c); return `<button type="button" class="trow ${c.id === S.cand ? "on" : ""}" data-cand="${esc(c.id)}" title="${esc(`${c.label} · ${w}${stale(c) ? " · 이전 설계도 기준" : ""}`)}">
            <b>${esc(String(c.label).replace("수정안 ", ""))}</b><span>${esc(c.summary || "바꾼 곳 정보 없음")}</span><em class="tw ${k}">${mark(k, w)}${esc(w)}${stale(c) ? " · 이전 설계도 기준" : ""}</em></button>`; }).join("")}</div>` : ""}` : ""}
      <div class="cg direct"><b class="cg-l">직접 올린 파일</b><div class="chips">${direct.slice(0, 6).map((c) => { const [k, w] = tone(c); return `<button type="button" class="cchip ${c.id === S.cand ? "on" : ""}" data-cand="${esc(c.id)}" title="${esc(`${c.label} · ${w}`)}"><b>${esc(String(c.label).replace("직접 제출 · ", ""))}</b>${mark(k, w)}</button>`; }).join("") || `<span class="muted small">아직 없음</span>`}</div>
        <span class="cg-a"><button type="button" class="mbtn sm ${S.src === "upload" ? "on" : ""}" data-src="upload">고친 파일 올리기 ▾</button></span></div>
      <p class="mnote">수정안을 하나 누르면 아래 오른쪽 그림이 그 수정안을 적용한 뒤로 바뀝니다. 팀 평가용 수정안은 번호와 '무엇을 바꿨는지' 만 보입니다 — 정답 · 오답은 검사해야 보입니다.</p>
    </div>`;
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

// ------------------------------------------------------------------ ⑤ 나란히: 왼쪽 설계도 · 오른쪽 이 수정안 적용 후 (6차 · D-34)
// B (11-01): "저 수정안 누르면 설계도가 저래, 토폴로지가 저래 바뀌고" — 한 그림에 겹치지 않는다. 수정안을 바꾸면 오른쪽만 바뀐다.
const rangeTxt = (rs) => [...new Set((rs || []).map((r) => (String(r[0]) === "-1" ? "전체" : +r[1] === +r[2] ? `${r[1]}` : `${r[1]}-${r[2]}`)))].join(", ");

// 오른쪽 그림에 겹칠 것: 설계도와 다른 것만 (설계도에 없는 통신 = 빨강 ✕, 설계도에 있는데 막힘 = 빨간 점선).
// '원하는 구조의 통신인데 출발지가 코드와 다름(desired)' 은 그리지 않는다 — 그 통신은 왼쪽 설계도에 있고, 코드의 더 넓은 허용이 빨간 선으로 보인다
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
// '통신 관련만' 은 통신 구조(보안 그룹) 문제일 때만 — IAM 문제는 권한 선 · IAM 상자가 핵심이라 늘 전체
const simpleOn = () => !S.mapFull && curSet().intent_kind === "topology";
export function drawAfter(id, im) {
  if (!im || !im.arch_after) return;
  const o = afterOpts(im);
  drawMap(id, im.arch_after, { ...o, simple: simpleOn() }, onPick(id, o.overlay));
}
// 왼쪽 설계도: 고른 기록이 설계도와 비교한 결과(빨강 표시)를 가지고 있으면 그 비교에 쓴 설계도, 아니면 지금 설계도
function leftSide() {
  const im = S.rec ? S.impact : null;
  if (curSet().intent_kind !== "topology") return { model: null, title: "설계도" };
  if (im && im.overlay_after && im.design_view) {
    const des = (im.design || {}).recorded || {};
    const old = des.sha256 && activeSha() && des.sha256 !== activeSha();
    return { model: im.design_view, title: `설계도 v${des.intent_version || designVersion()}${old ? ` — 이 수정안을 검사한 때의 설계도 (지금은 v${designVersion()})` : ""}` };
  }
  return { model: ((S.design || {}).compare || {}).view || null, title: `설계도 v${designVersion()}` };
}

function pairHtml() {
  const im = S.rec ? S.impact : null;
  const c = curCand();
  const topo = curSet().intent_kind === "topology";
  const L = leftSide();
  const lm = L.model;
  const left = mapBox("tDesign", L.title, lm ? MLEG.design : "", "",
    lm ? "" : topo ? "설계도 그림 없음 — ③ 에서 확인" : "이 고칠 문제는 통신 구조 설계도가 아니라 요구사항 표(IAM 등)로 검사합니다");
  let right;
  if (!S.rec) {
    const ready = c && (!c.latest || stale(c)) && !S.run;
    right = `<div class="mcanvas amap pholder"><div class="mc-head"><b>${c ? `${esc(c.label)} 적용 후` : "수정안 적용 후"}</b></div><div class="mempty">${ready
      ? `<b>${esc(c.label)}: ${c.latest ? "이전 설계도 기준 결과만 있음" : "아직 분석 전"}</b><p>적용한 뒤의 구조를 그리려면 Terraform 계획(plan)을 계산해야 합니다 — 배포 전 검사를 한 번에 돌립니다 (AWS 접속 없음).</p>
        <button type="button" class="mbtn primary" data-act="run-cand">${c.latest ? "지금 기준으로 다시 분석" : "분석 시작"} ▶</button>`
      : `<b>위에서 수정안을 누르세요</b><p>누른 수정안을 적용한 뒤의 구조가 여기에 그려집니다. 왼쪽 설계도와 다른 선만 빨강.</p>`}</div></div>`;
  } else if (!im) right = `<div class="mcanvas amap pholder"><div class="mempty">분석 결과 불러오는 중…</div></div>`;
  else {
    const d = designDiffs(im);
    const foot = im.arch_after && d ? `<div class="pdiff ${d.length ? "bad" : "ok"}">${d.length ? `<b>설계도와 다른 곳 ${d.length}개</b><ul>${d.map((x) => `<li class="${x.cls}">${esc(x.text)} <small>${esc(x.why)}</small></li>`).join("")}</ul>` : `<b>설계도와 같음</b> — 설계도에 없는 통신도, 막힌 필요한 통신도 없음`}</div>`
      : im.arch_after && topo ? `<div class="pdiff warn">이 기록에는 설계도와 비교한 결과가 없음 (예전 기록) — 빨강은 자체 검사가 본 위험한 허용. ${S.cand ? `<button type="button" class="linkbtn" data-act="recheck">지금 설계도로 다시 분석</button>` : ""}</div>` : "";
    right = mapBox("tAfter", `${im.label || "수정안"} 적용 후`, im.arch_after ? (im.overlay_after ? MLEG.after : MLEG.afterCode) : "", "",
      im.arch_after ? "" : NO_AFTER, im.arch_after ? foot : `<p class="mc-why">${esc(im.reason || "수정안 plan 없음")}</p>`);
  }
  const both = lm && im && im.arch_after ? `<button type="button" class="mc-zoom" data-act="pair-zoom" title="두 그림을 크게 나란히">⤢ 둘 다 크게</button>` : "";
  return `<div class="pairhead"><b>왼쪽 = 설계도 (고객이 원하는 구조) · 오른쪽 = ${im ? `${esc(im.label || "이 수정안")} 적용 후` : "고른 수정안을 적용한 뒤"}</b>${topo ? fullToggle() : ""}${both}</div>
    <p class="pairnote small muted">그림의 선 = 보안 그룹 규칙이 <b>허용</b>하는 통신 (코드 기준). 실제로 연결되는지는 AWS 시험 환경 검사(⑦ V8)에서 따로 잽니다.</p><div class="pair">${left}${right}</div>`;
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
  const basis = conf && !conf.confirmed
    ? `<div class="mcard warn small basis">기준: <b>확정 전 기준</b> — 설계도 v${esc(des.intent_version || conf.version || "?")} 는 검사 당시 초안이라 이 결과는 '고객 요구 충족' 이 아닙니다. ③ 에서 담당자가 확정한 뒤 다시 분석한 것만 승인할 수 있음. <button type="button" class="linkbtn" data-go="3">③ 설계도 확정</button></div>`
    : conf && conf.basis === "manifest" ? `<div class="mcard small basis">기준: 팀 작성 평가 기준 (실험 세트 설계도 — 고객이 확정한 설계도 아님)</div>`
    : conf && conf.confirmed ? `<div class="mcard small basis">기준: 설계도 v${esc(des.intent_version || conf.version || "?")} · ${esc(conf.by || "담당자")} 확정</div>` : "";
  return `<div class="cmp-head"><div><span class="kicker">고른 수정안</span><b>${esc(im.label || "")}</b><small>${esc(cc.title || "")}</small></div>
      <div class="cmp-r">${chip(toneChip(cc.tone), cc.status || cc.headline || "")}<button type="button" class="mbtn primary" data-go="6">이 수정안 적용해도 될까? ▶</button></div></div>
    ${basis}
    ${staleRec ? `<div class="mcard warn small">이 결과는 설계도 v${esc(des.intent_version)} 기준 — 지금 기준은 v${designVersion()}. <button type="button" class="linkbtn" data-act="recheck">지금 기준으로 다시 분석</button></div>` : ""}
    ${post ? `<div class="mcard small">이 수정안 파일로 AWS 시험 환경 검사까지 한 기록이 있습니다 (${esc(fmt(post.at))} · ${esc(post.status)}). <button type="button" class="linkbtn" data-rec="${esc(post.id)}">그 기록 보기</button></div>` : ""}`;
}

function detailsHtml() {
  const im = S.impact;
  if (!S.rec || !im) return "";
  const ch = im.changes || {};
  const changed = Object.entries(ch.changed || {}).map(([k, v]) => `<li><code>${esc(k)}</code> <small>${esc((v || []).join(", "))} 변경</small></li>`).join("")
    + (ch.added || []).map((k) => `<li><code>${esc(k)}</code> ${chip("warn", "새로 생김")}</li>`).join("") + (ch.removed || []).map((k) => `<li><code>${esc(k)}</code> ${chip("bad", "삭제")}</li>`).join("");
  const v6 = im.v6 || {};
  const tr = im.trivy || {};
  const df = im.arch_diff || null;
  const added = df ? df.added_list : (im.added || []), removed = df ? df.removed_list : (im.removed || []);
  const ai = S.llm.view && (S.llm.view.attempts || []).some((a) => a.record_id === S.rec);
  return `<div class="cmp-grid">
      <div class="mcard"><h4>이 수정안이 바꾼 통신 <small>적용 전 → 후, 보안 그룹 규칙 기준</small></h4><ul class="flist">${added.map((a) => `<li class="add">＋ ${esc(a.src)} → ${esc(a.dst)} <b>:${esc(a.port)}</b></li>`).join("")}${removed.map((a) => `<li class="gone">－ ${esc(a.src)} → ${esc(a.dst)} <b>:${esc(a.port)}</b></li>`).join("")}
        ${!added.length && !removed.length ? `<li class="muted">${im.arch_after || im.after ? "통신 변화 없음" : "계산 못 함"}</li>` : ""}</ul></div>
      <div class="mcard"><h4>해결 · 새로 생긴 문제</h4><ul class="flist">${(tr.resolved || []).map((x) => `<li class="add">해결 · Trivy: ${esc(x)}</li>`).join("")}${(im.sg_resolved || []).map((x) => `<li class="add">해결 · 자체 검사: ${esc(x.title)}</li>`).join("")}
        ${(tr.new || []).map((x) => `<li class="risk">새 문제 · Trivy: ${esc(x)}</li>`).join("")}${(im.sg_new || []).map((x) => `<li class="risk">새 문제 · 자체 검사: ${esc(x.title)} — ${esc(x.detail)}</li>`).join("")}
        ${(im.sg_remaining || []).map((x) => `<li>남음 · 자체 검사: ${esc(x.title)}</li>`).join("")}
        ${!(tr.resolved || []).length && !(tr.new || []).length && !(im.sg_resolved || []).length && !(im.sg_new || []).length && !(im.sg_remaining || []).length ? `<li class="muted">${tr.v1 ? "변화 없음" : "계산 못 함"}</li>` : ""}</ul></div>
    </div>
    <details class="mdetails" ${ai ? "open" : ""}><summary>자세히 — 바뀌는 리소스 · 설계도 비교 문장${ai ? " · AI 시도 기록" : ""}</summary>
      ${ai ? `<div class="mcard ai small"><b>이 AI 수정의 시도 기록</b> <span class="muted">시도마다 위 'AI 수정' 버튼으로 따로 볼 수 있음</span>${aiTimeline(S.llm.view)}</div>` : ""}
      <div class="cmp-grid">
        <div class="mcard"><h4>바뀌는 Terraform 리소스 <small>plan 기준</small></h4><ul class="flist">${changed || `<li class="muted">${ch.verdict ? "바뀌는 리소스 없음" : "계산 못 함 (변경 범위 검사 전에 멈춤)"}</li>`}</ul></div>
        <div class="mcard"><h4>설계도와 비교 (V6)</h4><p>${chip(v6.verdict === "PASS" ? "ok" : v6.verdict === "FAIL" ? "bad" : "warn", v6.verdict === "PASS" ? "일치" : v6.verdict === "FAIL" ? "불일치" : "검사 못 함")}</p><p class="small">${esc(v6.verdict === "PASS" || v6.verdict === "FAIL" ? v6.summary || "" : "앞 단계에서 멈춰 비교하지 않음")}</p>
          ${im.design_fallback ? `<p class="mnote">예전 기록 — 설계도 사본이 없어 이 묶음의 지금 설계도 파일로 그림 (판정은 기록 그대로).</p>` : ""}</div>
      </div></details>`;
}

// ⑤ 지금 상태 → 할 일 하나 (9차, D-43 "수정안 고르기 · AI · 파일 올리기가 어려움"): 세 가지 방법 중 지금 누를 것 하나를 맨 위에
function s5Now() {
  if (!S.cands || !S.target) return null;
  const [ak, aw] = aiState();
  const vv = S.verdict;
  const label = (S.impact && S.impact.label) || (vv && vv.label) || "이 수정안";
  const aiBtn = (word) => `<button type="button" class="mbtn primary" data-srcopen="ai" ${ak === "ok" ? "" : `disabled title="${esc(aw)}"`}>${esc(word)}</button>`;
  const teamBtn = teamList().length ? `<button type="button" class="mbtn" data-act="team-open">팀 평가용 수정안 펼치기 (${teamList().length}개)</button>` : "";
  const upBtn = `<button type="button" class="mbtn" data-srcopen="upload">내가 고친 파일 올리기</button>`;
  if (S.run) return { tone: "", title: `실행 중 — ${S.run.label || ""}`, text: "끝나면 결과가 아래에 나옵니다. 그동안 다른 버튼은 눌리지 않습니다.", btns: "", todo: `실행 중 — ${S.run.label || ""}. 끝날 때까지 기다리세요.` };
  if (S.rec && vv && vv.ok) {
    const c = vv.conclusion || {};
    if (c.tone === "good" && c.draft_design) return { tone: "warn", title: `${label} — 관문은 통과했지만 확정 전 기준 (검증 불가)`, text: "설계도가 초안이라 '고객 요구 충족' 으로 볼 수 없고 승인할 수 없습니다. ③ 에서 확정한 뒤 이 수정안을 다시 검사하세요.", btns: `<button type="button" class="mbtn primary" data-go="3">③ 설계도 확정하러 가기</button><button type="button" class="mbtn" data-act="recheck">확정했으면 다시 검사</button>`, todo: "설계도가 초안이라 승인 불가 — ③ 에서 확정한 뒤 [다시 검사]." };
    if (c.tone === "good") return { tone: "ok", title: `${label} — 배포 전 검사 통과`, text: "아래 오른쪽 그림이 이 수정안을 적용한 뒤 모습입니다 (설계도와 다른 선만 빨강). 다음 화면에서 다섯 질문의 답을 봅니다.", btns: `<button type="button" class="mbtn primary" data-go="6">다음 ▶ ⑥ 적용 판단</button>${teamBtn}`, todo: `${label} 은 배포 전 검사를 통과했습니다 — [다음 ▶ 적용 판단]. 다른 수정안과 비교하려면 펼쳐서 번호를 누르세요.` };
    return { tone: "bad", title: `${label} — 막힘: ${c.headline || c.title || ""}`, text: "막힌 이유는 아래 결과 칸에 있습니다. 다른 수정안을 고르거나, AI 에게 다시 만들게 하거나, 내가 고친 파일을 올리세요.", btns: `${aiBtn("AI 에게 다시 고치게 하기")}${teamBtn}${upBtn}`, todo: `${label} 은 막혔습니다 (이유는 결과 칸) — 다른 수정안을 고르거나 AI 에게 다시 시키세요.` };
  }
  if (S.llm.view && !S.rec) {
    const [, w] = AI_ST[S.llm.view.status] || ["", S.llm.view.status || ""];
    return { tone: "warn", title: `AI 수정 결과: ${w}`, text: `${S.llm.view.next || "검사할 수정안이 없습니다."} 팀 평가용 수정안을 고르거나 내가 고친 파일을 올려 같은 검사를 받을 수 있습니다.`, btns: `${upBtn}${teamBtn}${aiBtn("AI 에게 다시 시키기")}`, todo: `AI 수정 결과: ${w} — 내가 고친 파일을 올리거나 팀 평가용 수정안을 고르세요.` };
  }
  if (ak === "ok") return { tone: "", title: "수정안을 하나 만들거나 고르세요", text: "처음이면 [AI 에게 고치게 하기] — AI 가 고친 코드를 내고 바로 8개 관문으로 검사합니다. AI 없이 하려면 팀 평가용 수정안을 펼쳐 번호를 하나 누르거나, 내가 고친 파일을 올립니다.", btns: `${aiBtn("AI 에게 고치게 하기")}${teamBtn}${upBtn}`, todo: "[AI 에게 고치게 하기] 를 누르거나, 팀 평가용 수정안을 펼쳐 번호를 하나 누르거나, 고친 파일을 올리세요." };
  return { tone: "warn", title: "수정안을 하나 고르세요 — AI 는 지금 쓸 수 없음", text: `AI 상태: ${aw}. 팀 평가용 수정안을 펼쳐 번호를 하나 누르거나, 내가 고친 파일을 올리세요. (AI 를 쓰려면 Claude Code 설치 · 로그인 뒤 '상태 다시 확인')`, btns: `${teamBtn}${upBtn}${aiBtn("AI 에게 고치게 하기")}`, todo: `AI 는 지금 쓸 수 없음 (${aw}) — 팀 평가용 수정안을 펼쳐 번호를 누르거나 고친 파일을 올리세요.` };
}
registerTodo(5, () => { const n = s5Now(); return n ? n.todo : ""; });

register(5, () => {
  if (!S.cands) { $("#mbody").innerHTML = `<div class="mempty">불러오는 중…</div>`; return; }
  if (!sets().some((x) => x.set_id === S.target)) S.target = (sets().find((s) => s.intent_kind === "topology") || sets()[0] || {}).set_id;
  if (!S.target) {
    $("#mbody").innerHTML = `<div class="mempty"><b>먼저 ④ 에서 고칠 문제를 고르세요</b><p>④ 보안 문제 목록에서 문제를 누르고 '이 문제 고치기' 를 누르면, 그 문제가 여기의 '고칠 문제' 가 됩니다.<br>
      자동 수정 · 수정 검사는 보안 그룹(SSH · RDP 공개 등)과 IAM 일부 문제만 지원합니다 — 나머지는 탐지만.</p><div class="mnav center"><button type="button" class="mbtn primary" data-go="4">◀ ④ 보안 문제</button></div></div>`;
    return;
  }
  const noDesign = S.design && S.design.ok !== false && !S.design.exists && curSet().intent_kind !== "iam" && curSet().intent_kind !== "sg";
  const now = s5Now();
  $("#mbody").innerHTML = `${targetInfo()}${now ? guideCard(now) : ""}${noDesign ? `<div class="mcard warn small dsgwarn">고객 설계도가 아직 없어서 '고객이 원하는 통신 구조를 지키나요?' (V6) 는 <b>판정 불가</b> — 이대로는 승인할 수 없습니다.
      <button type="button" class="mbtn" data-go="3">③ 에서 설계도 확정하기</button></div>` : ""}${candBar()}
    ${S.src === "ai" ? aiPanel() : ""}${S.src === "upload" ? uploadPanel() : ""}
    ${S.run ? runPanel() : ""}
    ${S.llm.view && !S.rec && !S.run ? `<div class="mcard ai small airun"><b>AI 수정 결과</b> <span class="muted">검사할 수정안이 없어 아래 그림은 바뀌지 않음</span>${aiTimeline(S.llm.view)}</div>` : ""}
    <div class="cmpwrap">${pairHtml()}${resultHead()}${detailsHtml()}</div>`;
  const lm = leftSide().model;
  if (lm) drawMap("tDesign", lm, { simple: simpleOn() }, onPick("tDesign", null));
  if (S.rec && S.impact) drawAfter("tAfter", S.impact);
});

// 두 그림을 크게 나란히 (보기 전용)
export function zoomPair() {
  const L = leftSide();
  const im = S.impact;
  if (!L.model || !im || !im.arch_after) return;
  modal(`${L.title} · ${im.label || "수정안"} 적용 후`, `<div class="pair big"><div class="mcanvas amap"><div class="mc-head"><b>${esc(L.title)}</b></div><div class="amapwrap"><svg class="asvg" id="zDesign"></svg></div></div>
    <div class="mcanvas amap"><div class="mc-head"><b>${esc(im.label || "수정안")} 적용 후</b></div><div class="mc-leg">${im.overlay_after ? MLEG.after : MLEG.afterCode}</div><div class="amapwrap"><svg class="asvg" id="zAfter"></svg></div></div></div>`, true);
  drawMap("zDesign", L.model, { simple: simpleOn() }, null);
  const o = afterOpts(im);
  drawMap("zAfter", im.arch_after, { ...o, simple: simpleOn() }, null);
}

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
  const after = S.impact && S.impact.arch_after;
  $("#mbody").innerHTML = `${verdictBanner(vv, "배포 전(코드만, AWS 접속 없음) 검사 결과")}${stageStrip(vv)}
    <div class="lay6 one"><div class="qcol">${q.map((x, i) => `<div class="qrow ${x.tone}"><div class="qh"><em>${i + 1}</em><b>${esc(x.question)}</b><span class="mchip ${x.tone === "good" ? "ok" : x.tone === "bad" ? "bad" : x.tone === "unknown" ? "warn" : "dim"}">${esc(x.answer)}</span></div>
        ${x.note ? `<p class="qnote">${esc(x.note)}</p>` : ""}
        ${(x.problems || []).slice(0, 3).map((p) => `<div class="qprob"><b>${esc(p.what)}</b><dl><dt>왜</dt><dd>${esc(p.why)}</dd><dt>어떻게</dt><dd>${esc(p.how)}</dd></dl></div>`).join("")}
        <details><summary>자세히 (${esc(x.layers.join(" · "))})</summary><p class="small">${esc(x.summary)}</p></details></div>`).join("")}
      <div class="mcard small"><b>이번 검사에서 확인하지 않은 것</b><ul>${(vv.unchecked || []).map((u) => `<li>${esc(u)}</li>`).join("")}</ul></div>
      <div class="mnav"><a class="mbtn" href="/work#rec=${encodeURIComponent(S.rec)}">원본 증거 보기 (전문가 화면)</a></div></div>
      </div>${mapBox("tVerdict", `${esc((S.impact && S.impact.label) || "이 수정안")} 적용 후 (코드 기준 예상)`, S.impact && S.impact.overlay_after ? MLEG.after : MLEG.afterCode, curSet().intent_kind === "topology" ? fullToggle() : "", after ? "" : NO_AFTER,
        after ? "" : `<p class="mc-why">${esc((S.impact && S.impact.reason) || "수정안 plan 없음")}</p>`)}`;
  if (after) drawAfter("tVerdict", S.impact);
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
    <p class="small"><a href="/work#rec=${encodeURIComponent(S.rec)}&step=5">원본 증거 보기 (전문가 화면)</a></p></div>`;
}

function tbCommandsHtml(d) {
  const c = ((d && d.m) || {}).commands;
  if (!c) return "";
  return `<details class="mdetails tbcmd"><summary>직접 명령으로 하려면 (PowerShell · 사람)</summary><pre class="mlog">${esc([c.cd, c.profile, c.check, c.plan, c.apply, c.destroy].filter(Boolean).join("\n"))}</pre>
    <p class="small muted">이 프로그램이 하는 것: ${esc(((d.m || {}).does || []).join(" · "))}<br>하지 않는 것: ${esc(((d.m || {}).does_not || []).join(" · "))}</p></details>`;
}

register(7, () => {
  const vv = S.verdict || {};
  const pass = (vv.conclusion || {}).tone === "good";
  const c = curCand();
  const other = c && c.post && c.post.id !== S.rec ? c.post : null;
  if (tbTimer) { clearInterval(tbTimer); tbTimer = null; }
  if (!vv.testbed) {
    $("#mbody").innerHTML = `<div class="narrow">${stageStrip(vv)}<div class="mcard warn"><h3>미검증 — 이 프로젝트는 AWS 시험 환경이 없습니다</h3><p>코드 검사(배포 전)만 했고, AWS 에 반영해서 설정 · 연결을 재지 않았습니다 (실제 AWS 미검증). 이 결과를 '전체 검증 성공' 으로 보지 않습니다.</p>
      <p>⑧ 에서 승인하려면 <b>'실제 AWS 에서 확인하지 않은 것을 알고 승인'</b> 을 표시해야 하고, 그 사실이 결정 기록 · PR 제목 · 본문에 남습니다. 병합 · 적용 전에 스테이징(시험 환경)에서 확인하세요.</p>
      <p class="small muted">AWS 시험 환경 검사(V7 규칙 조회 · V8 연결 측정)는 비용 · 시간 때문에 3계층 예제에만 시험 환경(샌드박스)을 만들어 두었습니다. 운영 환경에는 반영하지 않습니다.</p></div>
      <p class="mnote">AI · 이 프로그램은 AWS 를 바꾸지 않습니다. 운영 환경 반영은 이 프로그램 밖(PR 병합 뒤 사람)입니다.</p></div>`;
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
    if (!S.dec) return { cur: 1, marks: {}, tone: !ap.ok && !ap.needs_ack ? "warn" : "", title: !ap.ok && !ap.needs_ack ? `승인 불가 — ${ap.why || ""}` : "1. 결정을 고르세요", text: !ap.ok && !ap.needs_ack ? "승인 조건을 어겨 승인은 누를 수 없습니다. 수정 요청 · 재생성 · 폐기 중 하나를 골라 이유와 함께 기록하세요." : "위 정리(해결된 것 · 남은 것 · 새 문제 · 설계 위반 · 검증 못 한 것 · AWS 시험 환경)와 맨 아래 '이 기록의 끝맺음' 을 보고, 승인 · 수정 요청 · 재생성 · 폐기 중 하나를 누르세요.", btns: jump,
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
      <ul>${items == null ? `<li class="muted">검사 못 함</li>` : items.map((x) => `<li>${esc(x)}</li>`).join("") || `<li class="muted">${esc(empty)}</li>`}</ul>${extra}</div>`;
  const dec = f.decision || {};
  const pr = S.pr || {};
  const ap = f.approve || { ok: false, why: "" };
  const rest = f.remaining_other_trivy;
  $("#mbody").innerHTML = `${verdictBanner(f, "배포 전 검사 결과 — AWS 시험 환경 결과는 아래 칸")}${stageStrip(S.verdict)}${decStepsHtml(now)}${guideCard(now)}
    <div class="final-grid">
      ${box("해결된 문제", f.resolved || [], "good", "없음")}
      ${box("남아 있는 문제", f.remaining || [], "warn", "이번 수정 대상 중 남은 것 없음", rest ? `<p class="small muted">그 밖에 이번 수정의 대상이 아닌 Trivy 지적 ${esc(rest)}개는 그대로입니다 (④ 보안 문제).</p>` : "")}
      ${box("새로 생긴 문제", f.new, "bad", "없음")}
      ${box("고객 설계 위반", f.design_violations, "bad", "없음")}
      ${box("검증하지 못한 부분", f.unverified || [], "dim", "없음")}
      <div class="mcard sum ${f.aws.status === "VERIFIED" ? "good" : "dim"}"><h4>AWS 시험 환경 검사 <small class="muted">V7 · V8 · 운영 아님</small></h4><p>${esc(f.aws.text)}</p></div></div>
    ${(f.opened || []).length || (f.closed || []).length ? `<div class="mcard flowchg"><b>통신 변화</b> <small class="muted">보안 그룹 규칙 기준 · 문제 여부는 위 칸</small>
      ${(f.opened || []).map((x) => `<span class="fc add">＋ ${esc(x)}</span>`).join("")}${(f.closed || []).map((x) => `<span class="fc gone">－ ${esc(x)}</span>`).join("")}</div>` : ""}
    <div class="lay8"><div class="mcard"><h3>결정 ${dec.decision ? chip("ok", `기록됨: ${f.decision_ko || dec.decision}`) : ""}</h3>
        <div class="decs">${DEC.map(([k, w, c, d]) => { const off = k === "APPROVED" && !ap.ok && !ap.needs_ack; return `<button type="button" class="dec ${c} ${S.dec === k ? "on" : ""}" data-dec="${k}" ${off ? `disabled title="${esc(ap.why)}"` : ""}><b>${esc(w)}</b><small>${esc(off ? "지금은 승인 불가 — 아래 이유" : k === "APPROVED" && ap.needs_ack ? "실제 AWS 미검증 확인 후 승인 → PR" : d)}</small></button>`; }).join("")}</div>
        ${!ap.ok && !ap.needs_ack ? `<p class="small warn">승인 불가: ${esc(ap.why)}</p>` : ""}
        ${ap.needs_ack && S.dec === "APPROVED" ? `<label class="ack"><input type="checkbox" id="decAck" ${form.ack ? "checked" : ""}> <span><b>실제 AWS 에서 확인하지 않은 것을 알고 승인합니다.</b> 이 프로젝트는 시험 환경이 없어 실제 적용 · 연결을 재지 못했습니다. 결정 기록 · PR 제목 · 본문에 '실제 AWS 미검증' 이 남습니다.</span></label>` : ""}
        <label class="ed-note">이유 (기록에 남음)<input id="decReason" value="${esc(form.reason || "")}" placeholder="예: 설계 일치 · 시험 환경 확인 끝"></label><label class="ed-note">결정한 사람<input id="decBy" value="${esc(form.by || "")}" placeholder="이름"></label>
        <div class="mnav"><button type="button" class="mbtn primary" data-act="decide" ${S.dec ? "" : "disabled"}>결정 기록하기</button></div>
        <p class="small muted">결정은 사람이 합니다. 프로그램은 승인 조건${f.testbed ? "(배포 전 검사 · AWS 시험 환경 검사 모두 통과)" : "(배포 전 검사 통과 + 실제 AWS 미검증 확인 표시 — 이 프로젝트는 시험 환경이 없음)"}을 어긴 승인을 거절합니다.</p></div>
      <div class="mcard prcard" id="prcard"><h3>PR (GitHub)</h3>
        ${dec.decision === "APPROVED" ? prCard(pr)
          : `<p class="muted">승인(APPROVED)을 기록하면 여기서 PR 을 만들 수 있습니다. 승인 전에는 만들지 않습니다.</p>
             <ol class="small muted prsteps"><li>승인 기록 → PR 초안(브랜치 · 제목 · 본문) 생성</li><li>PR 준비 확인 — 이 PC 의 git 상태 · 기준 브랜치의 원본이 검사한 원본과 같은지 (읽기만)</li><li>PR 미리보기 — 실행할 git 명령 확인</li><li>사람이 'PR 만들기' 입력 → 이 PC 에서 브랜치 push · PR 생성</li><li>GitHub 에서 검토 · 병합 (사람)</li></ol>`}</div></div>
    ${S.dec === "REGENERATE" || dec.decision === "REGENERATE" ? `<div class="mnav"><button type="button" class="mbtn primary" data-act="regen">AI 에게 다시 만들게 하기 ▶ (⑤ 수정안)</button></div>` : ""}
    ${closingCard(f.closing)}
    ${versionsCard(f.versions)}`;
});

// 끝맺음 세 줄 (검토 문서 11-02): 무엇을 확인했고 · 누가 어떤 결정을 했고 · 무엇이 남았는지 — 서버(product._closing)가 기록에서 문장으로 옮긴 것
function closingCard(c) {
  if (!c) return "";
  return `<div class="mcard closing"><h3>이 기록의 끝맺음</h3><dl class="kv3">
      <div><dt>확인한 것</dt><dd>${esc(c.checked || "")}</dd></div>
      <div><dt>결정</dt><dd>${esc(c.decided || "")}</dd></div>
      <div><dt>남은 것</dt><dd>${(c.left || []).length ? `<ul>${c.left.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : "없음"}</dd></div></dl></div>`;
}

// 이 판정을 만든 판 (D-37): 기록에 적힌 값만 — 프로그램 · 커밋 · 소스 지문 · 정책 · 위험도 기준표 · 설계도 · 도구. 기록에 없으면 '기록 전 판' 이라고 적는다
function versionsCard(v) {
  if (!v) return "";
  const t = v.tools || {}, d = ((v.design || {}).recorded) || v.design || {};     // 기록에 저장한 설계도 사본(버전 · 지문)
  const tool = (k) => { const x = t[k]; return x && typeof x === "object" ? (x.version || x.bin || "") : (x || ""); };
  const row = (k, val) => `<div><dt>${esc(k)}</dt><dd>${val ? esc(val) : `<span class="muted">—</span>`}</dd></div>`;
  return `<details class="mcard small vers"><summary><b>이 판정의 버전</b> <small class="muted">${v.recorded ? "검사 당시 기록" : "이 기록은 버전 기록 기능(11-02) 전에 만든 것 — 프로그램 판은 비어 있음"}</small></summary>
    <dl class="kv2">${row("프로그램", v.program ? `v${v.program}` : "")}${row("커밋", (v.commit || "").slice(0, 12))}${row("소스 지문", v.src_fingerprint)}
      ${row("정책 (허용 범위)", v.policy)}${row("위험도 기준표", String(v.rubric || "").split(" (")[0])}${row("AI 요청문 판", v.prompt)}
      ${row("설계도", d.intent_version || d.version ? `v${d.intent_version || d.version}${d.sha256 ? ` · ${String(d.sha256).slice(0, 12)}` : ""}` : "")}
      ${row("Trivy", tool("trivy"))}${row("Terraform", tool("terraform"))}</dl>
    <p class="mnote">같은 판(프로그램 · 정책 · 설계도 · 도구)으로 같은 입력을 다시 검사하면 같은 판정이 나와야 합니다. 판이 다르면 결과를 섞어 비교하지 않습니다.</p></details>`;
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
