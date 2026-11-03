// IaCPatch 배포 전 검증 — 6단계 화면 + 2D 설계도.
// 원칙: 판정은 서버(검증 엔진)가 계산한 값만 보여 준다. 이 파일은 숫자나 결과를 만들지 않는다.
import { Topology } from "./topo.js";
import { cardHtml, calHtml, policyHtml, topomapHtml, toneOf } from "./proof.js";
import { STEPS, mmss, stage2Plan } from "./flow2.js";

// ------------------------------------------------------------------ 기본 도구
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const api = {
  async get(p) {
    try {
      const r = await fetch(p, { cache: "no-store" });
      const j = await r.json().catch(() => ({}));
      if (!r.ok && !j.error) j.error = `HTTP ${r.status}`;
      return j;
    } catch (e) { return { error: "프로그램 서버 연결 실패 — 창을 닫고 다시 실행 필요" }; }
  },
  async post(p, b) {
    try {
      const r = await fetch(p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) });
      const j = await r.json().catch(() => ({}));
      j._status = r.status;
      return j;
    } catch (e) { return { error: "프로그램 서버 연결 실패", _status: 0 }; }
  },
};
const fmtTime = (iso) => { const m = String(iso || "").match(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/); return m ? `${+m[2]}/${+m[3]} ${m[4]}:${m[5]}` : String(iso || ""); };
const secs = (a, b) => (a && b ? Math.max(0, (new Date(b) - new Date(a)) / 1000) : null);
const ver = (s) => ((String(s || "").match(/\d+\.\d+\.\d+/) || [""])[0]);

// ------------------------------------------------------------------ 후보 표시 (2026-10-31, 교수 피드백 7)
// 화면은 서버가 준 표시 이름(후보 NN)과 '무엇을 바꿨나' 요약만 쓴다. 후보 id · 파일 이름 · 기대 결과는 화면에 없다 (서버도 보내지 않음).
const candName = (c) => (c && (c.label || c.id)) || "";
const recName = (rec) => (rec && (rec.candidate_label || "")) || "";
const CHECK = [["V1", "기존 보안 문제 해결", "Trivy"], ["V2", "새 보안 문제 없음", "Trivy"], ["V3", "코드 작성 오류 없음", "validate"], ["V4", "변경 예정 계산", "plan"], ["V5", "수정 허용 범위", "plan 비교"], ["V6", "고객 설계 일치 (보안 그룹 규칙)", "구조 검사"]];
const VKO = { PASS: "통과", FAIL: "실패", UNKNOWN: "판정 불가", NOT_RUN: "미실행", SKIPPED: "건너뜀", ERROR: "오류", WARN: "통과(경고)" };
const originChip = (o) => {
  const code = (o && o.code) || "";
  const cls = code === "llm" ? "ai" : code === "rule_based" ? "rb" : code === "paste" ? "paste" : "seed";
  return `<span class="chip ${cls}">${esc((o && o.label) || code || "후보")}</span>`;
};
const resultChip = (latest) => {
  if (!latest) return `<span class="chip dim">미검사</span>`;
  const lv = latest.level, st = latest.state;
  if (lv === "LIGHT_REVIEW" || lv === "FULL_REVIEW") return `<span class="chip ok">배포 전 검사 통과</span>`;
  if (st === "VALIDATION_FAILED" || st === "POLICY_BLOCKED") return `<span class="chip bad">차단</span>`;
  if (lv === "PENDING") return `<span class="chip warn">판정 불가</span>`;
  return `<span class="chip dim">${esc(latest.state_ko || st || "")}</span>`;
};

// ------------------------------------------------------------------ 상태
const S = {
  app: null, caseId: null, case: null, current: null, cands: null, setId: null,
  step: 1, visited: new Set([1]), sel: null, source: null, sourceKey: "", paste: "",
  running: null, progress: null, record: null, recordId: null, consoleMin: true, consoleAuto: false, decisionOpen: true,
  proof: null, proofRid: null, calLatest: null, jobLines: [], topomap: null, measure: null,
  walk: { i: 0, auto: true, dwell: 9000, t0: 0, key: "" },
  more: false, opsOpen: null,     // 카드의 '자세히' 펼침 · 실제 AWS 검사 화면의 '시험 환경 조작' 펼침 (null = 측정 기록이 없을 때만 펼침)
};
let T = null;

// ------------------------------------------------------------------ 화면 조각
const toast = (msg, tone = "") => { const d = document.createElement("div"); d.className = tone; d.textContent = msg; $("#toast").appendChild(d); setTimeout(() => d.remove(), 3800); };
const logEl = () => $("#log");
function logLine(s, cls = "") {
  const el = logEl(); const line = document.createElement("div");
  if (!cls) cls = /오류|실패|FAIL|error/i.test(s) ? "e" : /PASS|통과|완료/.test(s) ? "ok" : "";
  line.className = cls; line.textContent = s; el.appendChild(line);
  while (el.childNodes.length > 800) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}
const setConsoleState = (s) => { $("#consoleState").textContent = s; };
function enterAnim() { const b = $("#panelBody"); b.classList.remove("enter"); void b.offsetWidth; b.classList.add("enter"); clearTimeout(enterAnim.t); enterAnim.t = setTimeout(() => b.classList.remove("enter"), 700); }

// ------------------------------------------------------------------ 부팅
async function boot() {
  const lines = $("#bootLines");
  const say = (ok, text) => { const li = document.createElement("li"); if (!ok) li.className = "err"; li.innerHTML = `<b>${ok ? "■" : "✕"}</b>${esc(text)}`; lines.appendChild(li); };
  const fail = (text) => { say(false, text); lines.insertAdjacentHTML("afterend", `<div class="btns" style="justify-content:center"><button class="btn primary" data-action="reload">다시 시도</button></div>`); };
  const app = await api.get("/api/app");
  S.app = app;
  if (app.error) { fail("서버 응답 없음: " + app.error); return; }
  const t = app.tools || {};
  say(!!(t.trivy && t.trivy.ok), `Trivy ${t.trivy && t.trivy.ok ? ver(t.trivy.version) : "없음 — 해당 검사 미실행"}`);
  say(!!(t.terraform && t.terraform.ok), `Terraform ${t.terraform && t.terraform.ok ? ver(t.terraform.version) : "없음 — 해당 검사 미실행"}`);
  renderTools();
  const cases = await api.get("/api/cases");
  S.caseId = ((cases.cases || [])[0] || {}).id;
  await loadCase();
  if (S.case.error) { fail("사례 불러오기 실패: " + S.case.error); return; }
  say(true, `사례: ${S.case.name} · 설계 기준 경로 ${flowRows().length}개`);
  await loadTopoModel();
  T = new Topology($("#diagram"), S.topoModel);
  api.get(`/api/topomap?case=${encodeURIComponent(S.caseId)}&set=${encodeURIComponent(S.setId || "")}`).then((m) => { S.topomap = m; if (S.step === 1) render(); });
  setInterval(walkTick, 250);
  setInterval(s2Tick, 1000);
  $("#caseName").textContent = S.case.name || "";
  renderSetSwitch();
  api.get(`/api/case/current?id=${S.caseId}`).then((cur) => { S.current = cur; if (S.step === 2 || S.step === 3) { render(); applyDiagram(); } });
  await sleep(350);
  $("#boot").classList.add("done");
  gotoStep(1);
  if (app.job && app.job.running && ["review", "candidate", "review_all", "case_scan", "calibrate"].concat(STAGE2_JOBS).includes(app.job.name)) {
    S.running = { t0: Date.now() - ((Date.now() / 1000 - app.job.started) * 1000), since: 0, kind: app.job.name, label: "진행 중인 작업" };
    if (STAGE2_JOBS.includes(app.job.name)) gotoStep(5); else if (app.job.name !== "case_scan" && app.job.name !== "calibrate") gotoStep(4);
    poll();
  }
  setInterval(() => api.post("/api/heartbeat"), 30000);
  api.post("/api/heartbeat");
  // 흐름 화면에서 넘어온 경우: #rec=<기록>&step=<n> 이면 그 기록을, #submit 이면 3단계 제출 칸을 연다
  const h = new URLSearchParams(String(location.hash || "").replace(/^#/, ""));
  if (h.get("rec")) { await openRecord(h.get("rec"), false); const st = +(h.get("step") || 0); if (st >= 4 && st <= 6) gotoStep(st); }
  else if (location.hash === "#submit") { S.sel = "__paste"; S.subMode = "upload"; gotoStep(3); }
}

async function loadCase() {
  const [cs, cands] = await Promise.all([api.get(`/api/case?id=${S.caseId}`), api.get(`/api/case/candidates?id=${S.caseId}`)]);
  S.case = cs; S.cands = cands;
  if (!S.setId || !((cs.sets || []).some((s) => s.set_id === S.setId))) S.setId = ((cs.sets || [])[0] || {}).set_id;
}

function renderTools() {
  const t = (S.app && S.app.tools) || {};
  const pill = (name, v) => `<span class="pill ${v && v.ok ? "ok" : "bad"}" title="${esc((v && v.bin) || "")}">${name} ${v && v.ok ? esc(ver(v.version)) : "없음"}</span>`;
  // 화면을 단순하게: 도구가 없을 때만 빨간 표시 (버전은 설정에서)
  $("#tools").innerHTML = [["Trivy", t.trivy], ["Terraform", t.terraform]].filter(([, v]) => !(v && v.ok)).map(([n, v]) => pill(n, v)).join("");
}
function renderSetSwitch() {
  const sets = (S.case && S.case.sets) || [];
  $("#setSwitch").innerHTML = sets.length > 1 ? sets.map((s) => `<button type="button" role="tab" data-action="set" data-set="${esc(s.set_id)}" class="${s.set_id === S.setId ? "on" : ""}">${esc(s.label)}</button>`).join("") : "";
}

// ------------------------------------------------------------------ 자료 꺼내기
function curSet() { return ((S.case && S.case.sets) || []).find((s) => s.set_id === S.setId) || {}; }
function candSet(id = S.setId) { return ((S.cands && S.cands.sets) || []).find((s) => s.set_id === id) || { candidates: [] }; }
function setLabel(id) { const s = ((S.case && S.case.sets) || []).find((x) => x.set_id === id); return (s && s.label) || id || ""; }
// 이 기록이 쓴 설계 기준 (2026-10-31 부터 기록). 지금 설계도와 다르면 '기록 당시 기준' 임을 밝힌다 (교수 피드백 1)
function designLine(rec) {
  const d = (rec && rec.design) || {};
  const r = d.recorded;
  if (!r) return `<span class="small muted" style="display:block;margin-top:4px">설계 기준: 기록 없음 (10/31 이전 기록은 설계도 버전을 저장하지 않음)</span>`;
  const tag = `설계 기준 ${esc(r.intent_id || "")} v${esc(r.intent_version || "?")} · sha256 ${esc(String(r.sha256 || "").slice(0, 12))}`;
  if (d.same_as_current === false) return `<span class="small" style="display:block;margin-top:4px;color:var(--amber)">${tag} — 지금 설계도와 다름. 이 결과는 기록 당시 설계도 기준 (다시 검사하면 지금 설계도로 판정)</span>`;
  return `<span class="small muted" style="display:block;margin-top:4px">${tag} · 지금 설계도와 같음</span>`;
}
function curRows() { return (((S.current && S.current.sets) || []).find((s) => s.set_id === S.setId) || {}); }
function flowRows() { return (curSet().requirements || []).filter((r) => String(r.id).startsWith("flow:")); }
const findings = () => (S.case && S.case.findings) || {};
const trivyTargets = () => (findings().in_scope || []).filter((x) => x.set_id === S.setId);
const firstPass = (rec) => { const c = (rec && rec.conclusion) || {}; return c.tone === "good"; };
// 실제 AWS 검사 화면(5단계)에서 도는 작업 — 측정과 plan 확인
const STAGE2_JOBS = ["measure", "plan_check", "testbed_prepare", "testbed_apply"];
const stage2Live = () => !!(S.running && STAGE2_JOBS.includes(S.running.kind));
// 실제 AWS 검사 결과 이름 (기록의 post_deploy.status)
const POST_WORD = { VERIFIED: "통과", DEPLOY_FAILED: "실패", PLAN_BLOCKED: "차단", UNVERIFIED: "판정 불가" };
function stage2Status(rec) {
  if (!rec) return "none";
  if (!firstPass(rec)) return "skip";
  // 시험 환경(실제 AWS)이 없는 사례 (예: 2계층) — 실제 AWS 검사 해당 없음
  if (S.proof && S.proof.record === rec.id && S.proof.post && S.proof.post.na) return "na";
  const p = rec.post_deploy || {};
  if (p.status === "VERIFIED") return "pass";
  if (p.status) return "fail";
  return "wait";
}

// ------------------------------------------------------------------ 설계도 그림
function flowStates(rows) {
  const st = {};
  (rows || []).forEach((r) => { if (String(r.id).startsWith("flow:")) { const v = r.verdict || (r.after || {}).verdict; st[r.id.slice(5)] = v === "PASS" ? "ok" : v === "FAIL" ? "broken" : v === "UNKNOWN" ? "unknown" : "design"; } });
  return st;
}
// 3단계: 고른 후보의 구조 (그 후보의 최근 검사 기록) — 기록은 한 번 받아 둔다
const topoStates = (flows) => Object.fromEntries((flows || []).map((f) => [f.id, f.status === "ok" ? "ok" : f.status === "broken" ? "broken" : f.status === "unknown" ? "unknown" : "design"]));
function selCand() { return (S.sel && S.sel !== "__paste") ? (candSet().candidates || []).find((x) => x.id === S.sel) : null; }
function candTopo() {
  const c = selCand();
  if (!c || !c.latest) return null;
  const rec = (S.recCache || {})[c.latest.id];
  if (rec === undefined) { loadCandRec(c.latest.id); return null; }
  return rec && rec.topology && (rec.topology.flows || []).length ? { c, rec } : null;
}
function candTopoNote() {
  const c = selCand();
  if (S.sel === "__paste") return "제출한 코드의 구조는 배포 전 검사 뒤 표시 — 지금 그림은 원본 코드 구조.";
  if (!c) return "";
  if (!c.latest) return `${candName(c)}: 아직 검사 전 — 지금 그림은 원본 코드 구조. 배포 전 검사를 하면 이 후보 코드 기준 구조로 바뀜.`;
  const rec = (S.recCache || {})[c.latest.id];
  if (rec === undefined) return `${candName(c)} 검사 기록 불러오는 중…`;
  return `${candName(c)}의 마지막 검사는 구조 검사(V6) 전에 멈춤 (${(rec && rec.conclusion && (rec.conclusion.title || rec.conclusion.headline)) || "기록 없음"}) — 지금 그림은 원본 코드 구조.`;
}
async function loadCandRec(rid) {
  S.recCache = S.recCache || {};
  if (S.recCache[rid] !== undefined || (S._recLoading || {})[rid]) return;
  S._recLoading = { ...(S._recLoading || {}), [rid]: true };
  const r = await api.get(`/api/record?id=${encodeURIComponent(rid)}`);
  S.recCache[rid] = r && !r.error ? r : null;
  delete S._recLoading[rid];
  if (S.step === 3) applyDiagram();
}
// 그림 모델 — 고정 그림 없음. 지금 설계도(1~3단계 원본)는 /api/topology, 기록은 그 기록의 설계도 사본 + 후보 검사 결과 (rec.topology_model)
async function loadTopoModel() {
  const m = await api.get(`/api/topology?case=${encodeURIComponent(S.caseId)}&set=${encodeURIComponent(S.setId || "")}`);
  S.topoModel = m && !m.error ? m : { ok: false, reason: (m && m.error) || "그림 모델 없음", nodes: [], flows: [] };
  Topology.setDefault(S.topoModel);
  if (T) { T.setModel(S.topoModel); applyDiagram(); }
}
const recModel = (rec) => (rec && rec.topology_model && rec.topology_model.ok ? rec.topology_model : S.topoModel);
function applyDiagram() {
  if (!T) return;
  const proofMode = S.step === 4 || S.step === 5;
  $("#stage").classList.toggle("proofmode", proofMode);
  $("#proofPane").hidden = !proofMode;
  if (proofMode) { renderProofPane(); $("#stageNote").textContent = S.step === 4 ? "배포 전 검사 — AWS 접속 없이 이 PC 에서 코드만 검사한 결과" : "실제 AWS 검사 — 실제 AWS 시험 환경 측정 결과"; return; }
  let title = "설계 기준 — 허용 통신 경로", note = "회색 화살표: 설계 기준 경로. 이 경로만 허용, 그 외 통신은 모두 차단되어야 함.";
  if (S.step === 1) { T.setModel(S.topoModel).render({}, []); }
  else if (S.step === 3 && candTopo()) {
    // 3단계에서 고른 후보 — 그 후보를 검사한 기록의 구조 검사(V6) 결과로 그린다 (검사 없이 추측해서 그리지 않음)
    const { c, rec } = candTopo();
    const tp = rec.topology;
    T.setModel(recModel(rec)).render(topoStates(tp.flows), tp.excess || []);
    const n = (tp.excess || []).length;
    title = `${candName(c)} · 이 후보 코드의 구조`;
    note = `이전 검사 결과 (${fmtTime(c.latest.started_at)}) · 보안 그룹 규칙 기준. ` + (n ? `빨간 점선: 고객 설계에 없는 통신 ${n}곳.` : "고객 설계도와 일치.");
    // 그 검사 뒤에 설계도가 바뀌었으면 그렇다고 적는다 (예전 설계도로 그린 그림 — 새 설계도 기준은 다시 검사해야 나옴)
    if (rec.design && rec.design.same_as_current === false) note += " ※ 이전 설계도 기준 결과 — 지금 설계도 기준은 다시 검사 필요.";
  }
  else if (S.step <= 3) {
    const c = curRows();
    const why = S.step === 3 ? candTopoNote() : "";
    if (c && c.rows) {
      T.setModel(S.topoModel).render(flowStates(c.rows), (c.topology && c.topology.excess) || []);
      const n = ((c.topology && c.topology.excess) || []).length;
      title = why ? "원본 코드의 구조" : "현재 구조"; note = why || (n ? `빨간 점선: 설계 외 허용 경로 (${n}곳).` : "설계 기준과의 불일치 없음.");
    } else { T.setModel(S.topoModel).render({}, []); title = "현재 구조"; note = "원본 실행 계획(plan) 없음 — 현재 구조 표시 불가."; }
  } else if (S.record && !S.running) {
    const rec = S.record;
    const rows = (rec.requirements || []).map((r) => ({ id: r.id, verdict: (r.after || {}).verdict }));
    T.setModel(recModel(rec)).render(flowStates(rows), (rec.topology && rec.topology.excess) || []);
    title = `수정 후 구조 · ${recName(rec)}`;
    const n = ((rec.topology && rec.topology.excess) || []).length;
    note = rec.topology ? (n ? `수정 후에도 설계 외 허용 경로 ${n}곳 잔존.` : "수정 후 구조와 설계 기준 일치 (보안 그룹 규칙 기준).") : "이 기록에 구조 검사 결과 없음.";
  } else if (S.running) {
    // 실제 AWS 검사(시험 환경) 작업은 무엇을 하는 중인지 그대로 적는다 — 배포 전 검사와 헷갈리지 않게
    const k = S.running.kind;
    title = { testbed_apply: "시험 환경 반영 중", testbed_prepare: "plan 계산 중", plan_check: "plan 계산 중", measure: "측정 중" }[k] || "검사 중";
    note = { testbed_apply: "사람이 확인한 plan 그대로 AWS 시험 환경에 반영 중 (terraform apply).",
      testbed_prepare: "실제 배포 상태 기준 변경 예정 사항 계산 중 (terraform plan, 반영 없음).", plan_check: "실제 배포 상태 기준 변경 예정 사항 계산 중 (terraform plan, 반영 없음).",
      measure: "AWS 조회 · 통신 시험으로 V7·V8 측정 중 (설정 변경 없음)." }[k] || "이 PC 에서 Trivy · Terraform 실행 중.";
  }
  $("#diagramTitle").textContent = title;
  $("#stageNote").textContent = note;
}

// ------------------------------------------------------------------ 단계 이동
function canGo(n) {
  if (n <= 3) return true;
  if (n === 4) return !!(S.running || S.record);
  if (n === 5) return !S.running || stage2Live();
  return !!S.record && !S.running;
}
function gotoStep(n) {
  if (!canGo(n)) { toast(n === 4 ? "3단계에서 후보 선택 후 '배포 전 검사 시작' 필요" : "검사 결과가 있어야 이동 가능"); return; }
  S.step = n; S.visited.add(n);
  if (n !== 4 && n !== 5 && S.consoleAuto) { if (!S.consoleMin) toggleConsole(); S.consoleAuto = false; }
  render(); applyDiagram(); enterAnim();
  $("#panelBody").scrollTop = 0;
}
function renderSteps() {
  $$("#steps .step").forEach((b) => {
    const n = +b.dataset.step;
    b.classList.toggle("cur", n === S.step);
    b.classList.toggle("locked", !canGo(n));
    b.classList.toggle("done", n < S.step && S.visited.has(n));
    let badge = "";
    const rec = S.record;
    if (n === 4 && S.running && !stage2Live()) badge = `<span class="badge run">검사 중</span>`;
    else if (n === 5 && stage2Live()) badge = `<span class="badge run">진행 중</span>`;
    else if (n === 4 && rec) badge = firstPass(rec) ? `<span class="badge ok">통과</span>` : (rec.conclusion || {}).tone === "bad" ? `<span class="badge bad">차단</span>` : `<span class="badge warn">${(rec.state || {}).level === "PENDING" ? "판정 불가" : "경고"}</span>`;
    else if (n === 5 && rec && !S.running) { const s2 = stage2Status(rec); badge = s2 === "pass" ? `<span class="badge ok">통과</span>` : s2 === "fail" ? `<span class="badge bad">${(rec.post_deploy || {}).status === "PLAN_BLOCKED" ? "차단" : "실패"}</span>` : s2 === "wait" ? `<span class="badge warn">미검증</span>` : ""; }
    else if (n === 6 && rec && rec.decision) badge = `<span class="badge ok">결정 완료</span>`;
    const old = b.querySelector(".badge"); if (old) old.remove();
    if (badge) b.insertAdjacentHTML("beforeend", badge);
  });
}
function render() {
  const f = { 1: viewDesign, 2: viewCurrent, 3: viewCands, 4: viewCheck, 5: viewStage2, 6: viewDecision }[S.step];
  $("#panelBody").innerHTML = f();
  renderSteps();
  if (S.step === 3) afterCandsRender();
  if (S.step === 4 || S.step === 5) renderProofPane();
}
// 오른쪽 칸의 '자세히 보기' — 필수만 위에 두고 나머지는 여기 (열고 닫은 상태는 S.moreP 에 기억)
const moreBox = (key, label, body) => `<details class="more" data-more="${esc(key)}"${(S.moreP || {})[key] ? " open" : ""}><summary><b>자세히 보기</b><small>${esc(label)}</small></summary><div class="more-b">${body}</div></details>`;
const STEP_NAMES = ["", "고객 설계도", "지금 코드의 문제", "수정 코드", "배포 전 검사", "실제 AWS 검사", "승인 결정"];
const head = (n, title, sub) => `<div class="phead"><div class="tag">${n}단계 · ${esc(STEP_NAMES[n])}</div><h2>${title}</h2>${sub ? `<p>${sub}</p>` : ""}</div>`;

// 1. 설계도
// 프로그램의 목적 — 처음 보는 사람이 '왜 쓰는지 · 무엇을 얻는지' 를 먼저 보게 (교수 피드백 2026-10-31)
const PURPOSE = `<div class="purpose"><b>이 프로그램이 하는 일</b>
  <p>AI 가 만들었거나 사람이 고친 Terraform 수정 코드가 <b>① 기존 보안 문제를 없앴는지 ② 새 문제를 만들지 않았는지 ③ 고객 설계도의 통신 구조를 지키는지</b> 확인하고,
  결과와 증거를 사람에게 넘겨 승인 여부를 정하게 한다.</p>
  <ol class="pflow"><li>고객 설계도 확인</li><li>지금 코드의 문제 확인</li><li>수정 코드 고르기 · 제출</li><li>배포 전 검사</li><li>실제 AWS 검사</li><li>사람이 승인 결정</li></ol>
  <p class="small muted">이 프로그램은 운영 AWS 를 바꾸지 않는다 — 시험 환경 적용도 사람이 확인 창에서 [실행] 을 눌렀을 때만.</p></div>`;
function viewDesign() {
  const rows = flowRows();
  const design = curSet().design || {};
  const admin = (design.external || []).find((e) => e.id === "admin");
  let out = PURPOSE + head(1, "고객 설계도 — 허용하는 통신 경로", `고객이 허용한 통신 경로 ${rows.length}개 (가운데 그림의 화살표). 이 경로 외 통신은 모두 막혀야 함 — 수정 코드는 이 설계도를 기준으로 검사.`);
  // 설계도 버전 (D-30): 편집은 흐름 화면 ① 에서. 여기서는 지금 기준 버전만 보여 준다
  if (curSet().intent_kind === "topology") out += `<div class="keyline"><span>지금 기준</span><span class="chip keep">설계도 v${esc(curSet().design_version || 1)}</span><span class="small muted">버전 ${esc(curSet().design_versions || 1)}개 · 구성요소 · 통신을 바꾸려면 <a href="/">흐름 화면 ① 설계도 바꾸기</a></span></div>`;
  if (admin) out += `<div class="keyline"><span>관리자 SSH 허용 대역</span>${admin.cidrs_v4.map((c) => `<span class="chip">${esc(c)}</span>`).join("")}</div>`;
  out += moreBox("design", "설계 기준 경로 목록 · 코드 위치",
    rows.map((r, i) => `<div class="req" data-flow="${esc(r.id.slice(5))}"><span class="chip keep">${i + 1}</span><div class="t">${esc(r.text)}</div><span></span></div>`).join("")
    + `<div class="req"><span class="chip limit">그 외</span><div class="t">그 외 통신은 모두 차단</div><span></span></div>`
    + (admin ? `<div class="small muted" style="margin-top:8px">관리자 SSH 는 허용 대역에서만 허용. 인터넷 전체(0.0.0.0/0) 허용 금지.</div>` : "")
    + (S.topomap && S.topomap.ok ? `<div class="btns"><button class="btn" data-action="open-topomap">그림 요소별 코드 위치 보기</button></div>` : ""));
  out += `<div class="next"><button class="btn primary big" data-action="goto" data-step="2">현재 코드와 설계 기준 비교 →</button></div>`;
  return out;
}

// 2. 현재 구조
// Trivy 규칙 → 쉬운 설명 (화면 표시용 — 판정에 쓰지 않음)
const RULE_KO = { "AVD-AWS-0107": "보안 그룹의 SSH(22)·RDP(3389) 전체 IP 허용 금지", "AVD-AWS-0104": "아웃바운드 통신 전체 IP 허용",
  "AVD-AWS-0177": "DB 삭제 보호 비활성", "AVD-AWS-0133": "DB 성능 모니터링 비활성", "AVD-AWS-0010": "CloudFront 접근 로그 미설정", "AVD-AWS-0011": "CloudFront WAF 미연결",
  "AVD-AWS-0053": "로드밸런서 인터넷 공개", "AVD-AWS-0017": "로그 그룹 암호화에 고객 관리형 키(CMK) 미사용", "AVD-AWS-0178": "VPC 흐름 로그 미설정",
  "AVD-AWS-0089": "S3 접근 로그 미설정", "AVD-AWS-0132": "S3 암호화에 고객 관리형 키(CMK) 미사용" };
const portText = (p) => { const n = Number(p); const nm = { 22: "SSH", 3389: "RDP", 3306: "MySQL", 6379: "Redis", 8080: "API", 80: "HTTP", 443: "HTTPS" }[n]; return nm ? `${nm} ${n}` : String(p ?? ""); };
function issuesHtml(excess, broken, trivyRes) {
  let k = 0;
  const ex = (excess || []).map((e, i) => {
    const byTrivy = e.src === "internet" && trivyRes.some((r) => r.endsWith(`.${e.dst}`));
    return `<div class="issue" data-extra="${i}"><span class="n">${++k}</span><div><b>${esc(e.src_label)} → ${esc(e.dst_label)} (${esc(portText(e.ports))})</b><p>${esc(e.detail)}</p>
      <div class="who">${byTrivy ? `<span class="chip">Trivy 탐지</span>` : `<span class="chip warn">Trivy 미탐지</span>`}</div></div></div>`;
  }).join("");
  const br = (broken || []).map((r) => `<div class="issue off" data-flow="${esc(String(r.id).slice(5))}"><span class="n">${++k}</span><div><b>허용 규칙 없는 필수 통신: ${esc(r.text)}</b><p>${esc((r.reasons || [])[0] || "")}</p></div></div>`).join("");
  return ex + br;
}
function trivyHtml() {
  const f = findings();
  const mine = trivyTargets();
  if (f.need_scan) return `<div class="card"><div>${esc(f.error)}</div><div class="btns"><button class="btn primary" data-action="scan">원본 점검 실행 (Trivy · Terraform)</button></div></div>`;
  if (!f.ok) return `<div class="card">${esc(f.error || "점검 결과 없음")}</div>`;
  const others = f.out_of_scope || [];
  const cnt = {};
  others.forEach((x) => { const k = x.rule_id || "?"; cnt[k] = cnt[k] || { n: 0, sev: x.severity, title: x.title }; cnt[k].n += 1; });
  return mine.map((x) => `<div class="card"><div class="row"><span class="chip bad">${esc(x.severity)}</span><b class="mono">${esc(x.rule_id)}</b><span class="muted small grow">${esc(x.file)} ${esc(x.line)}행</span></div>`
      + `<div style="margin-top:6px"><b>${esc(RULE_KO[x.rule_id] || x.title || "")}</b></div><div class="small muted" style="margin-top:2px">Trivy 원문: ${esc(x.title || "")}</div></div>`).join("")
    + (others.length ? `<details class="mini-more"><summary>Trivy 기타 탐지 ${others.length}개 — 검사 범위(인바운드 규칙) 외</summary><table class="t"><thead><tr><th>규칙</th><th>내용</th><th>심각도</th><th>개수</th></tr></thead><tbody>`
      + Object.entries(cnt).map(([k, v]) => `<tr><td class="mono small">${esc(k)}</td><td class="small">${esc(RULE_KO[k] || v.title || "")}</td><td class="small">${esc(v.sev || "")}</td><td>${v.n}</td></tr>`).join("")
      + `</tbody></table></details>` : "");
}
function viewCurrent() {
  const cur = S.current;
  if (!cur) return head(2, "현재 코드와 설계 기준 비교 중…", "원본 Terraform 코드의 실행 계획(plan)과 설계 기준 비교.");
  if (!cur.ok) return head(2, "현재 코드 비교 불가", esc(cur.reason || "")) + `<div class="btns"><button class="btn primary" data-action="scan">원본 점검 실행 (Trivy · Terraform)</button></div>`;
  const s = curRows();
  const ex = (s.topology && s.topology.excess) || [];
  const broken = (s.rows || []).filter((r) => String(r.id).startsWith("flow:") && r.verdict === "FAIL");
  const n = ex.length + broken.length;
  const mine = trivyTargets();
  const trivyRes = mine.map((x) => x.resource);
  const byTrivy = (e) => e.src === "internet" && trivyRes.some((r) => r.endsWith(`.${e.dst}`));
  const missed = ex.filter((e) => !byTrivy(e));
  const flows = (s.rows || []).filter((r) => String(r.id).startsWith("flow:"));
  const open = flows.filter((r) => r.verdict === "PASS").length;
  let k = 0;
  const rowsHtml = ex.map((e) => `<div class="iss"><span class="n">${++k}</span><b>${esc(e.src_label)} → ${esc(e.dst_label)}</b><span class="muted">${esc(portText(e.ports))}</span><span class="grow"></span>${byTrivy(e) ? `<span class="chip">Trivy 탐지</span>` : `<span class="chip warn">Trivy 미탐지</span>`}</div>`).join("")
    + broken.map((r) => `<div class="iss"><span class="n">${++k}</span><b>허용 규칙 없는 필수 통신: ${esc(r.text)}</b></div>`).join("");
  return head(2, n ? `설계 기준과의 불일치 <span style="color:var(--red)">${n}곳</span>` : "설계 기준과의 불일치 없음", "원본 코드와 설계 기준 비교 결과 (AWS 접속 없이 이 PC 에서 계산).")
    + `<div class="compare"><div class="card"><b>Trivy 탐지 항목</b><div class="big">${mine.length}곳</div></div>
       <div class="card"><b>설계 기준과의 불일치</b><div class="big" style="color:${n ? "var(--red)" : "var(--green)"}">${n}곳</div></div></div>`
    + (n ? `<div class="isslist">${rowsHtml}</div>` : "")
    + moreBox("current", "Trivy 미탐지 사유 · 불일치 상세 · Trivy 탐지 원문 · 설계 기준 경로",
      (missed.length ? `<div class="small" style="line-height:1.6;margin-bottom:10px">Trivy 는 사전 정의 규칙에 해당하는 설정만 탐지. '${esc(missed[0].src_label)} → ${esc(missed[0].dst_label)}' 같은 <b>설계 외 허용 경로</b>는 해당 규칙이 없어 미탐지 — 설계 기준 비교 검사(V6)로 별도 확인.</div>` : "")
      + (n ? `<h4 class="more-h">설계 기준과의 불일치</h4>${issuesHtml(ex, broken, trivyRes)}` : "")
      + `<h4 class="more-h">Trivy 탐지 항목 (이번 수정 대상)</h4>${trivyHtml()}`
      + `<h4 class="more-h">설계 기준 경로 ${flows.length}개</h4><div class="small"><b style="color:${open === flows.length ? "var(--green)" : "var(--red)"}">${open}개 허용됨</b>${open === flows.length ? " — 필수 통신의 인바운드 허용 규칙 모두 있음" : ` — 허용 규칙 없는 필수 통신 ${flows.length - open}개`}</div>`
      + `<div class="small muted" style="margin-top:8px">이 비교는 보안 그룹 규칙 기준. 실제 통신 가능 여부는 실제 AWS 검사(V8)의 실제 AWS 통신 시험으로 확인.</div>`)
    + `<div class="next"><button class="btn primary big" data-action="goto" data-step="3">수정 후보 선택 →</button></div>`;
}

// 3. 수정 후보 — 이름('후보 NN') · 작성 주체만. 설명 줄 · 이전 결과로 묶기는 하지 않는다 (교수 피드백 10-31: 후보 밑 정답 내용 삭제).
// 결과는 검사해야 보인다: 후보를 고르면 그 후보 코드의 바뀐 줄과, 검사한 적이 있으면 그 검사 결과로 그린 구조 그림.
function viewCands() {
  const cs = candSet();
  const list = (cs.candidates || []).filter((c) => !/^(paste|upload)/.test(String(c.id)))
    .slice().sort((a, b) => String(candName(a)).localeCompare(String(candName(b)), "ko", { numeric: true }));
  const card = (c) => `<button type="button" class="cand ${S.sel === c.id ? "sel" : ""}" data-action="pick" data-cand="${esc(c.id)}">
      <div class="row">${originChip(c.origin)}</div><div class="id">${esc(candName(c))}</div></button>`;
  let out = head(3, "검사 대상 수정 후보 선택", "목록에서 선택하거나 수정한 Terraform 코드를 직접 제출. 작성 주체(사람 · AI)와 무관하게 동일한 검사 적용.")
    + `<button type="button" class="paste-wide ${S.sel === "__paste" ? "sel" : ""}" data-action="pick" data-cand="__paste"><b>✎ 수정 코드 제출</b><span>.tf 파일 여러 개 · 폴더 올리기 또는 코드 붙여넣기 — 목록과 같은 배포 전 검사 수행</span></button>`;
  if (S.sel === "__paste") out += `<div id="candDetail" class="sec"></div>`;
  // 고른 후보의 내용(바뀌는 줄 · 검사 시작)은 그 후보가 있는 줄 바로 아래에 펼친다 — 긴 목록 맨 아래까지 내려가지 않게
  const per = 2;
  out += `<div class="cgrp"><h4>수정 후보<span>${list.length}</span></h4>`;
  for (let i = 0; i < list.length; i += per) {
    const row = list.slice(i, i + per);
    out += `<div class="cands">${row.map(card).join("")}</div>`;
    if (row.some((c) => c.id === S.sel)) out += `<div id="candDetail" class="sec"></div>`;
  }
  out += `</div>`;
  return out + `<div class="small muted" style="margin-top:12px">전체 후보 순차 검사: <button class="mini" data-action="review-all">전체 검사</button> (후보당 20~60초)</div>`;
}
function afterCandsRender() {
  const box = $("#candDetail");
  if (!box) return;
  if (!S.sel) { box.innerHTML = ""; return; }
  const key = `${S.setId}/${S.sel}`;
  if (S.sourceKey !== key) {
    box.innerHTML = `<div class="card muted">파일 읽는 중…</div>`;
    const id = S.sel === "__paste" ? "" : S.sel;
    api.get(`/api/candidate/source?set_id=${encodeURIComponent(S.setId)}&id=${encodeURIComponent(id)}`).then((src) => {
      S.source = src; S.sourceKey = key;
      if (S.sel === "__paste" && !S.paste) S.paste = src.original || "";
      if (S.step === 3) { afterCandsRender(); scrollToDetail(); }
    });
    return;
  }
  const src = S.source || {};
  if (src.error) { box.innerHTML = `<div class="card">${esc(src.error)}</div>`; return; }
  if (S.sel === "__paste") {
    const mode = S.subMode || "upload";
    const tabs = `<div style="display:flex;gap:6px;margin-bottom:10px"><button class="mini ${mode === "upload" ? "on" : ""}" data-action="sub-mode" data-mode="upload">파일 · 폴더 올리기</button><button class="mini ${mode === "paste" ? "on" : ""}" data-action="sub-mode" data-mode="paste">코드 붙여넣기</button></div>`;
    if (mode === "upload") { box.innerHTML = tabs + uploadHtml(); return; }
    box.innerHTML = tabs + `<div class="small muted" style="margin-bottom:6px">${esc(src.file)} 원본 입력됨. 수정할 행만 변경 후 '이 내용으로 배포 전 검사 시작' 실행. (수정 위치: ${esc(src.resource)} ${esc(src.line)}행 부근)</div>
      <textarea class="code" id="pasteBox" spellcheck="false">${esc(S.paste)}</textarea>
      <div class="btns"><button class="btn" data-action="paste-reset">원본으로 복원</button><button class="btn primary" data-action="run-paste">이 내용으로 배포 전 검사 시작</button></div>`;
    return;
  }
  const c = (candSet().candidates || []).find((x) => x.id === S.sel) || {};
  const diffHtml = src.generated_at_run ? `<div class="card small">${esc(src.note || "검사 시 생성")}</div>` : lineDiff(src.original || "", src.candidate || "");
  // 사람이 적은 후보 설명은 보여 주지 않는다 — 코드에서 자동으로 센 '바뀐 블록'과 바뀐 줄만
  const chg = c.changes && c.changes.text ? `<div class="small muted" style="margin:-4px 0 8px">바뀐 블록: ${esc(c.changes.text)}</div>` : "";
  box.innerHTML = `<h3>${esc(candName(c))} — 변경 행</h3>${chg}${diffHtml}
    <div class="next"><button class="btn primary big" data-action="run" data-cand="${esc(S.sel)}">배포 전 검사 시작</button>
    ${c.latest ? `<div style="margin-top:8px;text-align:center"><button class="mini" data-action="open-record" data-rid="${esc(c.latest.id)}">이전 결과 보기 (${esc(fmtTime(c.latest.started_at))})</button></div>` : ""}</div>
    ${moreBox("cand", "후보 출처 · 원본 포함 재검사", `<div class="small"><div class="row">${originChip(c.origin)}<span class="grow">${esc((c.origin && c.origin.desc) || "")}</span></div>
      <div style="margin-top:8px">배포 전 검사는 이 PC 의 Trivy · Terraform 으로 실행 (AWS 접속 없음).</div>
      <div style="margin-top:8px"><button class="mini" data-action="run-fresh" data-cand="${esc(S.sel)}">원본 포함 재검사 (이전 결과 미사용)</button></div></div>`)}`;
}
// ------------------------------------------------------------------ 수정 코드 제출 (.tf 여러 개 · 폴더) — 2026-10-31, 교수 피드백 7
// 브라우저가 파일을 읽어 서버에 보낸다. 서버는 파일별 처리(검사에 사용 · 원본과 같음 · 검사에 안 씀 + 이유)를 돌려주고,
// 검사 시작 시 저장소 원본 폴더가 아닌 별도 폴더에 저장해 그 사본으로 검사한다 (web/submission.py). 경로는 그대로 보여 준다.
const SUB_ST = { changed: ["검사에 사용 · 바뀐 파일", "ok"], new: ["검사에 사용 · 원본에 없는 파일", "bad"], same: ["원본과 같음 · 제외", "dim"],
  excluded: ["검사에 안 씀", "dim"], rejected: ["받지 않음", "bad"] };
function uploadHtml() {
  const u = S.upload || {};
  const chk = u.check;
  let out = `<div class="small muted" style="margin-bottom:8px;line-height:1.6">원본 폴더에서 고친 .tf 파일을 올리면 원본과 비교해 <b>바뀐 파일만</b> 검사. 올린 파일은 IaCPatch 작업 폴더에 따로 보관 — 원본 폴더 · AWS 는 바뀌지 않음.
    Trivy · Terraform 실행 전에 '실행 전 안전 점검'(모듈 · 외부 조회 · 파일 읽기 함수 차단)을 먼저 실행.</div>
    <div class="btns" style="justify-content:flex-start"><label class="btn">파일 고르기 (.tf 여러 개)<input type="file" id="subFiles" multiple hidden></label><label class="btn">폴더 고르기<input type="file" id="subDir" webkitdirectory directory multiple hidden></label></div>`;
  if (u.reading) return out + `<div class="card muted">파일 읽는 중…</div>`;
  if (!chk) return out;
  if (chk.error && !(chk.files || []).length) return out + `<div class="card">${esc(chk.error)}</div>`;
  const rows = chk.files || [];
  out += `<div class="small" style="margin-top:10px">제출 ${rows.length}개 ${u.folder ? "(폴더)" : "(파일)"}${chk.summary ? ` · 바뀐 곳: ${esc(chk.summary)}` : ""}</div>`;
  out += `<div style="overflow-x:auto"><table class="t" style="margin-top:6px"><thead><tr><th>경로</th><th>처리</th><th>이유</th><th>크기</th></tr></thead><tbody>`
    + rows.map((f) => { const st = SUB_ST[f.status] || [f.status, ""]; return `<tr><td class="mono small">${esc(f.path)}</td><td><span class="chip ${st[1]}">${esc(st[0])}</span></td><td class="small">${esc(f.reason || "")}</td><td class="small mono">${f.bytes != null ? esc(Number(f.bytes).toLocaleString()) : ""}</td></tr>`; }).join("")
    + `</tbody></table></div>`;
  const used = rows.map((f, i) => ({ f, i })).filter(({ f }) => f.status === "changed" || f.status === "new");
  if (used.length > (chk.max_patch_files || 2)) out += `<div class="banner warn" style="margin-top:8px"><p>바뀐 파일 ${used.length}개 — 팀 정책상 한 번에 바꿀 수 있는 파일은 ${esc(chk.max_patch_files)}개. 이대로 검사하면 정책 확인에서 차단되고 그 결과가 기록됨.</p></div>`;
  used.forEach(({ f, i }) => {
    const sub = ((u.files || [])[i] || {}).content || "";
    const orig = (chk.originals || {})[f.used_as];
    out += `<h4 class="more-h">${esc(f.path)} — ${orig != null ? "변경 행" : "새 파일 (원본에 없음)"}</h4>${orig != null ? lineDiff(orig, sub) : `<div class="card small mono" style="white-space:pre-wrap;max-height:240px;overflow:auto">${esc(sub)}</div>`}`;
  });
  if (chk.error) out += `<div class="card" style="margin-top:8px">${esc(chk.error)}</div>`;
  return out + `<div class="next"><button class="btn primary big" data-action="run-upload" ${chk.ok ? "" : "disabled"}>이 파일들로 배포 전 검사 시작</button></div>`;
}
async function readPicked(input, folder) {
  const all = Array.from(input.files || []);
  if (!all.length) return;
  S.upload = { reading: true, folder, files: [] }; afterCandsRender();
  const files = [], hidden = {};
  for (const f of all) {
    const path = folder ? (f.webkitRelativePath || f.name) : f.name;
    const parts = path.split("/");
    const inner = folder ? parts.slice(1) : parts;
    const h = inner.findIndex((x) => x.startsWith("."));
    if (folder && h >= 0 && h < inner.length - 1) { const k = inner.slice(0, h + 1).join("/"); hidden[k] = (hidden[k] || 0) + 1; continue; }   // .terraform/ 같은 숨김 폴더는 묶어서 한 줄 (고른 폴더 기준 경로)
    const readIt = /\.tf$/i.test(path) && inner.length === 1 && f.size <= 1000000;
    let content = null;
    if (readIt) { try { content = await f.text(); } catch (e) { content = null; } }
    files.push({ path, content, size: f.size });
  }
  Object.entries(hidden).forEach(([k, n]) => files.push({ path: k + "/", content: null, aggregated: true, count: n }));
  const chk = await api.post("/api/submission/check", { set_id: S.setId, files, folder });
  S.upload = { folder, files, check: chk };
  input.value = "";
  afterCandsRender();
}

function scrollToDetail() { const d = $("#candDetail"); if (d) d.scrollIntoView({ behavior: "smooth", block: "start" }); }

function lineDiff(a, b) {
  const A = a.replace(/\r/g, "").split("\n"), B = b.replace(/\r/g, "").split("\n");
  const n = A.length, m = B.length;
  if (n * m > 4_000_000) return `<div class="card">파일 크기 초과 — 미리보기 축소</div>`;
  const Lt = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) Lt[i][j] = A[i] === B[j] ? Lt[i + 1][j + 1] + 1 : Math.max(Lt[i + 1][j], Lt[i][j + 1]);
  const ops = []; let i = 0, j = 0;
  while (i < n && j < m) { if (A[i] === B[j]) { ops.push(["c", A[i]]); i++; j++; } else if (Lt[i + 1][j] >= Lt[i][j + 1]) { ops.push(["r", A[i]]); i++; } else { ops.push(["a", B[j]]); j++; } }
  while (i < n) ops.push(["r", A[i++]]); while (j < m) ops.push(["a", B[j++]]);
  const keep = ops.map(() => false);
  ops.forEach((o, k) => { if (o[0] !== "c") for (let d = -2; d <= 2; d++) if (ops[k + d]) keep[k + d] = true; });
  if (!keep.some(Boolean)) return `<div class="card">원본과 동일 — 변경 행 없음</div>`;
  let out = "", gap = false;
  ops.forEach((o, k) => { if (keep[k]) { out += `<div class="${o[0]}">${esc(o[1])}</div>`; gap = false; } else if (!gap) { out += `<div class="gap">  ⋯</div>`; gap = true; } });
  return `<div class="diff">${out}</div>`;
}
function unifiedDiff(text) {
  const lines = String(text || "").replace(/\r/g, "").split("\n").filter((l) => !l.startsWith("---") && !l.startsWith("+++"));
  if (!lines.some((l) => l.startsWith("+") || l.startsWith("-"))) return `<div class="card muted small">변경 행 정보 없음</div>`;
  return `<div class="diff">${lines.map((l) => l.startsWith("@@") ? `<div class="gap">${esc(l)}</div>` : l.startsWith("+") ? `<div class="a">${esc(l.slice(1))}</div>` : l.startsWith("-") ? `<div class="r">${esc(l.slice(1))}</div>` : `<div class="c">${esc(l.slice(1))}</div>`).join("")}</div>`;
}

// 4. 배포 전 검사 — 탐지 방식 보기 (오른쪽: 단계 목록·조작, 가운데: 카드)
const LAYER_LABEL = { V1: ["기존 보안 문제가 해결됐나요?", "Trivy 재검사"], V2: ["수정하면서 새로운 문제가 생겼나요?", "Trivy 수정 전 · 후 비교"],
  V3: ["Terraform 코드가 올바르게 작성됐나요?", "terraform validate"], V4: ["이 코드를 실행하면 무엇이 변경되나요?", "terraform plan (AWS 적용 안 함)"],
  V5: ["허용하지 않은 부분까지 수정했나요?", "팀 정책 허용 목록과 비교"], V6: ["고객이 원하는 통신 구조를 유지하나요?", "보안 그룹 규칙 ↔ 고객 설계도 (실제 연결은 V8)"],
  임시: ["시험 환경 반영", "실제 AWS 에 apply (사람 실행)"], V7: ["실제 AWS에도 예상대로 적용됐나요?", "AWS 보안 그룹 조회"], V8: ["실제 연결과 차단이 정상적으로 동작하나요?", "시험 환경 통신 시험"] };
// 단계 표시 이름 — 기록의 단계 키(임시)는 그대로 두고 화면에서만 바꿔 보여 준다
const LAYER_TAG = { 임시: "반영" };
function jobIsReview() { return !!(S.running && S.running.kind === "review"); }
function walkItems() {
  if (S.step === 5) {
    const pc = (S.recordId && S.proof && S.proof.post ? S.proof.post.cards : (S.baseline && S.baseline.cards)) || [];
    return pc.map((c) => ({ key: c.layer, label: c.name, sub: (LAYER_LABEL[c.layer] || [])[1], done: c.status === "done", verdict: c.verdict, word: c.verdict_ko, card: c }));
  }
  const cards = (S.proof && S.proof.cards) || [];
  const cal = (S.proof && S.proof.calibration) || (S.calLatest ? { ...S.calLatest, _detached: !jobIsReview() && !!S.proof } : null);
  const items = [{ key: "0", label: "검증 도구 사전 점검", sub: "기대 결과가 고정된 점검 시료로 도구 동작 확인", done: !!cal, cal }];
  const bb = S.proof && S.proof.blocked_before;
  if (bb) items.push({ key: "정책", label: "정책 확인", sub: "검사 전 — 금지 문구·허용 범위", done: true, verdict: "FAIL", word: "차단", blocked: bb });
  if (cards.length) cards.forEach((c) => items.push({ key: c.layer, label: c.name, sub: (LAYER_LABEL[c.layer] || [])[1], done: c.status === "done", verdict: c.verdict, word: c.verdict_ko, card: c }));
  else ["V1", "V2", "V3", "V4", "V5", "V6"].forEach((k) => items.push({ key: k, label: LAYER_LABEL[k][0], sub: LAYER_LABEL[k][1], done: false }));
  return items;
}
function walkReset(i = 0) { S.walk.i = i; S.walk.t0 = Date.now(); S.walk.shown = null; }
function itemWord(it, k) {
  const live = jobIsReview() || stage2Live();
  if (it.key === "0") { if (!it.cal) return [live ? "검사 중" : "—", live ? "run" : "wait"]; const s = it.cal.summary || {}; const ok = s.trivy_total > 0 && s.trivy_correct === s.trivy_total && s.cidr_mismatches === 0 && s.validate_ok; return [ok ? "통과" : "경고", ok ? "ok" : "warn"]; }
  if (!it.done && it.card && it.card.skipped && !live) return [it.card.skipped === "case" ? "해당 없음" : "미실행", "wait"];
  if (!it.done && S.proof && S.proof.blocked_before && !live) return ["미실행", "wait"];
  if (!it.done) return [live ? (k === firstPending() ? "검사 중" : "대기") : "기록 없음", live && k === firstPending() ? "run" : "wait"];
  return [it.word || VKO[it.verdict] || it.verdict, toneOf(it.verdict)];
}
function firstPending() { return walkItems().findIndex((it) => !it.done); }
function walkListHtml() {
  return `<div class="walk">` + walkItems().map((it, k) => { const [w, tn] = itemWord(it, k); return `<button type="button" class="wk ${k === S.walk.i ? "cur" : ""}" data-action="walk" data-i="${k}"><span class="k">${esc(LAYER_TAG[it.key] || it.key)}</span><span class="tx"><b>${esc(it.label)}</b><small>${esc(it.sub || "")}</small></span><span class="s ${tn}">${esc(w)}</span></button>`; }).join("") + `</div>`;
}
function walkCtlHtml() {
  return `<div class="walkctl"><button class="mini" data-action="walk-prev">← 이전</button><button class="mini ${S.walk.auto ? "" : "on"}" data-action="walk-auto">${S.walk.auto ? "자동 넘김 멈춤" : "자동 넘김"}</button><button class="mini" data-action="walk-next">다음 →</button></div>`;
}
function renderWalkList() { const b = $("#walkList"); if (b) b.innerHTML = walkListHtml(); }
// 사전 점검 로그 줄 (이전 빌드의 '탐지기 점검' 로그도 함께 인식)
const CAL_HEAD = /^(검증 도구 사전 점검|탐지기 점검)/, CAL_END = /^(검증 도구 사전 점검|탐지기 점검) (끝|완료)|결과 재사용/;
function calLines() {
  const out = []; let on = false;
  for (const l of S.jobLines) { if (CAL_HEAD.test(l)) on = true; if (on && (CAL_HEAD.test(l) || /^ {2}/.test(l))) out.push(l); if (CAL_END.test(l)) on = false; }
  return out.slice(-24);
}
function walkTick() {
  if (!(S.step === 4 || S.step === 5)) return;
  const items = walkItems();
  const w = S.walk;
  const cur = items[w.i];
  if (!cur) return;
  const live = jobIsReview() || (S.step === 5 && stage2Live());
  const bar = $("#pfBar");
  if (!cur.done && live) { w.t0 = Date.now(); if (bar) bar.style.width = "0%"; return; }
  if (S.more) { w.t0 = Date.now(); if (bar) bar.style.width = "0%"; return; }   // '자세히'를 열어 둔 동안은 넘기지 않는다
  const el = Date.now() - w.t0;
  if (bar) bar.style.width = `${w.auto ? Math.min(100, (el / w.dwell) * 100) : 0}%`;
  if (w.auto && el >= w.dwell && w.i < items.length - 1) { w.i += 1; w.t0 = Date.now(); renderProofPane(); renderWalkList(); }
}
function renderProofPane() {
  const box = $("#proofPane");
  if (!box || box.hidden) return;
  const items = walkItems();
  if (!items.length) {
    const html = `<div class="pf-h"><span class="pf-l">반영</span><div class="grow"><b>측정 기록 없음</b><small>시험 환경 반영(apply) 후 측정 실행 시 반영 · V7 · V8 결과 표시.</small></div><span class="pf-v wait">—</span></div>`;
    if (box._last !== html) { box.innerHTML = html; box._last = html; }
    return;
  }
  if (S.walk.i >= items.length) S.walk.i = items.length - 1;
  const it = items[S.walk.i];
  if (box._ident !== `${S.step}:${S.walk.i}:${S.proofRid}`) S.more = false;   // 다른 카드로 넘어가면 '자세히'는 접힌 채로
  const live = jobIsReview() || stage2Live();
  let html;
  if (it.key === "0") html = calHtml(it.cal, { running: live, lines: calLines(), dwell: 1, more: S.more });
  else if (it.key === "정책") html = policyHtml(it.blocked, S.proofRid || "", { more: S.more });
  else html = cardHtml(it.card || { layer: it.key, name: it.label, question: it.sub, status: "pending", method: { steps: [], commands: [] } }, { running: live && !it.done, rid: S.proofRid || "", dwell: 1, more: S.more });
  const ident = `${S.step}:${S.walk.i}:${S.proofRid}`;
  if (html === box._last) return;
  const keep = box._ident === ident ? box.scrollTop : 0;
  const barW = ($("#pfBar") || {}).style ? $("#pfBar").style.width : "0%";
  box.innerHTML = html; box._last = html; box._ident = ident; box.scrollTop = keep;
  const nb = $("#pfBar"); if (nb && keep) nb.style.width = barW;
  $$("svg[data-diagram]", box).forEach((svg) => { const c = it.card; if (c && c.diagram) { try { new Topology(svg, recModel(S.record)).render(c.diagram.flows || {}, c.diagram.excess || []); } catch (e) { /* 그림 실패는 무시 */ } } });
}

// ------------------------------------------------------------------ 결과 화면 조각 (2026-10-31)
function flowMini(f) {
  return `<div class="fmini"><span class="node">${esc(f.src)}</span><span class="arrow ${f.missing ? "off" : "bad"}">${f.missing ? "✕" : "→"} ${esc(f.ports)}</span><span class="node">${esc(f.dst)}</span>
    <span class="chip ${f.missing ? "dim" : "bad"}">${f.missing ? "허용 규칙 없음" : "고객 설계에 없는 통신"}</span></div>`;
}
function problemsHtml(rec) {
  const ps = rec.problems || [];
  if (!ps.length) return "";
  return `<div class="sec"><h3>발견된 문제 ${ps.length}개</h3>` + ps.map((p, i) => `<div class="prob">
      <div class="ph"><span class="n">${i + 1}</span><span class="chip bad">${esc(p.tag)}</span>${p.layer ? `<button class="mini" data-action="goto-layer" data-layer="${esc(p.layer)}" title="이 판정의 증거 카드 보기">${esc(p.layer)} 증거</button>` : ""}</div>
      <p class="what">${esc(p.what)}</p>${p.flow ? flowMini(p.flow) : ""}
      <dl><dt>왜 문제인가요?</dt><dd>${esc(p.why)}</dd><dt>어떻게 해결하나요?</dt><dd>${esc(p.how)}</dd>${p.where ? `<dt>위치</dt><dd class="mono small">${esc(p.where)}</dd>` : ""}</dl></div>`).join("") + `</div>`;
}
function nextStepsHtml(rec) {
  const ok = firstPass(rec);
  const btns = ok
    ? `<button class="btn primary" data-action="goto" data-step="5">실제 AWS 검사로 →</button>`
    : `<button class="btn primary" data-action="resubmit">수정 코드 다시 제출</button><button class="btn" data-action="goto" data-step="3">다른 후보 선택</button>`;
  const txt = ok ? "배포 전 검사는 코드만 본 결과. 실제 AWS 에 적용했을 때 설계대로 연결 · 차단되는지 확인해야 승인 결정을 할 수 있음."
    : "위 '어떻게 해결하나요?' 대로 고친 코드를 다시 제출하면 처음부터 다시 검사함. 이 결과는 기록으로 그대로 남음.";
  return `<div class="sec"><h3>다음 할 일</h3><p class="small" style="margin:0 0 8px;line-height:1.6">${esc(txt)}</p><div class="btns" style="justify-content:flex-start">${btns}</div></div>`;
}
function uncheckedHtml(rec) {
  const xs = rec.unchecked || [];
  if (!xs.length) return "";
  return `<div class="sec unchecked"><h3>이번 검사에서 확인하지 않은 것</h3><ul>${xs.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
    <p class="small muted" style="margin:6px 0 0">여기 적힌 것은 통과한 것이 아니라 검사하지 않은 것.</p></div>`;
}

function viewCheck() {
  const rec = S.record;
  const running = jobIsReview();
  if (!running && !rec) return head(4, "검사 결과 없음", "3단계에서 후보 선택 후 배포 전 검사 시작.");
  const r = S.running || {};
  let out = running
    ? head(4, "배포 전 검사 중", `${esc(r.label || "")}<br>이 PC 에서 Trivy · Terraform 실행 중. AWS 접속 없음.`)
    : head(4, `배포 전 검사 · ${esc(recName(rec))}`, `${originChip(rec.candidate && rec.candidate.origin)} <span class="muted small">${esc(fmtTime(rec.state && rec.state.started_at))}</span>${designLine(rec)}`);
  if (running) out += `<div class="card row" style="margin-bottom:10px"><span class="muted small grow">경과</span><span class="bigtime" id="bigtime" style="font-size:24px">${((Date.now() - (r.t0 || Date.now())) / 1000).toFixed(1)}<small>초</small></span></div>`;
  if (rec && !running) {
    const c = rec.conclusion || {};
    const tone = c.tone === "good" ? "good" : c.tone === "bad" ? "bad" : "warn";
    // 결과 화면 (교수 피드백 2026-10-31): 결론 한 문장 → 발견된 문제(무엇 · 왜 · 어떻게) → 다음 할 일 → 확인하지 않은 것
    out += `<div class="banner ${tone} result" style="margin-bottom:12px"><span class="rstat ${tone}">${esc(c.status || c.headline || "")}</span>
      <h3>${esc(c.title || c.headline || "")}</h3><p>${esc(c.reason || "")}</p>${riskInline(rec)}</div>`;
    out += problemsHtml(rec) + nextStepsHtml(rec) + uncheckedHtml(rec);
  }
  out += `<div class="sec"><h3>검사 단계</h3><div id="walkList">${walkListHtml()}</div>${walkCtlHtml()}</div>`;
  if (rec && !running) {
    const sub = rec.submission;
    const subHtml = sub && (sub.files || []).length
      ? `<h4 class="more-h">제출한 파일 ${sub.files.length}개 (처리 결과 그대로)</h4><div style="overflow-x:auto"><table class="t"><thead><tr><th>경로</th><th>처리</th><th>이유</th><th>sha256</th></tr></thead><tbody>`
        + sub.files.map((f) => { const st = SUB_ST[f.status] || [f.status, ""]; return `<tr><td class="mono small">${esc(f.path)}</td><td><span class="chip ${st[1]}">${esc(st[0])}</span></td><td class="small">${esc(f.reason || "")}</td><td class="mono small">${esc(String(f.sha256 || "").slice(0, 12))}</td></tr>`; }).join("")
        + `</tbody></table></div>` : "";
    out += moreBox("check", "변경 코드 · 위험도 점수 근거 · 기록 번호" + (subHtml ? " · 제출 파일" : ""),
      subHtml + `<h4 class="more-h">변경 코드 (diff)</h4>${unifiedDiff(rec.diff)}` + `<h4 class="more-h">위험도 점수 근거</h4>${riskHtml(rec)}`
      + `<div class="small muted" style="margin-top:8px">기록 번호 ${esc(rec.id)} · 기록 폴더 data/reviews/${esc(rec.id)}${rec.candidate_sha256 ? ` · 후보 코드 sha256 ${esc(String(rec.candidate_sha256).slice(0, 12))}` : ""}</div>`)
      // 배포 전 검사를 통과한 후보만 실제 AWS 검사로 보낸다 — 막힌 후보는 다른 후보를 고르는 쪽이 다음 할 일
      + `<div class="btns"><button class="btn" data-action="open-report" data-rid="${esc(rec.id)}">증거 보고서</button>`
      + (firstPass(rec)
        ? `<button class="btn primary" data-action="goto" data-step="5">실제 AWS 검사로 →</button>`
        : `<button class="btn primary" data-action="goto" data-step="3">← 다른 후보 선택</button>`) + `</div>`;
  }
  return out;
}

// 결론 상자 안 한 줄: '위험도 중간 (3점) → 사람 상세 검토 · 승인 후 PR'
function riskInline(rec) {
  const r = rec.risk || {};
  if (!r.level) return "";
  const lvl = (rec.state || {}).level;
  // 차단 · 판정 불가 기록에서 '위험도 낮음'(초록)이 결론과 반대로 읽히지 않게 — 회색 칩 + 등급과 관계없이 차단됐다고 적는다
  if (lvl === "BLOCKED" || lvl === "PENDING") {
    return `<div class="risk-in"><span class="chip">변경 위험도 ${esc(r.level_ko || r.level)} · ${esc(r.score ?? "-")}점</span><span>${esc("→ " + LEVEL_MEANING[lvl] + (lvl === "BLOCKED" ? " (위험도와 관계없이 검사 실패 · 정책 위반이면 차단)" : ""))}</span></div>`;
  }
  return `<div class="risk-in"><span class="chip ${r.level === "LOW" ? "ok" : r.level === "HIGH" ? "bad" : "warn"}">변경 위험도 ${esc(r.level_ko || r.level)} · ${esc(r.score ?? "-")}점</span><span>${esc(LEVEL_MEANING[lvl] ? "→ " + LEVEL_MEANING[lvl] : "")}</span></div>`;
}
// 위험도 한 줄 — 사전에 정한 점수표로 계산한 값 (AI 가 정하지 않음). 같은 항목이 두 근거(plan·코드 글자)로 나오면 큰 점수 하나만.
const RISK_KO = { LOW: "낮음", MEDIUM: "중간", HIGH: "높음" };
const LEVEL_MEANING = { LIGHT_REVIEW: "사람 확인 후 PR", FULL_REVIEW: "사람 상세 검토 · 승인 후 PR", REPORT_ONLY: "자동 수정 금지 — 보고서만 생성 (사람이 직접 수정)",
  BLOCKED: "차단 — 승인 불가", PENDING: "판정 불가 — 승인 불가" };
function riskHtml(rec) {
  const r = rec.risk || {};
  if (!r.level) return "";
  const seen = {};
  (r.factors || []).forEach((f) => { if (!seen[f.name] || (f.points || 0) > (seen[f.name].points || 0)) seen[f.name] = f; });
  const val = (v) => (v === true ? "있음" : v === false ? "없음" : Array.isArray(v) ? `${v.length}개` : v);
  const fs = Object.values(seen).filter((f) => f.points).map((f) => `${f.name} ${val(f.value)} (+${f.points}점)`);
  const lvl = (rec.state || {}).level;
  return `<div class="riskline"><div class="row"><span class="chip ${r.level === "LOW" ? "ok" : r.level === "HIGH" ? "bad" : "warn"}">위험도 ${esc(r.level_ko || r.level)} · ${esc(r.score ?? "-")}점</span>`
    + `<span class="small grow">${esc(fs.join(" · ") || "가산 항목 없음")}</span></div>`
    + `<div class="small muted" style="margin-top:4px">→ ${esc(LEVEL_MEANING[lvl] || "")}${LEVEL_MEANING[lvl] ? " · " : ""}점수는 사전 정의 기준표로 계산 (AI 미관여)</div></div>`;
}

// 5. 실제 AWS 검사 — 실제 AWS 시험 환경. 진행 안내 카드가 다음 작업 하나만 보여 주고, 개별 조작은 '수동 조작'에 접어 둔다.
// 반영(apply · destroy)은 언제나 확인 창에서 사람이 plan 을 검토하고 [실행] 을 눌러야 한다 (D-19). 측정은 읽기 전용.
function s2Post() { return (S.recordId && S.proof && S.proof.post) || (S.baseline ? { before: S.baseline.before, after: {} } : {}); }
const _mkey = (x) => JSON.stringify({ ...x, since_apply_s: null, settled: null, _at: null });
function loadMeasure(quiet = false) {
  if (S._mload) return;
  S._mload = true;
  const rid = S.recordId || "";
  api.get(`/api/measure/setup?id=${encodeURIComponent(rid)}`).then((x) => {
    S._mload = false;
    x._rid = rid; x._at = Date.now();
    const old = S.measure;
    S.measure = x;
    if (S.step !== 5) return;
    // 주기 갱신: 버튼 상태가 바뀌지 않았으면 안내 카드만 다시 그린다 (입력칸·펼침 상태 유지)
    if (quiet && old && old._rid === rid && _mkey(old) === _mkey(x)) { refreshGuide(); return; }
    render();
  });
}
async function reloadStage2() {
  if (S.recordId) {
    const pr = await api.get(`/api/proof?id=${encodeURIComponent(S.recordId)}`); if (!pr.error) S.proof = pr;
    const rec = await api.get(`/api/record?id=${encodeURIComponent(S.recordId)}`); if (!rec.error) S.record = rec;
  } else { const b = await api.get("/api/proof/baseline"); if (!b.error) S.baseline = b; }
  const rid = S.recordId || "";
  const ms = await api.get(`/api/measure/setup?id=${encodeURIComponent(rid)}`);
  ms._rid = rid; ms._at = Date.now(); S.measure = ms;
  return ms;
}
function s2PlanNow() {
  const rec = S.record;
  const m = S.measure && S.measure._rid === (S.recordId || "") ? S.measure : null;
  return stage2Plan({ m, rec, passed: !!(rec && firstPass(rec)), post: s2Post(), running: stage2Live() ? S.running : null, now: Date.now(), fetchedAt: (m && m._at) || Date.now() });
}
function s2GuideHtml(p) {
  // ✓ = 단계 진행 완료 (판정 결과 아님) · ✕ = 차단 · – = 미실행
  const steps = STEPS.map((s, i) => {
    const n = i + 1, mk = (p.marks || {})[n];
    const cls = mk === "bad" ? " bad" : mk === "skip" ? " skip" : n < p.cur ? " past" : n === p.cur ? " cur" : "";
    return `<li class="s2c${cls}" title="${mk === "bad" ? "차단" : mk === "skip" ? "미실행" : n < p.cur ? "진행 완료" : n === p.cur ? "현재 단계" : "대기"}"><span>${mk === "bad" ? "✕" : mk === "skip" ? "–" : n < p.cur ? "✓" : n}</span><b>${esc(s)}</b></li>`;
  }).join("");
  const btn = (b, main) => (b ? `<button class="btn${b.danger ? " danger" : main ? " primary" : ""}" data-action="${esc(b.act)}"${b.kind ? ` data-kind="${esc(b.kind)}"` : ""}${b.disabled ? " disabled" : ""}>${esc(b.label)}</button>` : "");
  const w = p.wait;
  const wait = w ? `<div class="s2wait"><span>${w.kind === "before" ? "수정 전" : "수정 후"} 측정까지 남은 시간</span><b>${mmss(w.left)}</b><i style="width:${Math.max(0, Math.min(100, (1 - w.left / w.total) * 100)).toFixed(1)}%"></i></div>` : "";
  const measureNext = !!w || !!(p.primary && p.primary.act === "s2-measure");
  const auto = !measureNext ? "" : S.s2auto
    ? `자동 측정 사용 — 대기 종료 시 측정 시작 (읽기 전용) <button class="mini" data-action="s2-auto-off">사용 안 함</button>`
    : `<button class="mini" data-action="s2-auto-on">대기 종료 시 자동 측정</button>`;
  return `<div class="s2card${p.tone ? " " + p.tone : ""}"><ol class="s2steps">${steps}</ol><h3>${esc(p.title)}</h3><p>${esc(p.text)}</p>${wait}`
    + (p.primary || p.secondary.length ? `<div class="btns">${btn(p.primary, true)}${p.secondary.map((b) => btn(b, false)).join("")}</div>` : "")
    + (p.primary && p.primary.disabled && p.primary.why ? `<div class="s2meta">${esc(p.primary.why)}</div>` : "")
    + (auto ? `<div class="s2meta">${auto}</div>` : "") + `</div>`;
}
function refreshGuide() { const box = $("#s2guide"); if (!box) return; const html = s2GuideHtml(s2PlanNow()); if (box._last !== html) { box.innerHTML = html; box._last = html; } }
let _s2poll = 0;
function s2Tick() {
  if (S.step !== 5) return;
  refreshGuide();
  if (S.running || !$("#overlay").hidden) return;
  const now = Date.now();
  // 사람이 PowerShell 에서 apply 해도 화면이 따라가도록 10초마다 상태를 다시 읽는다 (버튼 상태가 같으면 안내 카드만 갱신)
  if (now - _s2poll > 10000 && !S._mload) { _s2poll = now; loadMeasure(true); }
  // 자동 측정 (읽기 전용): 켜져 있을 때만 (화면에서 실행한 apply 가 성공하면 켜짐 · 안내 카드의 [사용 안 함] 으로 끔), 대기가 끝난 뒤 반영 한 번당 한 번
  const p = s2PlanNow(), b = p.primary, m = S.measure || {};
  if (S.s2auto && !p.wait && b && b.act === "s2-measure" && !b.disabled) {
    const key = `${b.kind}:${(m.ops_last || {}).at || ""}:${(m.ops_last || {}).dir || ""}`;
    if (S.s2autoKey !== key) { S.s2autoKey = key; toast(`대기 종료 — ${b.label} 자동 시작 (읽기 전용)`, "ok"); runMeasure(b.kind); }
  }
}
function viewStage2() {
  const rec = S.record;
  const m = S.measure;
  if ((!m || m._rid !== (S.recordId || "")) && !S._mload) loadMeasure();
  if (!S.recordId && !S.baseline && !S._bload) { S._bload = true; api.get("/api/proof/baseline").then((x) => { S.baseline = x; S._bload = false; if (S.step === 5) render(); }); }
  const post = s2Post();
  const running = stage2Live();
  const passed = rec && firstPass(rec);
  // 결과 칸: 큰 글자는 상태 이름만, 이유는 작은 글자로
  const st = (x, none) => (!x || !x.dir ? `<div class="big muted" style="font-size:18px">${none}</div><div class="small muted">&nbsp;</div>`
    : `<div class="big" style="font-size:18px;color:${x.status === "VERIFIED" ? "var(--green)" : ["DEPLOY_FAILED", "PLAN_BLOCKED"].includes(x.status) ? "var(--red)" : "var(--amber)"}">${esc(POST_WORD[x.status] || x.status || "—")}</div>`
      + `<div class="small muted">${esc(POST_NOTE[x.status] || "")} · ${esc(fmtTime(x.at))}</div>`);
  let out = head(5, "실제 AWS 검사 — 실제 AWS 시험 환경", "배포 전 검사 통과 후보를 시험 환경에 반영(사람 확인)한 뒤 AWS 적용 규칙(V7)과 통신(V8)을 측정");
  if (post.na) {
    // 시험 환경(실제 AWS)은 3계층 웹 서비스 하나뿐 — 다른 사례의 기록은 실제 AWS 검사 대상이 아니고, 시험 환경 조작도 보이지 않는다
    return out + `<div class="banner warn" style="margin-bottom:12px"><h3>실제 AWS 검사 대상 아님 — 시험 환경 없는 사례</h3><p>${esc(post.na)}</p></div>`
      + `<div class="btns"><button class="btn" data-action="goto" data-step="4">배포 전 검사 결과</button><button class="btn primary" data-action="goto" data-step="3">← 다른 후보 선택</button></div>`;
  }
  out += `<div class="compare"><div class="card"><b>수정 전 · 원본</b>${st(post.before, "측정 기록 없음")}</div>`
    + (rec && !passed && !(post.after && post.after.dir)
      ? `<div class="card"><b>수정 후 · ${esc(recName(rec))}</b><div class="big muted" style="font-size:18px">대상 아님</div><div class="small muted">배포 전 검사 통과 후보만 실제 AWS 검사 진행</div></div></div>`
      : `<div class="card"><b>수정 후 · ${esc(recName(rec) || "기록 미선택")}</b>${st(post.after, "미검증")}</div></div>`);
  out += `<div id="s2guide" class="sec">${s2GuideHtml(s2PlanNow())}</div>`;
  out += `<div class="sec"><h3>검사 단계</h3><div id="walkList">${walkListHtml()}</div>${walkCtlHtml()}</div>`;
  if (m && !m.error) out += manualOpsHtml(m, { rec, passed, running });
  // 배포 전 검사 미통과 후보는 실제 AWS 검사·승인 대상이 아니다 — 다른 후보 선택이 다음 작업
  // 주 버튼은 안내 카드 하나뿐 — 아래 이동 버튼은 보조
  out += `<div class="btns"><button class="btn" data-action="goto" data-step="4" ${rec ? "" : "disabled"}>배포 전 검사 결과</button>`
    + (rec && !passed ? `<button class="btn" data-action="goto" data-step="3">← 다른 후보 선택</button>`
      : `<button class="btn" data-action="goto" data-step="6" ${rec ? "" : "disabled"}>승인 결정 →</button>`) + `</div>`;
  return out;
}
// 수동 조작 — 안내 카드와 같은 기능을 하나씩 실행 (운영자용, 기본 접힘)
const SYNC_KO = { apply: "마지막 apply 와 같은 내용", plan: "plan 결과 변경 없음", plan_check: "plan 확인 결과 변경 없음" };
function manualOpsHtml(m, { rec, passed, running }) {
  const notApplied = m.deployed_state_file && !m.applied_after_change;
  const wait = m.deployed_state_file && !notApplied && !m.settled ? `apply 직후 — ${Math.max(0, (m.settle_s || 120) - (m.since_apply_s || 0))}초 후 측정 가능 (변경 설정이 측정 지점 결과에 반영되는 시간)` : "";
  const noDeploy = m.destroyed ? "배포 없음 (destroy 완료)" : "apply 전";
  const gateBefore = !m.deployed_state_file ? noDeploy : notApplied ? "파일 변경 후 apply 미실행" : !m.is_original ? "시험 환경 파일이 원본과 다름" : wait;
  const gateAfter = !passed ? "배포 전 검사 통과 기록만 가능" : !m.is_record_candidate ? "시험 환경 파일이 이 기록의 후보와 다름"
    : m.plan_blocked ? "plan 확인 결과 교체 · 삭제 포함 — apply · 측정 대상 아님" : !m.deployed_state_file ? noDeploy : notApplied ? "파일 변경 후 apply 미실행" : wait;
  // plan 확인 (읽기 전용): 이 기록의 후보를 넣은 뒤, 배포가 있는 상태에서만 — 배포가 없으면 plan 이 전부 '생성' 이라 교체 여부를 볼 수 없다
  const gatePlan = !passed ? "배포 전 검사 통과 기록만 가능" : !m.is_record_candidate ? "먼저 이 기록의 후보 파일을 시험 환경에 넣기"
    : !m.deployed_state_file ? (m.destroyed ? "배포 없음 — 원본 apply 먼저" : "apply 전 — 원본 apply 먼저") : !m.tf_inited ? "시험 환경 폴더에서 terraform init 먼저 (사람)" : "";
  const pc = m.plan_check;
  const pcTone = !pc ? "" : pc.verdict === "BLOCKED" || pc.verdict === "ERROR" ? "var(--red)" : pc.verdict === "CLEAN" || pc.verdict === "NO_CHANGES" ? "var(--green)" : "var(--amber)";
  const pcLine = pc ? `<div class="small" style="margin-top:6px"><b>plan 확인</b> · <span style="color:${pcTone}">${esc(pc.summary || pc.verdict)}</span> <span class="muted">${esc(fmtTime(pc.at))}${pc.current ? "" : " · 현재 시험 환경 파일과 다른 파일 기준"}</span></div>` : "";
  const gateApplyOrig = !m.is_original ? "시험 환경 파일이 원본일 때만 가능 — 먼저 원본 파일로 복원" : !m.tf_inited ? "terraform init 전 (사람, 최초 1회)" : "";
  const gateApplyCand = !passed ? "배포 전 검사 통과 기록만 가능" : m.plan_blocked ? "plan 확인 결과 교체 · 삭제 포함 — 반영 대상 아님"
    : m.cand_applied && !m.plan_ready ? `반영 완료 (${fmtTime(m.cand_applied.at)}) — 2분 후 수정 후 측정`
    : !m.plan_ready ? "먼저 이 후보로 plan 확인 (보안 그룹 제자리 수정만 포함, 1시간 이내)" : "";
  const gateDestroy = !m.deployed_state_file ? "삭제 대상 없음 (destroy 완료 또는 apply 전)" : !m.tf_inited ? "terraform init 전 (사람, 최초 1회)" : "";
  const lo = m.ops_last;
  const lastLine = lo ? `<div class="small muted" style="margin-top:4px">최근 반영: ${esc(lo.op === "destroy" ? "destroy" : "apply")} ${lo.ok ? "성공" : "실패"} · ${esc(fmtTime(lo.at))}${lo.state_resources_after != null ? ` · 상태 파일 리소스 ${esc(lo.state_resources_after)}개` : ""}${lo.error ? ` · ${esc(lo.error)}` : ""}</div>` : "";
  const cmd = m.commands || {};
  const cmdRow = (k, label) => cmd[k] ? `<div class="cmdrow"><span class="small muted">${esc(label)}</span><code class="mono small">${esc(cmd[k])}</code><button class="mini" data-action="copytxt" data-txt="${esc(cmd[k])}">복사</button></div>` : "";
  const deployed = !m.deployed_state_file ? (m.destroyed ? "배포 없음 — 상태 파일 리소스 0개 (destroy 완료)" : "상태 파일 없음 — apply 전")
    : notApplied ? `<span style="color:var(--amber)">보안 그룹 파일 변경 후 apply 미실행</span>` : `apply 완료${m.state_resources ? ` · 리소스 ${esc(m.state_resources)}개` : ""}`
      + (m.sync_basis ? ` <span class="muted">· 파일 내용 = 배포 상태 (${esc(SYNC_KO[m.sync_basis] || m.sync_basis)})</span>` : "");
  const dis = (gate) => (running || gate ? "disabled" : "");
  return `<details class="ops"${S.opsOpen ? " open" : ""}><summary><b>수동 조작</b><small>파일 교체 · plan 확인 · 반영 · 측정을 개별 실행 (운영자용)</small></summary><div class="ops-b">
    <dl class="kv small"><dt>배포 상태</dt><dd>${deployed}</dd>
      <dt>보안 그룹 파일</dt><dd>${esc((m.matches || []).join(", ") || "원본·후보와 모두 다름")} <span class="mono muted">${esc(String(m.security_groups_sha256 || "").slice(0, 12))}</span></dd>
      ${m.aws_cli ? "" : `<dt>AWS CLI</dt><dd><span style="color:var(--red)">없음 (${esc(m.aws_bin)})</span></dd>`}</dl>
    <div class="mgrp"><b>시험 환경 파일 (이 PC 파일 복사만)</b><div class="btns"><button class="btn" data-action="tb-use" data-which="candidate" ${running || !passed || m.is_record_candidate ? "disabled" : ""}>이 기록의 후보 파일 넣기</button>
      <button class="btn" data-action="tb-use" data-which="original" ${running || m.is_original ? "disabled" : ""}>원본 파일로 복원</button></div></div>
    <div class="mgrp"><b>plan 확인 (읽기 전용 — 실제 배포 상태 기준 계산만)</b><div class="btns"><button class="btn" data-action="plan-check" ${dis(gatePlan)}>plan 확인</button></div>
      <div class="small muted">${esc(gatePlan || "실행 가능")}</div>${pcLine}</div>
    <div class="mgrp"><b>반영 — 시험 환경만, 확인 창에서 사람이 실행</b><span class="small muted">버튼을 누르면 plan 을 먼저 계산해 확인 창에 표시. 확인란 선택 후 [실행] 을 눌러야 그 plan 그대로 반영</span>
      <div class="btns"><button class="btn" data-action="tb-prepare" data-kind="apply_original" ${dis(gateApplyOrig)}>원본 apply (배포·복원)</button>
        <button class="btn" data-action="tb-cand-apply" ${dis(gateApplyCand)}>후보 apply</button>
        <button class="btn danger" data-action="tb-prepare" data-kind="destroy" ${dis(gateDestroy)}>destroy (전체 삭제)</button></div>
      <div class="small muted">원본 apply: ${esc(gateApplyOrig || "실행 가능")} · 후보 apply: ${esc(gateApplyCand || "실행 가능")} · destroy: ${esc(gateDestroy || "실행 가능")}</div>${lastLine}</div>
    <div class="mgrp"><b>측정 (읽기 전용 — AWS 조회·접속 시험, 최대 3분)</b>
      <div class="row" style="margin-top:6px;gap:8px"><label class="small muted">프로필</label><input class="f" id="mProfile" style="width:140px" value="${esc(S.mProfile ?? m.profile ?? "")}" placeholder="예: capstone-tf"><label class="small muted">리전</label><input class="f" id="mRegion" style="width:140px" value="${esc(S.mRegion ?? m.region ?? "ap-northeast-2")}"></div>
      <div class="btns"><button class="btn" data-action="measure" data-kind="before" ${dis(gateBefore)}>수정 전 측정 (원본)</button>
        <button class="btn" data-action="measure" data-kind="after" ${dis(gateAfter)}>수정 후 측정 (이 기록)</button></div>
      <div class="small muted">수정 전 측정: ${esc(gateBefore || "실행 가능")} · 수정 후 측정: ${esc(gateAfter || "실행 가능")}</div></div>
    <div class="mgrp"><b>PowerShell 명령 (버튼 대신 직접 실행할 때)</b>${cmdRow("login", "세션 만료 시")}${cmdRow("cd", "폴더")}${cmdRow("profile", "프로필")}${cmdRow("plan", "plan 확인")}${cmdRow("apply", "반영 (사람)")}${cmdRow("destroy", "삭제 (사람)")}</div>
    <div class="small muted" style="margin-top:10px">수행 작업: ${(m.does || []).map(esc).join(" · ")}<br>수행하지 않는 작업: ${(m.does_not || []).map(esc).join(" · ")}</div></div></details>`;
}
const POST_NOTE = { VERIFIED: "V7·V8 모두 통과", DEPLOY_FAILED: "설계 기준과의 불일치가 실제 AWS 에서 확인됨", UNVERIFIED: "판정 불가 항목 있음",
  PLAN_BLOCKED: "plan 에 교체·삭제 포함 — apply 미실행" };
// 시험 환경 반영 확인 창 — plan 요약을 보여 주고, 사람이 확인란을 선택해야 [실행] 이 켜진다
const PLAN_KIND_WORD = { create: "생성 (+)", update: "제자리 수정 (~)", replace: "교체 (-/+)", delete: "삭제 (-)" };
function applyModalHtml(p) {
  const word = p.kind === "destroy" ? "destroy" : "apply";
  const rows = (p.changes || []).slice(0, 15).map((c) => `<tr><td class="mono small">${esc(c.address)}</td><td>${esc(PLAN_KIND_WORD[c.kind] || c.kind)}</td></tr>`).join("");
  const more = (p.n_changes || 0) > 15 ? `<div class="small muted" style="margin-top:4px">외 ${esc(p.n_changes - 15)}개 — 전체 목록: 기록 폴더 ${esc(p.ops_dir)} 의 plan.txt</div>` : "";
  return `<div class="phead"><div class="tag">시험 환경 반영 · 사람 확인</div><h2>실행 전 확인 · ${esc(p.summary)}</h2>
    <p>아직 반영 안 됨. plan 생성 시각 ${esc(fmtTime(p.created_at))}. [${word} 실행] 을 누르면 이 plan 그대로 실제 AWS 시험 환경에 반영. plan 생성 후 시험 환경 파일이나 상태가 바뀌었으면 실행 거부.</p></div>
    <table class="t"><thead><tr><th>리소스</th><th>변경 방식</th></tr></thead><tbody>${rows || `<tr><td colspan="2">없음</td></tr>`}</tbody></table>${more}
    <div class="small muted" style="margin-top:8px">실행에 수 분 소요 (원본 apply 실측 5~8분). 완료 전까지 IaCPatch 창 유지 — 진행 내용은 실행 로그에 표시.</div>
    <label class="ack"><input type="checkbox" id="tbAck"><span>plan 내용을 확인함. 시험 환경(AWS)에 실제로 반영됨${p.kind === "destroy" ? " — 시험 환경 리소스 전체 삭제" : ""}.</span></label>
    <div class="btns"><button class="btn" data-action="close-overlay">취소</button><button class="btn ${p.kind === "destroy" ? "danger" : "go"}" id="tbExec" data-action="tb-exec" data-plan="${esc(p.plan_id)}" data-confirm="${word}" data-label="${esc(p.kind_ko || word)}" disabled>${word} 실행</button></div>`;
}
async function runTestbedPrepare(kind) {
  S.mProfile = ($("#mProfile") || {}).value || S.mProfile || "";
  await startJob("/api/testbed/prepare", { kind, profile: (S.mProfile || "").trim() }, kind === "destroy" ? "시험 환경 삭제 준비 · plan -destroy (반영 없음)" : "원본 반영 준비 · plan (반영 없음)", "testbed_prepare");
}
async function runTestbedExecute(btn) {
  const ack = $("#tbAck");
  if (!ack || !ack.checked) { toast("plan 내용 확인란 선택 필요"); return; }
  closeOverlay("exec");
  await startJob("/api/testbed/execute", { plan_id: btn.dataset.plan, confirm: btn.dataset.confirm, profile: (S.mProfile || "").trim() }, `${btn.dataset.label} · 사람 확인 후 실행`, "testbed_apply");
}
async function runPlanCheck(fromGuide = false) {
  S.mProfile = ($("#mProfile") || {}).value || S.mProfile || "";
  S.s2guidePlan = fromGuide;
  await startJob("/api/plan_check", { record_id: S.recordId || "", profile: (S.mProfile || "").trim() }, `plan 확인 · ${recName(S.record)}`, "plan_check");
}
// 안내 카드의 [원본 배포 시작]: 시험 환경 파일이 원본이 아니면 원본으로 바꾼 뒤 plan 계산 → 확인 창 (실행은 사람)
async function s2Deploy() {
  if (S.running) { toast("실행 중인 작업 완료 후 가능"); return; }
  if (!(S.measure || {}).is_original) {
    const r = await api.post("/api/testbed/use", { which: "original", record_id: S.recordId || "" });
    if (!r.ok) { toast(r.error || "원본 파일 복원 실패", "bad"); return; }
    // 복원한 원본이 이미 배포 상태와 같으면 (마지막 apply 가 원본) apply 할 것이 없다 — 안내만 다음 단계로
    const ms = await reloadStage2();
    if (ms && !ms.error && ms.deployed_state_file && ms.applied_after_change && ms.is_original) { toast("원본 파일로 복원 — 배포 상태와 같음 (apply 불필요)", "ok"); render(); return; }
  }
  await runTestbedPrepare("apply_original");
}
// 안내 카드의 [후보 반영 시작]: 이 기록의 후보 파일을 넣고 plan 확인 → 보안 그룹 제자리 수정만이면 확인 창 (실행은 사람)
async function s2Candidate() {
  if (S.running) { toast("실행 중인 작업 완료 후 가능"); return; }
  if (!(S.measure || {}).is_record_candidate) {
    const r = await api.post("/api/testbed/use", { which: "candidate", record_id: S.recordId || "" });
    if (!r.ok) { toast(r.error || "후보 파일 넣기 실패", "bad"); return; }
  }
  await runPlanCheck(true);
}
async function runMeasure(kind) {
  S.mProfile = ($("#mProfile") || {}).value || S.mProfile || ""; S.mRegion = ($("#mRegion") || {}).value || S.mRegion || "";
  const body = { record_id: kind === "after" ? S.recordId : "", profile: (S.mProfile || "").trim(), region: (S.mRegion || "").trim() };
  await startJob("/api/measure", body, kind === "after" ? `수정 후 측정 · ${recName(S.record)}` : "수정 전 측정 · 원본 배포 상태", "measure");
}
async function openFile(rid, path) {
  openOverlay(`<div class="phead"><div class="tag">기록 파일</div><h2 class="mono" style="font-size:16px">${esc(path)}</h2></div><div class="muted">불러오는 중…</div>`);
  const f = await api.get(`/api/proof/file?id=${encodeURIComponent(rid)}&path=${encodeURIComponent(path)}`);
  if (f.error) { openOverlay(`<div class="card">${esc(f.error)}</div>`); return; }
  openOverlay(`<div class="phead"><div class="tag">기록 파일 · 원본 (계정 번호만 마스킹)</div><h2 class="mono" style="font-size:16px">${esc(f.path)}</h2>
    <p class="mono small">${esc(f.bytes)} bytes · sha256 ${esc(f.sha256)}${f.truncated ? " · 앞 400KB 만 표시" : ""}</p></div><pre class="rawfile">${esc(f.text)}</pre>`);
}

// 6. 승인 결정 (사람)
function viewDecision() {
  const rec = S.record || {};
  const c = rec.conclusion || {};
  const dec = rec.decision;
  const s2 = stage2Status(rec);
  const can = !!c.can_approve;
  const g1 = firstPass(rec), g2 = s2 === "pass";
  const s2word = s2 === "fail" ? (POST_WORD[(rec.post_deploy || {}).status] || "실패") : "실패";
  let out = head(6, "승인 결정 — 사람 최종 승인", "배포 전 · 실제 AWS 검사 모두 통과한 후보만 적용 승인 가능.")
    + `<div class="compare"><div class="card"><b>배포 전 검사 (코드)</b><div class="big" style="font-size:19px;color:${g1 ? "var(--green)" : "var(--red)"}">${g1 ? "통과" : "미통과"}</div></div>
       <div class="card"><b>실제 AWS 검사 (시험 환경)</b><div class="big" style="font-size:19px;color:${g2 ? "var(--green)" : s2 === "wait" || s2 === "na" ? "var(--amber)" : "var(--red)"}">${g2 ? "통과" : s2 === "wait" ? "미검증" : s2 === "skip" ? "대상 아님" : s2 === "na" ? "해당 없음 (시험 환경 없는 사례)" : esc(s2word)}</div></div></div>`;
  if (dec && dec.decision) {
    out += `<div class="sec"><h3>기록된 결정</h3><div class="card"><div class="row"><span class="chip ${dec.decision === "APPROVED" ? "ok" : dec.decision === "DISCARDED" ? "bad" : "warn"}">${esc(rec.decision_ko || dec.decision)}</span><b>${esc(dec.by || "")}</b><span class="muted small grow">${esc(fmtTime(dec.at))}</span></div>${dec.reason ? `<div class="small" style="margin-top:8px">사유: ${esc(dec.reason)}</div>` : ""}</div></div>`
      + `<div class="btns"><button class="btn" data-action="redecide">다시 결정</button><button class="btn primary" data-action="open-summary">결과 요약 보기</button></div>`;
    if (!S.decisionOpen) return out + afterRejectCard();
  }
  out += `<div class="sec"><h3>결정</h3>
      <label class="fl" for="decBy">결정자 (이름)</label><input class="f" id="decBy" autocomplete="off" placeholder="예: 김보성">
      <label class="fl" for="decReason">사유 (적용 승인 외 결정 시 필수)</label><textarea class="f" id="decReason" placeholder="예: 두 대역을 합치면 인터넷 전체에 SSH 허용"></textarea>
      ${can ? "" : `<div class="card small" style="margin-top:10px;border-color:#fecaca;background:var(--red-bg)"><b style="color:var(--red)">적용 승인 불가</b><div style="margin-top:4px">${esc(c.approve_blocked_reason || "배포 전 · 실제 AWS 검사 모두 통과한 후보만 적용 승인 가능")}</div><div class="muted" style="margin-top:4px">버튼을 우회한 요청도 서버에서 거부.</div></div>`}
      ${can ? `<div class="sec"><h3>적용 승인 전 확인 항목</h3><div class="checklist">${(rec.human_checks || []).map((t, i) => `<label><input type="checkbox" data-chk="${i}"><span>${esc(t)}</span></label>`).join("")}</div></div>` : ""}
      <div class="btns">
        <button class="btn go" data-action="decide" data-d="APPROVED" ${can ? "" : "disabled"}>적용 승인</button>
        <button class="btn" data-action="decide" data-d="CHANGES_REQUESTED">수정 요청</button>
        <button class="btn" data-action="decide" data-d="REGENERATE">재생성 요청</button>
        <button class="btn danger" data-action="decide" data-d="DISCARDED">폐기</button>
      </div></div>`;
  return out + afterRejectCard();
}
function afterRejectCard() {
  return moreBox("decide", "버튼별 처리 내용", `<div class="small" style="line-height:1.7">적용 승인: PR 초안만 생성 (push · 병합 · 실제 terraform apply 는 사람이 직접 수행).<br>
    수정 요청 · 재생성 요청 · 폐기: 실제 환경 변경 없음, 결정자와 사유만 기록. 재생성 후보는 배포 전 검사부터 다시 수행.</div>`);
}

// ------------------------------------------------------------------ 검사 실행
async function startJob(path, payload, label, kind) {
  if (S.running) { toast("실행 중인 작업 있음"); return; }
  const r = await api.post(path, payload);
  if (!r.started) { toast(r.error || (r._status === 409 ? "다른 작업 실행 중 — 완료 후 다시 실행 (다른 IaCPatch 창의 검사 · 측정 포함)" : "작업 시작 실패"), "bad"); return; }
  S.running = { t0: Date.now(), since: 0, kind, label, setId: S.setId };
  if (kind === "review") { S.record = null; S.recordId = null; S.proof = null; S.proofRid = null; S.calLatest = null; S.jobLines = []; walkReset(0); }
  S.progress = null;
  $("#log").innerHTML = ""; logLine(`▶ ${label}`, "h"); setConsoleState("실행 중");
  if (S.consoleMin && kind !== "review") { toggleConsole(); S.consoleAuto = true; }
  $(".logbtn").classList.add("run");
  if (kind === "case_scan" || kind === "calibrate") { render(); } else if (STAGE2_JOBS.includes(kind)) gotoStep(5); else gotoStep(4);
  tickClock(); poll();
}
function tickClock() { if (!S.running) return; const b = $("#bigtime"); if (b) b.innerHTML = `${((Date.now() - S.running.t0) / 1000).toFixed(1)}<small>초</small>`; requestAnimationFrame(tickClock); }
async function poll() {
  if (!S.running) return;
  const [lg, pg] = await Promise.all([api.get(`/api/log?since=${S.running.since}`), api.get("/api/job/progress")]);
  if (lg.error && !lg.log) { setTimeout(poll, 1200); return; }
  (lg.log || []).forEach((l) => { logLine(l); S.jobLines.push(l); });
  if (S.jobLines.length > 400) S.jobLines = S.jobLines.slice(-400);
  if (typeof lg.log_total === "number") S.running.since = lg.log_total;
  S.running.prog = lg.progress;
  const changed = JSON.stringify((S.progress || {}).stages) !== JSON.stringify(pg.stages) || S.running.kind === "review_all";
  S.progress = pg;
  if (S.running.kind === "review" && pg.record_id) {
    if (!S.calLatest) { const c = await api.get("/api/proof/calibration"); if (c && c.ok) S.calLatest = c; }
    const pr = await api.get(`/api/proof?id=${encodeURIComponent(pg.record_id)}`);
    if (!pr.error) { const sig = JSON.stringify(pr.cards.map((c) => [c.status, c.verdict, (c.method.commands || []).length])); if (sig !== S.proofSig) { S.proofSig = sig; S.proof = pr; S.proofRid = pg.record_id; if (S.step === 4) { render(); } } }
  } else if (S.running.kind === "review" && S.step === 4 && S.walk.i === 0) renderProofPane();
  if (changed && (S.running.kind === "case_scan")) render();
  if (lg.running) { setTimeout(poll, 500); return; }
  const kind = S.running.kind;
  S.running = null; setConsoleState(lg.error ? "오류" : "완료"); $(".logbtn").classList.remove("run");
  if (lg.error) { logLine("오류: " + lg.error, "e"); toast("작업 오류 — 실행 로그 확인 필요", "bad"); render(); return; }
  if (kind === "calibrate") { toast("검증 도구 사전 점검 완료", "ok"); S.calLatest = await api.get("/api/proof/calibration"); render(); return; }
  if (kind === "testbed_prepare") {
    const p = (lg.result || {}).plan || {};
    await reloadStage2(); render();
    if (p.plan_id) openOverlay(applyModalHtml(p));
    else if (p.verdict === "NO_CHANGES") toast("변경 없음 — 배포 상태와 파일 내용이 같음 (apply 불필요)", "ok");
    else toast(`실행 불가 — ${p.why || p.summary || "plan 생성 실패"}`, "bad");
    return;
  }
  if (kind === "testbed_apply") {
    const res = lg.result || {};
    toast(res.ok ? `${res.kind_ko || "반영"} 완료${res.reverted ? " — 시험 환경 파일을 원본으로 복원" : ""}` : `실패 — ${res.error || "실행 로그 확인 필요"}`, res.ok ? "ok" : "bad");
    // apply 가 끝나면 대기 후 측정(읽기 전용)을 자동으로 — 안내 카드에서 끌 수 있다. destroy 뒤에는 측정할 것이 없다.
    if (res.ok && res.kind !== "destroy") S.s2auto = true;
    await reloadStage2();
    await refreshCandidates();
    walkReset(0); render(); return;
  }
  if (kind === "plan_check") {
    const res = lg.result || {};
    const tone = res.verdict === "CLEAN" || res.verdict === "NO_CHANGES" ? "ok" : res.verdict === "BLOCKED" || res.verdict === "ERROR" ? "bad" : "";
    toast(`plan 확인 완료 · ${res.summary || res.verdict || ""}`, tone);
    const fromGuide = !!S.s2guidePlan; S.s2guidePlan = false;
    const ms = await reloadStage2();
    await refreshCandidates();
    walkReset(0); render();
    // 안내 카드에서 시작했고 보안 그룹만 제자리 수정이면 확인 창을 바로 연다 (실행은 사람이 확인란 선택 후 [apply 실행])
    if (fromGuide && res.verdict === "CLEAN" && ms && ms.plan_ready) openOverlay(applyModalHtml(ms.plan_ready));
    return;
  }
  if (kind === "measure") {
    const res = lg.result || {};
    toast(`${res.record_id ? "수정 후" : "수정 전"} 측정 완료 · 결과: ${POST_WORD[res.status] || res.status || "기록 없음"}`, res.record_id && res.status === "VERIFIED" ? "ok" : "");
    await reloadStage2();
    walkReset(0); render(); return;
  }
  if (kind === "case_scan") {
    toast("원본 점검 완료", "ok");
    await loadCase(); S.current = await api.get(`/api/case/current?id=${S.caseId}`);
    render(); applyDiagram(); return;
  }
  await refreshCandidates();
  if (kind === "review_all") { toast("전체 후보 검사 완료", "ok"); gotoStep(3); openSummary(); return; }
  const res = lg.result || {};
  if (res.record_id) await openRecord(res.record_id, true);
  else { toast(res.message || "결과 기록 없음", "bad"); gotoStep(3); }
}
async function refreshCandidates() { const c = await api.get(`/api/case/candidates?id=${S.caseId}`); if (!c.error) S.cands = c; }
async function openRecord(rid, fresh = false) {
  const rec = await api.get(`/api/record?id=${encodeURIComponent(rid)}`);
  if (rec.error) { toast(rec.error, "bad"); return; }
  S.record = rec; S.recordId = rid; S.decisionOpen = !rec.decision; if (S.proofRid !== rid) S.opsOpen = null;
  if (rec.set && rec.set.set_id && rec.set.set_id !== S.setId && ((S.case.sets || []).some((s) => s.set_id === rec.set.set_id))) { S.setId = rec.set.set_id; renderSetSwitch(); }
  const same = S.proofRid === rid;
  const pr = await api.get(`/api/proof?id=${encodeURIComponent(rid)}`);
  if (!pr.error) { S.proof = pr; S.proofRid = rid; }
  if (!pr.error && !pr.calibration && !S.calLatest) { const c = await api.get("/api/proof/calibration"); if (c && c.ok) S.calLatest = c; }
  if (!fresh || !same) walkReset(0);
  S.step = 4; S.visited.add(4); $("#panelBody").scrollTop = 0;
  closeOverlay(); render(); applyDiagram(); enterAnim();
  if (fresh) { const c = rec.conclusion || {}; logLine(`결과: ${c.headline || ""}`, c.tone === "good" ? "ok" : c.tone === "bad" ? "e" : ""); }
}

// ------------------------------------------------------------------ 결정
async function decide(d) {
  const by = ($("#decBy") || {}).value || "";
  const reason = ($("#decReason") || {}).value || "";
  if (!by.trim()) { toast("결정자 이름 입력 필요", "bad"); $("#decBy").focus(); return; }
  if (d !== "APPROVED" && !reason.trim()) { toast("적용 승인 외 결정은 사유 입력 필요", "bad"); $("#decReason").focus(); return; }
  if (d === "APPROVED" && $$("[data-chk]").some((b) => !b.checked)) { toast("확인 항목 전체 체크 후 적용 승인 가능", "bad"); return; }
  const r = await api.post("/api/decision", { record_id: S.recordId, decision: d, reason: reason.trim(), by: by.trim(), base_branch: "main" });
  if (!r.ok) { toast(r.error || "기록 실패", "bad"); return; }
  logLine(`■ 결정: ${d} · ${by.trim()}`, "h");
  const rec = await api.get(`/api/record?id=${encodeURIComponent(S.recordId)}`);
  if (!rec.error) S.record = rec;
  S.decisionOpen = false;
  await refreshCandidates(); render();
  toast(`${{ APPROVED: "적용 승인", CHANGES_REQUESTED: "수정 요청", REGENERATE: "재생성 요청", DISCARDED: "폐기" }[d] || d} 기록됨`, d === "APPROVED" ? "ok" : "");
}

// ------------------------------------------------------------------ 겹침 창
function openOverlay(html) { $("#ovBody").innerHTML = html; $("#overlay").hidden = false; }
// 확인 창(반영 plan)을 실행 없이 닫으면 알린다 — 닫은 것을 반영 완료로 오해하지 않게 (10-27 실제 사례)
function closeOverlay(reason = "") {
  const pending = !$("#overlay").hidden && $("#tbExec");
  $("#overlay").hidden = true;
  if (pending && reason !== "exec") toast("취소 — 반영하지 않음 (실행하려면 버튼을 다시 누름)");
}
async function openSummary() {
  openOverlay(`<div class="phead"><div class="tag">결과 요약</div><h2>불러오는 중…</h2></div>`);
  await refreshCandidates();
  const rows = [];
  ((S.cands && S.cands.sets) || []).forEach((s) => (s.candidates || []).forEach((c) => { if (c.latest && !/^(paste|upload)/.test(String(c.id))) rows.push({ set: s, c }); }));
  const lay = (c, k) => (c.latest.layers || {})[k];
  const total = rows.length;
  const tp = rows.filter(({ c }) => lay(c, "V1") === "PASS" && lay(c, "V2") === "PASS");
  const v6pass = rows.filter(({ c }) => lay(c, "V6") === "PASS");
  const blocked = tp.filter(({ c }) => lay(c, "V6") === "FAIL");
  const passed = rows.filter(({ c }) => ["LIGHT_REVIEW", "FULL_REVIEW"].includes(c.latest.level));
  const ds = rows.map(({ c }) => secs(c.latest.started_at, c.latest.finished_at)).filter((x) => x != null);
  const avg = ds.length ? Math.round(ds.reduce((a, b) => a + b, 0) / ds.length) : null;
  const bar = (label, p, f, n) => `<div class="bar"><span>${esc(label)}</span><div class="track"><i class="p" style="width:${n ? (p / n) * 100 : 0}%"></i><i class="f" style="width:${n ? (f / n) * 100 : 0}%"></i></div><b>${p} / ${n}</b></div>`;
  const table = (s) => {
    const list = rows.filter((r) => r.set.set_id === s.set_id);
    if (!list.length) return "";
    // 실제 AWS 검사 결과: 같은 후보 파일(sha256 이 같은 기록)을 실제 AWS 에서 잰 가장 최근 결과. 누르면 그 기록이 열린다.
    const post = (c) => {
      const p = c.post;
      if (p && p.status) return `<button class="mini ${p.status === "VERIFIED" ? "okb" : "badb"}" data-action="open-record" data-rid="${esc(p.id)}" title="${esc(fmtTime(p.at))} 기록">${esc(POST_WORD[p.status] || "판정 불가")}</button>`;
      return ["LIGHT_REVIEW", "FULL_REVIEW"].includes(c.latest.level) ? `<span class="small muted">미검증</span>` : `<span class="small muted">—</span>`;
    };
    return `<div class="sec"><h3>${esc(s.label)} · 후보 ${list.length}개 (후보별 최근 기록)</h3><table class="t"><thead><tr><th>후보</th><th>출처</th>${CHECK.map(([k, q]) => `<th title="${esc(q)}">${k}</th>`).join("")}<th>배포 전 검사 결과</th><th>실제 AWS 검사</th><th>사람의 결정</th></tr></thead><tbody>`
      + list.map(({ c }) => `<tr class="click" data-action="open-record" data-rid="${esc(c.latest.id)}"><td>${esc(candName(c))}</td><td>${originChip(c.origin)}</td>${CHECK.map(([k]) => { const v = lay(c, k) || "NONE"; return `<td><span class="cell ${v}">${v === "PASS" ? "✓" : v === "FAIL" ? "✕" : v === "NONE" ? "·" : "?"}</span></td>`; }).join("")}<td>${resultChip(c.latest)}</td><td>${post(c)}</td><td class="small">${esc(c.latest.decision_ko || "")}</td></tr>`).join("")
      + `</tbody></table><p class="small muted" style="margin-top:6px">V1 기존 탐지 해소 · V2 신규 탐지 · V3 구문 · 속성 · 참조(validate) · V4 실행 계획(plan) · V5 변경 허용 범위 · V6 설계 기준 비교 — ✓ 통과 · ✕ 실패 · ? 판정 불가 · · 미실행 (이전 단계에서 중단)</p></div>`;
  };
  openOverlay(`<div class="phead"><div class="tag">결과 요약 · ${esc((S.case && S.case.name) || "")}</div><h2>${tp.length ? `Trivy 재검사 통과 ${tp.length}개 중 <span style="color:var(--red)">${blocked.length}개</span> 설계 기준 위반으로 차단` : "결과 요약"}</h2>
      <p>Trivy 재검사는 기존 탐지 해소 여부만 확인. 목록에는 팀이 작성한 수정안이 섞여 있음 — 이 비율은 AI 수정안의 실제 위반 비율이 아님.</p></div>
    <div class="kpis"><div class="kpi"><b>${total}</b><span>검사 후보</span></div><div class="kpi"><b>${tp.length}</b><span>Trivy 재검사 통과</span></div>
      <div class="kpi bad"><b>${blocked.length}</b><span>그중 설계 기준 위반 차단</span></div><div class="kpi good"><b>${passed.length}</b><span>배포 전 검사 통과${avg != null ? ` · 평균 ${avg}초` : ""}</span></div></div>
    <div class="sec"><h3>동일 후보 · 두 기준 비교</h3><div class="card"><div class="bars">${bar("Trivy 기준 통과", tp.length, total - tp.length, total)}${bar("설계 기준 통과", v6pass.length, total - v6pass.length, total)}</div></div></div>`
    + ((S.cands && S.cands.sets) || []).map(table).join("")
    + `<p class="small muted">행 선택 시 해당 후보의 최근 기록 표시. '실제 AWS 검사' 칸 선택 시 실제 AWS 측정 기록 표시.</p>`);
}
async function openRecords() {
  openOverlay(`<div class="phead"><div class="tag">기록</div><h2>불러오는 중…</h2></div>`);
  const r = await api.get("/api/records");
  const list = (r.records || []).filter((x) => x.ui);
  openOverlay(`<div class="phead"><div class="tag">기록</div><h2>검사 기록 ${list.length}개</h2><p>화면에서 실행한 검사 기록은 모두 data/reviews 에 보존 (삭제하지 않음).</p></div>
    <table class="t"><thead><tr><th>시각</th><th>영역 / 후보</th><th>배포 전 검사 결과</th><th>위험도</th><th>사람의 결정</th></tr></thead><tbody>`
    + list.map((x) => `<tr class="click" data-action="open-record" data-rid="${esc(x.id)}"><td class="mono small">${esc(fmtTime(x.started_at))}</td><td><span class="muted small">${esc(setLabel(x.set_id))}</span><br><b>${esc(x.label || "")}</b></td><td>${resultChip(x)} <span class="small muted">${esc(String(x.classification ? x.classification.label : "").replace(/^(차단|통과|정상) — /, ""))}</span></td><td class="small">${esc(RISK_KO[x.risk] || x.risk || "")}</td><td class="small">${esc(x.decision_ko || "")}</td></tr>`).join("")
    + `</tbody></table>`);
}
function openSettings() {
  const a = S.app || {}, t = a.tools || {};
  openOverlay(`<div class="phead"><div class="tag">설정</div><h2>검사 도구 · 수행하지 않는 작업</h2></div>
    <div class="sec"><h3>검사 도구</h3><table class="t"><tbody>
      <tr><td>Trivy</td><td>${t.trivy && t.trivy.ok ? `<span class="chip ok">있음</span>` : `<span class="chip bad">없음</span>`}</td><td class="mono small">${esc((t.trivy && t.trivy.version) || "")}</td></tr>
      <tr><td>Terraform</td><td>${t.terraform && t.terraform.ok ? `<span class="chip ok">있음</span>` : `<span class="chip bad">없음</span>`}</td><td class="mono small">${esc((t.terraform && t.terraform.version) || "")}</td></tr>
    </tbody></table><div class="btns"><button class="btn" data-action="setup-tools">도구 설치 · 확인 (tools 폴더)</button><button class="btn" data-action="scan">원본 점검 다시 실행</button></div></div>
    <div class="sec"><h3>수행하지 않는 작업</h3><div class="card">${(a.does_not || []).map((x) => `<span class="chip" style="margin:2px">${esc(x)}</span>`).join("")}</div></div>
    <div class="sec"><h3>이전 화면</h3><div class="card small"><a class="btn" href="/classic">이전 화면 열기</a> <span class="muted">개발용 (실험 재현 · 리포트). 화면 문구는 이전 버전 기준</span></div></div>`);
}
async function setupTools() {
  const r = await api.post("/api/job/setup_tools");
  if (!r.started) { toast("다른 작업 실행 중", "bad"); return; }
  closeOverlay(); $("#log").innerHTML = ""; logLine("▶ 도구 설치 · 확인", "h"); setConsoleState("도구 설치 중");
  if (S.consoleMin) toggleConsole();
  let since = 0;
  for (;;) { const lg = await api.get(`/api/log?since=${since}`); (lg.log || []).forEach((l) => logLine(l)); if (typeof lg.log_total === "number") since = lg.log_total; if (!lg.running) break; await sleep(600); }
  S.app = await api.get("/api/app"); renderTools(); setConsoleState("완료"); toast("도구 확인 완료", "ok");
}
function toggleConsole() { S.consoleMin = !S.consoleMin; $("#console").classList.toggle("min", S.consoleMin); if (!S.consoleMin) { const el = logEl(); el.scrollTop = el.scrollHeight; } }

// ------------------------------------------------------------------ 이벤트
document.addEventListener("click", async (e) => {
  const t = e.target.closest("[data-action],.step");
  if (!t) return;
  if (t.classList.contains("step")) { gotoStep(+t.dataset.step); return; }
  const a = t.dataset.action;
  if (a === "goto") gotoStep(+t.dataset.step);
  else if (a === "set") { if (S.running) { toast("검사 완료 후 변경 가능"); return; } S.setId = t.dataset.set; S.sel = null; S.sourceKey = ""; S.paste = ""; renderSetSwitch(); gotoStep(Math.min(S.step, 3)); loadTopoModel(); }
  else if (a === "pick") { S.sel = t.dataset.cand; render(); if (S.step === 3) applyDiagram(); }
  else if (a === "run") {
    const cid = t.dataset.cand;
    const c = (candSet().candidates || []).find((x) => x.id === cid) || {};
    const body = { case_id: S.caseId, set_id: S.setId, candidate_id: cid };
    if (c.origin && c.origin.code === "rule_based") body.generator = "rule_based";
    startJob("/api/review", body, `${curSet().label} · ${candName(c)}`, "review");
  }
  else if (a === "run-fresh") {
    const cid = t.dataset.cand;
    const c = (candSet().candidates || []).find((x) => x.id === cid) || {};
    startJob("/api/review", { case_id: S.caseId, set_id: S.setId, candidate_id: cid, fresh_baseline: true }, `${curSet().label} · ${candName(c)} · 원본 포함 재검사`, "review");
  }
  else if (a === "run-paste") { const v = ($("#pasteBox") || {}).value || ""; if (!v.trim()) { toast("입력 내용 없음", "bad"); return; } S.paste = v; startJob("/api/review", { case_id: S.caseId, set_id: S.setId, paste: v }, `${curSet().label} · 직접 제출 (붙여넣기)`, "review"); }
  else if (a === "sub-mode") { S.subMode = t.dataset.mode; afterCandsRender(); }
  else if (a === "goto-layer") { const k = walkItems().findIndex((it) => it.key === t.dataset.layer); if (k >= 0) { walkReset(k); S.walk.auto = false; render(); } }
  else if (a === "resubmit") { S.sel = "__paste"; S.subMode = "upload"; gotoStep(3); }
  else if (a === "run-upload") {
    const u = S.upload || {};
    if (!u.check || !u.check.ok) { toast("검사할 변경 파일 없음", "bad"); return; }
    startJob("/api/review", { case_id: S.caseId, set_id: S.setId, upload: { files: u.files, folder: !!u.folder } }, `${curSet().label} · 직접 제출 (파일 ${(u.check.files || []).filter((f) => f.status === "changed" || f.status === "new").length}개)`, "review");
  }
  else if (a === "paste-reset") { S.paste = (S.source && S.source.original) || ""; render(); }
  else if (a === "review-all") startJob("/api/review_all", { case_id: S.caseId, set_id: S.setId }, `${curSet().label} · 전체 후보`, "review_all");
  else if (a === "scan") { closeOverlay(); startJob("/api/case/scan", { case_id: S.caseId }, `원본 점검 · ${S.case.name}`, "case_scan"); }
  else if (a === "open-record") { e.stopPropagation(); await openRecord(t.dataset.rid, false); }
  else if (a === "decide") decide(t.dataset.d);
  else if (a === "redecide") { S.decisionOpen = true; render(); }
  else if (a === "copy") { const c = ((S.record || {}).postdeploy_howto || {}).commands || []; try { await navigator.clipboard.writeText(c[+t.dataset.i] || ""); toast("복사 완료", "ok"); } catch (err) { toast("복사 실패 — 직접 선택 후 Ctrl+C"); } }
  else if (a === "walk") { S.walk.i = +t.dataset.i; S.walk.t0 = Date.now(); renderProofPane(); renderWalkList(); }
  else if (a === "walk-auto") { S.walk.auto = !S.walk.auto; S.walk.t0 = Date.now(); render(); }
  else if (a === "walk-prev") { S.walk.i = Math.max(0, S.walk.i - 1); S.walk.t0 = Date.now(); renderProofPane(); renderWalkList(); }
  else if (a === "walk-next") { S.walk.i = Math.min(walkItems().length - 1, S.walk.i + 1); S.walk.t0 = Date.now(); renderProofPane(); renderWalkList(); }
  else if (a === "walk-dwell") { S.walk.dwell = +t.dataset.ms; S.walk.t0 = Date.now(); render(); }
  else if (a === "open-topomap") openOverlay(topomapHtml(S.topomap));
  else if (a === "open-file") openFile(t.dataset.rid, t.dataset.path);
  else if (a === "open-report") openOverlay(`<div class="phead"><div class="tag">증거 보고서 · 기록 폴더 evidence/report.html 로도 저장됨</div><h2 class="mono" style="font-size:16px">data/reviews/${esc(t.dataset.rid)}/evidence/report.html</h2></div><iframe class="repframe" src="/api/proof/report?id=${encodeURIComponent(t.dataset.rid)}"></iframe>`);
  // 수동 조작 칸의 버튼을 눌렀으면, 작업이 끝나고 다시 그려도 그 칸을 펼친 채로 둔다 (다음 버튼을 바로 누르게)
  if (t.closest("details.ops")) S.opsOpen = true;
  if (a === "measure" || a === "s2-measure") runMeasure(t.dataset.kind);
  else if (a === "plan-check") runPlanCheck(false);
  else if (a === "tb-prepare") runTestbedPrepare(t.dataset.kind);
  else if (a === "s2-deploy") s2Deploy();
  else if (a === "s2-cand") s2Candidate();
  else if (a === "s2-destroy") runTestbedPrepare("destroy");
  else if (a === "s2-auto-on" || a === "s2-auto-off") { S.s2auto = a === "s2-auto-on"; refreshGuide(); }
  else if (a === "s2-pick") gotoStep(3);
  else if (a === "s2-decide") gotoStep(6);
  else if (a === "tb-cand-apply" || a === "s2-open-apply") { const p = S.measure && S.measure.plan_ready; if (p) openOverlay(applyModalHtml(p)); else toast("먼저 이 후보로 plan 확인 필요"); }
  else if (a === "tb-exec") runTestbedExecute(t);
  else if (a === "copytxt") { try { await navigator.clipboard.writeText(t.dataset.txt || ""); toast("복사 완료", "ok"); } catch (err) { toast("복사 실패 — 직접 선택 후 Ctrl+C"); } }
  else if (a === "tb-use") {
    const r = await api.post("/api/testbed/use", { which: t.dataset.which, record_id: S.recordId || "" });
    if (!r.ok) { toast(r.error || "파일 교체 실패", "bad"); return; }
    toast(r.changed === false ? `이미 ${r.label} 파일 — 변경 없음` : t.dataset.which === "candidate" ? `${r.label} 파일 적용 — 다음: plan 확인 → 보안 그룹 제자리 수정만이면 후보 apply` : `${r.label} 파일로 복원`, "ok");
    await reloadStage2(); render();
  }
  else if (a === "calibrate") startJob("/api/proof/calibrate", { case_id: S.caseId }, "검증 도구 사전 점검", "calibrate");
  else if (a === "open-summary") openSummary();
  else if (a === "open-records") openRecords();
  else if (a === "open-settings") openSettings();
  else if (a === "close-overlay") closeOverlay();
  else if (a === "setup-tools") setupTools();
  else if (a === "toggle-console") toggleConsole();
  else if (a === "reload") location.reload();
});
$("#overlay").addEventListener("click", (e) => { if (e.target.id === "overlay") closeOverlay(); });
// 반영 확인 창: 'plan 내용을 확인했다' 에 체크해야 [실행] 이 켜진다
document.addEventListener("change", (e) => {
  if (e.target && e.target.id === "tbAck") { const b = $("#tbExec"); if (b) b.disabled = !e.target.checked; }
  else if (e.target && (e.target.id === "subFiles" || e.target.id === "subDir")) readPicked(e.target, e.target.id === "subDir");
});
// 접기·펼치기는 사람이 제목(summary)을 눌렀을 때만 기억한다 — toggle 이벤트는 처음부터 펼쳐 그릴 때도 생겨서, 그것까지 기억하면 다른 기록에서도 계속 펼쳐진다
document.addEventListener("click", (e) => {
  const sm = e.target instanceof Element ? e.target.closest("summary") : null;
  const d = sm ? sm.parentElement : null;
  if (!(d instanceof HTMLDetailsElement)) return;
  const willOpen = !d.open;
  if (d.classList.contains("pf-more")) { S.more = willOpen; const box = $("#proofPane"); if (box) box._last = null; }
  else if (d.classList.contains("ops")) S.opsOpen = willOpen;
  else if (d.classList.contains("more") && d.dataset.more) { S.moreP = S.moreP || {}; S.moreP[d.dataset.more] = willOpen; }
  else if (d.classList.contains("fold") && d.dataset.fold) {
    S.moreP = S.moreP || {}; S.moreP[d.dataset.fold] = willOpen;
    const sm2 = d.querySelector(":scope > summary small"); if (sm2) sm2.textContent = willOpen ? "접기" : "펼치기";
  }
}, true);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { hideCopyMenu(); closeOverlay(); } });

// ------------------------------------------------------------------ 글자 복사 (드래그로 고른 뒤 오른쪽 클릭 · Ctrl+C)
// 프로그램 창(pywebview)은 기본 오른쪽 클릭 메뉴가 꺼져 있다 → 고른 글자가 있을 때만 '복사' 메뉴를 직접 띄운다. Ctrl+C 는 원래 된다.
function hideCopyMenu() { const m = document.getElementById("copyMenu"); if (m) m.remove(); }
function copyText(t) {
  let ok = false;
  try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
  if (!ok && navigator.clipboard) { navigator.clipboard.writeText(t).then(() => toast("복사 완료", "ok"), () => toast("복사 실패 — Ctrl+C 사용", "bad")); return; }
  toast(ok ? "복사 완료" : "복사 실패 — Ctrl+C 사용", ok ? "ok" : "bad");
}
document.addEventListener("contextmenu", (e) => {
  hideCopyMenu();
  const sel = String(window.getSelection ? window.getSelection() : "");
  if (!sel.trim()) return;                          // 고른 글자가 없으면 아무것도 안 한다
  e.preventDefault();
  const m = document.createElement("div");
  m.id = "copyMenu"; m.className = "copymenu";
  m.innerHTML = `<button type="button">복사<small>Ctrl+C</small></button>`;
  document.body.appendChild(m);
  m.style.left = `${Math.max(4, Math.min(e.clientX, window.innerWidth - m.offsetWidth - 8))}px`;
  m.style.top = `${Math.max(4, Math.min(e.clientY, window.innerHeight - m.offsetHeight - 8))}px`;
  const btn = m.querySelector("button");
  btn.addEventListener("mousedown", (ev) => ev.preventDefault());   // 누르는 순간 고른 글자가 풀리지 않게
  btn.addEventListener("click", () => { copyText(sel); hideCopyMenu(); });
});
document.addEventListener("mousedown", (e) => { if (!(e.target instanceof Element) || !e.target.closest("#copyMenu")) hideCopyMenu(); }, true);
document.addEventListener("scroll", hideCopyMenu, true);
document.addEventListener("input", (e) => { if (e.target.id === "pasteBox") S.paste = e.target.value; });
// 통신 행·문제 행에 마우스를 올리면 그림에서 그 화살표만 강조 (마우스가 실제로 움직였을 때만)
let _mx = -1, _my = -1, _hk = null;
document.addEventListener("mousemove", (e) => {
  if (e.clientX === _mx && e.clientY === _my) return;
  _mx = e.clientX; _my = e.clientY;
  const f = e.target.closest("[data-flow]"), x = e.target.closest("[data-extra]");
  const key = f ? "f:" + f.dataset.flow : x ? "x:" + x.dataset.extra : null;
  if (key === _hk) return;
  _hk = key;
  if (T) T.highlight(f ? f.dataset.flow : null, x ? x.dataset.extra : null);
});

window.__iacpatch = { S, get T() { return T; } };
boot();
