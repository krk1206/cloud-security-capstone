// 새 프로그램 진입점 (2026-11-01 갈아엎기 3차 — B 문서 '스토리 중심 UI').
// 사용자는 V1~V8 을 배우려고 실행하지 않는다: '내 인프라에 문제가 있나 · 고쳐도 되나 · 서비스는 그대로인가' 를 알려고 실행한다.
// ① 시작 → ② 현재 인프라 → ③ 고객 설계 → ④ 보안 문제 → ⑤ 수정안 → ⑥ 적용 판단 → ⑦ 실제 AWS → ⑧ 최종 결정 · PR
import { $, S, api, render, go, toast, writeHash, modal, followJob, jumpTo, flash } from "./m_core.js";
import "./m_one.js";
import { showCoverage } from "./m_one.js";
import { structAct, structNote, dirty, reqImport, reqActivate } from "./m_struct.js";
import { zoomMap, closePop } from "./m_map.js";
import { loadRecord, runCandidate, runUpload, runAi, openAiRun, openAiAttempt, zoomPair, readPicked, decide, prPreview, prCreate, prCheck, showPrompt, refreshCands, testbedAct, refresh8 } from "./m_two.js";
import { runSetup, startTour, showGlossary, toggleBig, loadBig, toolsOk } from "./m_help.js";

async function boot() {
  const msg = (t) => { $("#mbootMsg").textContent = t; };
  loadBig();
  const app = await api.get("/api/app");
  if (app.error) { msg("서버 응답 없음: " + app.error); return; }
  S.app = app;
  const pr = await api.get("/api/p/projects");
  S.projects = (pr && pr.projects) || [];
  const h = new URLSearchParams(location.hash.slice(1));
  $("#mboot").classList.add("done");
  if (h.get("p") && S.projects.some((p) => p.id === h.get("p"))) {
    await openProject(h.get("p"), false);
    if (h.get("rec")) await loadRecord(h.get("rec"));
    const st = +h.get("s") || 2;
    S.step = Math.max(1, Math.min(8, st));
    if (S.step >= 6 && !S.rec) S.step = 5;
  }
  render();
  setInterval(() => api.post("/api/heartbeat"), 30000);
  api.post("/api/heartbeat");
}

// 프로젝트 열기: 현재 인프라 · 고객 설계 · 보안 문제 · 수정안 목록을 한꺼번에 (서버가 코드에서 계산)
async function openProject(pid, goNext = true) {
  if (S.pid !== pid) Object.assign(S, { issue: null, node: null, cand: null, rec: null, impact: null, verdict: null, final: null, edit: null, sedit: null, target: null, upload: null, pr: null, dec: null, src: null, issueFilter: "all", designView: "design", aiPick: null });
  if (S.pid !== pid) S.llm.view = null;
  S.pid = pid;
  S.proj = S.projects.find((p) => p.id === pid) || null;
  S.infra = S.design = S.issues = S.cands = null;
  if (goNext) { S.step = 2; writeHash(); render(); }
  await reloadProject();
  if (goNext) render();
  // 7차: 처음 여는 프로젝트(점검 전)는 도구가 있으면 바로 점검한다 — '점검 실행' 을 따로 찾지 않게. 실패한 점검을 되풀이하지는 않는다 (한 번만)
  const I = S.infra;
  if (goNext && I && !I.ok && I.need_scan && toolsOk() && !S.run && !S.autoScanned[pid]) { S.autoScanned[pid] = true; await startScan(); }
}

// 점검 시작: 도구가 없으면 시작하지 않고 '검사 도구 준비' 를 안내한다 (전에는 눌러도 반응이 없었음 — 7차)
async function startScan() {
  if (S.run) return;
  if (!toolsOk()) {
    S.app = await api.get("/api/app");
    if (!toolsOk()) { toast("검사 도구(Trivy · Terraform)가 없습니다 — 먼저 '검사 도구 준비하기' 를 누르세요"); render(); return; }
  }
  const r = await api.post("/api/case/scan", { case_id: S.pid });
  if (!r || !r.started) { toast((r && r.error) || "점검을 시작하지 못함 (다른 작업이 진행 중일 수 있음)"); return; }
  if (S.step !== 2) go(2);
  await watchScan("프로젝트 점검 (Trivy · Terraform plan)");
}

async function reloadProject() {
  const q = (u) => api.get(u);
  const id = encodeURIComponent(S.pid);
  let [infra, design, issues, cands, st] = await Promise.all([q(`/api/p/infra?id=${id}`), q(`/api/p/design?id=${id}`), q(`/api/p/issues?id=${id}`), q(`/api/case/candidates?id=${id}`), q("/api/llm/status")]);
  // 원하는 구조가 아직 없으면 자동 기준(지금 코드 − 위험한 통신)을 v1 로 저장하고 다시 읽는다 (D-33 — 설계도를 처음부터 입력하는 단계 없음)
  if (design && design.ok && !design.exists && design.can_auto) {
    const r = await api.post("/api/p/structure/auto", { project: S.pid });
    if (r && r.created) [design, issues, cands] = await Promise.all([q(`/api/p/design?id=${id}`), q(`/api/p/issues?id=${id}`), q(`/api/case/candidates?id=${id}`)]);
  }
  Object.assign(S, { infra, design, issues, cands });
  S.llm.status = st;
  const runs = await q(`/api/llm/runs?set=`);
  S.llm.runs = (runs && runs.runs) || [];
  const pr = await q("/api/p/projects");
  S.projects = (pr && pr.projects) || S.projects;
  S.proj = S.projects.find((p) => p.id === S.pid) || S.proj;
}

// 프로젝트 점검(Trivy · plan) 진행을 ② 화면에 보여 주고, 끝나면 다시 그린다
async function watchScan(label) {
  S.run = { kind: "scan", t0: Date.now(), since: 0, label, stages: [] }; S.log = [];
  render();
  const res = await followJob(async () => {
    const el = $("#mlog"); if (el) { el.textContent = S.log.slice(-10).join("\n"); el.scrollTop = el.scrollHeight; }
  });
  S.run = null;
  if (res.error) toast(`점검 실패: ${res.error}`);
  const lines = S.log.slice(-14);
  await reloadProject();
  // 점검이 끝났는데도 그림을 못 그리면 ② 에 그 기록을 남겨 보인다 (알림은 몇 초 뒤 사라지므로)
  S.scanLast = { pid: S.pid, at: new Date().toISOString(), ok: !!(S.infra && S.infra.ok), error: res.error || "", lines };
  render();
}

async function refreshProjects() {
  const pr = await api.get("/api/p/projects");
  S.projects = (pr && pr.projects) || S.projects;
}

// ------------------------------------------------------------------ 버튼
document.addEventListener("click", async (e) => {
  const t = e.target.closest("[data-go],[data-open],[data-act],[data-issue],[data-ifilter],[data-fix],[data-dview],[data-ver],[data-rver],[data-cand],[data-target],[data-ctx],[data-airun],[data-prompt],[data-rec],[data-dec],[data-src],[data-mzoom],[data-node-clear],[data-unlink],[data-sundo],[data-aiatt],[data-mapfull],[data-issue-go],[data-totop],[data-tb],[data-srcopen],[data-jump]");
  if (!t || t.disabled) return;
  const d = t.dataset;
  if (d.go) { go(+d.go); return; }
  if (d.tb) { await testbedAct(d.tb, d.kind || ""); return; }     // ⑦ AWS 시험 환경 (9차, D-43) — 반영 · 삭제는 testbedAct 안의 확인 창을 거친다
  if (d.jump) { flash(d.jump); return; }
  if (d.srcopen) { S.src = d.srcopen; render(); const el = $(".srcpanel"); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); return; }   // ⑤ '다음 할 일' 의 버튼: 토글이 아니라 펼치기만
  if (d.mzoom) { zoomMap(d.mzoom); return; }
  if (d.sundo !== undefined) { structAct("s-undo", t); return; }
  if (t.hasAttribute("data-mapfull")) { S.mapFull = !S.mapFull; render(); return; }
  if (d.totop) { const el = document.getElementById(d.totop); if (el) el.closest(".mcanvas").scrollIntoView({ behavior: "smooth", block: "start" }); return; }
  if (d.issueGo) { closePop(); S.issue = d.issueGo; S.issueFilter = "all"; go(4); return; }
  if (d.unlink) {
    const p = (S.projects || []).find((x) => x.id === d.unlink) || {};
    const m = modal("프로젝트 연결 끊기", `<p><b>${p.name || d.unlink}</b> 의 연결을 끊습니다. 이 프로그램의 점검 결과 · 고칠 대상 목록만 지우고, 연결했던 폴더 <code>${p.tf_dir || ""}</code> 는 그대로 둡니다.</p>
      <p class="small muted">고객 설계도 · 검토(검사) 기록 · AI 수정 기록은 지우지 않습니다 (증거 보존). 같은 폴더를 다시 연결하면 설계도가 다시 붙습니다.</p>
      <p>계속하려면 <b>연결 끊기</b> 를 입력하세요.</p><input id="ulConfirm" class="minput" placeholder="연결 끊기"><div class="mnav"><button type="button" class="mbtn primary" id="ulGo">끊기</button><button type="button" class="mbtn" data-close>취소</button></div>`);
    m.querySelector("#ulGo").addEventListener("click", async () => {
      const r = await api.post("/api/p/project/remove", { id: d.unlink, confirm: (m.querySelector("#ulConfirm") || {}).value || "" });
      if (!r || !r.ok) { toast((r && r.error) || "끊지 못함"); return; }
      m.remove();
      if (S.pid === d.unlink) { S.pid = null; S.proj = null; S.step = 1; writeHash(); }
      await refreshProjects(); render(); toast("연결을 끊음 (폴더는 그대로)", "good");
    });
    return;
  }
  if (t.hasAttribute("data-node-clear")) { S.node = null; render(); return; }
  if (d.src) { S.src = S.src === d.src ? null : d.src; render(); return; }
  if (d.open) { await openProject(d.open); return; }
  if (d.issue) { S.issue = d.issue; render(); return; }
  if (d.ifilter) { S.issueFilter = d.ifilter; render(); return; }
  if (d.fix) {
    // ④ 에서 고른 문제 → ⑤ 의 고칠 대상. 연결한 프로젝트는 고칠 대상(세트)을 그때 만든다
    const it = ((S.issues || {}).issues || []).find((x) => x.id === d.fix);
    if (!it || !(await pickFix(it))) return;
    if (!S.rec && (S.proj || {}).kind === "user") S.src = "ai";       // 연결한 프로젝트: 준비된 수정안이 없으니 AI 수정부터 펼쳐 둔다
    go(5); return;
  }
  if (d.dview) { S.designView = d.dview; render(); return; }
  if (d.ver) { askActivate(+d.ver); return; }
  if (d.rver) { if (!t.classList.contains("on")) await reqActivate(d.rver, async () => { await reloadProject(); }); return; }
  if (d.cand) {
    S.cand = d.cand; S.llm.view = null; S.src = null; S.aiPick = null;
    const c = (((S.cands || {}).sets || []).find((s) => s.set_id === S.target) || {}).candidates?.find((x) => x.id === d.cand);
    if (c && c.latest) await loadRecord(c.latest.id); else { S.rec = null; S.impact = null; S.verdict = null; render(); }
    // 7차: 펼친 수정안 목록에서 고르면 비교 그림이 화면 밖일 수 있다 — 그림으로 내려 준다 (목록은 그대로 두어 다른 수정안을 바로 고를 수 있게)
    const cw = $(".cmpwrap");
    if (cw && S.teamOpen && cw.getBoundingClientRect().top > window.innerHeight * 0.6) cw.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  if (d.target) { S.target = d.target; S.cand = null; S.rec = null; S.impact = null; S.verdict = null; S.llm.view = null; S.upload = null; render(); return; }
  if (d.ctx) { S.llm.context = d.ctx; render(); return; }
  if (d.airun) { await openAiRun(d.airun); return; }
  if (d.aiatt) { await openAiAttempt(d.aiatt); return; }
  if (d.prompt) { e.preventDefault(); showPrompt(d.prompt, d.n); return; }
  if (d.rec) { e.preventDefault(); await loadRecord(d.rec); return; }
  if (d.dec) { S.dec = d.dec; render(); return; }
  const a = d.act;
  if (a === "tour") startTour(S.step);
  else if (a === "goto-pr") await jumpTo(8, "#prcard");     // 왼쪽 메뉴 'PR 만들기' — ⑧ 의 PR 칸으로 가서 밝게 (이동만, PR 은 만들지 않음)
  else if (a === "glossary") showGlossary();
  else if (a === "big") toggleBig();
  else if (a === "setup") await runSetup(async () => { if (S.pid && S.infra && !S.infra.ok && S.infra.need_scan) await startScan(); });
  else if (a === "team-toggle") { S.teamOpen = !S.teamOpen; render(); }
  else if (a === "team-open") { S.teamOpen = true; render(); const el = $(".tlist"); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); }
  else if (a === "np-open") { S.npOpen = !S.npOpen; render(); const el = $("#npName"); if (S.npOpen && el) el.focus(); }
  else if (a === "coverage") showCoverage();
  else if (a === "s-clear" || a === "s-save" || a === "s-confirm" || a === "r-confirm") await structAct(a, t, async () => { await reloadProject(); });
  else if (a === "pair-zoom") zoomPair();
  else if (a === "run-cand") await runCandidate(S.cand);
  else if (a === "recheck") { const c = S.cand; if (c) await runCandidate(c); else toast("수정안을 다시 고르세요"); }
  else if (a === "run-upload") await runUpload();
  else if (a === "ai-run") await runAi();
  else if (a === "ai-refresh") { S.llm.status = await api.get("/api/llm/status?refresh=1"); render(); }
  else if (a === "decide") await decide();
  else if (a === "regen") { S.src = "ai"; go(5); }
  else if (a === "pr-check") await prCheck();
  else if (a === "pr-preview") await prPreview();
  else if (a === "pr-create") prCreate();
  else if (a === "activate") {
    const r = await api.post("/api/design/activate", { set_id: S.design.set_id, version: +d.v });
    if (!r || !r.ok) { toast((r && (r.errors || [r.error]).join(" ")) || "바꾸지 못함"); return; }
    await reloadProject(); toast(`지금 기준 = 고객 설계도 v${r.version}`, "good"); render();
  } else if (a === "no-activate") { const b = $("#verAsk"); if (b) b.innerHTML = ""; }
  else if (a === "scan") await startScan();
  else if (a === "np-check") {
    S.np = { name: ($("#npName") || {}).value || "", path: ($("#npPath") || {}).value || "" };
    S.np.info = await api.post("/api/p/project/inspect", { path: S.np.path });
    render();
  } else if (a === "np-create") {
    S.np = { name: ($("#npName") || {}).value || "", path: ($("#npPath") || {}).value || "", info: (S.np || {}).info };
    const r = await api.post("/api/p/project/create", S.np);
    if (!r || !r.ok) { S.np.info = (r && r.inspect) || { ok: false, errors: (r && (r.errors || [r.error])) || ["연결 실패"], notes: [] }; render(); return; }
    if (r.existing) toast("이미 연결한 폴더 — 그 프로젝트를 엽니다", "good");
    S.np = null; S.npOpen = false;
    if (r.started) S.autoScanned[r.project] = true;     // 서버가 이미 점검을 시작함 — 여는 쪽에서 또 시작하지 않게
    await refreshProjects();
    await openProject(r.project);
    if (r.started) await watchScan("프로젝트 점검 (Trivy · Terraform plan)");
  }
});

// 고칠 문제 → ⑤ 의 고칠 대상 (연결한 프로젝트는 대상 세트를 그때 만든다)
async function pickFix(it) {
  if (!it || !it.fix) return false;
  let sid = it.fix.set_id;
  if (!sid && it.fix.target) {
    const r = await api.post("/api/p/target", { project: S.pid, rule: it.fix.target.rule, resource: it.fix.target.resource });
    if (!r || !r.ok) { toast((r && r.error) || "고칠 대상을 만들지 못함"); return false; }
    sid = r.set_id;
    await refreshCands();
    S.issues = await api.get(`/api/p/issues?id=${encodeURIComponent(S.pid)}`);
  }
  if (!sid) return false;
  if (S.target !== sid) Object.assign(S, { cand: null, rec: null, impact: null, verdict: null, final: null, upload: null, src: null });
  S.target = sid; S.issue = it.id; S.llm.view = null;
  return true;
}

function askActivate(v) {
  const cur = ((S.design || {}).design || {}).active_version;
  if (v === cur || dirty()) return;
  const box = $("#verAsk");
  if (!box) return;
  box.innerHTML = `<div class="mcard warn small">v${v} 을(를) 지금 기준으로 바꿀까요? 앞으로 검사 · AI 수정이 v${v} 기준으로 돌고, 이미 끝난 결과는 그때 기준 그대로 남습니다.
    <div class="mnav"><button type="button" class="mbtn primary" data-act="activate" data-v="${v}">v${v} 로 바꾸기</button><button type="button" class="mbtn" data-act="no-activate">취소</button></div></div>`;
}

document.addEventListener("input", (e) => {
  if (e.target.id === "npName" || e.target.id === "npPath") { S.np = { ...(S.np || {}), [e.target.id === "npName" ? "name" : "path"]: e.target.value }; return; }
  if (e.target.id === "sNote") structNote(e.target.value);
  // ⑧ 이유 · 이름 · 미검증 확인, ⑦ 프로필 — 다시 그려도 지워지지 않게 상태에 둔다 (9차: 결정 카드를 누르면 적어 둔 이유가 사라지던 버그)
  if (e.target.id === "decReason" || e.target.id === "decBy") { S.decForm = { ...(S.decForm || {}), [e.target.id === "decReason" ? "reason" : "by"]: e.target.value }; refresh8(); return; }
  if (e.target.id === "tbProfile" && S.tb) S.tb.profile = e.target.value.trim();
});
document.addEventListener("change", (e) => {
  if (e.target.id === "decAck") { S.decForm = { ...(S.decForm || {}), ack: e.target.checked }; refresh8(); }
});
document.addEventListener("change", (e) => {
  if (e.target.id === "upFiles") readPicked(e.target, false);
  if (e.target.id === "upDir") readPicked(e.target, true);
  if (e.target.dataset && e.target.dataset.reqfile) reqImport(e.target, async () => { await reloadProject(); });
});
window.addEventListener("hashchange", () => {});

boot();
export { refreshCands };
