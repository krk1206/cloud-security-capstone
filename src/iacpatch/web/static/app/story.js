// 흐름 화면 (첫 화면). 2026-11-01 갈아엎기 2차 — B: "설계도 따라 토폴로지가 바뀌게. Redis · MySQL 필요 없으면 빼고, 필요하면 넣고."
//   ① 고객 설계도   편집 가능 (구성요소 · 외부 출처 · 통신 추가/삭제). 저장하면 새 버전 = 지금 기준 (web/designs.py, D-30).
//                   편집하는 동안 그림은 '이 설계도 + 지금 코드' 를 겹쳐 그린다 — 설계에서 뺐는데 코드에 남은 리소스는 빨간 상자.
//   ② 지금 코드     Trivy 가 찾은 것 / 설계도로만 보이는 것 (설계에 없는 연결 · 설계에 없는 리소스 · 코드에 없는 구성요소)
//   ③ 수정 코드     AI 에게 고치게 하기 (Claude Code, 막히면 이유를 붙여 최대 3번 — llmfix, D-27) · 팀 평가용 수정안 · 직접 제출
//   ④ 8개 관문      검사 중 (AI 수정이면 시도별로)
//   ⑤ 결과          어느 설계도 버전 기준 결과인지. 지금 기준과 다르면 다시 검사
// 판정은 만들지 않는다 — 서버 기록을 그대로 보여 준다. apply · 승인 같은 사람 전용 조작은 이 화면에 없다 (작업 화면 5 · 6단계).

import { Topology } from "./topo.js";

const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const api = {
  async get(u) { try { const r = await fetch(u); return await r.json(); } catch (e) { return { error: String(e) }; } },
  async post(u, b) { try { const r = await fetch(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return await r.json(); } catch (e) { return { error: String(e) }; } },
};

// 8개 관문 — 교수님이 주신 질문 그대로 (배포 전 6개 + 실제 AWS 2개)
const GATES = [
  ["V1", "기존 보안 문제가 해결됐나요?"], ["V2", "수정하면서 새로운 문제가 생겼나요?"], ["V3", "Terraform 코드가 올바르게 작성됐나요?"],
  ["V4", "이 코드를 실행하면 무엇이 변경되나요?"], ["V5", "허용하지 않은 부분까지 수정했나요?"], ["V6", "고객이 원하는 통신 구조를 유지하나요?"],
  ["V7", "실제 AWS에도 예상대로 적용됐나요?"], ["V8", "실제 연결과 차단이 정상적으로 동작하나요?"],
];
const CHAPTERS = ["고객 설계도", "지금 코드", "수정 코드", "8개 관문", "결과"];
const RULE_KO = { "AVD-AWS-0107": "SSH(22) · RDP(3389)를 인터넷 전체(0.0.0.0/0)에 열어 둠", "AVD-AWS-0104": "아웃바운드를 인터넷 전체로 허용",
  "AVD-AWS-0345": "S3 권한을 무제한(s3:*)으로 줌", "AVD-AWS-0342": "역할 전달 권한(iam:PassRole)을 제한 없이 줌" };
const STAGE_GATES = { trivy_after: ["V1", "V2"], plan_candidate: ["V3", "V4"], verify: ["V5", "V6"] };
const VERDICT = { PASS: ["pass", "통과"], FAIL: ["fail", "실패"], UNKNOWN: ["unknown", "판정 불가"], ERROR: ["unknown", "오류"], NOT_RUN: ["skip", "미실행"], SKIPPED: ["skip", "건너뜀"],
  DONE: ["done", "계산 끝"] };
const KIND_SUB = { elb: "로드밸런서", ec2: "서버 (EC2)", ecs: "컨테이너 서비스 (ECS)", rds: "데이터베이스 (RDS)", elasticache: "캐시 (ElastiCache)" };
const AI_ST = { PASSED: ["ok", "통과"], BLOCKED: ["bad", "막힘"], AI_ERROR: ["bad", "AI 오류"], GAVE_UP: ["bad", "3번 모두 막힘 — 사람이 직접 수정"], REPEATED: ["bad", "같은 수정안 반복 — 중단"], TOOL_ERROR: ["warn", "실행 오류 — 환경 복구 후 다시"], UNDECIDABLE: ["warn", "검증 불가 — 사람 검토"], RUNNING: ["run", "진행 중"], ASKING: ["run", "AI 답 기다리는 중"] };

const S = { ch: 1, maxCh: 1, caseId: null, setId: null, case: null, current: null, cands: null, model: null, design: null, edit: null,
  sel: null, src: null, record: null, run: null, gates: {}, log: [], recCache: {},
  ai: { status: null, context: "trivy", runs: [], live: null, view: null } };
let T = null;

// ------------------------------------------------------------------ 자료
const curSet = () => ((S.current && S.current.sets) || []).find((s) => s.set_id === S.setId) || {};
const curTopo = () => curSet().topology || {};
const candList = () => ((((S.cands && S.cands.sets) || []).find((s) => s.set_id === S.setId) || {}).candidates || []).filter((c) => !/^(paste|upload)/.test(String(c.id)) && !/^ai-\d{8}-\d{6}-[0-9a-f]{6}-a\d+$/.test(String(c.id)))
  .slice().sort((a, b) => String(a.label).localeCompare(String(b.label), "ko", { numeric: true }));
const flowStates = (rows) => Object.fromEntries((rows || []).filter((r) => String(r.id).startsWith("flow:")).map((r) => {
  const v = r.verdict || (r.after || {}).verdict; return [r.id.slice(5), v === "PASS" ? "ok" : v === "FAIL" ? "broken" : v === "UNKNOWN" ? "unknown" : "design"];
}));
const topoStates = (flows) => Object.fromEntries((flows || []).map((f) => [f.id, f.status === "ok" ? "ok" : f.status === "broken" ? "broken" : f.status === "unknown" ? "unknown" : "design"]));
const nodeLabel = (id, m = S.model) => ((m && m.nodes) || []).find((n) => n.id === id)?.label || id;
const sgOf = (id) => ((S.model && S.model.nodes) || []).find((n) => n.id === id)?.security_group || "";
const activeV = () => (S.design && S.design.active_version) || 1;
const activeSha = () => (((S.design && S.design.versions) || []).find((v) => v.active) || {}).sha256;
const fmt = (iso) => { const t = String(iso || ""); return t.length >= 16 ? `${+t.slice(5, 7)}/${+t.slice(8, 10)} ${t.slice(11, 16)}` : t; };
// ① 보기용: 설계도만 (코드에만 있는 리소스 · 코드 상태 표시를 뺀다)
const designOnly = (m) => (m && m.ok ? { ...m, nodes: (m.nodes || []).filter((n) => n.kind !== "unmapped").map((n) => ({ ...n, code: null, sub: n.kind === "tier" ? (KIND_SUB[n.icon] || n.sub) : n.sub })) } : m);

async function boot() {
  const msg = (t) => { $("#sbootMsg").textContent = t; };
  const app = await api.get("/api/app");
  if (app.error) { msg("서버 응답 없음: " + app.error); return; }
  const cases = await api.get("/api/cases");
  msg("사례 · 설계도 불러오는 중…");
  for (const c of cases.cases || []) {           // 토폴로지 설계도가 있는 첫 사례 (흐름 화면은 설계도 그림이 중심)
    const cs = await api.get(`/api/case?id=${encodeURIComponent(c.id)}`);
    const st = (cs.sets || []).find((s) => s.intent_kind === "topology");
    if (st) { S.caseId = c.id; S.case = cs; S.setId = st.set_id; break; }
  }
  if (!S.caseId) { msg("토폴로지 설계도가 있는 사례 없음 — 작업 화면(/work)을 쓰세요"); return; }
  await reloadAll(true);
  T = new Topology($("#sdia"), S.model);
  Topology.setDefault(S.model);
  $("#sboot").classList.add("done");
  render();
  loadAi();
  setInterval(() => api.post("/api/heartbeat"), 30000);
  api.post("/api/heartbeat");
}

// 설계도가 바뀌면(저장 · 기준 바꾸기) 사례 · 지금 코드 · 수정안 목록을 전부 다시 읽는다 (서버가 '지금 기준' 으로 다시 계산)
async function reloadAll(first = false) {
  const q = (u) => api.get(u);
  const [design, model, cands, cs] = await Promise.all([q(`/api/design?set=${encodeURIComponent(S.setId)}`), q(`/api/topology?case=${encodeURIComponent(S.caseId)}&set=${encodeURIComponent(S.setId)}`),
    q(`/api/case/candidates?id=${encodeURIComponent(S.caseId)}`), first ? Promise.resolve(S.case) : q(`/api/case?id=${encodeURIComponent(S.caseId)}`)]);
  Object.assign(S, { design, model, cands, case: cs });
  if (T) { T.setModel(S.model); Topology.setDefault(S.model); }
  S.current = null;
  q(`/api/case/current?id=${encodeURIComponent(S.caseId)}`).then((c) => { S.current = c; if (S.ch === 2) render(); });
}

async function loadAi() {
  const [st, runs] = await Promise.all([api.get("/api/llm/status"), api.get(`/api/llm/runs?set=${encodeURIComponent(S.setId)}`)]);
  S.ai.status = st; S.ai.runs = (runs && runs.runs) || [];
  if (S.ch === 3 && !S.run) render();
}

// ------------------------------------------------------------------ 그리기
function render() {
  // 관문 막대 = 지금 보고 있는 결과. ①~③ 에서는 비우고, ⑤ 로 돌아오면 그 기록 값으로 다시 (검사 중에는 손대지 않음)
  if (!S.run && S.ch <= 3) S.gates = {};
  else if (!S.run && !S.anim && S.ch === 5 && S.record && !Object.keys(S.gates).length) (S.record.layers || []).forEach((l) => { S.gates[l.layer] = { verdict: l.verdict, summary: l.summary }; });
  renderChapters();
  renderGates();
  ({ 1: ch1, 2: ch2, 3: ch3, 4: ch4, 5: ch5 }[S.ch] || ch1)();
}
function go(n) { if (n > S.maxCh || S.run || S.edit) return; S.ch = n; render(); }
function unlock(n) { S.maxCh = Math.max(S.maxCh, n); }

function renderChapters() {
  $("#chapters").innerHTML = CHAPTERS.map((t, i) => {
    const n = i + 1;
    const off = n > S.maxCh || S.run || S.edit;
    return `<li><button type="button" data-ch="${n}" class="${n === S.ch ? "cur" : n < S.ch || n <= S.maxCh ? "done" : ""}" ${off ? "disabled" : ""}><em>${n}</em>${esc(t)}</button></li>`;
  }).join("");
  $("#workLink").href = S.record ? `/work#rec=${encodeURIComponent(S.record.id)}` : "/work";
  $("#dver").textContent = S.design && S.design.ok ? `설계도 v${activeV()}` : "";
}

function renderGates() {
  const cell = ([k, q]) => {
    const g = S.gates[k] || {};
    const aws = k === "V7" || k === "V8";
    // V7 · V8 은 실제 AWS 시험 환경에서만 — 배포 전 검사 기록의 '미실행' 은 '검사 전' 으로 (실패처럼 보이지 않게)
    const [cls, word] = g.run ? ["run", "검사 중"] : aws && (!g.verdict || g.verdict === "NOT_RUN") ? ["", "검사 전"] : (VERDICT[g.verdict] || ["", "대기"]);
    return `<div class="gate ${cls}" data-gate="${k}" title="${esc(g.summary || q)}"><div class="gk">${k}<i>${esc(word)}</i></div><div class="gq">${esc(q)}</div></div>`;
  };
  $("#gates").innerHTML = `<div class="gl">배포 전<br>코드 검사</div>${GATES.slice(0, 6).map(cell).join("")}<div class="gsep"></div><div class="gl">실제 AWS<br>시험 환경</div>${GATES.slice(6).map(cell).join("")}`;
}

function diagram(title, note, model, flows, extras) {
  $("#sdTitle").textContent = title;
  $("#sdNote").textContent = note || "";
  if (T) T.setModel(model || S.model).render(flows || {}, extras || []);
}

function card(html) { $("#scard").innerHTML = html; $("#scard").scrollTop = 0; }

// ------------------------------------------------------------------ ① 고객 설계도
function versionStrip() {
  const vs = (S.design && S.design.versions) || [];
  return `<div class="vstrip">${vs.map((v) => `<button type="button" class="vchip ${v.active ? "on" : ""}" data-ver="${v.version}" title="${esc(v.note || v.changes || "")}">v${v.version}${v.version === 1 ? " · 실험 기준" : ""}${v.active ? " · 지금 기준" : ""}</button>`).join("")}</div>`;
}

function ch1() {
  if (S.edit) { ch1Edit(); return; }
  const D = S.design || {};
  const m = designOnly(S.model) || {};
  const flows = m.flows || [];
  const nTier = (m.nodes || []).filter((n) => n.kind === "tier").length;
  const nExt = (m.nodes || []).filter((n) => n.kind === "external").length;
  diagram(`고객 설계도 v${activeV()}`, `회색 화살표 = 고객이 허용한 통신 ${flows.length}개. 이 선 밖의 연결은 모두 막혀 있어야 함. 설계도를 바꾸면 그림도 검사 기준도 바뀜.`, m, {}, []);
  const av = ((D.versions || []).find((v) => v.active) || {});
  const editable = D.ok && D.editable;
  card(`<div class="kicker">① 고객이 원하는 구조</div>
    <h2>기준은 우리가 아니라 고객 설계도</h2>
    <p class="lead">고객이 "이 통신만 허용"이라고 정한 설계도로 검사함. 구성요소(서버 · DB · 캐시 등)와 통신은 고객 요구에 따라 넣고 뺄 수 있고, 바꾸면 새 버전으로 저장돼 그 기준으로 처음부터 다시 검사함.</p>
    ${versionStrip()}
    ${activeV() !== 1 && av.changes ? `<div class="vchange"><b>v${esc(av.from_version || 1)} → v${activeV()} 바뀐 것</b>${esc(av.changes)}${av.note ? `<small>이유: ${esc(av.note)}</small>` : ""}</div>` : ""}
    <div class="big"><div><b>${nTier}</b><span>구성요소</span></div><div><b>${flows.length}</b><span>허용 통신</span></div><div><b>${nExt}</b><span>외부 출처</span></div></div>
    <ul class="slist">${flows.map((f) => `<li>${esc(nodeLabel(f.src, m))} → ${esc(nodeLabel(f.dst, m))} <b>:${esc(f.ports)}</b><small>${esc(f.label || "")}</small></li>`).join("")}</ul>
    <div id="verAsk"></div>
    <div class="sbtns">${editable ? `<button class="sbtn" data-act="edit">설계도 바꾸기</button>` : ""}<button class="sbtn primary" data-act="to2">다음 ▶ 지금 코드 검사 결과</button></div>`);
}

// 편집: 초안(S.edit.draft)을 고치고, 바꿀 때마다 서버에 미리보기(저장 안 함)를 물어 그림을 다시 그린다
function startEdit() {
  const d = JSON.parse(JSON.stringify((S.design && S.design.design) || {}));
  S.edit = { draft: { vpc_cidr: d.vpc_cidr, tiers: d.tiers || [], external: d.external || [], flows: d.flows || [] }, note: "", preview: null, errors: [], seq: 0 };
  render();
  schedulePreview(0);
}

const uid = (p) => p + Math.random().toString(36).slice(2, 7).replace(/[^a-z0-9]/g, "x");
const portText = (f) => (f.protocol === "-1" ? "전체" : f.port != null ? String(f.port) : f.from_port != null ? (f.from_port === f.to_port ? String(f.from_port) : `${f.from_port}-${f.to_port}`) : "");
const sgShort = (a) => String(a || "").split(".").pop();

function sgOptions(cur) {
  const list = (S.design && S.design.code_security_groups) || [];
  const used = new Set(((S.edit && S.edit.draft.tiers) || []).map((t) => t.security_group));
  const opts = list.map((g) => `<option value="${esc(g.address)}" ${g.address === cur ? "selected" : ""}>${esc(sgShort(g.address))}${g.resources.length ? ` · 리소스 ${g.resources.length}` : " · 리소스 없음"}${used.has(g.address) && g.address !== cur ? " (사용 중)" : ""}</option>`);
  if (cur && !list.some((g) => g.address === cur)) opts.unshift(`<option value="${esc(cur)}" selected>${esc(sgShort(cur))} · 코드에 없음</option>`);
  return opts.join("") + `<option value="__new">＋ 새 보안 그룹 이름…</option>`;
}

function ch1Edit() {
  const E = S.edit, d = E.draft;
  const nextV = Math.max(...((S.design.versions || []).map((v) => v.version)), 1) + 1;
  drawPreview();
  const typeSel = (t) => `<select data-f="type" title="종류 (그림 아이콘)"><option value="">종류 자동</option>${Object.entries(KIND_SUB).map(([k, v]) => `<option value="${k}" ${t.type === k ? "selected" : ""}>${esc(v)}</option>`).join("")}</select>`;
  const srcOpts = (cur) => [...d.external.map((e) => [e.id, `${e.label || e.id} (외부)`]), ...d.tiers.map((t) => [t.id, t.label || t.id])]
    .map(([id, l]) => `<option value="${esc(id)}" ${id === cur ? "selected" : ""}>${esc(l)}</option>`).join("");
  const dstOpts = (cur) => d.tiers.map((t) => `<option value="${esc(t.id)}" ${t.id === cur ? "selected" : ""}>${esc(t.label || t.id)}</option>`).join("");
  card(`<div class="kicker">① 설계도 편집 · v${activeV()} 에서 → 저장하면 v${nextV}</div>
    <h2>구성요소 · 통신 바꾸기</h2>
    <p class="lead">필요 없는 구성요소는 지우고, 필요한 건 넣어. 바꿀 때마다 왼쪽 그림이 '이 설계도 + 지금 코드' 로 다시 그려짐 (저장 전에는 기준이 안 바뀜).</p>
    <div class="ed-sec"><div class="ed-h"><b>구성요소 ${d.tiers.length}</b><span>종류 · 이름 · 코드의 보안 그룹</span><button class="mini" data-act="addTier">+ 구성요소</button></div>
      ${d.tiers.map((t, i) => `<div class="ed-row tier" data-k="tiers" data-i="${i}">${typeSel(t)}<input data-f="label" value="${esc(t.label)}" placeholder="이름 (예: 캐시)">
        <select data-f="sg">${sgOptions(t.security_group)}</select><button class="x" data-act="del" title="삭제">×</button></div>`).join("")}</div>
    <div class="ed-sec"><div class="ed-h"><b>외부 출처 ${d.external.length}</b><span>이름 · IP 대역 (쉼표로)</span><button class="mini" data-act="addExt">+ 외부 출처</button></div>
      ${d.external.map((e, i) => `<div class="ed-row ext" data-k="external" data-i="${i}"><input data-f="label" value="${esc(e.label)}" placeholder="이름"><input data-f="cidrs" value="${esc((e.cidrs_v4 || []).join(", "))}" placeholder="203.0.113.0/24">
        <button class="x" data-act="del" title="삭제">×</button></div>`).join("")}</div>
    <div class="ed-sec"><div class="ed-h"><b>허용 통신 ${d.flows.length}</b><span>출발 → 도착 · 포트</span><button class="mini" data-act="addFlow">+ 통신</button></div>
      ${d.flows.map((f, i) => `<div class="ed-row flow" data-k="flows" data-i="${i}"><select data-f="from">${srcOpts(f.from)}</select><span class="ar">→</span><select data-f="to">${dstOpts(f.to)}</select>
        <input data-f="port" value="${esc(portText(f))}" placeholder="443" ${f.protocol === "-1" ? "disabled" : ""}><select data-f="proto"><option value="tcp" ${f.protocol === "tcp" || !f.protocol ? "selected" : ""}>TCP</option><option value="udp" ${f.protocol === "udp" ? "selected" : ""}>UDP</option><option value="-1" ${f.protocol === "-1" ? "selected" : ""}>전체</option></select>
        <button class="x" data-act="del" title="삭제">×</button></div>`).join("")}</div>
    <div id="edCheck" class="ed-check">${checkHtml()}</div>
    <label class="ed-note">바꾼 이유 (기록에 남음)<input data-f="note" value="${esc(E.note)}" placeholder="예: 세션을 DB 에 저장해서 Redis 안 씀"></label>
    <div class="sbtns"><button class="sbtn primary" data-act="saveDesign" ${E.saving ? "disabled" : ""}>저장 → v${nextV} (지금 기준으로)</button><button class="sbtn" data-act="cancelEdit">취소</button></div>`);
}

function checkHtml() {
  const E = S.edit;
  if (!E) return "";
  if (E.errors && E.errors.length) return `<b class="bad">저장할 수 없음</b><ul>${E.errors.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`;
  const p = E.preview;
  if (!p) return `<span class="muted">지금 코드와 비교 중…</span>`;
  if (!p.computed) return `<span class="muted">${esc(p.reason || "원본 plan 없음")} — 그림만 바뀜 (코드 비교는 '원본 점검' 뒤)</span>`;
  const t = p.topology || {};
  const ex = (t.excess || []).filter((e) => e.kind !== "undesigned_target").length;
  const und = (t.undesigned || []).filter((u) => u.inbound > 0).length;
  const br = (t.flows || []).filter((f) => f.status === "broken").length;
  const miss = (t.tiers || []).filter((x) => x.sg_in_code === false).length;
  const ch = (p.changes && !p.changes.empty) ? `<div class="small" style="margin-top:6px">바뀐 것: ${esc(p.changes.text)}</div>` : `<div class="small muted" style="margin-top:6px">아직 바뀐 것 없음</div>`;
  return `<b>이 설계도로 지금 코드를 보면</b><div class="ed-nums"><span class="${ex ? "bad" : ""}"><i>${ex}</i>설계에 없는 연결</span><span class="${und ? "bad" : ""}"><i>${und}</i>설계에 없는 리소스</span>
    <span class="${br ? "warn" : ""}"><i>${br}</i>막힌 필수 통신</span><span class="${miss ? "warn" : ""}"><i>${miss}</i>코드에 없는 구성요소</span></div>${ch}`;
}

function drawPreview() {
  const E = S.edit;
  if (!E) return;
  const p = E.preview;
  if (p && p.ok && p.model) {
    const t = p.topology || {};
    diagram("설계도 편집 중 — 이 설계도로 본 지금 코드", p.computed ? "빨간 상자 = 코드에는 있는데 설계도에 없는 리소스 · 점선 상자 = 설계도에는 있는데 코드에 없는 구성요소 · 빨간 점선 = 설계에 없는 연결." : "원본 plan 이 없어 설계도만 그림.",
      p.model, topoStates(t.flows), t.excess || []);
  } else if (!p) diagram("설계도 편집 중", "지금 코드와 비교 중…", designOnly(S.model), {}, []);
}

let previewTimer = null;
function schedulePreview(ms = 320) {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(async () => {
    const E = S.edit;
    if (!E) return;
    const seq = ++E.seq;
    const r = await api.post("/api/design/preview", { set_id: S.setId, design: E.draft });
    if (!S.edit || seq !== S.edit.seq) return;
    if (r && r.ok) { E.preview = r; E.errors = []; drawPreview(); }
    else E.errors = (r && (r.errors || [r.error])) || ["미리보기 실패"];
    const box = $("#edCheck"); if (box) box.innerHTML = checkHtml();
  }, ms);
}

function editInput(t) {
  const E = S.edit;
  if (!E) return;
  if (t.dataset.f === "note") { E.note = t.value; return; }
  const row = t.closest("[data-k]");
  if (!row) return;
  const item = E.draft[row.dataset.k][+row.dataset.i];
  const f = t.dataset.f;
  if (row.dataset.k === "tiers") {
    if (f === "label") item.label = t.value;
    else if (f === "type") { if (t.value) item.type = t.value; else delete item.type; }
    else if (f === "sg") {
      if (t.value === "__new") {          // 새 보안 그룹 이름: 선택 칸을 입력 칸으로 바꾼다
        const inp = document.createElement("input");
        inp.dataset.f = "sgnew"; inp.placeholder = "보안 그룹 이름 (예: cache)";
        t.replaceWith(inp); inp.focus(); return;
      }
      item.security_group = t.value;
    } else if (f === "sgnew") item.security_group = t.value.trim() ? `aws_security_group.${t.value.trim()}` : "";
  } else if (row.dataset.k === "external") {
    if (f === "label") item.label = t.value;
    else if (f === "cidrs") item.cidrs_v4 = t.value.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
  } else if (row.dataset.k === "flows") {
    if (f === "from" || f === "to") item[f] = t.value;
    else if (f === "proto") {
      item.protocol = t.value;
      const pin = row.querySelector('[data-f="port"]');
      if (t.value === "-1") { delete item.port; delete item.from_port; delete item.to_port; if (pin) { pin.value = "전체"; pin.disabled = true; } }
      else if (pin) { pin.disabled = false; if (pin.value === "전체") pin.value = ""; }
    } else if (f === "port") {
      delete item.port; delete item.from_port; delete item.to_port;
      const m = t.value.trim().match(/^(\d+)\s*(?:-\s*(\d+))?$/);
      if (m && m[2]) { item.from_port = +m[1]; item.to_port = +m[2]; } else if (m) item.port = +m[1]; else item.port = t.value.trim();
    }
  }
  schedulePreview();
}

function editAct(a, t) {
  const E = S.edit, d = E.draft;
  if (a === "addTier") {
    const id = uid("c");
    d.tiers.push({ id, label: "", security_group: "" });
  } else if (a === "addExt") d.external.push({ id: uid("x"), label: "", cidrs_v4: [] });
  else if (a === "addFlow") {
    const from = (d.external[0] || d.tiers[0] || {}).id, to = (d.tiers[0] || {}).id;
    d.flows.push({ id: uid("f"), from, to, protocol: "tcp", port: 443 });
  } else if (a === "del") {
    const row = t.closest("[data-k]");
    const k = row.dataset.k, i = +row.dataset.i;
    const gone = d[k][i];
    d[k].splice(i, 1);
    if (k !== "flows") d.flows = d.flows.filter((f) => f.from !== gone.id && f.to !== gone.id);   // 지운 구성요소 · 출처의 통신도 같이
  }
  render();
  schedulePreview(0);
}

async function saveDesign() {
  const E = S.edit;
  E.saving = true; render();
  const r = await api.post("/api/design/save", { set_id: S.setId, design: E.draft, note: E.note, base_version: activeV() });
  if (!r || !r.ok) { E.saving = false; E.errors = (r && (r.errors || [r.error])) || ["저장 실패"]; render(); return; }
  S.edit = null; S.record = null; S.gates = {}; S.recCache = {};
  await reloadAll();
  render();
  toast(`설계도 v${r.version} 저장 — 이제부터 검사는 v${r.version} 기준. ${r.changes && r.changes.text ? r.changes.text : ""}`, "good");
}

async function askActivate(v) {
  if (v === activeV() || S.edit) return;
  const box = $("#verAsk");
  if (!box) return;
  box.innerHTML = `<div class="vask">v${v} 을(를) 지금 기준으로 바꿀까? 앞으로 검사 · AI 수정이 v${v} 기준으로 돌고, 이미 끝난 결과는 그때 기준 그대로 남음.
    <div class="sbtns"><button class="sbtn primary" data-act="activate" data-v="${v}">v${v} 로 바꾸기</button><button class="sbtn" data-act="noActivate">취소</button></div></div>`;
}

// ------------------------------------------------------------------ ② 지금 코드 — Trivy 가 찾은 것 / 고객 설계 기준으로만 보이는 것
function ch2() {
  unlock(2);
  const cur = curSet();
  const f = (S.case && S.case.findings) || {};
  const inScope = (f.in_scope || []).filter((x) => x.set_id === S.setId);
  const outN = (f.out_of_scope || []).length;
  const tp = curTopo();
  const ex = (tp.excess || []).filter((e) => e.kind !== "undesigned_target");
  const toUnd = (tp.excess || []).filter((e) => e.kind === "undesigned_target");
  const undAll = tp.undesigned || [];
  const broken = (tp.flows || []).filter((x) => x.status === "broken");
  const missing = (tp.tiers || []).filter((x) => x.sg_in_code === false);
  if (!S.current) { diagram("지금 코드의 구조", "원본 코드 계산 중…", S.model, {}, []); card(`<div class="kicker">② 지금 코드</div><h2>원본 코드 계산 중…</h2>`); return; }
  if (!cur.ok) {
    diagram("지금 코드의 구조", cur.reason || (S.current && S.current.reason) || "원본 실행 계획(plan) 없음", S.model, {}, []);
    card(`<div class="kicker">② 지금 코드</div><h2>원본 코드 검사 결과 없음</h2><p class="lead">${esc(cur.reason || (S.current && S.current.reason) || "")}</p>
      <p class="lead">작업 화면에서 '원본 점검 실행'을 하면 이 PC 의 Terraform 으로 계산함 (AWS 접속 없음).</p><div class="sbtns"><a class="sbtn" href="/work">작업 화면 열기</a></div>`);
    return;
  }
  const nBad = ex.length + toUnd.length;
  diagram(`지금 코드의 구조 · 설계도 v${activeV()} 기준`, nBad || missing.length ? `빨간 점선 = 지금 코드가 허용하는데 설계도에는 없는 연결 ${nBad}곳.${undAll.length ? ` 빨간 상자 = 설계도에 없는 리소스 ${undAll.length}개.` : ""}${missing.length ? ` 점선 상자 = 코드에 없는 구성요소 ${missing.length}개.` : ""}` : "고객 설계도와 같은 구조.",
    S.model, flowStates(cur.rows), tp.excess || []);
  const trivyRes = new Set(inScope.map((x) => x.resource));
  const seenBy = (e) => trivyRes.has(sgOf(e.dst));
  const items = ex.map((e) => {
    const hit = seenBy(e);
    return `<li class="${hit ? "" : "bad"}"><span class="chip ${hit ? "warn" : "bad"}">${hit ? "Trivy 도 찾음" : "Trivy 는 못 봄"}</span>${esc(e.src_label)} → ${esc(e.dst_label)} <b>:${esc(e.ports)}</b>
      <small>${hit ? "인터넷 전체 공개 같은 알려진 위험 규칙이라 Trivy 규칙에 걸림" : "규칙 자체는 흔한 설정이라 Trivy 는 문제로 안 봄 — 고객 설계도에 없는 연결이라 우리가 찾음"}</small></li>`;
  }).join("")
    + toUnd.map((e) => `<li class="bad"><span class="chip bad">설계에 없는 리소스</span>${esc(e.src_label)} → ${esc(String(e.dst_label).replace("설계에 없는 리소스 ", ""))} <b>:${esc(e.ports)}</b>
      <small>설계도 v${activeV()} 에 없는 리소스인데 들어오는 통신이 열려 있음 — 설계에서 뺐다면 코드에서도 빼야 함 (Trivy 는 설계도를 모름)</small></li>`).join("")
    + broken.map((b) => `<li class="bad"><span class="chip bad">필수 통신 막힘</span>${esc(b.src_label)} → ${esc(b.dst_label)} <b>:${esc(b.ports)}</b><small>설계도에 있는 통신인데 허용 규칙이 없음</small></li>`).join("")
    + missing.map((x) => `<li><span class="chip warn">코드에 없음</span>${esc(x.label)} <small>설계도에는 있는데 코드에 보안 그룹 ${esc(x.security_group)} 이 없음 — 이 구성요소로 가는 통신은 '막힘'으로 나옴</small></li>`).join("");
  const nTrivyOnly = ex.filter(seenBy).length;
  card(`<div class="kicker">② 지금 코드의 문제 · 설계도 v${activeV()} 기준</div>
    <h2>Trivy 가 찾은 것과 못 본 것</h2>
    <p class="lead">Trivy 는 '알려진 위험 규칙'으로 코드를 검사함. 고객 설계도는 모르기 때문에, 흔한 규칙이지만 고객이 원하지 않는 연결이나 설계에서 뺀 리소스는 찾지 못함.</p>
    <div class="big"><div class="warn"><b>${inScope.length}</b><span>Trivy 가 찾은 보안 그룹 문제</span></div><div class="bad"><b>${nBad - nTrivyOnly + broken.length}</b><span>Trivy 는 못 보고 설계도로만 보이는 문제</span></div></div>
    <ul class="slist">${inScope.map((x) => `<li><span class="chip warn">Trivy</span>${esc(RULE_KO[x.rule_id] || x.title)}<small>${esc(x.resource)} · ${esc(x.file)} ${esc(x.line)}행 · ${esc(x.rule_id)}</small></li>`).join("")}${items}</ul>
    <p class="small muted" style="line-height:1.6">그 밖의 Trivy 지적 ${outN}개는 이번 검사 범위(보안 그룹 · 설계도) 밖 — Trivy 결과 그대로 보고만 함.</p>
    <div class="sbtns"><button class="sbtn primary" data-act="to3">다음 ▶ 수정 코드</button></div>`);
}

// ------------------------------------------------------------------ ③ 수정 코드 — AI · 팀 평가용 수정안 · 직접 제출
function aiBox() {
  const st = S.ai.status;
  const ready = st && st.found;
  const stText = !st ? "확인 중…" : !st.found ? "Claude Code 없음" : st.logged_in === false ? "로그인 필요" : `준비됨 · ${esc(st.version || "")}`;
  const runs = (S.ai.runs || []).slice(0, 3);
  return `<div class="aibox">
    <div class="aihead"><b>AI 에게 고치게 하기</b><span class="chip ai">Claude Code (구독)</span><span class="aist ${ready ? (st.logged_in === false ? "warn" : "ok") : "bad"}">${stText}</span></div>
    <p class="small">Trivy 가 지목한 문제를 AI 가 고침 → 8개 관문 → 막히면 <b>막힌 이유를 붙여 다시 요청</b> (최대 3번). AI 는 도구 없이 글만 씀 · 저장소 · AWS 접근 없음 · 적용(apply)은 사람.</p>
    ${st && !st.found ? `<p class="small bad">${esc(st.note || "")}</p>` : st && st.logged_in === false ? `<p class="small warn">${esc(st.note || "")}</p>` : ""}
    <div class="seg2" role="group" aria-label="AI 에게 주는 정보"><button type="button" data-ctx="trivy" class="${S.ai.context === "trivy" ? "on" : ""}">Trivy 결과만 주기</button><button type="button" data-ctx="design" class="${S.ai.context === "design" ? "on" : ""}">+ 고객 설계도 v${activeV()}도 주기</button></div>
    <div class="sbtns"><button class="sbtn primary" data-act="aiRun" ${ready ? "" : "disabled"}>AI 수정 시작 ▶</button><button class="sbtn" data-act="aiRefresh">상태 다시 확인</button></div>
    ${runs.length ? `<ul class="airuns">${runs.map((r) => { const [c, w] = AI_ST[r.status] || ["", r.status]; return `<li data-airun="${esc(r.run_id)}"><span class="chip ${c}">${esc(w)}</span> ${esc(fmt(r.started_at))} · 시도 ${r.n_attempts}/${r.max_attempts} · ${r.context === "design" ? "설계도 포함" : "Trivy만"} · 설계도 v${esc((r.design || {}).version || "?")}<em>보기 ›</em></li>`; }).join("")}</ul>` : ""}
  </div>`;
}

function ch3() {
  unlock(3);
  const list = candList();
  const c = list.find((x) => x.id === S.sel);
  const rec = c && c.latest && S.recCache[c.latest.id];
  if (rec && rec.topology && (rec.topology.flows || []).length) {
    diagram(`${c.label} · 이 수정안 코드의 구조`, `이전 검사 결과 (${fmt(c.latest.started_at)} · 설계도 v${esc(((rec.design || {}).recorded || {}).intent_version || "?")} 기준).` + ((rec.topology.excess || []).length ? ` 빨간 점선: 고객 설계에 없는 연결 ${(rec.topology.excess || []).length}곳.` : " 고객 설계도와 일치."),
      rec.topology_model && rec.topology_model.ok ? rec.topology_model : S.model, topoStates(rec.topology.flows), rec.topology.excess || []);
  } else {
    diagram("수정 전 구조", c ? `${c.label}: 아직 검사하지 않았거나 구조 검사(V6) 전에 멈춤 — 지금 그림은 원본 코드 구조.` : "수정안을 고르면 그 수정안 코드의 구조로 바뀜.", S.model, flowStates(curSet().rows), curTopo().excess || []);
  }
  const stale = (x) => x.latest && x.latest.design && activeSha() && x.latest.design.sha256 !== activeSha();
  const grid = list.map((x) => `<button type="button" class="${x.id === S.sel ? "sel" : ""}" data-cand="${esc(x.id)}">${esc(String(x.label).replace("수정안 ", ""))}<span class="o">${esc((x.origin || {}).label || "")}${stale(x) ? " · 이전 설계도" : ""}</span></button>`).join("");
  let detail = `<p class="small muted" style="line-height:1.6">사람이 쓴 코드든 AI 가 쓴 코드든 같은 검사를 받음. 수정안 설명 · 기대 결과는 화면에 없음 — 결과는 검사해야 보임.</p>`;
  if (c) {
    const src = S.src && S.src.key === c.id ? S.src : null;
    detail = `<h3 style="margin:4px 0 6px">${esc(c.label)} — 바뀐 줄</h3><div class="small muted" style="margin-bottom:6px">${esc((c.changes && c.changes.text) || "")}</div>`
      + (src ? diffHtml(src.original || "", src.candidate || "") : `<div class="small muted">불러오는 중…</div>`);
  }
  card(`<div class="kicker">③ 수정 코드 · 설계도 v${activeV()} 기준으로 검사</div>
    <h2>누가 고친 코드를 검사할까</h2>
    ${aiBox()}
    <h3 class="subh">팀이 평가용으로 만든 수정안 ${list.length}개</h3>
    <div class="sgrid">${grid}</div>${detail}
    <div class="sbtns"><button class="sbtn primary" data-act="run" ${c ? "" : "disabled"}>8개 관문 통과시키기 ▶</button><a class="sbtn" href="/work#submit">파일 · 폴더로 제출 (작업 화면)</a></div>`);
}

// ------------------------------------------------------------------ ④ 8개 관문 (검사 중)
function aiTimeline(run, live = false) {
  const atts = (run && run.attempts) || [];
  const n = (run && run.max_attempts) || 3;
  const rows = [];
  for (let i = 1; i <= n; i++) {
    const a = atts.find((x) => x.n === i);
    if (!a) { rows.push(`<li class="wait"><em>${i}</em><div><b>시도 ${i}</b><small>${live && run.status === "RUNNING" ? "대기" : "안 함"}</small></div></li>`); continue; }
    const st = a.status === "ASKING" ? (a.response_file ? ["run", "8개 관문 검사 중"] : ["run", "AI 답 기다리는 중"]) : (AI_ST[a.status] || ["", a.status]);
    const probs = (a.problems || []).slice(0, 2).map((p) => `<span class="pr">${esc(p.layer)} · ${esc(p.what)}</span>`).join("");
    rows.push(`<li class="${st[0]}"><em>${i}</em><div><b>시도 ${i} <span class="chip ${st[0]}">${esc(st[1])}</span></b>
      <small>${esc(a.title || a.error || "")}${a.seconds != null ? ` · AI 응답 ${a.seconds}초` : ""}</small>${probs}
      <span class="lnk">${run.run_id ? `<a href="#" data-prompt="${esc(run.run_id)}" data-n="${i}">AI 에게 보낸 요청</a>` : ""}${a.record_id ? ` · <a href="/work#rec=${encodeURIComponent(a.record_id)}">검사 증거</a>` : ""}</span></div></li>`);
  }
  return `<ol class="aitl">${rows.join("")}</ol>`;
}

function ch4() {
  unlock(4);
  const r = S.run || {};
  const sec = r.t0 ? ((Date.now() - r.t0) / 1000).toFixed(1) : "0.0";
  const curGate = GATES.slice(0, 6).find(([k]) => (S.gates[k] || {}).run);
  if (!S.record || S.run) diagram(S.run ? "검사 중 — 원본 구조" : "8개 관문", "검사가 끝나면 이 코드로 계산한 구조로 바뀜.", S.model, flowStates(curSet().rows), curTopo().excess || []);
  const ai = r.kind === "ai";
  const live = S.ai.live;
  card(`<div class="kicker">④ 8개 관문${ai ? " · AI 수정" : ""} · 설계도 v${activeV()} 기준</div>
    <h2>${S.run ? (ai ? `AI 수정 · 시도 ${((live && live.attempts) || []).length || 1}/${(live && live.max_attempts) || 3}` : `${esc(r.label || "")} 검사 중`) : "검사 대기"}</h2>
    <p class="lead">${ai ? "AI 가 낸 수정 코드도 사람 코드와 똑같이 검사함. 막히면 막힌 이유(무엇 · 왜 · 어떻게)를 붙여 다시 요청." : "이 PC 에서 Trivy · Terraform 으로 코드만 검사 (AWS 접속 없음). 아래 관문이 차례로 켜짐."}</p>
    <div class="srun"><b id="srunSec">${sec}</b><span>초</span><span>${curGate ? `지금: ${esc(curGate[0])} ${esc(curGate[1])}` : ""}</span></div>
    ${ai ? `<div id="aiLive">${aiTimeline(live || { attempts: [], max_attempts: 3, status: "RUNNING" }, true)}</div>` : ""}
    <div class="slog" id="slog">${esc(S.log.slice(-12).join("\n"))}</div>`);
}

// ------------------------------------------------------------------ ⑤ 결과
function designBanner(rec) {
  const recd = ((rec.design || {}).recorded) || null;
  if (!recd) return "";
  const same = recd.sha256 && activeSha() && recd.sha256 === activeSha();
  if (same) return `<div class="dbanner ok">설계도 v${esc(recd.intent_version)} 기준 결과 = 지금 기준</div>`;
  const cid = rec.candidate_id || "";
  const can = candList().some((x) => x.id === cid);
  return `<div class="dbanner warn"><b>설계도 v${esc(recd.intent_version)} 기준 결과</b> — 지금 기준은 v${activeV()}. 설계도가 바뀌어서 이 결과를 그대로 쓰면 안 됨.
    <div class="sbtns">${can ? `<button class="sbtn primary" data-act="recheck" data-cid="${esc(cid)}">v${activeV()} 기준으로 다시 검사 ▶</button>` : `<button class="sbtn" data-act="to3">수정 코드 다시 고르기</button>`}</div></div>`;
}

function ch5() {
  unlock(5);
  const rec = S.record;
  const view = S.ai.view;
  if (!rec && !view) { ch3(); return; }
  if (!rec && view) {               // AI 가 한 번도 수정안을 못 낸 경우 (AI 오류)
    diagram("AI 수정 — 검사할 코드 없음", "AI 가 답하지 못해 검사하지 않음. 그림은 원본 코드 구조.", S.model, flowStates(curSet().rows), curTopo().excess || []);
    card(`<div class="kicker">⑤ 결과 · AI 수정</div>
      <div class="sverdict bad"><span class="rstat bad">AI 오류</span><h3>AI 가 수정안을 내지 못했습니다</h3><p>${esc(view.run_error || view.status_ko || "")} — 자동 패치는 하지 않음. 사람이 직접 고치거나 다시 시도.</p></div>
      ${aiTimeline(view)}<div class="sbtns"><button class="sbtn primary" data-act="to3">수정 코드로 돌아가기</button></div>`);
    return;
  }
  const c = rec.conclusion || {};
  const tone = c.tone === "good" ? "good" : c.tone === "bad" ? "bad" : "warn";
  const tp = rec.topology;
  if (tp && (tp.flows || []).length) {
    diagram(`${rec.candidate_label || ""} · 검사한 코드의 구조`, (tp.excess || []).length ? `빨간 점선 = 이 코드가 허용하는데 고객 설계도에는 없는 연결 ${(tp.excess || []).length}곳.` : "고객 설계도와 같은 구조 (보안 그룹 규칙 기준 — 실제 연결은 V8).",
      rec.topology_model && rec.topology_model.ok ? rec.topology_model : S.model, topoStates(tp.flows), tp.excess || []);
  } else diagram(`${rec.candidate_label || ""} · 구조 검사(V6) 전에 멈춤`, "구조를 계산하기 전 단계에서 막혀 원본 구조를 보여 줌.", S.model, flowStates(curSet().rows), curTopo().excess || []);
  const ps = (rec.problems || []).slice(0, 3);
  const pass = tone === "good";
  const aiHead = view ? (() => { const [cc, w] = AI_ST[view.status] || ["", view.status]; return `<div class="aires"><span class="chip ai">AI 수정</span> <span class="chip ${cc}">${esc(w)}</span> 시도 ${(view.attempts || []).length}/${view.max_attempts} · ${view.context === "design" ? "Trivy + 설계도를 줌" : "Trivy 결과만 줌"}${view.status === "GAVE_UP" ? " — 자동 패치 안 함, 사람에게 넘김" : ""}</div>`; })() : "";
  card(`<div class="kicker">⑤ 결과${view ? " · AI 수정" : ""}</div>
    ${aiHead}
    <div class="sverdict ${tone}"><span class="rstat ${tone}">${esc(c.status || c.headline || "")}</span><h3>${esc(c.title || c.headline || "")}</h3><p>${esc(c.reason || "")}</p></div>
    ${designBanner(rec)}
    ${ps.map((p, i) => `<div class="sprob"><span class="chip bad">${i + 1} · ${esc(p.tag)}</span> <span class="small muted">${esc(p.layer)}</span><div class="w">${esc(p.what)}</div>
      <dl><dt>왜 문제인가요?</dt><dd>${esc(p.why)}</dd><dt>어떻게 해결하나요?</dt><dd>${esc(p.how)}</dd></dl></div>`).join("")}
    ${(rec.problems || []).length > 3 ? `<p class="small muted">문제 ${rec.problems.length}개 중 3개 — 나머지는 '증거 자세히'에서.</p>` : ""}
    ${view ? `<h3 class="subh">AI 시도 기록</h3>${aiTimeline(view)}` : ""}
    <div class="sbtns">
      ${pass ? `<a class="sbtn primary" href="/work#rec=${encodeURIComponent(rec.id)}&step=5">실제 AWS 검사로 (V7 · V8) ▶</a>` : `<button class="sbtn primary" data-act="to3">다른 수정 코드 고르기</button>`}
      <a class="sbtn" href="/work#rec=${encodeURIComponent(rec.id)}">증거 자세히 (작업 화면)</a>
    </div>
    <p class="small muted" style="margin-top:12px;line-height:1.6">이번 검사에서 확인하지 않은 것: ${esc((rec.unchecked || []).join(" · "))}</p>`);
}

function diffHtml(a, b) {
  const A = a.replace(/\r/g, "").split("\n"), B = b.replace(/\r/g, "").split("\n");
  const n = A.length, m = B.length;
  if (n * m > 4_000_000) return `<div class="small muted">파일이 커서 미리보기 생략</div>`;
  const L = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = A[i] === B[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const ops = []; let i = 0, j = 0;
  while (i < n && j < m) { if (A[i] === B[j]) { ops.push(["c", A[i]]); i++; j++; } else if (L[i + 1][j] >= L[i][j + 1]) { ops.push(["d", A[i]]); i++; } else { ops.push(["a", B[j]]); j++; } }
  while (i < n) ops.push(["d", A[i++]]); while (j < m) ops.push(["a", B[j++]]);
  const keep = ops.map(() => false);
  ops.forEach((o, k) => { if (o[0] !== "c") for (let dd = -2; dd <= 2; dd++) if (ops[k + dd]) keep[k + dd] = true; });
  if (!keep.some(Boolean)) return `<div class="small muted">원본과 같음</div>`;
  let out = "", gap = false;
  ops.forEach((o, k) => { if (keep[k]) { out += `<div class="${o[0] === "c" ? "" : o[0]}">${o[0] === "a" ? "+ " : o[0] === "d" ? "- " : "  "}${esc(o[1])}</div>`; gap = false; } else if (!gap) { out += `<div class="gap">  ⋯</div>`; gap = true; } });
  return `<div class="sdiff">${out}</div>`;
}

// ------------------------------------------------------------------ 수정안 고르기 · 검사
async function pick(cid) {
  S.sel = cid; S.src = null;
  render();
  const c = candList().find((x) => x.id === cid);
  const [src, rec] = await Promise.all([api.get(`/api/candidate/source?set_id=${encodeURIComponent(S.setId)}&id=${encodeURIComponent(cid)}`),
    c && c.latest ? api.get(`/api/record?id=${encodeURIComponent(c.latest.id)}`) : Promise.resolve(null)]);
  S.src = { key: cid, ...(src || {}) };
  if (rec && !rec.error) S.recCache[c.latest.id] = rec;
  if (S.sel === cid && S.ch === 3) render();
}

// 진행 표시: 기록 폴더에 생긴 파일로만 안다 (서버 job_progress) — 끝난 관문은 '계산 끝', 결과(통과 · 실패)는 검사가 끝난 뒤 기록에서
function tickGates(pg) {
  const done = new Set();
  ((pg && pg.stages) || []).forEach((st) => { if (st.done && STAGE_GATES[st.key]) STAGE_GATES[st.key].forEach((g) => done.add(g)); });
  let first = true;
  GATES.slice(0, 6).forEach(([k]) => { if (done.has(k)) S.gates[k] = { verdict: "DONE" }; else { S.gates[k] = first ? { run: true } : {}; first = false; } });
  renderGates();
}

async function pollJob(onTick) {
  for (;;) {
    await sleep(600);
    const [lg, pg] = await Promise.all([api.get(`/api/log?since=${S.run.since}`), api.get("/api/job/progress")]);
    if (lg && Array.isArray(lg.log)) { S.log.push(...lg.log.map((x) => (typeof x === "string" ? x : x.text || x.line || JSON.stringify(x)))); S.run.since = lg.log_total ?? (S.run.since + lg.log.length); }
    tickGates(pg);
    const sec = $("#srunSec"); if (sec) sec.textContent = ((Date.now() - S.run.t0) / 1000).toFixed(1);
    const lgEl = $("#slog"); if (lgEl) { lgEl.textContent = S.log.slice(-12).join("\n"); lgEl.scrollTop = lgEl.scrollHeight; }
    if (onTick) await onTick();
    if (lg && lg.running === false) return { result: lg.result, error: lg.error, pg };
  }
}

async function runCheck(cid, designVersion = null) {
  const c = candList().find((x) => x.id === (cid || S.sel));
  if (!c || S.run) return;
  const body = { case_id: S.caseId, set_id: S.setId, candidate_id: c.id };
  if (designVersion) body.design_version = designVersion;
  const r = await api.post("/api/review", body);
  if (!r || !r.started) { toast(r && r.error ? r.error : "검사를 시작하지 못함 (다른 작업 진행 중일 수 있음)"); return; }
  S.sel = c.id;
  S.run = { kind: "review", t0: Date.now(), label: c.label, since: 0 };
  S.record = null; S.ai.view = null; S.log = []; S.gates = {};
  GATES.slice(0, 6).forEach(([k], i) => { S.gates[k] = i === 0 ? { run: true } : {}; });
  unlock(4); S.ch = 4; render();
  const res = await pollJob();
  const rid = (res.result && res.result.record_id) || (res.pg && res.pg.record_id);
  S.run = null;
  if (res.error || !rid) { S.gates = {}; render(); toast(`검사 실패: ${res.error || "기록 없음"}`); return; }
  await refreshCands();
  await showRecord(rid);
}

async function aiRun() {
  if (S.run) return;
  const r = await api.post("/api/llm/fix", { set_id: S.setId, context: S.ai.context, max_attempts: 3 });
  if (!r || !r.started) { toast(r && r.error ? r.error : "AI 수정을 시작하지 못함 (다른 작업 진행 중일 수 있음)"); return; }
  S.run = { kind: "ai", t0: Date.now(), label: "AI 수정", since: 0 };
  S.record = null; S.ai.view = null; S.ai.live = null; S.log = []; S.gates = {};
  GATES.slice(0, 6).forEach(([k], i) => { S.gates[k] = i === 0 ? { run: true } : {}; });
  unlock(4); S.ch = 4; render();
  let runId = null, lastN = 0;
  const res = await pollJob(async () => {
    if (!runId) {
      const rs = await api.get(`/api/llm/runs?set=${encodeURIComponent(S.setId)}`);
      const hit = ((rs && rs.runs) || []).find((x) => x.status === "RUNNING");
      if (hit) runId = hit.run_id;
    }
    if (runId) {
      const live = await api.get(`/api/llm/run?id=${encodeURIComponent(runId)}`);
      if (live && !live.error) {
        S.ai.live = live;
        const last = (live.attempts || [])[(live.attempts || []).length - 1];
        if (last && last.status === "ASKING" && !last.response_file) { GATES.slice(0, 6).forEach(([k]) => { S.gates[k] = {}; }); renderGates(); }   // AI 가 답을 쓰는 중 — 관문은 아직
        const n = (live.attempts || []).length;
        if (n !== lastN) { lastN = n; const h = $("#scard h2"); if (h) h.textContent = `AI 수정 · 시도 ${n}/${live.max_attempts}`; }
        const box = $("#aiLive"); if (box) box.innerHTML = aiTimeline(live, true);
      }
    }
  });
  S.run = null;
  const out = res.result || {};
  if (res.error && !out.run_id) { S.gates = {}; render(); toast(`AI 수정 실패: ${res.error}`); loadAi(); return; }
  const view = await api.get(`/api/llm/run?id=${encodeURIComponent(out.run_id || runId)}`);
  S.ai.view = view && !view.error ? view : null;
  loadAi();
  await refreshCands();
  if (out.record_id) await showRecord(out.record_id, true);
  else { S.record = null; S.gates = {}; unlock(5); S.ch = 5; render(); }
}

async function openAiRun(runId) {
  const view = await api.get(`/api/llm/run?id=${encodeURIComponent(runId)}`);
  if (!view || view.error) { toast((view && view.error) || "기록을 읽지 못함"); return; }
  S.ai.view = view;
  if (view.final_record_id) await showRecord(view.final_record_id, true);
  else { S.record = null; S.gates = {}; unlock(5); S.ch = 5; render(); }
}

async function refreshCands() {
  S.cands = await api.get(`/api/case/candidates?id=${encodeURIComponent(S.caseId)}`);
}

async function showRecord(rid, keepAi = false) {
  const rec = await api.get(`/api/record?id=${encodeURIComponent(rid)}`);
  if (!rec || rec.error) { toast((rec && rec.error) || "기록을 읽지 못함"); return; }
  if (!keepAi) S.ai.view = null;
  S.record = rec;
  S.gates = {};
  (rec.layers || []).forEach((l) => { S.gates[l.layer] = { verdict: l.verdict, summary: l.summary }; });
  // 관문 하나씩 켜기 (실제 결과 순서대로 — 연출용 지연만 있고 판정은 기록 그대로)
  const order = GATES.slice(0, 6).map(([k]) => k);
  const final = { ...S.gates };
  S.gates = {}; S.anim = true;
  unlock(5); S.ch = 5; render();
  for (const k of order) { S.gates[k] = final[k] || {}; renderGates(); await sleep(260); }
  S.gates = final; S.anim = false; renderGates();
}

async function showPrompt(runId, n) {
  const r = await api.get(`/api/llm/text?id=${encodeURIComponent(runId)}&n=${n}&what=prompt`);
  const el = document.createElement("div");
  el.className = "smodal";
  el.innerHTML = `<div class="sm-box" role="dialog" aria-label="AI 에게 보낸 요청"><div class="sm-h"><b>시도 ${n} — AI 에게 보낸 요청 그대로</b><button class="x" data-close>×</button></div>
    <p class="small muted">수정안 이름 · 기대 결과 같은 정답 정보는 들어가지 않음. 아래가 전부임 (지문 sha256 ${esc(String(r.sha256 || "").slice(0, 16))}…).</p>
    <pre>${esc(r.text || r.error || "")}</pre></div>`;
  el.addEventListener("click", (e) => { if (e.target === el || e.target.closest("[data-close]")) el.remove(); });
  document.body.appendChild(el);
}

function toast(text, tone = "bad") {
  const el = document.createElement("div");
  el.className = `sverdict ${tone} stoast`;
  el.innerHTML = `<h3 style="font-size:15px;margin:0">${esc(text)}</h3>`;
  document.body.appendChild(el); setTimeout(() => el.remove(), 5200);
}

// ------------------------------------------------------------------ 버튼 · 입력
document.addEventListener("click", (e) => {
  const pr = e.target.closest("[data-prompt]");
  if (pr) { e.preventDefault(); showPrompt(pr.dataset.prompt, pr.dataset.n); return; }
  const t = e.target.closest("[data-ch],[data-act],[data-cand],[data-ctx],[data-ver],[data-airun]");
  if (!t) return;
  if (t.dataset.ch) { go(+t.dataset.ch); return; }
  if (t.dataset.cand) { pick(t.dataset.cand); return; }
  if (t.dataset.ctx) { S.ai.context = t.dataset.ctx; render(); return; }
  if (t.dataset.ver) { askActivate(+t.dataset.ver); return; }
  if (t.dataset.airun) { openAiRun(t.dataset.airun); return; }
  const a = t.dataset.act;
  if (S.edit && ["addTier", "addExt", "addFlow", "del"].includes(a)) { editAct(a, t); return; }
  if (a === "to2") { unlock(2); S.ch = 2; render(); }
  else if (a === "to3") { unlock(3); S.ch = 3; S.record = null; S.ai.view = null; S.gates = {}; render(); loadAi(); }
  else if (a === "run") runCheck();
  else if (a === "recheck") runCheck(t.dataset.cid);
  else if (a === "edit") startEdit();
  else if (a === "cancelEdit") { S.edit = null; render(); }
  else if (a === "saveDesign") saveDesign();
  else if (a === "activate") {
    (async () => {
      const r = await api.post("/api/design/activate", { set_id: S.setId, version: +t.dataset.v });
      if (!r || !r.ok) { toast((r && (r.errors || [r.error]).join(" ")) || "바꾸지 못함"); return; }
      S.record = null; S.recCache = {}; S.gates = {};
      await reloadAll(); render(); toast(`지금 기준 = 설계도 v${r.version}`, "good");
    })();
  } else if (a === "noActivate") { const b = $("#verAsk"); if (b) b.innerHTML = ""; }
  else if (a === "aiRun") aiRun();
  else if (a === "aiRefresh") { (async () => { S.ai.status = await api.get("/api/llm/status?refresh=1"); render(); })(); }
});
document.addEventListener("input", (e) => { if (S.edit && e.target.tagName !== "SELECT" && e.target.closest("#scard")) editInput(e.target); });
document.addEventListener("change", (e) => { if (S.edit && e.target.closest("#scard") && e.target.tagName === "SELECT") editInput(e.target); });

boot();
