// 화면 ③ 원하는 구조 (설계도) — 2026-11-01 6차 (D-34). B: "너무 어렵게 되어 있음 · 설계도랑 토폴로지를 합치지 말고 따로"
//   왼쪽  = 설계도만 그린 그림 (서버 archmap.design_view: 상자 자리는 지금 코드 그림과 같음, 선 = 설계도의 통신만). 기본은 '통신 관련만'
//   오른쪽 = 통신 목록. 한 줄 = 출발 → 도착 : 포트, [허용] / [막기]. 인터넷 · IP 대역 출처는 '이 IP만 허용', VPC 대역 출처는 '이 서버만 허용',
//            맨 아래 '통신 추가'. 바꾸면 바로 미리보기(저장 안 함) — 그림 · 목록이 바뀐 설계도로 다시 그려진다. 저장하면 새 버전
//   첫 설계도는 자동 기준 (지금 코드 − 위험한 통신, 서버 web/structure.py). 판정은 서버(V6 와 같은 비교)가 한다 — 이 화면은 바꾼 것 목록만 들고 있다.
import { S, api, esc, register, registerTodo, guideCard, render, toast, designVersion, chip, $, modal, mdLite, caseMode } from "./m_core.js";
import { mapBox, drawMap, MLEG, pop, nodeInfo, linkInfo, mapView, simple } from "./m_map.js";
import { layout } from "./archlayout.js";

export function sedit() {
  if (!S.sedit || S.sedit.pid !== S.pid) S.sedit = { pid: S.pid, edits: [], preview: null, errors: [], note: "", seq: 0, saving: false, open: null, add: false };
  return S.sedit;
}
export function dirty() { return !!(S.sedit && S.sedit.pid === S.pid && S.sedit.edits.length); }

function cur() {
  const D = S.design || {};
  const E = sedit();
  const p = E.preview && E.preview.ok ? E.preview : null;
  return { D, E, p, cmp: p || D.compare || {} };
}
const baseRows = () => (((S.design || {}).compare || {}).rows) || [];

// 지금 보이는 목록 = 미리보기(또는 저장된 설계도)의 목록 + 이번에 뺀 '설계도에만 있던 통신' (다시 [허용] 으로 되돌릴 수 있게)
function shownRows() {
  const { E, cmp } = cur();
  const rows = (cmp.rows || []).slice();
  const have = new Set(rows.map((r) => r.key));
  for (const e of E.edits) {
    if (e.op !== "drop" || have.has(e.key)) continue;
    const b = baseRows().find((r) => r.key === e.key);
    if (b) rows.push({ ...b, allow: false, fix: false, note: "설계도에서 뺌 (저장 전)" });
  }
  return rows;
}
// 목록 순서 = 그림의 흐름 순 (위 → 아래: 도착 상자가 몇 번 거쳐 오는가 → 출발 상자). 같은 설계도면 한 번만 계산
let rankOf = { view: null, rank: {} };
function flowSort(rows, view) {
  if (view && rankOf.view !== view) { try { rankOf = { view, rank: layout(simple(view)).rank || {} }; } catch { rankOf = { view, rank: {} }; } }
  const rk = (id) => (rankOf.rank[id] === undefined ? 99 : rankOf.rank[id]);
  return rows.slice().sort((a, b) => rk(a.dst_node) - rk(b.dst_node) || String(a.dst).localeCompare(String(b.dst)) || rk(a.src_node) - rk(b.src_node)
    || String(a.src).localeCompare(String(b.src)) || (parseInt(a.port, 10) || 0) - (parseInt(b.port, 10) || 0));
}
const changed = (r) => sedit().edits.some((e) => e.key === r.key) || (!baseRows().some((b) => b.key === r.key) && sedit().edits.length > 0);

let timer = null;
function schedule(ms = 200) {
  clearTimeout(timer);
  timer = setTimeout(async () => {
    const E = sedit();
    const seq = ++E.seq;
    if (!E.edits.length) { E.preview = null; E.errors = []; if (S.step === 3) render(); return; }
    const r = await api.post("/api/p/structure/preview", { project: S.pid, edits: E.edits.map(strip), base_version: S.design && S.design.exists ? designVersion() : null });
    if (!S.sedit || seq !== S.sedit.seq) return;
    if (r && r.ok) { E.preview = r; E.errors = []; (r.done || []).forEach((t, i) => { if (E.edits[i]) E.edits[i].text = t; }); }
    else { E.preview = null; E.errors = (r && (r.errors || [r.error])) || ["미리보기 실패"]; }
    if (S.step === 3) render();
  }, ms);
}
const strip = (e) => { const o = { ...e }; delete o.key; delete o.text; return o; };

// 같은 줄을 다시 고르면 앞의 선택을 바꾼다. 원래(저장된 설계도) 상태로 되돌리는 선택이면 바꾼 것에서 뺀다
function setEdit(e) {
  const E = sedit();
  const i = E.edits.findIndex((x) => x.key === e.key);
  const b = baseRows().find((r) => r.key === e.key);
  const back = b && ((e.op === "keep" && b.allow === true) || (e.op === "block" && b.allow === false));
  if (i >= 0) { if (back) E.edits.splice(i, 1); else E.edits.splice(i, 1, e); } else if (!back) E.edits.push(e);
  E.open = null; E.add = false;
  render(); schedule(0);
}
function unEdit(key) {
  const E = sedit();
  E.edits = E.edits.filter((x) => x.key !== key);
  render(); schedule(0);
}

function boxes() {
  const A = (S.design || {}).arch || {};
  return (A.nodes || []).filter((n) => (n.sgs || []).length && !n.ghost && n.cat !== "external");
}
const boxOpts = (sel = "") => boxes().map((n) => `<option value="${esc(n.id)}" ${n.id === sel ? "selected" : ""}>${esc(n.label)} · ${esc(n.type_ko || "")}</option>`).join("");

function rowHtml(r) {
  const E = sedit();
  const on = r.allow === true, off = r.allow === false;
  const ch = changed(r);
  const form = E.open === r.key;
  const extra = r.kind === "ip" ? `<button type="button" class="linkbtn" data-fr="ip">이 IP만 허용 ▾</button>` : r.kind === "vpc" ? `<button type="button" class="linkbtn" data-fr="via">이 서버만 허용 ▾</button>` : "";
  return `<li class="frow ${on ? "on" : off ? "off" : "unk"}${ch ? " chg" : ""}${r.fix ? " fix" : ""}" data-key="${esc(r.key)}">
      <div class="fr-top"><span class="fr-path">${esc(r.src)} <i>→</i> ${esc(r.dst)} <b><span class="c">:</span>${esc(r.port)}</b></span>
        <span class="fr-seg" role="group" aria-label="허용 여부"><button type="button" class="${on ? "on" : ""}" data-fr="allow" ${r.can_allow ? "" : `disabled title="${esc(r.why_not)}"`}>허용</button><button type="button" class="${off ? "on" : ""}" data-fr="block">막기</button></span></div>
      ${r.note || r.fix || ch || extra ? `<div class="fr-sub">${r.note ? `<span>${esc(r.note)}</span>` : ""}${r.fix ? chip("warn", "지금 코드와 다름") : ""}${ch ? chip("run", "바꿈 · 저장 전") : ""}${extra}</div>` : ""}
      ${form && r.kind === "ip" ? `<div class="fr-form"><input class="minput sm" data-i="cidr" placeholder="203.0.113.0/24"><input class="minput sm" data-i="label" placeholder="이름 (예: 운영팀 사무실)"><button type="button" class="mbtn sm primary" data-fr="ip-ok">이 IP만 허용</button></div>` : ""}
      ${form && r.kind === "vpc" ? `<div class="fr-form"><select class="minput sm" data-i="via">${boxOpts()}</select><button type="button" class="mbtn sm primary" data-fr="via-ok">이 서버만 허용</button></div>` : ""}</li>`;
}

function addHtml() {
  const E = sedit();
  if (!E.add) return `<button type="button" class="mbtn sm" data-fr="add">＋ 통신 추가</button>`;
  return `<div class="fadd"><b>통신 추가</b>
      <label>출발 <select class="minput sm" data-a="from"><option value="__any">인터넷 전체 (0.0.0.0/0)</option><option value="__cidr">IP 대역 직접 입력</option>${boxOpts()}</select></label>
      <label class="fadd-cidr" hidden>IP 대역 <input class="minput sm" data-a="cidr" placeholder="198.51.100.0/24"> 이름 <input class="minput sm" data-a="label" placeholder="협력사"></label>
      <label>도착 <select class="minput sm" data-a="to">${boxOpts()}</select></label>
      <label>포트 <input class="minput sm" data-a="port" placeholder="443"></label>
      <select class="minput sm" data-a="proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="all">전체</option></select>
      <span class="fadd-btns"><button type="button" class="mbtn sm primary" data-fr="add-ok">추가</button><button type="button" class="mbtn sm" data-fr="add-x">닫기</button></span></div>`;
}

// 요구사항 파일(IAM 등) 한 칸 (D-40): 버전 칩(v1 = 팀 작성 평가 기준 · v2~ = 올린 판) · 규칙 목록 · 새 판 올리기 · 확정. 설계도와 같은 규칙 — 초안 기준 검사는 승인 불가
function reqHtml(r) {
  const vs = r.versions || [];
  const conf = r.confirmation || null;
  const st = conf && conf.basis === "manifest" ? ["dim", "팀 작성 평가 기준"] : conf && conf.confirmed ? ["ok", `확정 · ${conf.by || ""}`] : conf ? ["warn", "초안 — 확정 전"] : ["dim", ""];
  const chips = vs.length > 1 ? `<div class="vstrip"><span class="small muted">버전</span>${vs.map((x) => `<button type="button" class="vchip ${x.active ? "on" : ""}" data-rver="${esc(r.set_id)}|${x.version}" title="${esc(x.note || x.changes || "")}">v${x.version}${x.version === 1 ? " · 팀 작성" : ""}${x.active ? " · 지금" : ""}${(x.confirmation || {}).basis === "human" ? " · 확정" : (x.confirmation || {}).basis === "draft" ? " · 초안" : ""}</button>`).join("")}</div>` : "";
  const act = `<div class="reqact mnav"><label class="mbtn sm">고친 JSON 올리기 → v${Math.max(1, ...vs.map((x) => x.version)) + 1}<input type="file" accept=".json,application/json" data-reqfile="${esc(r.set_id)}" hidden></label>
      ${conf && !conf.confirmed && conf.basis === "draft" ? `<button type="button" class="mbtn sm primary" data-act="r-confirm" data-set="${esc(r.set_id)}" data-v="${esc(r.version)}">이 판 확정하기 (v${esc(r.version)})</button>` : ""}
      ${conf && conf.basis === "manifest" ? `<span class="small muted">v1 은 팀이 평가용으로 쓴 파일 — 고객 요구사항은 고친 파일을 올려 새 판으로 두고 담당자가 확정</span>` : ""}
      ${conf && conf.confirmed && conf.basis === "human" ? `<span class="small muted">${esc(conf.by)} 확정${conf.at ? ` · ${esc(String(conf.at).slice(0, 16).replace("T", " "))}` : ""}${conf.note ? ` — ${esc(conf.note)}` : ""}</span>` : ""}</div>`;
  return `<details class="reqv" open><summary>${esc(r.label)} <b>${r.rows.length}</b> ${chip(st[0], `v${esc(r.version || 1)} · ${st[1]}`)}</summary>
      ${chips}<ul class="inv">${(r.rows || []).map((x) => `<li>${esc(x.text)}</li>`).join("")}</ul>${r.importable ? act : ""}</details>`;
}

// ③ 지금 상태 → 할 일 하나 (9차, D-43 "설계도 고치기 · 확정이 어려움"): 머리말 '할 일' 과 맨 위 '다음 할 일' 칸이 같은 판단을 쓴다
function s3Now() {
  const D = S.design;
  if (!D || !D.ok) return null;
  const { E, p } = cur();
  const pay = D.design || {};
  const conf = D.exists ? (pay.confirmation || null) : null;
  const nextV = D.exists ? Math.max(1, ...((pay.versions || []).map((x) => x.version))) + 1 : 2;
  if (!D.exists) return { key: "none", tone: "warn", title: "설계도가 아직 없음", todo: "설계도가 아직 없음 — ② 에서 점검을 먼저 하세요.", text: "② 에서 점검이 끝나면 지금 코드에서 자동 초안(v1)을 만듭니다. 점검이 안 됐으면 ② 로 가세요.", btns: `<button type="button" class="mbtn primary" data-go="2">◀ ② 현재 인프라</button>` };
  if (E.edits.length) return { key: "dirty", tone: "warn", title: `바꾼 것 ${E.edits.length}개 — 저장하면 v${nextV}`, todo: `바꾼 것 ${E.edits.length}개 — [저장 → v${nextV}] 를 누르고, 그 다음 [이 설계도 확정하기].`, text: `저장하기 전에는 기준이 그대로입니다. 오른쪽 아래 '바꾼 이유' 를 적고 [저장 → v${nextV}] 를 누르세요. 저장한 새 판은 초안이라 그 다음에 [이 설계도 확정하기] 를 누릅니다.`,
    btns: `<button type="button" class="mbtn primary" data-act="s-save" ${E.saving || E.errors.length || !p ? "disabled" : ""}>저장 → v${nextV}</button><button type="button" class="mbtn" data-act="s-clear">모두 취소</button>` };
  if (conf && conf.confirmed && conf.basis === "manifest") return { key: "manifest", tone: "ok", title: "이 예제의 설계도는 팀이 미리 확정한 평가 기준입니다", todo: "이 예제는 설계도가 이미 확정돼 있습니다 — 바꿀 것 없이 [다음 ▶ 보안 문제].", text: "바꿀 것이 없습니다 — 그대로 다음으로 가세요. (고객이 확정한 설계도와 구분해서 읽습니다)", btns: `<button type="button" class="mbtn primary" data-go="4">다음 ▶ ④ 보안 문제</button>` };
  if (conf && conf.confirmed) return { key: "confirmed", tone: "ok", title: `설계도 v${conf.version} 확정됨 — ${conf.by || ""}`, todo: `설계도 v${conf.version} 은 확정됐습니다 — 바꿀 것이 없으면 [다음 ▶ 보안 문제].`, text: "이 버전을 기준으로 검사합니다. 바꿀 것이 없으면 다음으로 가세요. 오른쪽 목록에서 바꿔 저장하면 새 판(초안)이 되고 다시 확정해야 합니다.", btns: `<button type="button" class="mbtn primary" data-go="4">다음 ▶ ④ 보안 문제</button>` };
  const btns = `<button type="button" class="mbtn primary" data-act="s-confirm">이 설계도 확정하기 (v${esc(designVersion())})</button><button type="button" class="mbtn" data-go="4" title="확정하지 않고 넘어가면 검사 결과를 승인할 수 없음">확정 없이 다음 ▶ (승인 불가)</button>`;
  // 고객 제안서 · 팀 설계 문서 예제 (D-46 · D-49): v1 은 원문의 허용 통신을 옮긴 초안 — 원문(왼쪽 아래)과 목록을 맞춰 보고 담당자가 확정
  if (conf && conf.source === "proposal") { const lab = conf.source_label || "고객 제안서"; return { key: "proposal", tone: "warn", title: `${lab}에서 옮긴 설계도 v${designVersion()} 초안 — 원문과 맞는지 확인하고 확정하세요`, todo: `왼쪽 아래 '${lab}' 의 통신과 오른쪽 통신 목록이 같은지 보고, 같으면 [이 설계도 확정하기].`, text: `1. 왼쪽 아래 '${lab}' 의 통신과 오른쪽 목록을 하나씩 맞춰 봅니다 → 2. 다르면 [허용] · [막기] 를 바꾸고 저장 → 3. 같으면 담당자 이름을 적고 확정. 확정 전 기준으로 검사한 결과는 승인할 수 없습니다.`, btns }; }
  return { key: "draft", tone: "warn", title: `설계도 v${designVersion()} 은 초안 — 확인하고 확정하세요`, todo: "오른쪽 목록이 고객이 허용한 통신과 같으면 [이 설계도 확정하기], 다르면 [허용] · [막기] 를 바꿔 저장한 뒤 확정.", text: `1. 오른쪽 목록이 고객이 허용한 통신과 같은지 봅니다 → 2. 다르면 [허용] · [막기] 를 바꾸고 저장 → 3. 같으면 담당자 이름을 적고 확정. 확정 전 기준으로 검사한 결과는 승인할 수 없습니다.`, btns };
}

// 17차 (D-53): 원문은 확정 전(맞춰 볼 때)에만 펼쳐 둔다 — 확정 뒤에는 접어 두고 누르면 펼침
function proposalHtml(pr, open = true) {
  if (!pr || !pr.text) return "";
  const lab = pr.label || "고객 제안서";
  return `<details class="mcard proposal small" ${open ? "open" : ""}><summary><b>${esc(lab)}</b> <small class="muted">원문 그대로 · 설계도 v1 은 이 글의 허용 통신을 옮긴 것 · ${esc(pr.path || "")}</small></summary><div class="mdtext">${mdLite(pr.text)}</div></details>`;
}
registerTodo(3, () => { const n = (S.design || {}).mode === "iam" ? iamNow() : s3Now(); return n ? n.todo : ""; });

// ------------------------------------------------------------------ ③ 권한 요구사항 (15차, D-51 — 팀 3계층 요청 3)
// 통신 설계도 대신 IAM 요구사항(웹 서버 역할이 가져도 되는 권한)이 기준인 예제. 왼쪽 = 요구사항 그림 ↔ 지금 코드와 비교(전환),
// 오른쪽 = 요구사항 목록 · 지금 코드와 다른 곳 · 버전 · 확정. 판정은 서버(V6 IAM 오라클 — 원본 plan + 코드에 지금 요구사항을 대입) 그대로.
function iamNow() {
  const D = S.design || {};
  const I = D.iam || {};
  const conf = I.confirmation || null;
  const btn = `<button type="button" class="mbtn primary" data-act="r-confirm" data-set="${esc(I.set_id || "")}" data-v="${esc(I.version || 1)}">이 요구사항 확정하기 (v${esc(I.version || 1)})</button>`;
  if (!I.ok) return { key: "none", tone: "warn", title: "요구사항을 읽지 못함", todo: "② 에서 점검을 먼저 하세요.", text: I.reason || "", btns: `<button type="button" class="mbtn primary" data-go="2">◀ ② 현재 인프라</button>` };
  if (conf && conf.confirmed) return { key: "confirmed", tone: "ok", title: `IAM 요구사항 v${conf.version} 확정됨 — ${conf.by || ""}`, todo: `IAM 요구사항 v${conf.version} 은 확정됐습니다 — [다음 ▶ 보안 문제].`,
    text: "이 판을 기준으로 검사합니다. 바꾸려면 고친 JSON 을 올려 새 판(초안)을 만들고 다시 확정합니다.", btns: `<button type="button" class="mbtn primary" data-go="4">다음 ▶ ④ 보안 문제</button>` };
  const lab = (conf && conf.source_label) || "팀 설계 문서";
  return { key: "draft", tone: "warn", title: `${lab}에서 옮긴 IAM 요구사항 v${I.version || 1} 초안 — 원문과 맞는지 확인하고 확정하세요`,
    todo: `왼쪽 아래 '${lab}' 의 권한 문장과 오른쪽 요구사항 목록이 같은지 보고, 같으면 [이 요구사항 확정하기].`,
    text: `1. 왼쪽 아래 '${lab}' 의 문장과 오른쪽 '요구사항' 목록을 맞춰 봅니다 → 2. 다르면 고친 JSON 을 올려 새 판 → 3. 같으면 담당자 이름을 적고 확정. 확정 전 기준으로 검사한 결과는 승인할 수 없습니다.`,
    btns: `${btn}<button type="button" class="mbtn" data-go="4" title="확정하지 않고 넘어가면 검사 결과를 승인할 수 없음">확정 없이 다음 ▶ (승인 불가)</button>` };
}
function iamDesignHtml() {
  const D = S.design;
  const I = D.iam || {};
  const req = (D.requirements || []).find((r) => r.set_id === I.set_id) || {};
  const now = iamNow();
  const view = S.iamPic === "now" ? "now" : "req";
  const conf = I.confirmation || null;
  const seg = `<div class="seg sm picseg"><button type="button" class="${view === "req" ? "on" : ""}" data-ipv="req">요구사항 v${esc(I.version || 1)}</button><button type="button" class="${view === "now" ? "on" : ""}" data-ipv="now">지금 코드와 비교</button></div>`;
  const title = view === "req" ? `IAM 요구사항 v${I.version || 1}${conf && conf.confirmed ? " · 확정" : " · 초안"} — 웹 서버 역할이 가져도 되는 권한` : "지금 코드의 권한 — 요구사항과 비교";
  const diffs = I.diffs || [];
  const cbox = conf && conf.confirmed ? `<div class="mcard confirm ok small"><b>확정된 IAM 요구사항 v${esc(conf.version)}</b> ${chip("ok", "확정")}<br>${esc(conf.by)} 확정${conf.at ? ` · ${esc(String(conf.at).slice(0, 16).replace("T", " "))}` : ""}${conf.note ? ` — ${esc(conf.note)}` : ""}. 이 판을 기준으로 한 검사만 '고객 요구 충족' 으로 봅니다.</div>`
    : `<div class="mcard confirm draft small"><b>초안 — 아직 확정 전</b> ${chip("warn", "판정 근거로 쓰지 않음")}<br>${esc((conf && conf.source_label) || "팀 설계 문서")}의 권한 문장을 옮긴 초안입니다 — 원문(아래)과 같은지 담당자가 확인하고, 위 '다음 할 일' 칸에서 확정하세요. 확정 전 기준으로 검사한 결과는 승인할 수 없습니다.</div>`;
  const pr = I.proposal;
  // 17차 (D-53): 확정된 뒤의 '다음 할 일' 칸은 [다음 ▶] 하나뿐이라 (오른쪽 위 단추와 같음) 뺐다 — 확정 · 저장처럼 할 것이 있을 때만
  return `${now.key === "confirmed" ? "" : guideCard({ ...now, kicker: "다음 할 일" })}<div class="s3">
      <div class="s3-pic">${(view === "req" ? I.view : I.current) ? mapBox("tMap", title, view === "req" ? MLEG.permDesign : MLEG.permNow, seg) : `<div class="mempty">${esc(I.verdict_reason || D.reason || "원본 plan 이 없어 그림을 그리지 못함 — ② 에서 점검")}</div>`}
        ${cbox}
        ${pr && pr.text ? `<details class="mcard proposal small" ${conf && conf.confirmed ? "" : "open"}><summary><b>${esc(pr.label || "팀 설계 문서")}</b> <small class="muted">원문 그대로 · 요구사항 v1 은 이 글의 권한 문장을 옮긴 것 · ${esc(pr.path || "")}</small></summary><div class="mdtext">${mdLite(pr.text)}</div></details>` : ""}</div>
      <div class="s3-list"><div class="mcard reqs"><h3>요구사항 <small>${esc(I.label || "")} · 편집기 없음 — 고친 JSON 파일을 올리면 새 판</small></h3>${req.rows ? reqHtml(req) : ""}</div>
        <div class="mcard"><h3>지금 코드와 다른 곳 <small>V6 IAM 요구사항 검사 — 원본 plan + 코드에 지금 요구사항을 대입</small></h3>
          ${diffs.length ? `<ul class="flist">${diffs.map((x) => `<li class="${esc(x.cls)}">${esc(x.text)}</li>`).join("")}</ul><p class="small muted">④ 보안 문제에 같은 문제가 나오고, ⑤ 에서 고칩니다.</p>`
            : `<p class="sdiff ok">지금 코드가 요구사항과 같습니다${I.verdict === "PASS" ? "" : ` (판정: ${esc(I.verdict || "?")})`}.</p>`}
          ${(I.info || []).length ? `<p class="small muted">${(I.info || []).map(esc).join("<br>")}</p>` : ""}</div></div>
    </div>`;
}
function drawIamDesign() {
  const I = (S.design || {}).iam || {};
  const now = S.iamPic === "now";
  const model = now ? I.current : I.view;
  if (!model) return;
  drawMap("tMap", model, { perm: true, overlay: now ? I.overlay : null }, (pk) => {
    const v = mapView("tMap");
    if (pk.type === "node") pop(nodeInfo(v, pk.node), pk.x, pk.y);
    else pop((pk.links || [pk.link]).map((l) => linkInfo(v, l, now ? I.overlay : null)).join("<hr>"), pk.x, pk.y);
  });
}
document.addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-ipv]");
  if (!b || S.step !== 3) return;
  S.iamPic = b.dataset.ipv; render();
});

register(3, () => {
  const D = S.design;
  if (!D) { $("#mbody").innerHTML = `<div class="mempty">불러오는 중…</div>`; return; }
  if (!D.ok) { $("#mbody").innerHTML = `<div class="mempty">${esc(D.reason || "")}</div>`; return; }
  if (D.mode === "iam") { $("#mbody").innerHTML = iamDesignHtml(); drawIamDesign(); return; }
  if (D.mode === "handoff" || caseMode() === "handoff") {
    $("#mbody").innerHTML = `<div class="mempty"><b>이 요청은 설계도 · 요구사항으로 검사하지 않습니다</b><p>${esc(D.reason || "")}</p>
      <div class="mnav center"><button type="button" class="mbtn" data-go="2">◀ ② 사람에게 넘김 칸</button><button type="button" class="mbtn primary" data-go="4">④ 찾은 문제 보기 ▶</button></div></div>`;
    return;
  }
  const { E, p, cmp } = cur();
  const pay = D.design || {};
  const auto = D.exists ? !!D.auto : true;
  const view0 = cmp.view || null;
  const rows = flowSort(shownRows(), (((S.design || {}).compare) || {}).view || view0);
  const nextV = D.exists ? Math.max(1, ...((pay.versions || []).map((x) => x.version))) + 1 : D.can_auto ? 2 : 1;
  const reqs = (D.requirements || []).filter((r) => (r.rows || []).length);
  const view = view0;
  const title = `설계도 v${D.exists ? designVersion() : 1}${auto && !E.edits.length ? " · 자동으로 만든 것" : ""}${E.edits.length ? " → 바꾸는 중 (저장 전)" : ""}`;
  const vstrip = (pay.versions || []).length > 1 ? `<div class="vstrip"><span class="small muted">버전</span>${pay.versions.map((x) => `<button type="button" class="vchip ${x.active ? "on" : ""}" data-ver="${x.version}" title="${esc(x.note || x.changes || "")}">v${x.version}${x.auto ? " · 자동" : x.version === 1 && x.source === "manifest" ? " · 실험 기준" : x.version === 1 && x.source === "proposal" ? ` · ${(D.proposal && D.proposal.label) || "제안서"}` : ""}${x.active ? " · 지금" : ""}${(x.confirmation || {}).basis === "human" ? " · 확정" : (x.confirmation || {}).basis === "draft" ? " · 초안" : ""}</button>`).join("")}</div><div id="verAsk"></div>` : "";
  const conf = D.exists ? (pay.confirmation || null) : null;
  // 확정 상태 (D-38): 초안이면 '고객 요구 충족' 판정 · 승인이 안 된다 — 담당자 이름을 적고 확정. 실험 세트 설계도는 '팀 작성 평가 기준' 으로만 표시
  const confirmBox = !D.exists ? "" : conf && conf.confirmed && conf.basis === "manifest" ? `<div class="mcard confirm manifest small"><b>팀 작성 평가 기준</b> ${chip("dim", "실험 세트")}<br>${esc(conf.by || "")}. 고객이 확정한 설계도와 구분해서 읽습니다 — 이 예제에서는 이 설계도를 기준으로 검사합니다.</div>`
    : conf && conf.confirmed ? `<div class="mcard confirm ok small"><b>확정된 설계도 v${esc(conf.version)}</b> ${chip("ok", "확정")}<br>${esc(conf.by)} 확정${conf.at ? ` · ${esc(String(conf.at).slice(0, 16).replace("T", " "))}` : ""}${conf.note ? ` — ${esc(conf.note)}` : ""}. 이 버전을 기준으로 한 검사만 '고객 요구 충족' 으로 봅니다. 바꿔서 저장하면 새 버전은 다시 초안이 됩니다.</div>`
    : `<div class="mcard confirm draft small"><b>초안 — 아직 확정 전</b> ${chip("warn", "판정 근거로 쓰지 않음")}<br>${conf && conf.note ? esc(conf.note) + " " : ""}${auto ? "프로그램이 지금 코드에서 만든 것이라 고객 의도가 아닙니다. " : conf && conf.source === "proposal" ? `${esc(conf.source_label || "고객 제안서")}의 허용 통신을 옮긴 초안입니다 — 원문(아래)과 같은지 담당자가 확인해야 합니다. ` : "저장만 한 상태입니다. "}목록이 고객이 허용한 통신과 같으면 담당자가 이름을 적고 확정하세요 — 그 뒤 검사한 것만 승인할 수 있습니다.
      ${E.edits.length ? `<p class="small muted">바꾸는 중 — 먼저 저장(새 버전)한 뒤 확정</p>` : `<div class="mnav"><button type="button" class="mbtn primary sm" data-act="s-confirm">이 설계도 확정하기 (v${esc(D.exists ? designVersion() : 1)})</button></div>`}</div>`;
  const diff = p ? p.diff : (cmp.diff || 0);
  const save = E.edits.length ? `<div class="ssave"><div class="ss-h"><b>바꾼 것 ${E.edits.length}개</b><span class="small muted">저장하기 전에는 기준이 그대로</span></div>
      <ol class="elist">${E.edits.map((e, i) => `<li><span>${esc(e.text || "")}</span><button type="button" class="x" data-sundo="${i}" title="되돌리기">×</button></li>`).join("")}</ol>
      ${E.errors.length ? `<ul class="notes">${E.errors.map((x) => `<li class="bad">${esc(x)}</li>`).join("")}</ul>` : ""}
      <label class="ed-note">바꾼 이유 (기록에 남음)<input id="sNote" class="minput" value="${esc(E.note)}" placeholder="예: 운영팀 사무실에서만 SSH"></label>
      <div class="mnav"><button type="button" class="mbtn primary" data-act="s-save" ${E.saving || E.errors.length || !p ? "disabled" : ""}>저장 → v${nextV}</button><button type="button" class="mbtn" data-act="s-clear">모두 취소</button></div></div>` : "";
  const now = s3Now();
  $("#mbody").innerHTML = `${now && now.key !== "confirmed" && now.key !== "manifest" ? guideCard({ ...now, kicker: "다음 할 일" }) : ""}<div class="s3">
      <div class="s3-pic">${view ? mapBox("tMap", title, MLEG.design) : `<div class="mempty">${esc(D.reason || cmp.reason || (cmp.errors || []).join(" ") || "원본 plan 이 없어 그림을 그리지 못함 — ② 에서 점검")}</div>`}
        ${vstrip}
        ${confirmBox}
        ${proposalHtml(D.proposal, !(conf && conf.confirmed))}
        ${auto && !E.edits.length ? `<div class="mcard auto small"><b>v1 은 프로그램이 자동으로 만든 설계도입니다</b> ${chip("warn", "사람이 확인한 고객 설계 아님")}<br>지금 코드의 통신을 그대로 두고, 위험한 통신(인터넷 전체 → 관리 포트 등)만 막았습니다. 고객이 원하는 것과 다르면 오른쪽 목록에서 바꾸고 저장하세요.</div>` : ""}</div>
      <div class="s3-list"><div class="mcard flist3"><h3>통신 목록 <small>한 줄 = 출발 → 도착 : 포트 · 설계도에 [허용] 이면 그림에 선이 생김</small></h3>
          ${rows.length ? `<ul class="frows">${rows.map(rowHtml).join("")}</ul>` : `<p class="muted small">보안 그룹 허용이 없음</p>`}
          <div class="fadd-wrap">${addHtml()}</div>
          <p class="sdiff ${diff ? "warn" : "ok"}">${diff ? `지금 코드와 다른 곳 <b>${diff}개</b> ('지금 코드와 다름' 표시) — ④ 보안 문제에 '설계 위반' 으로 나오고, ⑤ 에서 고칩니다.` : "지금 코드가 설계도와 같습니다."}</p></div>
        ${save}
        ${reqs.length ? `<div class="mcard reqs"><h3>그 밖의 고객 요구사항 <small>IAM 등 별도 형식 — 편집기 없음, 고친 JSON 파일을 올리면 새 판</small></h3>${reqs.map(reqHtml).join("")}</div>` : ""}</div>
    </div>`;
  if (view) {
    drawMap("tMap", view, { simple: true }, (pk) => {
      const v = mapView("tMap");
      if (pk.type === "node") pop(nodeInfo(v, pk.node), pk.x, pk.y);
      else pop((pk.links || [pk.link]).map((l) => linkInfo(v, l)).join("<hr>"), pk.x, pk.y);
    });
  }
});

// 목록의 버튼들 (③ 에서만)
document.addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-fr]");
  if (!b || b.disabled || S.step !== 3) return;
  const E = sedit();
  const a = b.dataset.fr;
  if (a === "add") { E.add = true; E.open = null; render(); return; }
  if (a === "add-x") { E.add = false; render(); return; }
  if (a === "add-ok") {
    const box = b.closest(".fadd");
    const v = (k) => ((box.querySelector(`[data-a="${k}"]`) || {}).value || "").trim();
    const from = v("from"), to = v("to"), proto = v("proto");
    const port = proto === "all" ? "0" : v("port");
    if (!to) { toast("도착 상자를 고르세요"); return; }
    if (!port) { toast("포트를 적으세요 (예: 443)"); return; }
    const e = { op: "add", to, port, protocol: proto === "all" ? "-1" : proto, key: `add|${Date.now()}` };
    if (from === "__any") e.cidr = "0.0.0.0/0";
    else if (from === "__cidr") { if (!v("cidr")) { toast("IP 대역을 적으세요 (예: 198.51.100.0/24)"); return; } e.cidr = v("cidr"); e.label = v("label"); }
    else { if (from === to) { toast("출발과 도착이 같음"); return; } e.from = from; }
    E.edits.push(e); E.add = false; render(); schedule(0);
    return;
  }
  const li = b.closest("[data-key]");
  const r = li && shownRows().find((x) => x.key === li.dataset.key);
  if (!r) return;
  const base = { edges: r.edges || [r.edge], only: r.only, key: r.key };
  if (a === "allow") { if (r.kind === "design") unEdit(r.key); else setEdit({ op: "keep", ...base }); return; }
  if (a === "block") { if (r.kind === "design") setEdit({ op: "drop", flow: r.flow, key: r.key }); else setEdit({ op: "block", ...base }); return; }
  if (a === "ip" || a === "via") { E.open = E.open === r.key ? null : r.key; render(); return; }
  if (a === "ip-ok") {
    const cidr = ((li.querySelector('[data-i="cidr"]') || {}).value || "").trim();
    if (!cidr) { toast("IP 대역을 적으세요 (예: 203.0.113.0/24)"); return; }
    setEdit({ op: "narrow", ...base, cidr, label: ((li.querySelector('[data-i="label"]') || {}).value || "").trim() });
    return;
  }
  if (a === "via-ok") { setEdit({ op: "narrow", ...base, via: (li.querySelector('[data-i="via"]') || {}).value }); }
});
document.addEventListener("change", (ev) => {
  if (S.step !== 3 || !ev.target.matches('.fadd [data-a="from"]')) return;
  const row = ev.target.closest(".fadd").querySelector(".fadd-cidr");
  if (row) row.hidden = ev.target.value !== "__cidr";
});

export async function structAct(a, t, reload) {
  const E = sedit();
  if (a === "s-clear") { S.sedit = null; render(); return; }
  if (a === "s-confirm" || a === "r-confirm") {
    // 확정 (D-38 · D-40): 담당자 이름 필수 · 메모 선택. 서버가 확정 기록(이름 · 시각 · 파일 지문)을 남긴다. r-confirm = 요구사항 파일(IAM 등)의 올린 판
    const req = a === "r-confirm";
    const sid = req ? t.dataset.set : S.design.set_id;
    const v = req ? +t.dataset.v : designVersion();
    const word = req ? "요구사항" : "설계도";
    const m = modal(`${word} v${v} 확정`, `<p>이 ${req ? "요구사항 파일(허용 · 필수 권한)" : "설계도(통신 목록)"}이 <b>고객이 허용한 것 그대로</b>라고 담당자가 확정합니다. 확정한 사람 · 시각이 기록에 남고, 이 버전을 기준으로 한 검사만 승인할 수 있습니다.</p>
      <label class="ed-note">확정한 사람 (필수)<input id="cfBy" class="minput" placeholder="이름"></label><label class="ed-note">메모 (선택 — 어디서 받은 요구사항인지)<input id="cfNote" class="minput" placeholder="예: 고객 네트워크 담당자 11/2 회의"></label>
      <div class="mnav"><button type="button" class="mbtn primary" id="cfGo">확정</button><button type="button" class="mbtn" data-close>취소</button></div>`);
    m.querySelector("#cfGo").addEventListener("click", async () => {
      const by = (m.querySelector("#cfBy") || {}).value || "", note = (m.querySelector("#cfNote") || {}).value || "";
      const r = await api.post("/api/design/confirm", { set_id: sid, version: v, by, note });
      if (!r || !r.ok) { toast((r && (r.errors || [r.error]).join(" ")) || "확정하지 못함"); return; }
      m.remove();
      if (reload) await reload();
      render(); toast(`${word} v${r.version} 확정 — 이제부터 검사 결과를 승인할 수 있음 (이미 끝난 검사는 확정 전 기준 → 다시 검사)`, "good");
    });
    m.querySelector("#cfBy").focus();
    return;
  }
  if (a === "s-undo") { E.edits.splice(+t.dataset.sundo, 1); render(); schedule(0); return; }
  if (a === "s-save") {
    E.saving = true; render();
    const r = await api.post("/api/p/structure/save", { project: S.pid, edits: E.edits.map(strip), note: E.note, base_version: S.design && S.design.exists ? designVersion() : null });
    if (!r || !r.ok) { E.saving = false; E.errors = (r && (r.errors || [r.error])) || ["저장 실패"]; render(); return; }
    S.sedit = null;
    await reload();
    toast(`설계도 v${r.version} 저장 — 이제부터 검사 · AI 수정은 v${r.version} 기준`, "good");
    render();
  }
}
export function structNote(v) { sedit().note = v; }

// 요구사항 파일 새 판 올리기 (D-40): 파일 → 본문 그대로 서버로 (형식 · 대상 검사는 서버) · 바꾼 이유 · 올린 사람
export async function reqImport(input, reload) {
  const f = (input.files || [])[0];
  const sid = input.dataset.reqfile;
  if (!f || !sid) return;
  const text = await f.text();
  input.value = "";
  const m = modal(`요구사항 새 판 올리기 — ${esc(f.name)}`, `<p class="small">파일 내용을 바꾸지 않고 그대로 저장합니다. 지금 기준과 같은 종류 · 같은 intent_id 여야 하고, 바뀐 것이 없으면 거절합니다. 올린 판은 <b>초안</b>이라 담당자가 확정해야 승인 기준이 됩니다.</p>
    <label class="ed-note">바꾼 이유 (기록에 남음)<input id="riNote" class="minput" placeholder="예: 고객이 ListBucket 을 뺌"></label><label class="ed-note">올린 사람<input id="riBy" class="minput" placeholder="이름"></label>
    <div class="mnav"><button type="button" class="mbtn primary" id="riGo">올리기</button><button type="button" class="mbtn" data-close>취소</button></div>`);
  m.querySelector("#riGo").addEventListener("click", async () => {
    const r = await api.post("/api/design/req/import", { set_id: sid, json: text, note: (m.querySelector("#riNote") || {}).value || "", by: (m.querySelector("#riBy") || {}).value || "" });
    if (!r || !r.ok) { toast((r && (r.errors || [r.error]).join(" ")) || "올리지 못함"); return; }
    m.remove();
    if (reload) await reload();
    render(); toast(`요구사항 v${r.version} 저장 (초안) — ${(r.changes || {}).text || ""}. 담당자가 확정하면 그 판이 승인 기준`, "good");
  });
}

export async function reqActivate(key, reload) {
  const [sid, v] = String(key).split("|");
  const r = await api.post("/api/design/activate", { set_id: sid, version: +v });
  if (!r || !r.ok) { toast((r && (r.errors || [r.error]).join(" ")) || "바꾸지 못함"); return; }
  if (reload) await reload();
  render(); toast(`요구사항 v${v} 를 지금 기준으로 — 이미 끝난 결과는 그때 기준 그대로`, "good");
}
