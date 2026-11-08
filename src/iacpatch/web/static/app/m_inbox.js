// 고객 요청함 (16차, D-52 — B 11-06 "고객 요청을 실시간으로 들어오게 … 시간 지나면 진짜 새로 들어온 거마냥, 실제 기반처럼").
// 서버(web/inbox.py)가 정한 도착(정해 둔 날짜 · 시각 · 고객 역할로 넣기)을 ① 목록 · 모든 화면의 알림 · 왼쪽 숫자로 보여 준다.
// 17차 (D-53, B 11-07 "발표용 타이머 같은 쓸데없는 내용 빼라"): 타이머 · [다음 요청 지금 받기] · [처음부터] · 방식 고르기 · 다음 도착 줄 ·
// 요청 줄의 숫자 칩 · 받은 방식 글을 뺐다. [고객 역할로 요청 넣기]만 남김.
// 요청 내용 · 판정은 바꾸지 않는다 — 언제 보이는지 · 받은 시각 · 누가 넣었는지 · 읽었는지만. 요청 · 고객 · 사연은 가상.
import { $, S, api, esc, chip, toast, modal, renderSide, onEnter } from "./m_core.js";

const PRI = { 긴급: "bad", 높음: "warn", 보통: "dim" };
const STAT = { new: "new", dim: "dim", run: "run", good: "ok", warn: "warn" };
const POLL_MS = 10000;
let known = null;           // 지금까지 본 요청 id (처음 불러온 것은 '새로 도착' 으로 알리지 않는다)
let polling = false;
let onArrive = null;        // 새 요청이 오면 프로젝트 목록을 다시 받는 함수 (main.js 가 건다)

// ① 카드 · 요청함 줄이 같이 쓰는 칩 · 숫자 칸 (전에는 m_one.js 의 projCard 안에 있었음)
export function kindChip(p) {
  if (p.kind === "user") return chip("run", "내 프로젝트");
  if (p.testbed) return chip("ok", "예제 · AWS 시험 환경 있음");
  if (p.fix_scope === "out_of_policy") return chip("warn", "예제 · 정책 범위 밖 → 사람에게");
  if (p.request && p.request.kind === "iam") return chip("warn", `예제 · ${p.proposal_label || "팀 설계 문서"} → 권한 요구사항`);
  if (p.proposal) return chip("warn", `예제 · ${p.proposal_label || "고객 제안서"} → 설계도`);
  return chip("dim", "예제 · 실제 AWS 시험 환경 없음");
}
export function statCells(p) {
  const last = p.fix_scope === "out_of_policy" ? `<div><dt>고객 설계도</dt><dd>해당 없음</dd></div>`
    : !p.design && p.iam_req ? `<div><dt>IAM 요구사항</dt><dd>v${esc(p.iam_req.version)}</dd></div>`
      : `<div><dt>고객 설계도</dt><dd>${p.design ? `v${esc(p.design.version)}` : "없음 (초안부터)"}</dd></div>`;
  return `<div><dt>Terraform 파일</dt><dd>${p.files == null ? "—" : esc(p.files)}</dd></div><div><dt>리소스</dt><dd>${p.resources != null ? esc(p.resources) : p.kind !== "user" ? "열면 점검" : p.scanned ? "plan 없음" : "점검 전"}</dd></div>
    <div><dt>Trivy 지적</dt><dd>${p.trivy_findings == null ? "점검 전" : esc(p.trivy_findings)}</dd></div>${last}`;
}

// 서버 시각 기준 '지금' (PC 시계가 조금 달라도 '몇 분 전' 이 맞게)
function nowMs() {
  const v = S.inbox;
  const base = v && Date.parse(v.now);
  return Number.isFinite(base) ? base + (Date.now() - (S.inboxAt || Date.now())) : Date.now();
}
function ago(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const s = Math.max(0, Math.round((nowMs() - t) / 1000));
  if (s < 60) return "방금";
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`;
  return `${Math.floor(s / 86400)}일 전`;
}

export const isInboxCase = (id) => !!S.inbox && (S.inbox.items.some((i) => i.id === id) || (S.inbox.pending || []).some((i) => i.id === id));

// ------------------------------------------------------------------ ① 요청함
function row(i) {
  const p = (S.projects || []).find((x) => x.id === i.id);
  const st = i.status || {};
  return `<article class="ibrow ${i.unread ? "unread" : ""} ${i.id === S.pid ? "on" : ""} ${S.ibFresh && S.ibFresh[i.id] ? "fresh" : ""}" data-rid="${esc(i.id)}">
    <span class="ib-dot" title="${i.unread ? "안 읽음" : "읽음"}" aria-label="${i.unread ? "안 읽음" : "읽음"}"></span>
    <div class="ib-main">
      <div class="ib-l1"><span class="ib-seq">요청 ${esc(i.seq)}</span><b class="ib-t">${esc(i.title)}</b></div>
      <div class="ib-l2">${chip(PRI[i.priority] || "dim", i.priority)}${p ? kindChip(p) : ""}<span class="ib-from">${esc(i.sender)} · ${esc(i.channel)} · 기한 ${esc(i.due)}</span></div>
      <p class="ib-sum">${esc(i.summary)}</p>
      ${i.by ? `<p class="ib-by">고객 역할로 넣은 사람 <b>${esc(i.by)}</b>${i.memo ? ` — “${esc(i.memo)}”` : ""}</p>` : ""}
    </div>
    <div class="ib-r"><time datetime="${esc(i.at)}">${esc(i.at_text)}</time><small class="ib-ago" data-ago="${esc(i.at)}">${esc(ago(i.at))}</small>
      <span class="mchip ${STAT[st.tone] || "dim"}">${esc(st.word || "")}</span>
      <button type="button" class="mbtn primary" data-open="${esc(i.id)}" ${p ? "" : "disabled"} title="${esc(p ? p.name : "프로젝트 목록을 다시 불러오는 중")}">${i.id === S.pid ? "계속하기 ▶" : "열기 ▶"}</button></div>
  </article>`;
}

export function inboxHtml() {
  const v = S.inbox;
  if (!v) return `<div class="ib-h"><h2 class="msec">고객 요청함</h2></div><p class="muted small">요청함을 불러오지 못했습니다 — 서버가 켜져 있는지 확인하세요.</p>`;
  return `<div class="ib-h"><div><h2 class="msec">고객 요청함 <small>${esc(v.customer)} · 받은 요청 ${esc(v.items.length)}건${v.unread ? ` · <b class="ib-unread">안 읽음 ${esc(v.unread)}</b>` : ""}</small></h2>
      <p class="small muted">요청 · 보낸 사람 · 사연은 예제를 위해 만든 가상입니다. 최근에 받은 요청이 위에 있습니다.</p></div>
      <button type="button" class="mbtn" data-act="ib-insert" ${v.pending_count ? "" : `disabled title="넣을 요청이 없습니다 — ${esc(v.total)}건 모두 도착"`}>고객 역할로 요청 넣기</button></div>
    <div class="iblist">${v.items.map(row).join("") || `<p class="muted">아직 받은 요청이 없습니다.</p>`}</div>`;
}

// 요청함 칸만 다시 그린다 — 폴더 연결 칸에 적던 글이 지워지지 않게 (① 전체를 다시 그리지 않음)
export function drawInbox() {
  const box = $("#ibox");
  if (box) box.innerHTML = inboxHtml();
}

// ------------------------------------------------------------------ 알림 · 왼쪽 숫자 · 창 제목
function badge() {
  const n = (S.inbox && S.inbox.unread) || 0;
  document.title = n ? `(${n}) IaCPatch` : "IaCPatch";
}
export const unreadCount = () => (S.inbox && S.inbox.unread) || 0;

function announce(items) {
  document.querySelectorAll(".ibtoast").forEach((x) => x.remove());
  const el = document.createElement("div");
  el.className = "ibtoast";
  el.setAttribute("role", "status");
  const one = items.length === 1 ? items[0] : null;
  el.innerHTML = `<div class="ibt-k"><span class="ibt-dot"></span>새 고객 요청${items.length > 1 ? ` ${items.length}건` : ""} 도착 <small>가상</small></div>
    ${items.slice(0, 3).map((i) => `<div class="ibt-r"><b>요청 ${esc(i.seq)} · ${esc(i.title)}</b><small>${esc(i.sender)} · ${esc(i.channel)} · ${esc(i.priority)}${i.by ? ` · 고객 역할 ${esc(i.by)}` : ""}</small></div>`).join("")}
    <div class="ibt-b">${one ? `<button type="button" class="mbtn primary sm" data-open="${esc(one.id)}">열기 ▶</button>` : ""}<button type="button" class="mbtn sm" data-go="1">요청함 보기</button><button type="button" class="mbtn sm" data-ibclose>닫기</button></div>`;
  el.addEventListener("click", (e) => { if (e.target.closest("[data-open],[data-go],[data-ibclose]")) setTimeout(() => el.remove(), 0); });
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 15000);
}

function sig(v) {
  return JSON.stringify([v.pending_count, v.items.map((i) => [i.id, i.unread, (i.status || {}).word])]);
}

// 10초마다 — 도착 처리는 서버가 한다
export async function inboxPoll(force = false) {
  if (polling && !force) return;
  polling = true;
  try {
    const v = await api.get("/api/inbox");
    if (!v || v.error || !Array.isArray(v.items)) return;
    await apply(v);
  } finally { polling = false; }
}

async function apply(v) {
  const prev = S.inbox;
  S.inbox = v; S.inboxAt = Date.now();
  const fresh = known ? v.items.filter((i) => !known.has(i.id)) : [];
  known = new Set(v.items.map((i) => i.id));
  if (fresh.length) {
    S.ibFresh = Object.fromEntries(fresh.map((i) => [i.id, true]));
    setTimeout(() => { S.ibFresh = null; document.querySelectorAll(".ibrow.fresh").forEach((x) => x.classList.remove("fresh")); }, 6000);
    if (onArrive) await onArrive();
    announce(fresh);
  }
  badge();
  if (!prev || sig(prev) !== sig(v) || fresh.length) { renderSide(); if (S.step === 1) drawInbox(); }
}

// 1초마다: '몇 분 전' 글자만 고친다 (화면을 다시 그리지 않음)
function tick() {
  if (!S.inbox || S.step !== 1) return;
  document.querySelectorAll("[data-ago]").forEach((el) => { el.textContent = ago(el.dataset.ago); });
}

export function startInbox(refresh) {
  onArrive = refresh;
  setInterval(() => inboxPoll(), POLL_MS);
  setInterval(tick, 1000);
  onEnter(1, () => inboxPoll(true));       // ① 로 돌아오면 바로 새로 — 다른 화면에서 승인 · 검토한 결과가 상태 줄에 곧바로 보이게 (10초를 기다리지 않음)
}

// 연 요청은 '읽음' — 상태 줄이 '새 요청' → '확인함' (넘김 요청은 '사람에게 넘김')
export async function markRead(id) {
  const it = S.inbox && S.inbox.items.find((i) => i.id === id);
  if (!it || !it.unread) return;
  it.unread = false;
  S.inbox.unread = Math.max(0, (S.inbox.unread || 0) - 1);
  badge(); renderSide();
  await api.post("/api/inbox/read", { id });
  inboxPoll(true);
}

// ------------------------------------------------------------------ 조작 (① 요청함의 단추 — 17차: [고객 역할로 요청 넣기] 하나)
const withoutOk = (r) => Object.fromEntries(Object.entries(r).filter(([k]) => k !== "ok"));   // 서버 답 = {ok, ...요청함 보기}

export async function inboxAct(a) {
  if (a === "ib-insert") openInsert();
}

// [고객 역할로 요청 넣기] — 아직 안 온 요청 하나를 골라 이름 · 메모와 함께 바로 도착시킨다 (새 문제를 만들어 내지는 않음)
function openInsert() {
  const v = S.inbox;
  if (!v || !(v.pending || []).length) { toast("아직 안 온 요청이 없습니다"); return; }
  const KIND = { handoff: "사람에게 넘김", iam: "권한 요구사항", topology: "통신 설계도" };
  const m = modal("고객 역할로 요청 넣기", `<p class="small">팀원이 고객(가상 운영팀) 역할로 <b>아직 안 온 요청</b> 하나를 지금 보냅니다. 요청 내용 · 조건은 정해 둔 그대로이고, 받은 시각 · 넣은 사람 · 메모만 기록됩니다.</p>
    <label class="iblab"><span>보낼 요청</span><select id="ibPick" class="minput">${v.pending.map((x) => `<option value="${esc(x.id)}">요청 ${esc(x.seq)} · ${esc(x.title)} (${esc(KIND[x.kind] || x.kind)})</option>`).join("")}</select></label>
    <label class="iblab"><span>고객 역할을 하는 사람 이름 <small>(필수 · 30자까지)</small></span><input id="ibBy" class="minput" maxlength="30" placeholder="예: 김판종"></label>
    <label class="iblab"><span>메모 <small>(선택 · 200자까지 — 예: 발표 중 질문 받고 넣음)</small></span><input id="ibMemo" class="minput" maxlength="200"></label>
    <p class="small bad" id="ibErr"></p>
    <div class="mnav"><button type="button" class="mbtn primary" id="ibSend">이 요청 보내기</button><button type="button" class="mbtn" data-close>취소</button></div>`);
  const by = m.querySelector("#ibBy");
  by.focus();
  m.querySelector("#ibSend").addEventListener("click", async () => {
    const body = { id: m.querySelector("#ibPick").value, by: by.value, memo: m.querySelector("#ibMemo").value };
    if (!body.by.trim()) { m.querySelector("#ibErr").textContent = "이름을 적어 주세요"; by.focus(); return; }
    const r = await api.post("/api/inbox/insert", body);
    if (!r || !r.ok) { m.querySelector("#ibErr").textContent = ((r && (r.errors || [r.error])) || ["보내지 못함"]).join(" "); return; }
    m.remove();
    await apply(withoutOk(r));
    drawInbox();
  });
}
