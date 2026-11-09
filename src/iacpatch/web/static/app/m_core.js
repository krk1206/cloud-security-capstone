// 새 프로그램 공통 (2026-11-01 갈아엎기 3차): 상태 · 서버 호출 · 그림 · 창 · 단계 이동.
// 판정은 만들지 않는다 — 서버(web/product.py · 검사 기록)가 준 값을 그대로 보여 준다.

export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// 긴 리소스 이름(aws_vpc_security_group_ingress_rule.db_from_bastion)은 '.' · '_' · '/' 뒤에서 줄을 바꿀 수 있게 (17차: 칸 끝에서 'bastio|n' 처럼 끊기던 것)
export const escBrk = (s) => esc(s).replace(/([._/])(?=[A-Za-z0-9])/g, "$1<wbr>");
// ② · 왼쪽 메뉴의 '리소스 N개' = plan 의 리소스(managed) 수 — AWS 를 읽기만 하는 data 소스는 빼고 센다 (① 카드와 같은 수, 14차: 팀 3계층이 ① 54 · ② 55 로 달랐다)
export const resCount = (inv) => (inv ? (inv.total || 0) - ((inv.counts || {}).data || 0) : 0);
// 이 예제가 무엇으로 검사되나 (15차, D-51): topology(통신 설계도) · iam(권한 요구사항 — 그림 = 권한 그림) · handoff(팀 정책의 자동 수정 범위 밖 → 사람에게)
export const caseMode = () => (S.proj && S.proj.fix_scope === "out_of_policy" ? "handoff" : S.proj && S.proj.request && S.proj.request.kind === "iam" ? "iam" : "topology");
export const fmt = (iso) => { const t = String(iso || ""); return t.length >= 16 ? `${+t.slice(5, 7)}/${+t.slice(8, 10)} ${t.slice(11, 16)}` : t; };

export const api = {
  async get(u) { try { const r = await fetch(u); return await r.json(); } catch (e) { return { error: String(e) }; } },
  async post(u, b) { try { const r = await fetch(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return await r.json(); } catch (e) { return { error: String(e) }; } },
};

// 8단계 — 사용자의 질문 (V 번호는 '자세히' 에만)
// 7차 (D-35, B 11-02 "청중 · 사용자가 쓰기 쉽게"): 단계마다 '할 일' 한 줄(todo)을 머리말에 크게, 설명(sub)은 '이 화면 안내' 첫 칸으로.
// 왼쪽 메뉴는 8단계 그대로 두고 보기 · 고치기 · 확인 · 결정 네 묶음으로 나눠 보인다 (grp)
export const GROUPS = { see: "01 · 현황", fix: "02 · 수정", check: "03 · 검증", decide: "04 · 승인" };
export const STEPS = [
  { n: 1, short: "프로젝트", grp: null, q: "프로젝트 선택", sub: "프로젝트를 고르면 현재 인프라부터 차례로 확인합니다.",
    todo: "검토할 프로젝트를 여세요. 내 Terraform 폴더도 연결할 수 있습니다." },
  { n: 2, short: "현재 인프라", grp: "see", q: "현재 인프라", sub: "Terraform 코드의 리소스 전부를 AWS 구성도처럼 — VPC · 서브넷 · 로드밸런서 · 서버 · DB · S3 · IAM, 보안 그룹 허용(포트)은 선으로.",
    todo: "그림에서 빨간 선(위험한 허용)을 찾아보세요. 상자 · 선을 누르면 설명이 나옵니다." },
  { n: 3, short: "원하는 구조", grp: "see", q: "허용 통신 기준", sub: "설계도 = 고객이 허용하는 통신. 처음엔 프로그램이 자동으로 만들고(지금 코드에서 위험한 통신만 막음), 오른쪽 목록에서 통신마다 허용 · 막기를 고르면 왼쪽 설계도 그림이 바뀝니다.",
    todo: "오른쪽 목록에서 통신마다 허용 · 막기를 고르세요. 왼쪽 그림이 바로 바뀌고, 저장하면 검사 기준이 됩니다." },
  { n: 4, short: "보안 문제", grp: "see", q: "보안 문제", sub: "Trivy(알려진 설정 오류) + 자체 보안 그룹 검사 + 고객 설계 위반을 한 목록으로.",
    todo: "문제를 하나 누르세요. 고칠 수 있는 문제면 '이 문제 고치기' 버튼이 나옵니다." },
  { n: 5, short: "수정안", grp: "fix", q: "수정안 비교", sub: "수정안 번호를 누르면 그림이 '그 수정안을 적용한 뒤' 모습으로 바뀝니다. 설계도와 다른 곳만 빨강 ✕. AI · 내가 고친 파일도 같은 검사.",
    todo: "'AI 에게 고치게 하기' 를 누르거나, 팀 평가용 수정안을 하나 골라 설계도와 비교하세요." },
  { n: 6, short: "배포 전 검증", grp: "check", q: "배포 전 검증", sub: "배포 전에 코드만으로 확인하는 다섯 가지 질문의 답.",
    todo: "다섯 질문의 답을 보세요. 빨간 답이나 '검사 못 함' 이 있으면 승인할 수 없습니다." },
  { n: 7, short: "AWS 시험 환경", grp: "check", q: "AWS 시험 환경", sub: "사람이 승인한 뒤 AWS 시험 환경(샌드박스)에 반영해서 설정과 연결을 잽니다 — 운영 환경이 아닙니다.",
    todo: "'다음 할 일' 칸의 버튼을 순서대로 누르세요 (원본 반영 → 측정 → 수정안 반영 → 측정 → 삭제). 반영 · 삭제는 확인 창에서 plan 을 보고 사람이 실행합니다." },
  { n: 8, short: "승인 및 PR", grp: "decide", q: "승인 및 PR", sub: "해결된 것 · 남은 것 · 새로 생긴 것 · 확인 못 한 것을 보고 결정합니다. 승인하면 PR 을 만듭니다.",
    todo: "승인 · 수정 요청 · 재생성 · 폐기 중 하나를 고르고 이유와 함께 기록하세요." },
];

export const SEV = { CRITICAL: ["crit", "매우 높음"], HIGH: ["high", "높음"], MEDIUM: ["med", "중간"], LOW: ["low", "낮음"], UNKNOWN: ["unk", "판정 불가"] };
export const SRC = { trivy: ["trivy", "Trivy"], sg: ["ours", "자체 검사"], design: ["design", "설계 위반"], iam: ["ours", "자체 IAM 검사"], requirement: ["design", "요구사항 위반"] };

// 전역 상태 — 프로젝트 하나를 처음부터 끝까지
export const S = {
  step: 1, pid: null, projects: [], proj: null, infra: null, design: null, issues: null, cov: null, cands: null,
  issue: null, node: null, cand: null, rec: null, impact: null, verdict: null, final: null,
  edit: null, run: null, log: [], llm: { status: null, runs: [], context: "trivy", live: null, view: null }, upload: null,
  designView: "design", lastRec: {}, src: null, issueFilter: "all", dec: null, pr: null,
  // 7차: 도구 상태(/api/app) · 크게 보기 · 팀 평가용 수정안 펼침 · 폴더 연결 칸 펼침 · 마지막 점검 · 준비 기록
  app: null, big: false, teamOpen: false, npOpen: false, scanLast: null, setupLast: null, autoScanned: {},
};

const screens = {};
export function register(n, fn) { screens[n] = fn; }
// 9차 (D-43 "사용법이 어려움"): 머리말의 '할 일' 은 고정 문장이 아니라 지금 상태에서 할 일 하나 — 화면마다 registerTodo 로 함수를 건다 (없으면 STEPS 의 기본 문장)
const todos = {};
export function registerTodo(n, fn) { todos[n] = fn; }
export function todoNow(st) { try { return (todos[st.n] && todos[st.n]()) || st.todo; } catch { return st.todo; } }
export function refreshTodo() { const el = $(".mh-todo span"); if (el) el.textContent = todoNow(STEPS[S.step - 1]); }   // 입력 중에는 화면 전체를 다시 그리지 않고 머리말 '할 일' 만
// '다음 할 일' 칸 — ⑦ 과 같은 모양을 ③ ⑤ ⑧ 에서도 쓴다. btns 는 완성된 버튼 HTML
export function guideCard({ tone = "", title, text, btns = "", kicker = "다음 할 일", extra = "" }) {
  return `<div class="mcard guide ${esc(tone)}"><div class="kicker">${esc(kicker)}</div><h3>${esc(title)}</h3>${text ? `<p>${esc(text)}</p>` : ""}${extra}${btns ? `<div class="mnav">${btns}</div>` : ""}</div>`;
}

export function canGo(n) {
  if (n === 1) return true;
  if (!S.pid) return false;
  if (n >= 6) return !!S.rec;
  return true;
}

export function lockReason(n) {
  if (!S.pid) return "프로젝트를 먼저 고르세요";
  if (n >= 6 && !S.rec) return "⑤ 에서 수정안을 분석한 뒤";
  return "";
}

const onStep = {};
export function onEnter(n, fn) { onStep[n] = fn; }        // 단계에 들어갈 때 한 번 (11차: ⑤ 미리 분석)
export function go(n, opts = {}) {
  if (!canGo(n) || S.run) return;
  if (S.sedit && S.sedit.pid === S.pid && S.sedit.edits.length && !opts.force && n !== S.step) { toast("원하는 구조를 바꾸는 중 — 저장하거나 '모두 취소' 한 뒤 이동"); return; }
  S.step = n;
  writeHash();
  render();
  $("#mbody").scrollTop = 0;
  if (onStep[n]) onStep[n]();
}

// 7차: 한 곳을 잠깐 밝게 (바로 가기로 넘어간 자리 · 화면 안내의 '바로 가기')
export function flash(sel) {
  const el = document.querySelector(sel);
  if (!el) return false;
  el.scrollIntoView({ behavior: "smooth", block: "center" });
  el.classList.remove("flash");
  void el.offsetWidth;          // 같은 자리를 다시 눌러도 다시 빛나게
  el.classList.add("flash");
  setTimeout(() => el.classList.remove("flash"), 2400);
  return true;
}
// 단계로 바로 가서 그 안의 자리를 밝게 — 화면이 서버 값을 받아 그려질 때까지 잠깐 기다린다 (예: ⑧ PR 칸)
export async function jumpTo(n, sel) {
  if (!canGo(n)) { toast(`아직 갈 수 없음 — ${lockReason(n)}`); return; }
  if (S.step !== n) go(n);
  if (!sel) return;
  for (let i = 0; i < 40; i++) { if (flash(sel)) return; await sleep(150); }
}

export function writeHash() {
  const p = [];
  if (S.pid) p.push(`p=${encodeURIComponent(S.pid)}`);
  if (S.step > 1) p.push(`s=${S.step}`);
  if (S.rec && S.step >= 5) p.push(`rec=${encodeURIComponent(S.rec)}`);
  const h = p.length ? "#" + p.join("&") : "";
  if (location.hash !== h) history.replaceState(null, "", location.pathname + h);
}

// 머리말 오른쪽 IAM 요구사항 표시 (15차): 권한 요청 예제의 ③ 이후 — 확정 · 초안을 글자로
function iamTag() {
  const I = S.design && S.design.mode === "iam" ? S.design.iam || {} : null;
  if (!I || S.step < 3) return "";
  const c = I.confirmation || {};
  return `<span class="mh-ver ${c.confirmed ? "ok" : "draft"}" title="${esc(c.confirmed ? `${c.by || ""} 확정` : "초안 — 확정 전 기준의 검사는 승인 불가")}">IAM 요구사항 v${esc(I.version || 1)} · ${c.confirmed ? "확정" : "초안"}</span>`;
}
export function render() {
  renderSide();
  const st = STEPS[S.step - 1];
  const p = S.proj;
  const prev = STEPS[S.step - 2], next = STEPS[S.step];
  // 이전 · 다음은 모든 화면에서 같은 자리(머리말 오른쪽)에 둔다
  const nav = S.pid ? `<div class="mh-nav">${prev ? `<button type="button" class="mbtn" data-go="${prev.n}" ${S.run ? "disabled" : ""}>◀ ${esc(prev.short)}</button>` : ""}
      ${next ? `<button type="button" class="mbtn primary" data-go="${next.n}" ${canGo(next.n) && !S.run ? "" : "disabled"} title="${esc(canGo(next.n) ? next.q : lockReason(next.n))}">다음 ▶ ${esc(next.short)}</button>` : ""}</div>` : "";
  const q = st.n === 3 && caseMode() === "iam" ? "허용 권한 기준" : st.q;       // 15차: 권한 요청의 ③ = IAM 요구사항
  $("#mhead").innerHTML = `<div class="mh-q"><span class="mh-n">${st.n}</span><div><h1>${esc(q)}</h1>
      <p class="mh-todo"><b>할 일</b><span>${esc(todoNow(st))}</span></p></div></div>
    <div class="mh-r"><div class="mh-tags">${p ? `<span class="mh-proj"><i>프로젝트</i>${esc(p.name)}</span>` : ""}${S.design && S.design.exists && S.step >= 3 ? `<span class="mh-ver ${designConf().cls}" title="${esc(designConf().title)}">원하는 구조 v${esc(designVersion())}${S.design.auto ? " · 자동" : ""} · ${esc(designConf().word)}</span>` : ""}${iamTag()}</div>${nav}</div>`;
  const fn = screens[S.step];
  if (fn) fn();
  refreshTodo();          // 화면 함수가 상태(고칠 대상 등)를 정한 뒤 머리말 '할 일' 을 그 상태로
}

export function designVersion() {
  const d = S.design || {};
  return ((d.design || {}).active_version) || 1;
}
// 설계도 확정 상태 글자 (D-38): 확정 · 초안 · 팀 작성 평가 기준
export function designConf() {
  const c = (((S.design || {}).design || {}).confirmation) || null;
  if (!c) return { word: "", cls: "", title: "" };
  if (c.basis === "manifest") return { word: "팀 작성 평가 기준", cls: "manifest", title: c.by || "" };
  if (c.confirmed) return { word: "확정", cls: "ok", title: `${c.by || ""} 확정${c.at ? " · " + String(c.at).slice(0, 16).replace("T", " ") : ""}` };
  return { word: "초안", cls: "draft", title: "아직 확정 전 — 이 기준으로 검사한 결과는 승인할 수 없음 (③ 에서 확정)" };
}

function stepNote(n) {
  if (!S.pid) return "";
  if (S.run && S.run.kind === "scan" && n >= 2 && n <= 4) return "점검 중…";
  if (n === 2 && S.infra && S.infra.ok && S.infra.arch) {
    const perm = caseMode() === "iam";             // 15차: 권한 요청이면 권한 선 수 · 넓은 권한 수
    const sg = (S.infra.arch.edges || []).filter((e) => e.kind === (perm ? "perm" : "sg"));
    return `리소스 ${resCount(S.infra.arch.inventory)}개 · ${perm ? "권한" : "허용"} ${sg.length}개${sg.some((e) => e.risk) ? ` · ${perm ? "넓음" : "위험"} ${sg.filter((e) => e.risk).length}` : ""}`;
  }
  if (n === 3 && S.design && S.design.mode === "iam") { const I = S.design.iam || {}; const c = I.confirmation || {}; return `IAM 요구사항 v${I.version || 1} · ${c.confirmed ? "확정" : "초안"}`; }
  if (n === 3 && S.design && S.design.mode === "handoff") return "해당 없음 (사람에게 넘김)";
  if (n === 3 && S.design) return S.design.exists ? `v${designVersion()}${S.design.auto ? " 자동 기준" : ""} 지금 기준` : "아직 없음";
  if (n === 4 && S.issues && S.issues.ok) return `문제 ${S.issues.issues.length}개 · Trivy 못 본 것 ${S.issues.only_ours}`;
  if (n === 5 && S.bg && S.bg.kind === "prefetch") return `수정안 미리 분석 중 ${S.bg.i}/${S.bg.n}`;     // 11차 (D-47): 배경 작업 진행을 왼쪽 메뉴에도
  if (n === 5 && S.rec) return `${S.lastRec.label || "수정안"} 분석함`;
  if (n === 6 && S.verdict) return (S.verdict.conclusion || {}).status || "";
  if (n === 7 && S.verdict) return (S.verdict.post_deploy || {}).status ? "시험 환경 결과 있음" : (S.verdict.testbed ? "아직 안 함" : "시험 환경 없음 → 미검증");
  if (n === 8 && S.verdict && S.verdict.decision_ko) return S.verdict.decision_ko;
  return "";
}

export function renderSide() {
  const p = S.proj;
  const un = (S.inbox && S.inbox.unread) || 0;          // 16차 (D-52): 안 읽은 고객 요청 수 — 이 칸을 누르면 ① 요청함
  $("#mproj").innerHTML = `<span>프로젝트</span><b>${esc(p ? p.name : "고르기")}</b>${un ? `<i class="mbadge" title="① 고객 요청함에 안 읽은 요청">새 고객 요청 ${un}</i>` : ""}`;
  let last = null;
  const shown = new Set();     // 잠긴 이유는 같은 이유마다 한 번만 적는다 (일곱 줄 반복은 소음 — 7차)
  $("#msteps").innerHTML = STEPS.map((s) => {
    const ok = canGo(s.n);
    const cls = s.n === S.step ? "cur" : ok ? "open" : "lock";
    let note = stepNote(s.n);
    if (!ok && !note) { const why = lockReason(s.n); note = shown.has(why) ? "" : why; shown.add(why); }
    const head = s.grp && s.grp !== last ? `<li class="sgrp" aria-hidden="true">${esc(GROUPS[s.grp])}</li>` : "";
    last = s.grp || last;
    const li = `${head}<li><button type="button" class="${cls}" data-go="${s.n}" ${ok && !S.run ? "" : "disabled"} title="${esc(ok ? s.q : lockReason(s.n))}">
      <em>${s.n}</em><span><b>${esc(s.short)}</b>${note ? `<small>${esc(note)}</small>` : ""}</span></button></li>`;
    // 7차 (B 11-02 "PR 할 링크도 바로 넘어갈 수 있게"): ⑧ 밑에 'PR 만들기' 바로 가기 — ⑧ 의 PR 칸으로 내려가 밝게 보여 준다.
    // 바로 가기일 뿐 PR 을 만들지는 않는다 (승인 기록 → 준비 확인 → 미리보기 → 확인 문구 입력은 그대로)
    if (s.n !== 8) return li;
    const approved = ((S.verdict && S.verdict.decision) || {}).decision === "APPROVED";
    const prNote = !ok ? "" : approved ? "승인됨 — 여기서 만들기" : "승인을 기록한 뒤 만들 수 있음";
    return `${li}<li class="ssub"><button type="button" class="${ok ? "open" : "lock"}" data-act="goto-pr" ${ok && !S.run ? "" : "disabled"} title="${esc(ok ? "⑧ 최종 결정의 PR 칸으로 바로 가기" : lockReason(8))}">
      <em aria-hidden="true">↳</em><span><b>PR 만들기</b>${prNote ? `<small>${esc(prNote)}</small>` : ""}</span></button></li>`;
  }).join("");
}

// ------------------------------------------------------------------ 창 · 알림
export function toast(text, tone = "bad") {
  document.querySelectorAll(".mtoast").forEach((x) => x.remove());   // 새 알림이 이전 알림(예: 거절 → 승인)을 덮어쓴다 — 겹쳐 보이지 않게
  const el = document.createElement("div");
  el.className = `mtoast ${tone}`;
  el.textContent = text;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 5200);
}

// 원문 그대로 보여 주는 글 (고객 제안서 D-46 · 팀 설계 문서 D-49 · 고객 요청서 D-50) — 해석하지 않고 그대로. 제목 · 목록 · 굵게만 간단히 꾸민다 (마크다운 라이브러리 없음)
export function mdLite(text) {
  const out = [];
  let list = null;          // "ul" | "ol"
  const close = () => { if (list) { out.push(`</${list}>`); list = null; } };
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trimEnd();
    const inline = (t) => esc(t).replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
    let m;
    if ((m = /^(#{1,3})\s+(.*)$/.exec(line))) { close(); out.push(`<h${Math.min(m[1].length + 2, 5)}>${inline(m[2])}</h${Math.min(m[1].length + 2, 5)}>`); continue; }
    if ((m = /^[-*]\s+(.*)$/.exec(line))) { if (list !== "ul") { close(); list = "ul"; out.push("<ul>"); } out.push(`<li>${inline(m[1])}</li>`); continue; }
    if ((m = /^\d+\.\s+(.*)$/.exec(line))) { if (list !== "ol") { close(); list = "ol"; out.push("<ol>"); } out.push(`<li>${inline(m[1])}</li>`); continue; }
    close();
    if (line.trim()) out.push(`<p>${inline(line)}</p>`);
  }
  close();
  return out.join("");
}
export function modal(title, html, wide = false) {
  const el = document.createElement("div");
  el.className = "mmodal";
  el.innerHTML = `<div class="mm-box ${wide ? "wide" : ""}" role="dialog" aria-label="${esc(title)}"><div class="mm-h"><b>${esc(title)}</b><button type="button" class="mm-x" data-close aria-label="닫기">×</button></div><div class="mm-b">${html}</div></div>`;
  el.addEventListener("click", (e) => { if (e.target === el || e.target.closest("[data-close]")) el.remove(); });
  document.body.appendChild(el);
  return el;
}

// 작업(검사 · AI 수정 · PR) 진행 — 서버 작업 기록(/api/log)을 따라간다
export async function followJob(onTick) {
  for (;;) {
    await sleep(700);
    const [lg, pg] = await Promise.all([api.get(`/api/log?since=${S.run.since}`), api.get("/api/job/progress")]);
    if (lg && Array.isArray(lg.log)) { S.log.push(...lg.log.map((x) => (typeof x === "string" ? x : x.text || x.line || JSON.stringify(x)))); S.run.since = lg.log_total ?? (S.run.since + lg.log.length); }
    if (onTick) await onTick(lg, pg);
    if (lg && lg.running === false) return { result: lg.result, error: lg.error, pg };
  }
}

export function chip(kind, text) { return `<span class="mchip ${kind}">${esc(text)}</span>`; }
export function sevChip(sev) { const [c, w] = SEV[sev] || ["unk", sev || ""]; return `<span class="msev ${c}">${esc(w)}</span>`; }
