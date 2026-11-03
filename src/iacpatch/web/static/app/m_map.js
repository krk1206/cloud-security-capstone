// 구성도 공통 (2026-11-01 갈아엎기 5차 D-33 · 6차 D-34): 코드의 리소스를 AWS 구성도처럼 (archview.js) — ②③④⑤⑥ 이 같은 그림 방식을 쓴다.
// 그림에 겹쳐 그리는 것(설계 비교 · 위험)은 서버가 계산한 값 그대로. 판정을 만들지 않는다.
// 6차 (B 11-01 "너무 어려움 · 설계도랑 토폴로지를 합치지 말고 따로"): ③ 설계도 · ⑤ 적용 후 그림은 기본이 '통신 관련만', [전체 보기] 로 전부
import { ArchView, STATE_KO } from "./archview.js";
import { esc, modal, S } from "./m_core.js";

const VIEWS = {};
const LAST = {};

export const MLEG = {
  code: `<span class="lg traffic">요청 경로 (로드밸런서 → 서비스 등)</span><span class="lg sgl">보안 그룹 허용 (포트)</span><span class="lg block">위험한 허용 (자체 검사)</span><span class="lg perm">권한 (IAM 역할 · 정책)</span><span class="lg badge">보안 문제 수</span>`,
  design: `<span class="lg okl">설계도가 허용하는 통신 (포트)</span><span class="lg nodeM">코드에 없는 구성요소</span>`,
  // 선 = 보안 그룹 규칙이 '허용' 하는 통신 (실제로 연결되는지는 ⑦ V8 에서 잰다) — 글자로 구분 (검토 문서 11-02)
  after: `<span class="lg okl">보안 그룹 허용 · 설계도대로</span><span class="lg block">보안 그룹 허용 · 설계도에 없음 ✕</span><span class="lg missr">설계도에 있는데 허용 규칙 없음</span>`,
  afterCode: `<span class="lg sgl">보안 그룹 허용 (포트)</span><span class="lg block">위험한 허용 (자체 검사)</span>`,
};

// '통신 관련만' 보기: 보안 그룹이 붙은 상자 · 출발지 · 설계도에만 있는 것, 선은 보안 그룹 허용 · 설계도 통신만.
// 설계도 그림(서버 archmap.design_view)은 상자마다 core 가 있다 (설계도 구성요소 · 출처) — 그것만 남긴다
export function simple(model) {
  if (!model || !model.ok) return model;
  const keep = (n) => (n.core !== undefined ? !!n.core : n.cat === "external" || !!n.ghost || (n.sgs || []).length > 0);
  const nodes = (model.nodes || []).filter(keep);
  const ids = new Set(nodes.map((n) => n.id));
  const edges = (model.edges || []).filter((e) => (e.kind === "sg" || e.kind === "ghost") && ids.has(e.src) && ids.has(e.dst));
  return { ...model, nodes, edges };
}
export function fullToggle() {
  return `<button type="button" class="mc-zoom" data-mapfull title="${S.mapFull ? "통신(보안 그룹)에 관련된 것만 보기" : "로드밸런서 경로 · IAM · S3 등 코드의 리소스 전부 보기"}">${S.mapFull ? "통신 관련만" : "전체 보기"}</button>`;
}

export function mapBox(id, title, legend = "", head = "", empty = "", foot = "") {
  const body = empty ? `<div class="mc-empty">${esc(empty)}</div>` : `<div class="amapwrap"><svg class="asvg" id="${id}" role="img" aria-label="${esc(title)}"></svg></div>`;
  return `<div class="mcanvas amap"><div class="mc-head"><b>${esc(title)}</b>${head}${empty ? "" : `<button type="button" class="mc-zoom" data-mzoom="${id}" title="크게 보기">⤢ 크게</button>`}</div>
    ${legend ? `<div class="mc-leg">${legend}</div>` : ""}${body}${foot}</div>`;
}

// opts.simple = '통신 관련만' (그리기 전에 모델을 줄인다). 나머지 opts 는 ArchView.render 그대로
export function drawMap(id, model, opts = {}, onPick = null) {
  const svg = document.getElementById(id);
  if (!svg) return null;
  let v = VIEWS[id];
  if (!v || v.svg !== svg) { v = new ArchView(svg); VIEWS[id] = v; }
  v.onPick = onPick;
  v.render(opts.simple ? simple(model) : model, opts);
  LAST[id] = { model, opts };
  return v;
}
export function mapView(id) { return VIEWS[id]; }

// 크게 보기 — 같은 그림을 창 하나에 (누르기는 하지 않음: 보기 전용)
export function zoomMap(id) {
  const a = LAST[id];
  if (!a) return;
  const title = (document.getElementById(id) || {}).getAttribute?.("aria-label") || "구성도";
  modal(title, `<div class="amapwrap big"><svg class="asvg big" id="zoomMap" role="img" aria-label="${esc(title)}"></svg></div>`, true);
  drawMap("zoomMap", a.model, a.opts, null);
  const z = document.getElementById("zoomMap");
  if (z) z.style.maxWidth = "none";
  delete LAST.zoomMap;
}

// ------------------------------------------------------------------ 떠 있는 작은 창 (선 · 상자를 누르면)
export function closePop() { document.querySelectorAll(".apop").forEach((x) => x.remove()); }
export function pop(html, x, y, cls = "") {
  closePop();
  const el = document.createElement("div");
  el.className = `apop ${cls}`;
  el.innerHTML = `<button type="button" class="apop-x" aria-label="닫기" data-popclose>×</button>${html}`;
  document.body.appendChild(el);
  const w = el.offsetWidth, h = el.offsetHeight;
  const vw = window.innerWidth, vh = window.innerHeight;
  el.style.left = `${Math.max(8, Math.min(vw - w - 8, x + 12))}px`;
  el.style.top = `${Math.max(8, Math.min(vh - h - 8, y + 12))}px`;
  return el;
}
document.addEventListener("click", (e) => {
  if (e.target.closest("[data-popclose]")) { closePop(); return; }
  if (!e.target.closest(".apop") && !e.target.closest(".asvg")) closePop();
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closePop(); });

// 상자 · 선 설명 (보기 전용 창에 공통)
export function nodeInfo(v, n) {
  const facts = (n.facts || []).map((f) => `<dt>${esc(f[0])}</dt><dd>${esc(f[1])}</dd>`).join("");
  const L = v.L || { links: [] };
  const ins = L.links.filter((l) => l.dst === n.id), outs = L.links.filter((l) => l.src === n.id);
  const row = (l, other) => `<li class="${l.risk ? "risk" : ""}">${esc(v.name(other))} <b>${esc(l.text || (l.kinds.includes("traffic") ? "요청 경로" : l.kinds.includes("protect") ? "보호" : ""))}</b>${l.risk ? ` <span class="mchip bad">위험</span>` : ""}</li>`;
  return `<h4>${esc(n.label)} <small>${esc(n.type_ko || "")}</small></h4>
    ${(n.addresses || []).length ? `<p class="small"><code>${(n.addresses || []).slice(0, 3).map(esc).join("</code> <code>")}</code>${(n.addresses || []).length > 3 ? " …" : ""}</p>` : ""}
    ${facts ? `<dl class="kv small">${facts}</dl>` : ""}
    ${ins.length ? `<b class="small">들어오는 것</b><ul class="flist small">${ins.map((l) => row(l, l.src)).join("")}</ul>` : ""}
    ${outs.length ? `<b class="small">나가는 것</b><ul class="flist small">${outs.map((l) => row(l, l.dst)).join("")}</ul>` : ""}`;
}
export function linkInfo(v, l, ov = null) {
  const st = ov && l.edges.map((id) => ((ov.edges || {})[id] || {}).state).find(Boolean);
  const kinds = new Set(l.kinds);
  const what = kinds.has("sg") && (v.model || {}).source === "design" ? "설계도의 통신 (고객이 허용한 것)" : kinds.has("sg") ? "보안 그룹 허용 규칙" : kinds.has("traffic") ? "요청 경로 (코드의 연결 설정)" : kinds.has("perm") ? "권한 (IAM 정책)" : kinds.has("role") ? "IAM 역할 사용" : kinds.has("protect") ? "WAF 보호" : kinds.has("replica") ? "DB 복제" : "원하는 구조의 통신";
  return `<h4>${esc(v.name(l.src))} → ${esc(v.name(l.dst))} ${l.text ? `<b>${esc(l.text)}</b>` : ""}</h4>
    <p class="small">${esc(what)}${l.traffic ? ` · 요청 경로: ${esc(l.traffic)}` : ""}${kinds.has("perm") || kinds.has("role") ? ` · ${esc(l.label)}` : ""}</p>
    ${l.risk && !ov ? `<p class="small bad">자체 검사가 위험으로 본 허용 (${esc(l.risk)})</p>` : ""}
    ${st ? `<p class="small"><b>${esc(STATE_KO[st] || st)}</b></p>` : ""}`;
}
