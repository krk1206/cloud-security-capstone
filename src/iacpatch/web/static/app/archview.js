// 구성도 그리기 — 2D SVG (2026-11-01 갈아엎기 5차, D-33). 판정을 만들지 않는다: 서버가 준 모델(web/archmap.py)과
// 겹쳐 그릴 결과(V6 구조 검사 결과 · 자체 검사 위험 · 수정 전후 변화 · 사람이 그림에서 바꾼 것)를 그대로 그린다. 배치는 archlayout.js.
// 아이콘: AWS 공식 Architecture Icons(2026-07-31 패키지) ./aws/*.svg

import { layout, SZ, HALF, NAME_DY, SUB_DY } from "./archlayout.js";

const NS = "http://www.w3.org/2000/svg";
const ICON = (f) => new URL(`./aws/${f}.svg`, import.meta.url).href;
const el = (tag, attrs = {}, parent) => {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null) e.setAttribute(k, v);
  if (parent) parent.appendChild(e);
  return e;
};
const SEVC = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low" };
const BAND_ICON = { public: "public-subnet", mixed: "public-subnet" };
const cut = (s, n = 18) => { const t = String(s || ""); return t.length > n ? t.slice(0, n - 1) + "…" : t; };

// 선 상태 → 글자 (마우스를 올리면 나오는 설명)
export const STATE_KO = {
  excess: "원하는 구조에 없는 통신", ok: "원하는 구조대로", missing: "원하는 구조의 통신인데 허용 규칙 없음", desired: "원하는 구조의 통신 (출처가 코드와 다름)",
  unknown: "판정 불가 (출처 미확정)", added: "이 수정으로 새로 생긴 통신", removed: "이 수정으로 없어진 통신",
  block: "막을 예정", narrow: "출발지를 좁힐 예정", port: "포트를 바꿀 예정", keep: "그대로 둠", new: "추가할 통신", gone: "들어오는 통신을 모두 막을 예정",
};

// 점 p 와 선분 a-b 의 거리
const segDist = (p, a, b) => {
  const dx = b[0] - a[0], dy = b[1] - a[1];
  const t = dx || dy ? Math.max(0, Math.min(1, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy))) : 0;
  return Math.hypot(p[0] - (a[0] + t * dx), p[1] - (a[1] + t * dy));
};

export class ArchView {
  constructor(svg) { this.svg = svg; this.L = null; this.onPick = null; this.kind = "arch"; }
  has(id) { return !!(this.L && this.L.nodes[id]); }

  // opts: { overlay: {edges: {edgeId: {state, why}}, ghost_nodes, ghost_edges, nodes: {id: {state}}},
  //         changes: {edgeId: 'added'}, removed: [edges], badges: {nodeId: {n, sev}},
  //         marks: {linkId: 'block'|'narrow'|'port'|'keep'|'new'}, nodeMarks: {nodeId: 'gone'}, extraLinks: [edges] }
  render(model, opts = {}) {
    const s = this.svg;
    s.innerHTML = "";
    if (!model || !model.ok || !(model.nodes || []).length) {
      s.setAttribute("viewBox", "0 0 640 120");
      s.style.maxWidth = "";
      const t = el("text", { x: 320, y: 64, class: "a-empty", "text-anchor": "middle" }, s);
      t.textContent = (model && model.reason) || "그릴 리소스 없음";
      this.L = null;
      return null;
    }
    const ov = opts.overlay || null;
    const extra = {
      ghost_nodes: [...((ov && ov.ghost_nodes) || []), ...(opts.ghostNodes || [])],
      ghost_edges: [...((ov && ov.ghost_edges) || []), ...((opts.removed || []).map((e) => ({ ...e, kind: "ghost", state: "removed" }))),
        ...((opts.extraLinks || []).map((e) => ({ ...e, kind: "ghost", state: "new" })))],
      edges: (ov && ov.edges) || {},
    };
    const L = layout(model, extra);
    this.L = L;
    this.model = model;
    s.setAttribute("viewBox", L.viewBox.join(" "));
    s.style.maxWidth = `${Math.round(L.viewBox[2])}px`;
    const defs = el("defs", {}, s);
    for (const [id, cls] of [["a-ah", "ah"], ["a-ah-sg", "ah sg"], ["a-ah-risk", "ah risk"], ["a-ah-perm", "ah perm"], ["a-ah-ok", "ah ok"], ["a-ah-add", "ah add"],
      ["a-ah-miss", "ah miss"], ["a-ah-off", "ah off"], ["a-ah-edit", "ah edit"]]) {
      const m = el("marker", { id, viewBox: "0 0 10 10", refX: "8.6", refY: "5", markerWidth: "6.4", markerHeight: "6.4", orient: "auto-start-reverse" }, defs);
      el("path", { d: "M0 1L9 5L0 9z", class: cls }, m);
    }
    const base = el("g", { class: "a-base" }, s);
    // 틀: VPC · 서브넷 띠 · VPC 밖
    for (const v of L.boxes.vpcs) {
      el("rect", { x: v.x0, y: v.y0, width: v.x1 - v.x0, height: v.y1 - v.y0, rx: 14, class: "a-vpc" }, base);
      const gx = v.x0 + 14 + (v.gw || []).length * 46;
      el("image", { href: ICON("vpc"), x: gx, y: v.y0 + 8, width: 24, height: 24 }, base);
      const t = el("text", { x: gx + 30, y: v.y0 + 25, class: "a-vpct" }, base);
      t.textContent = `${v.label || "VPC"}${v.cidr ? ` · ${v.cidr}` : ""}`;
      if ((v.gw || []).length) {
        const c = el("text", { x: gx + 30, y: v.y0 + 42, class: "a-vpcs" }, base);
        c.textContent = `인터넷 게이트웨이 ${(v.gw || []).map((id) => (L.nodes[id] || {}).label).filter(Boolean).join(" · ")} (VPC 경계)`;
      }
    }
    for (const b of L.boxes.bands) {
      el("rect", { x: b.x0, y: b.y0, width: b.x1 - b.x0, height: b.y1 - b.y0, rx: 10, class: `a-band ${b.kind}` }, base);
      el("image", { href: ICON(BAND_ICON[b.kind] || "private-subnet"), x: b.x0 + 8, y: b.y0 + 6, width: 18, height: 18 }, base);
      const t = el("text", { x: b.x0 + 32, y: b.y0 + 20, class: `a-bandt ${b.kind}` }, base);
      t.textContent = [b.label, (b.names || []).join(" · "), (b.azs || []).length ? `가용 영역 ${(b.azs || []).join(" · ")}` : ""].filter(Boolean).join("   ");
    }
    if (L.boxes.outside) {
      const o = L.boxes.outside;
      el("rect", { x: o.x0, y: o.y0, width: o.x1 - o.x0, height: o.y1 - o.y0, rx: 12, class: "a-out" }, base);
      const t = el("text", { x: o.x0 + 12, y: o.y0 + 20, class: "a-outt" }, base);
      t.textContent = "VPC 밖 AWS 서비스";
    }
    // 선 (위험 · 바꿀 선을 나중에 = 위에)
    const linkLayer = el("g", { class: "a-links" }, s);
    const labLayer = el("g", { class: "a-labs" }, s);
    const nodeLayer = el("g", { class: "a-nodes" }, s);
    const edgeState = (ov && ov.edges) || {};
    const changes = opts.changes || {};
    const marks = opts.marks || {};
    this.linkEls = {};
    this.linkCls = {};
    const order = L.links.map((l) => {
      const kinds = new Set(l.kinds);
      let st = "";
      if (l.ghost) st = l.state || "missing";
      else {
        const sts = l.edges.map((id) => (edgeState[id] || {}).state).filter(Boolean);
        if (sts.includes("excess")) st = "excess"; else if (sts.includes("unknown")) st = "unknown"; else if (sts.length) st = "ok";
        const chs = l.edges.map((id) => changes[id]).filter(Boolean);
        if (chs.includes("added")) st = st === "excess" ? "excess added" : "added";
      }
      const mk = marks[l.id] || "";
      const risk = !ov && l.risk ? " risk" : "";
      const cls = `al ${[...kinds].join(" ")}${risk}${st ? ` st-${st.split(" ").join(" st-")}` : ""}${mk ? ` mk-${mk}` : ""}`;
      const z = (mk ? 4 : 0) + (st.includes("excess") || risk ? 3 : 0) + (kinds.has("sg") ? 1 : 0);
      return { l, kinds, st, mk, risk, cls, z };
    }).sort((a, b) => a.z - b.z);
    for (const { l, kinds, st, mk, risk, cls } of order) {
      const p = L.paths[l.id];
      if (!p) continue;
      const marker = mk && mk !== "keep" ? "a-ah-edit" : l.ghost ? (st === "removed" ? "a-ah-off" : st === "desired" || st === "new" ? "a-ah-add" : "a-ah-miss")
        : st.includes("excess") || risk ? "a-ah-risk" : st.includes("added") ? "a-ah-add" : kinds.has("perm") || kinds.has("role") ? "a-ah-perm" : kinds.has("sg") ? (st === "ok" ? "a-ah-ok" : "a-ah-sg") : "a-ah";
      const g = el("g", { class: "a-link", "data-link": l.id }, linkLayer);
      el("path", { d: p.d, class: "hit" }, g);                       // 누르기 쉽게 굵은 투명 선
      const path = el("path", { d: p.d, class: cls, "marker-end": `url(#${marker})` }, g);
      const why = l.edges.map((id) => (edgeState[id] || {}).why).filter(Boolean)[0] || (l.ghost ? (extra.ghost_edges.find((e) => l.edges.includes(e.id)) || {}).why : "");
      const tip = el("title", {}, g);
      tip.textContent = [`${this.name(l.src)} → ${this.name(l.dst)}`, l.ports ? `포트 ${l.ports}` : "", l.traffic ? `요청 경로: ${l.traffic}` : "", l.kinds.includes("perm") || l.kinds.includes("role") ? l.label : "",
        st ? STATE_KO[st.split(" ")[0]] || "" : "", why || "", risk ? "자체 검사: 위험한 허용" : "", mk ? STATE_KO[mk] || "" : ""].filter(Boolean).join("\n");
      if (this.onPick) g.addEventListener("click", (ev) => { ev.stopPropagation(); this._pickAt(ev, l.id); });
      if (st.includes("excess") || mk === "block") {
        // 막을 통신 표시 (✕) — 도착 화살촉 조금 앞 (머리 글자와 겹치지 않게)
        const a = p.pts[p.pts.length - 2], b = p.pts[p.pts.length - 1];
        if (a && b) {
          const len = Math.hypot(b[0] - a[0], b[1] - a[1]) || 1, back = Math.min(len * 0.5, 24);
          const mx = b[0] - ((b[0] - a[0]) / len) * back, my = b[1] - ((b[1] - a[1]) / len) * back;
          const xg = el("g", { class: `a-x${mk === "block" ? " edit" : ""}`, transform: `translate(${mx},${my})` }, labLayer);
          el("circle", { r: 8 }, xg);
          const xt = el("text", { y: 4, "text-anchor": "middle" }, xg); xt.textContent = "✕";
        }
      }
      this.linkEls[l.id] = { g, path };
      this.linkCls[l.id] = cls;
    }
    for (const b of L.labels) {
      // 같은 자리 같은 글자는 하나 — 선 상태가 여럿이면 바꿀 선 > 막을(초과) 선 > 위험 > 나머지 순으로 색
      const cl = (b.links || [b.link]).map((id) => this.linkCls[id] || "").sort((x, y) => (/mk-(block|narrow|port)/.test(y) - /mk-(block|narrow|port)/.test(x))
        || (/st-excess| risk/.test(y) - /st-excess| risk/.test(x)))[0] || "";
      const t = el("text", { x: b.x, y: b.y, "text-anchor": b.anchor, class: `alab ${cl.replace("al ", "")}`, "data-link": b.link }, labLayer);
      // 포트마다 색: 겹쳐 보기가 있으면 '원하는 구조에 없는 포트' 만 빨강, 없으면 자체 검사가 위험으로 본 포트만 빨강 (예: 22 빨강 · 80 파랑)
      const exr = ov ? (b.links || [b.link]).flatMap((id) => (this.L.links.find((x) => x.id === id) || { edges: [] }).edges).flatMap((id) => (edgeState[id] || {}).ranges || []) : [];
      const bad = (it) => (ov ? exr.some((r) => it.range && (r[0] === it.range[0] || r[0] === "-1" || it.range[0] === "-1") && r[1] <= it.range[2] && it.range[1] <= r[2]) : !!it.risk);
      if (b.items && b.items.length && !/mk-/.test(cl) && !/st-(missing|desired|removed|new|added)/.test(cl)) {
        const sp = el("tspan", {}, t); sp.textContent = ":";
        b.items.forEach((it, i) => { const x = el("tspan", { class: bad(it) ? "rk" : "nk" }, t); x.textContent = `${i ? ", " : ""}${it.text}`; });
      } else t.textContent = b.text;
    }
    // 상자
    const nodeState = (ov && ov.nodes) || {};
    const nodeMarks = opts.nodeMarks || {};
    const badges = opts.badges || {};
    this.nodeEls = {};
    for (const n of Object.values(L.nodes)) {
      const st = (nodeState[n.id] || {}).state;
      const mk = nodeMarks[n.id];
      const gw = n.gw;
      const sz = gw ? 40 : SZ, hf = sz / 2;
      const g = el("g", { class: `anode cat-${n.cat}${n.ghost ? " ghost" : ""}${st ? ` st-${st}` : ""}${mk ? ` mk-${mk}` : ""}${gw ? " gwb" : ""}`,
        transform: `translate(${n.x - hf},${n.y - hf})`, "data-node": n.id }, nodeLayer);
      el("rect", gw ? { x: -4, y: -4, width: sz + 8, height: sz + 8, rx: 8, class: "nbg" } : { x: -10, y: -8, width: SZ + 20, height: SZ + 54, rx: 10, class: "nbg" }, g);
      if (n.ghost || st || mk) el("rect", { x: -8, y: -6, width: sz + 16, height: sz + 12, rx: 10, class: "nring" }, g);
      el("image", { href: ICON(n.icon || "client"), width: sz, height: sz, class: "ico" }, g);
      if (!gw) {
        const t = el("text", { x: HALF, y: NAME_DY + HALF, class: "anl" }, g); t.textContent = cut(n.label, 20);
        const c = el("text", { x: HALF, y: SUB_DY + HALF, class: "ans" }, g); c.textContent = cut(n.sub || n.type_ko || "", 24);
      }
      const b = badges[n.id];
      if (b && b.n) {
        const bg = el("g", { class: `abadge ${SEVC[b.sev] || "low"}`, transform: `translate(${sz + 5},${8})` }, g);
        el("circle", { r: 11 }, bg);
        const bt = el("text", { y: 4.2, "text-anchor": "middle" }, bg); bt.textContent = String(b.n);
      }
      if (mk === "gone") {
        const xg = el("g", { class: "a-x edit", transform: `translate(${-2},${-2})` }, g);
        el("circle", { r: 9 }, xg);
        const xt = el("text", { y: 4, "text-anchor": "middle" }, xg); xt.textContent = "✕";
      }
      const tip = el("title", {}, g);
      tip.textContent = [`${n.label} — ${n.type_ko || ""}`, ...(n.addresses || []).slice(0, 4), ...((n.facts || []).map((f) => `${f[0]}: ${f[1]}`)),
        b && b.n ? `보안 문제 ${b.n}개` : "", st ? (nodeState[n.id] || {}).why || "" : "", mk ? STATE_KO[mk] || "" : ""].filter(Boolean).join("\n");
      if (this.onPick) { g.style.cursor = "pointer"; g.addEventListener("click", (ev) => { ev.stopPropagation(); this.onPick({ type: "node", id: n.id, node: n, x: ev.clientX, y: ev.clientY }); }); }
      this.nodeEls[n.id] = g;
    }
    return L;
  }

  // 누른 자리를 지나는 선을 모두 찾는다 (같은 상자로 가는 선은 마지막 부분을 함께 쓰므로)
  _pickAt(ev, firstId) {
    const L = this.L;
    let ids = [firstId];
    try {
      const pt = this.svg.createSVGPoint();
      pt.x = ev.clientX; pt.y = ev.clientY;
      const q = pt.matrixTransform(this.svg.getScreenCTM().inverse());
      const near = L.links.filter((l) => {
        const p = L.paths[l.id];
        return p && p.pts.some((a, i) => i > 0 && segDist([q.x, q.y], p.pts[i - 1], a) < 6);
      }).map((l) => l.id);
      if (near.length) ids = [firstId, ...near.filter((x) => x !== firstId)];
    } catch { /* 좌표 변환 실패 → 누른 선 하나 */ }
    const ls = ids.map((id) => L.links.find((l) => l.id === id)).filter(Boolean);
    this.onPick({ type: "link", id: firstId, link: ls[0], links: ls, x: ev.clientX, y: ev.clientY });
  }

  name(id) { const n = (this.L && this.L.nodes[id]) || {}; return n.label || id; }

  // 상자 · 선 강조 (빈 값이면 해제). 선은 링크 id 또는 원래 선(edge) id 로
  focus(nodes = [], edgeIds = []) {
    if (!this.L) return;
    const on = new Set(nodes || []), ed = new Set(edgeIds || []);
    const any = on.size || ed.size;
    this.svg.classList.toggle("focus", !!any);
    for (const l of this.L.links) {
      const hit = ed.has(l.id) || l.edges.some((x) => ed.has(x));
      const x = this.linkEls[l.id];
      if (x) x.g.classList.toggle("hl", hit);
      if (hit) { on.add(l.src); on.add(l.dst); }
    }
    for (const [id, g] of Object.entries(this.nodeEls || {})) g.classList.toggle("hl", on.has(id));
  }
}
