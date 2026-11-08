// 설계도(토폴로지) 그림 — 2D SVG. 판정을 만들지 않는다: 서버가 계산한 '설계 통신 상태'와 '설계 밖 연결(excess)'을 그대로 그린다.
// 고정 그림 없음 (2026-10-31): 노드 · 연결은 그림 모델(서버 web/topomodel.py — 설계도 + 후보 검사 결과)에서, 배치는 topolayout.js 가 매번 계산한다.
// 그래서 설계도가 바뀌거나(계층 · 통신 추가) 후보 코드가 다른 연결을 만들면 그림도 바뀐다.
// 아이콘은 AWS 공식 Architecture Icons(2026-07-31 패키지): ./aws/*.svg — 계층에 실제로 붙은 리소스 종류로 고른다.

import { layout, SZ, HALF, NAME_DY, CAT_DY } from "./topolayout.js";

const NS = "http://www.w3.org/2000/svg";
const ICON = (f) => new URL(`./aws/${f}.svg`, import.meta.url).href;
const BG = { out: "#ffffff", public: "#f2f6e8", private: "#e6f6f7" };   // 노드 글자 테두리 = 놓인 바탕색

const el = (tag, attrs = {}, parent) => {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (parent) parent.appendChild(e);
  return e;
};

let DEFAULT_MODEL = null;

export class Topology {
  // model: 그림 모델 {nodes, flows}. 없으면 Topology.setDefault 로 정한 모델 (증거 카드의 작은 그림 등)
  constructor(svg, model = null) {
    this.svg = svg;
    this.model = model || DEFAULT_MODEL;
    this.state = { flows: {}, extras: [] };
    this.L = null;
  }

  static setDefault(model) { DEFAULT_MODEL = model; }

  setModel(model) {
    if (model && model !== this.model) { this.model = model; this.L = null; }
    return this;
  }

  _group(box, cls, title, icon) {
    if (!box) return;
    const [x0, y0, x1, y1] = box;
    const g = el("g", { class: `grp ${cls}` }, this.base);
    el("rect", { x: x0, y: y0, width: x1 - x0, height: y1 - y0, class: "box" }, g);
    el("image", { href: ICON(icon), x: x0, y: y0, width: 32, height: 32 }, g);
    const t = el("text", { x: x0 + 40, y: y0 + 22, class: "gt" }, g); t.textContent = title;
  }

  // flows: {flowId: 'design'|'ok'|'broken'|'unknown'}, extras: [{src, dst, ports, src_label, dst_label, kind}]
  render(flows = {}, extras = [], opts = {}) {
    this.state = { flows, extras };
    const s = this.svg;
    const m = this.model;
    if (!m || !m.ok || !(m.nodes || []).length) {
      s.setAttribute("viewBox", "0 0 600 120");
      s.innerHTML = "";
      const t = el("text", { x: 300, y: 64, class: "gt", "text-anchor": "middle" }, s);
      t.textContent = (m && m.reason) || "설계도 그림 없음";
      this.L = null;
      return;
    }
    const L = layout(m, extras);
    this.L = L;
    s.setAttribute("viewBox", L.viewBox.join(" "));
    s.innerHTML = `<defs>
      <marker id="ah" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0 1L9 5L0 9z" class="ah"/></marker>
      <marker id="ah-ok" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0 1L9 5L0 9z" class="ah ok"/></marker>
      <marker id="ah-bad" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7.5" markerHeight="7.5" orient="auto-start-reverse"><path d="M0 1L9 5L0 9z" class="ah bad"/></marker>
      <marker id="ah-off" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0 1L9 5L0 9z" class="ah off"/></marker>
      <marker id="ah-risk" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 1L9 5L0 9z" class="ah bad"/></marker>
      <marker id="ah-add" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 1L9 5L0 9z" class="ah add"/></marker>
    </defs>`;
    this.base = el("g", { class: "base" }, s);
    // 구역 이름: '외부 노출'(외부 출처가 바로 들어오는 묶음) · '내부'. 설계도에는 서브넷이 없고 코드의 실제 서브넷 · 라우팅도 검사하지 않으므로
    // '공개 · 비공개 서브넷' 이라고 부르지 않는다 (2026-11-01, D-32). 모델이 이름을 주면 그 이름.
    const zt = m.zone_titles || {};
    this._group(L.zones.vpc, "vpc", "VPC" + (m.vpc_cidr ? ` ${m.vpc_cidr}` : ""), "vpc");
    this._group(L.zones.pub, "pub", zt.pub || "외부 노출", "public-subnet");
    this._group(L.zones.priv, "priv", zt.priv || "내부", "private-subnet");
    this.linkLayer = el("g", { class: "links" }, s);
    this.portLayer = el("g", { class: "ports" }, s);
    this.extraLayer = el("g", { class: "extras" }, s);
    this.nodeLayer = el("g", { class: "nodes" }, s);
    // 노드 (서브넷 영역이 겹치는 설계면 노드마다 바탕판)
    this.nodes = {};
    for (const n of Object.values(L.nodes)) {
      if (L.zones.plates && n.kind !== "external") {
        el("rect", { x: n.x - HALF - 26, y: n.y - HALF - 12, width: SZ + 52, height: SZ + 70, rx: 10, class: `plate ${n.zone}` }, this.base);
      }
      const code = n.code === "missing" ? " missing" : n.code === "unattached" ? " unattached" : "";
      const g = el("g", { class: `node tier${n.kind === "unmapped" ? " unmapped" : ""}${code}`, transform: `translate(${n.x - HALF},${n.y - HALF})`, "data-node": n.id, "data-tier": n.id, "data-code": n.code || "" }, this.nodeLayer);
      if (n.kind === "unmapped") el("rect", { x: -9, y: -9, width: SZ + 18, height: SZ + 18, rx: 10, class: "unmapped-box" }, g);   // 설계도에 없는 리소스 (코드에만 있음)
      if (n.code === "missing") el("rect", { x: -9, y: -9, width: SZ + 18, height: SZ + 18, rx: 10, class: "missing-box" }, g);     // 설계도에 있는데 코드에 없음
      el("image", { href: ICON(n.icon), width: SZ, height: SZ, class: "ico" }, g);
      const bg = L.zones.plates ? "#fff" : (BG[n.zone] || "#fff");
      const t = el("text", { x: HALF, y: NAME_DY + HALF, class: "nl", style: `stroke:${bg}` }, g); t.textContent = n.label;
      const c = el("text", { x: HALF, y: CAT_DY + HALF, class: "ns" }, g); c.textContent = n.sub || "";
      if ((n.extra_security_groups || []).length) {
        const x = el("text", { x: HALF, y: CAT_DY + HALF + 16, class: "ns warnsg" }, g); x.textContent = `+ 설계 밖 보안 그룹 ${n.extra_security_groups.length}개`;
      }
      el("circle", { cx: SZ - 2, cy: 2, r: 10, class: "mark" }, g);
      const mt = el("text", { x: SZ - 2, y: 6.5, class: "markt" }, g); mt.textContent = "";
      const tip = el("title", {}, g);
      tip.textContent = [n.label, n.security_group || "", (n.resources || []).join(", ")].filter(Boolean).join("\n");
      if (this.onPick) { g.style.cursor = "pointer"; g.addEventListener("click", (ev) => { ev.stopPropagation(); this.onPick({ type: "node", id: n.id }); }); }
      this.nodes[n.id] = { g, n };
    }
    // 설계 통신 선 + 포트 글자
    this.flowEls = {}; this.portEls = {};
    for (const f of m.flows || []) {
      const r = L.flows[f.id];
      if (!r) continue;
      const st = flows[f.id] || "design";
      const mk = { ok: "url(#ah-ok)", broken: "url(#ah-off)", removed: "url(#ah-off)", risk: "url(#ah-risk)", added: "url(#ah-add)" }[st] || "url(#ah)";
      const p = el("path", { d: r.d, class: `flow ${st}`, "marker-end": mk, "data-flow": f.id }, this.linkLayer);
      const tip = el("title", {}, p); tip.textContent = `${f.label || f.id} · ${f.ports}`;
      if (this.onPick) p.addEventListener("click", (ev) => { ev.stopPropagation(); this.onPick({ type: "flow", id: f.id }); });
      this.flowEls[f.id] = [p];
      const dst = L.nodes[f.dst];
      const t = el("text", { x: r.lab[0], y: r.lab[1], class: `plab ${st}`, "data-flow": f.id, "text-anchor": r.lab[2], style: `stroke:${BG[(dst || {}).zone] || "#fff"}` }, this.portLayer);
      t.textContent = `:${f.ports}`;
      this.portEls[f.id] = t;
    }
    // 설계 밖 연결 (빨간 점선) + 설계도에 없는 출처
    this.extraEls = [];
    const marks = {};
    (extras || []).forEach((e, i) => {
      const r = L.extras[i];
      if (!r) return;
      const g = el("g", { class: "extra", "data-extra": String(i) }, this.extraLayer);
      el("path", { d: r.d, class: "flow bad", "marker-end": "url(#ah-bad)" }, g);
      const t = el("text", { x: r.lab[0], y: r.lab[1], class: "plab bad", "text-anchor": r.lab[2] }, g); t.textContent = `:${e.ports || ""}`;
      const tip = el("title", {}, g); tip.textContent = `설계도에 없는 연결: ${e.src_label || e.src} → ${e.dst_label || e.dst} ${e.ports || ""}`;
      this.extraEls.push(g);
      marks[e.dst] = (marks[e.dst] || 0) + 1;
    });
    for (const [k, p] of Object.entries(L.pseudo)) {
      const b = el("g", { class: "vpcbadge", transform: `translate(${p.x - 75},${p.y - 14})`, "data-pseudo": k }, this.extraLayer);
      el("rect", { width: 150, height: 26, rx: 13 }, b);
      const t = el("text", { x: 75, y: 17.5 }, b); t.textContent = p.label;
    }
    // 경고 표시: 설계 밖 연결이 들어오는 노드(!), 허용 규칙이 없는 필수 통신의 도착 노드(×)
    for (const [id, x] of Object.entries(this.nodes)) {
      const brokenHere = (m.flows || []).some((f) => f.dst === id && flows[f.id] === "broken");
      x.g.classList.toggle("warn", !!marks[id]);
      x.g.classList.toggle("broken", brokenHere && !marks[id]);
      x.g.querySelector(".markt").textContent = marks[id] ? "!" : brokenHere ? "×" : "";
    }
    this.svg.classList.toggle("has-extra", (extras || []).length > 0);
  }

  // 여러 노드 · 선을 한꺼번에 강조 (보안 문제 · 질문 화면). 빈 값이면 해제
  focus(nodes = [], flowIds = []) {
    if (!this.L) return;
    const on = new Set(nodes || []), fl = new Set(flowIds || []);
    const any = on.size || fl.size;
    this.svg.classList.toggle("focus", !!any);
    for (const [fid, paths] of Object.entries(this.flowEls || {})) paths.forEach((p) => p.classList.toggle("hl", fl.has(fid)));
    for (const [fid, t] of Object.entries(this.portEls || {})) t.classList.toggle("hl", fl.has(fid));
    const m = this.model || {};
    (m.flows || []).forEach((f) => { if (fl.has(f.id)) { on.add(f.src); on.add(f.dst); } });
    for (const [id, x] of Object.entries(this.nodes || {})) x.g.classList.toggle("hl", on.has(id));
  }

  highlight(flowId = null, extraIdx = null) {
    if (!this.L) return;
    this.svg.classList.toggle("focus", flowId != null || extraIdx != null);
    for (const [fid, paths] of Object.entries(this.flowEls || {})) paths.forEach((p) => p.classList.toggle("hl", fid === flowId));
    for (const [fid, t] of Object.entries(this.portEls || {})) t.classList.toggle("hl", fid === flowId);
    (this.extraEls || []).forEach((g, i) => g.classList.toggle("hl", String(i) === String(extraIdx)));
    const on = new Set();
    const f = (this.model.flows || []).find((x) => x.id === flowId);
    if (f) { on.add(f.src); on.add(f.dst); }
    const e = extraIdx != null ? (this.state.extras || [])[extraIdx] : null;
    if (e) { on.add(e.src); on.add(e.dst); }
    for (const [id, x] of Object.entries(this.nodes || {})) x.g.classList.toggle("hl", on.has(id));
  }
}
