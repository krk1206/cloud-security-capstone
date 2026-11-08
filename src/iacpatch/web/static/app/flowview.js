// 흐름 그림 (11차, D-48 — B 2026-11-04 "토폴로지도 설계도도 필요 없는 거 빼라"): 상자 = 통신의 출발지(인터넷 · IP 대역)와 보안 그룹이 붙은 묶음,
// 화살표 = 보안 그룹이 허용하는 통신(포트). VPC · 서브넷 틀, 게이트웨이, IAM · S3 같이 통신과 무관한 리소스는 그리지 않는다.
// 판정을 만들지 않는다 — 서버가 준 모델(archmap)과 겹쳐 그릴 결과(설계도 비교 · 자체 검사 위험)를 그대로 그린다. 전체 그림은 archview.js (전체 보기).
// 왼쪽 → 오른쪽 = 통신이 들어오는 순서 (외부 → 첫 계층 → 다음 계층). 같은 모델 · 같은 id 라서 ②③④⑤⑥ 어디서든 상자 · 선을 누르면 같은 설명이 나온다.

import { links } from "./archlayout.js";
import { STATE_KO } from "./archview.js";

const NS = "http://www.w3.org/2000/svg";
const ICON = (f) => new URL(`./aws/${f}.svg`, import.meta.url).href;
const el = (tag, attrs = {}, parent) => {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null) e.setAttribute(k, v);
  if (parent) parent.appendChild(e);
  return e;
};
const SEVC = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low" };
const cut = (s, n) => { const t = String(s || ""); return t.length > n ? t.slice(0, n - 1) + "…" : t; };
// 상자 안 글자 (17차, D-53): 칸(상자 너비 - 아이콘)에 안 들어가면 글자를 조금 작게 → 그래도 길면 그때만 '…' ('203.0.113.10…' · 'Auto Scal…' 처럼 잘리던 것).
// 그리기 전(안 보이는 칸)이라 길이를 못 재면 전처럼 글자 수로 자른다
const fitText = (t, full, n, minPx, maxW = 108) => {
  const s = String(full || "");
  t.textContent = s;
  try {
    let w = t.getComputedTextLength();
    if (!w) { t.textContent = cut(s, n); return; }
    let px = parseFloat(getComputedStyle(t).fontSize) || 14;
    while (w > maxW && px > minPx) { px -= 0.5; t.style.fontSize = `${px}px`; w = t.getComputedTextLength(); }
    let k = s.length;
    while (w > maxW && k > 2) { k -= 1; t.textContent = s.slice(0, k) + "…"; w = t.getComputedTextLength(); }
  } catch { t.textContent = cut(s, n); }
};
const fx = (v) => Number(Number(v).toFixed(1));

export const BOX_W = 172, BOX_H = 60, COL_X = 268, ROW_Y = 96, PAD = 24;
const FLOW_KINDS = new Set(["sg", "ghost", "traffic", "role", "perm"]);          // role · perm = 권한 그림 (15차) — 통신 그림에는 이 선이 없다

// 3차 베지에 곡선 위의 점
const bez = (p0, p1, p2, p3, t) => {
  const u = 1 - t;
  return [u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0],
    u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1]];
};

// 배치 — 순수 함수. 열 = 외부에서 몇 번 거쳐 오는가 (가장 긴 경로, 되돌아가는 선 제외).
// 높이 = 들어오는 선의 출발 상자 높이 평균 (출발지는 도착 상자 높이 평균) — 그래서 '인터넷 → 웹' 처럼 한 열을 건너뛰는 선이 중간 상자를 지나지 않는다.
// 그래도 지나면 (sampled 충돌 검사) 중간 상자 위나 아래로 돌아간다.
export function flowLayout(model, overlay = null, opt = {}) {
  const colX = opt.colX || COL_X;           // 권한 그림(15차)은 선 글자(동작 이름)가 길어 열 사이를 넓힌다
  const nodes = [...((model && model.nodes) || []), ...(((overlay || {}).ghost_nodes) || [])];
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const L = links(model, overlay).filter((l) => byId[l.src] && byId[l.dst] && l.src !== l.dst);
  const flow = L.filter((l) => l.kinds.some((k) => FLOW_KINDS.has(k)));
  const isExt = (n) => n.cat === "external" || ((n.place || {}).area === "external");
  // 되돌아가는 선 (순환) 은 순위 계산에서 뺀다
  const adj = {};
  flow.forEach((l) => { (adj[l.src] = adj[l.src] || []).push(l.dst); });
  const st = {}, back = new Set();
  const dfs = (u) => { st[u] = 1; for (const v of adj[u] || []) { if (st[v] === 1) back.add(`${u}>${v}`); else if (!st[v]) dfs(v); } st[u] = 2; };
  nodes.filter(isExt).forEach((n) => { if (!st[n.id]) dfs(n.id); });
  nodes.forEach((n) => { if (!st[n.id]) dfs(n.id); });
  const fwd = flow.filter((l) => !back.has(`${l.src}>${l.dst}`) && !isExt(byId[l.dst]));
  const rank = {};
  nodes.forEach((n) => { rank[n.id] = isExt(n) ? 0 : 1; });
  for (let it = 0; it < nodes.length + 1; it++) {
    let ch = false;
    for (const l of fwd) { const r = rank[l.src] + 1; if (r > rank[l.dst]) { rank[l.dst] = r; ch = true; } }
    if (!ch) break;
  }
  const cols = {};
  nodes.forEach((n) => { (cols[rank[n.id]] = cols[rank[n.id]] || []).push(n); });
  const colIds = Object.keys(cols).map(Number).sort((a, b) => a - b);
  // 열 안 순서: 처음엔 이름순, 그 다음 들어오는 선의 출발 상자 순서 평균으로 두 번 고쳐 잡는다
  const order = {};
  colIds.forEach((c) => cols[c].sort((a, b) => String(a.label).localeCompare(String(b.label), "ko")).forEach((n, i) => { order[n.id] = i; }));
  for (let pass = 0; pass < 2; pass++) {
    colIds.forEach((c) => {
      const bary = (n) => { const ins = fwd.filter((l) => l.dst === n.id).map((l) => order[l.src]).filter((v) => v !== undefined); return ins.length ? ins.reduce((s, v) => s + v, 0) / ins.length : order[n.id]; };
      cols[c].sort((a, b) => bary(a) - bary(b) || order[a.id] - order[b.id]).forEach((n, i) => { order[n.id] = i; });
    });
  }
  // 높이 (상자 가운데 y): 열마다 '원하는 높이' 를 정한 뒤 겹치지 않게 벌리고, 벌린 만큼 절반을 되돌려 가운데를 맞춘다
  const cy = {};
  const mean = (a) => (a.length ? a.reduce((s, v) => s + v, 0) / a.length : null);
  const settle = (list, want) => {
    // 원하는 높이 순서로 먼저 줄을 세운다 (같으면 원래 순서) — 안 그러면 위쪽 상자로 가는 출발지가 아래로 밀려 선이 다른 선을 가로지른다 (13차)
    const pos = new Map(list.map((n, i) => [n.id, i]));
    list.sort((a, b) => (want[a.id] - want[b.id]) || (pos.get(a.id) - pos.get(b.id)));
    let prev = null;
    const got = list.map((n) => { let y = want[n.id]; if (prev !== null && y < prev + ROW_Y) y = prev + ROW_Y; prev = y; return y; });
    const shift = (mean(got) - mean(list.map((n) => want[n.id]))) || 0;
    list.forEach((n, i) => { cy[n.id] = got[i] - shift; });
  };
  const leftToRight = () => colIds.forEach((c, ci) => {
    const list = cols[c];
    const want = {};
    list.forEach((n, i) => {
      const ins = fwd.filter((l) => l.dst === n.id).map((l) => cy[l.src]).filter((v) => v !== undefined);
      const m = mean(ins);
      want[n.id] = ci === 0 && cy[n.id] !== undefined ? cy[n.id] : m !== null ? m : (i ? want[list[i - 1].id] + ROW_Y : 0);
    });
    settle(list, want);
  });
  leftToRight();
  // 출발지(첫 열)는 도착 상자 높이에 맞춘다 — 그 뒤 나머지 열을 한 번 더
  if (colIds.length > 1) {
    const list = cols[colIds[0]];
    const want = {};
    list.forEach((n, i) => { const m = mean(fwd.filter((l) => l.src === n.id).map((l) => cy[l.dst]).filter((v) => v !== undefined)); want[n.id] = m !== null ? m : (i ? want[list[i - 1].id] + ROW_Y : cy[n.id] || 0); });
    settle(list, want);
    leftToRight();
  }
  const minCy = Math.min(...Object.values(cy));
  const placed = {};
  colIds.forEach((c, ci) => cols[c].forEach((node) => { placed[node.id] = { ...node, rank: rank[node.id], col: ci, x: PAD + ci * colX, y: PAD + (cy[node.id] - minCy) }; }));
  const colBoxes = colIds.map((c) => cols[c].map((n) => placed[n.id]));
  // 선: 같은 상자로 들어가는 · 나가는 선은 세로로 조금씩 벌린다
  const ins = {}, outs = {};
  L.forEach((l) => { (ins[l.dst] = ins[l.dst] || []).push(l); (outs[l.src] = outs[l.src] || []).push(l); });
  const srcY = (l) => placed[l.src].y + BOX_H / 2;
  Object.values(ins).forEach((a) => a.sort((p, q) => srcY(p) - srcY(q)));
  Object.values(outs).forEach((a) => a.sort((p, q) => (placed[p.dst].y) - (placed[q.dst].y)));
  const off = (arr, l) => { const i = arr.indexOf(l); return (i - (arr.length - 1) / 2) * 13; };
  const inBox = (p, b, m = 10) => p[0] > b.x - m && p[0] < b.x + BOX_W + m && p[1] > b.y - m && p[1] < b.y + BOX_H + m;
  const paths = {};
  let lanesUp = 0, lanesDown = 0;
  for (const l of L) {
    const s = placed[l.src], d = placed[l.dst];
    const sy = s.y + BOX_H / 2 + off(outs[l.src], l), dy = d.y + BOX_H / 2 + off(ins[l.dst], l);
    let pts, dAttr, mid, tip;
    if (d.col > s.col) {
      const p0 = [s.x + BOX_W, sy], p3 = [d.x - 8, dy];
      const k = Math.max(40, (p3[0] - p0[0]) / 2);
      const p1 = [p0[0] + k, sy], p2 = [p3[0] - k, dy];
      const between = colBoxes.slice(s.col + 1, d.col).flat();
      const hit = between.length && [0.15, 0.3, 0.4, 0.5, 0.6, 0.7, 0.85].some((t) => { const q = bez(p0, p1, p2, p3, t); return between.some((b) => inBox(q, b)); });
      if (!hit) {
        dAttr = `M${p0[0]},${p0[1]} C${p1[0]},${p1[1]} ${p2[0]},${p2[1]} ${p3[0]},${p3[1]}`;
        mid = bez(p0, p1, p2, p3, 0.5); tip = bez(p0, p1, p2, p3, 0.78);
        pts = [p0, mid, p3];
      } else {
        // 중간 상자를 지나는 긴 선: 가까운 쪽(위 · 아래)으로 돌아간다
        const top = Math.min(...between.map((b) => b.y)), bot = Math.max(...between.map((b) => b.y + BOX_H));
        const avg = (sy + dy) / 2;
        const up = Math.abs(top - avg) <= Math.abs(bot - avg);
        const lane = up ? top - 26 - 12 * lanesUp++ : bot + 26 + 12 * lanesDown++;
        const xa = Math.min(...between.map((b) => b.x)) - 26, xb = Math.max(...between.map((b) => b.x + BOX_W)) + 26;
        const c0 = [p0, [p0[0] + 40, sy], [xa - 40, lane], [xa, lane]], c1 = [[xb, lane], [xb + 40, lane], [p3[0] - 40, dy], p3];
        dAttr = `M${p0[0]},${p0[1]} C${c0[1][0]},${c0[1][1]} ${c0[2][0]},${c0[2][1]} ${c0[3][0]},${c0[3][1]} L${xb},${lane} C${c1[1][0]},${c1[1][1]} ${c1[2][0]},${c1[2][1]} ${c1[3][0]},${c1[3][1]}`;
        mid = [(xa + xb) / 2, lane]; tip = bez(c1[0], c1[1], c1[2], c1[3], 0.7);
        pts = [p0, [xa, lane], [xb, lane], p3];
      }
    } else {
      // 같은 열 · 되돌아가는 선: 아래로 돌아서 (상자를 가로지르지 않게)
      const lowY = Math.max(s.y, d.y) + BOX_H + 22;
      const x1 = s.x + BOX_W + 18, x2 = d.x - 18;
      pts = [[s.x + BOX_W, sy], [x1, sy], [x1, lowY], [x2, lowY], [x2, dy], [d.x - 8, dy]];
      dAttr = "M" + pts.map((p) => `${fx(p[0])},${fx(p[1])}`).join(" L");
      mid = [(x1 + x2) / 2, lowY]; tip = [x2, dy + (dy > lowY ? -16 : 16)];
    }
    paths[l.id] = { d: dAttr, pts, mid, tip };
  }
  const xs = Object.values(placed).flatMap((n) => [n.x, n.x + BOX_W]), ys = Object.values(placed).flatMap((n) => [n.y, n.y + BOX_H]);
  Object.values(paths).forEach((p) => p.pts.forEach((q) => { xs.push(q[0]); ys.push(q[1]); }));
  const vb = xs.length ? [fx(Math.min(...xs) - PAD), fx(Math.min(...ys) - PAD - 10), fx(Math.max(...xs) - Math.min(...xs) + 2 * PAD), fx(Math.max(...ys) - Math.min(...ys) + 2 * PAD + 10)] : [0, 0, 400, 120];
  return { viewBox: vb, nodes: placed, links: L, paths, rank };
}

// 권한 선이 허용하는 동작들 (서버 archmap 이 선마다 (동작, 리소스) 짝을 준다 — 15차)
const permActs = (l) => [...new Set((l.pairs || []).map((p) => p[0]))];

export class FlowView {
  constructor(svg) { this.svg = svg; this.L = null; this.onPick = null; this.kind = "flow"; }

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
    const extra = { ghost_nodes: [...((ov && ov.ghost_nodes) || []), ...(opts.ghostNodes || [])],
      ghost_edges: [...((ov && ov.ghost_edges) || []), ...((opts.removed || []).map((e) => ({ ...e, kind: "ghost", state: "removed" }))), ...((opts.extraLinks || []).map((e) => ({ ...e, kind: "ghost", state: "new" })))],
      edges: (ov && ov.edges) || {} };
    const L = flowLayout(model, extra, opts.perm ? { colX: 330 } : {});
    this.L = L;
    this.model = model;
    s.setAttribute("viewBox", L.viewBox.join(" "));
    s.style.maxWidth = `${Math.round(L.viewBox[2])}px`;
    const defs = el("defs", {}, s);
    for (const [id, cls] of [["f-ah", "ah"], ["f-ah-sg", "ah sg"], ["f-ah-risk", "ah risk"], ["f-ah-ok", "ah ok"], ["f-ah-add", "ah add"], ["f-ah-miss", "ah miss"], ["f-ah-off", "ah off"], ["f-ah-perm", "ah perm"]]) {
      const m = el("marker", { id, viewBox: "0 0 10 10", refX: "8.6", refY: "5", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" }, defs);
      el("path", { d: "M0 1L9 5L0 9z", class: cls }, m);
    }
    const linkLayer = el("g", { class: "a-links" }, s);
    const labLayer = el("g", { class: "a-labs" }, s);
    const nodeLayer = el("g", { class: "a-nodes" }, s);
    const edgeState = (ov && ov.edges) || {};
    const changes = opts.changes || {};
    this.linkEls = {};
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
      const risk = !ov && l.risk ? " risk" : "";
      const cls = `al fl ${[...kinds].join(" ")}${risk}${st ? ` st-${st.split(" ").join(" st-")}` : ""}`;
      return { l, kinds, st, risk, cls, z: (st.includes("excess") || risk ? 2 : 0) + (l.ghost ? 1 : 0) };
    }).sort((a, b) => a.z - b.z);
    for (const { l, kinds, st, risk, cls } of order) {
      const p = L.paths[l.id];
      if (!p) continue;
      const marker = l.ghost ? (st === "removed" ? "f-ah-off" : st === "desired" || st === "new" ? "f-ah-add" : "f-ah-miss")
        : st.includes("excess") || risk ? "f-ah-risk" : st.includes("added") ? "f-ah-add" : kinds.has("sg") ? (st === "ok" ? "f-ah-ok" : "f-ah-sg") : kinds.has("perm") ? "f-ah-perm" : "f-ah";
      const g = el("g", { class: "a-link", "data-link": l.id }, linkLayer);
      el("path", { d: p.d, class: "hit" }, g);
      el("path", { d: p.d, class: cls, "marker-end": `url(#${marker})` }, g);
      const why = l.edges.map((id) => (edgeState[id] || {}).why).filter(Boolean)[0] || (l.ghost ? (extra.ghost_edges.find((e) => l.edges.includes(e.id)) || {}).why : "");
      const tip = el("title", {}, g);
      const stKo = (kinds.has("perm") || l.ghostText ? { excess: "요구사항 밖 권한", ok: "요구사항 안의 권한", missing: "꼭 필요한데 없는 권한", unknown: "판정 불가" } : STATE_KO)[st.split(" ")[0]];
      tip.textContent = [`${this.name(l.src)} → ${this.name(l.dst)}`, l.ports ? `포트 ${l.ports}` : kinds.has("perm") ? `허용 동작 ${l.label}` : "", st ? stKo || "" : "", why || "",
        risk ? (kinds.has("perm") ? "자체 검사: 넓은 권한" : "자체 검사: 위험한 허용") : ""].filter(Boolean).join("\n");
      if (this.onPick) g.addEventListener("click", (ev) => { ev.stopPropagation(); this.onPick({ type: "link", id: l.id, link: l, links: [l], x: ev.clientX, y: ev.clientY }); });
      if (st.includes("excess")) {
        const xg = el("g", { class: "a-x", transform: `translate(${fx(p.tip[0])},${fx(p.tip[1])})` }, labLayer);
        el("circle", { r: 9 }, xg);
        const xt = el("text", { y: 4, "text-anchor": "middle" }, xg); xt.textContent = "✕";
      }
      // 포트 글자 — 선 가운데. 겹쳐 보기가 있으면 설계도에 없는 포트만 빨강, 없으면 자체 검사가 위험으로 본 포트만 빨강
      if (l.text) {
        const exr = ov ? l.edges.flatMap((id) => (edgeState[id] || {}).ranges || []) : [];
        const bad = (it) => (ov ? exr.some((r) => it.range && (r[0] === it.range[0] || r[0] === "-1" || it.range[0] === "-1") && r[1] <= it.range[2] && it.range[1] <= r[2]) : !!it.risk);
        const t = el("text", { x: fx(p.mid[0]), y: fx(p.mid[1] - 7), "text-anchor": "middle", class: `alab fl ${cls.replace("al fl ", "")}`, "data-link": l.id }, labLayer);
        const items = (kinds.has("sg") || kinds.has("ghost")) ? (l.items || []) : [];
        if (items.length && !/st-(missing|desired|removed|new|added)/.test(cls)) {
          const sp = el("tspan", {}, t); sp.textContent = ":";
          items.forEach((it, i) => { const x = el("tspan", { class: bad(it) ? "rk" : "nk" }, t); x.textContent = `${i ? ", " : ""}${it.text}`; });
        } else if (l.ghost && st === "missing") {
          // 두 줄: 포트 / '허용 규칙 없음' (한 줄이면 다음 상자 밑으로 들어간다). 권한 그림의 유령 선은 동작 / '꼭 필요한데 없음'
          t.setAttribute("y", fx(p.mid[1] - 19));
          const a1 = el("tspan", {}, t); a1.textContent = l.text;
          const a2 = el("tspan", { x: fx(p.mid[0]), dy: 13, class: "fl2" }, t); a2.textContent = l.ghostText ? "꼭 필요한데 없음" : "허용 규칙 없음";
        } else if (kinds.has("perm") && (permActs(l).length > 1 || String(l.label || "").includes(" · "))) {
          // 권한 선: 동작이 여럿이면 줄을 나눠 다 적는다 (흐름 그림은 선이 적어 자리가 있다) — 넷이 넘으면 '외 N'
          const all = permActs(l).length ? permActs(l) : String(l.label).split(" · ");
          const parts = all.length > 4 ? [...all.slice(0, 3), `외 ${all.length - 3}`] : all;
          t.setAttribute("y", fx(p.mid[1] - 7 - 13 * (parts.length - 1)));
          parts.forEach((x, i) => { const sp = el("tspan", i ? { x: fx(p.mid[0]), dy: 13 } : {}, t); sp.textContent = x; });
        } else t.textContent = kinds.has("perm") ? (permActs(l)[0] || String(l.label || l.text)) : l.text;
      }
      this.linkEls[l.id] = { g };
    }
    const nodeState = (ov && ov.nodes) || {};
    const badges = opts.badges || {};
    this.nodeEls = {};
    for (const n of Object.values(L.nodes)) {
      const st = (nodeState[n.id] || {}).state;
      const g = el("g", { class: `anode fnode cat-${n.cat}${n.ghost ? " ghost" : ""}${st ? ` st-${st}` : ""}`, transform: `translate(${fx(n.x)},${fx(n.y)})`, "data-node": n.id }, nodeLayer);
      el("rect", { x: 0, y: 0, width: BOX_W, height: BOX_H, rx: 12, class: "fbox" }, g);
      el("image", { href: ICON(n.icon || "client"), x: 12, y: (BOX_H - 34) / 2, width: 34, height: 34, class: "ico" }, g);
      const t = el("text", { x: 56, y: BOX_H / 2 - 3, class: "fname" }, g); fitText(t, n.label, 13, 11);
      const c = el("text", { x: 56, y: BOX_H / 2 + 14, class: "fsub" }, g); fitText(c, n.sub || n.type_ko || "", 17, 9.5);
      const b = badges[n.id];
      if (b && b.n) {
        const bg = el("g", { class: `abadge ${SEVC[b.sev] || "low"}`, transform: `translate(${BOX_W - 4},${4})` }, g);
        el("circle", { r: 11 }, bg);
        const bt = el("text", { y: 4.2, "text-anchor": "middle" }, bg); bt.textContent = String(b.n);
      }
      const tip = el("title", {}, g);
      tip.textContent = [`${n.label} — ${n.type_ko || ""}`, ...(n.addresses || []).slice(0, 4), ...((n.facts || []).map((f) => `${f[0]}: ${f[1]}`)), b && b.n ? `보안 문제 ${b.n}개` : "", st ? (nodeState[n.id] || {}).why || "" : ""].filter(Boolean).join("\n");
      if (this.onPick) { g.style.cursor = "pointer"; g.addEventListener("click", (ev) => { ev.stopPropagation(); this.onPick({ type: "node", id: n.id, node: n, x: ev.clientX, y: ev.clientY }); }); }
      this.nodeEls[n.id] = g;
    }
    this.declutter(labLayer, L);
    return L;
  }

  // 17차 (D-53, B "글자 겹친 것도 수정"): 포트 글자가 ✕ 표시 · 다른 포트 글자 · 상자와 겹치면 위아래로 조금씩 옮긴다 (그린 뒤 실제 글자 크기로).
  // 예: 요청 4 수정안 1 의 'web (ASG) → mysql :3306' 글자가 '인터넷 → mysql' 선의 ✕ 와 겹쳐 ':330⊗' 로 보였다
  declutter(layer, L) {
    try {
      const hit = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
      const busy = Object.values(L.nodes).map((n) => ({ x: n.x, y: n.y, w: BOX_W, h: BOX_H }));
      layer.querySelectorAll(".a-x").forEach((g) => {
        const m = /translate\(([-\d.]+),([-\d.]+)\)/.exec(g.getAttribute("transform") || "");
        if (m) busy.push({ x: +m[1] - 11, y: +m[2] - 11, w: 22, h: 22 });
      });
      for (const t of layer.querySelectorAll("text.alab")) {
        const b0 = t.getBBox();
        if (!b0.width) continue;                       // 안 보이는 칸(접힌 곳)에서는 크기를 못 잼 — 그대로
        const box = (dy) => ({ x: b0.x - 2, y: b0.y + dy - 1, w: b0.width + 4, h: b0.height + 2 });
        const dy = [0, -14, 14, -26, 26, -38, 38].find((d) => !busy.some((r) => hit(box(d), r)));
        if (dy) t.setAttribute("y", fx(+t.getAttribute("y") + dy));
        busy.push(box(dy || 0));
      }
    } catch { /* getBBox 를 못 쓰는 환경 — 그대로 둔다 */ }
  }

  name(id) { const n = (this.L && this.L.nodes[id]) || {}; return n.label || id; }
  has(id) { return !!(this.L && this.L.nodes[id]); }

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
