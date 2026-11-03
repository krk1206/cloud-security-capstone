// 구성도 배치 — 순수 함수 (DOM 없음, node 로 시험 가능). 그리기는 archview.js. 모델은 서버 web/archmap.py.
// 고정 좌표 없음: 코드(리소스 · 서브넷 · 통신)가 바뀌면 배치도 바뀐다 (2026-11-01 갈아엎기 5차, D-33).
//   위 줄    = VPC 밖에서 들어오는 것: 외부 출처(인터넷 · IP 대역) + 앞단 서비스(CloudFront · DNS · WAF · API Gateway)
//   VPC 상자 = 머리(인터넷 게이트웨이 · 'VPC 안 모든 서버' 출처) + 서브넷 띠(공개 → 비공개). 띠 안은 [로드밸런서 · 서버] 줄과 [DB · 캐시] 줄
//   오른쪽   = VPC 밖 AWS 서비스 (IAM 역할 → 그 역할이 쓰는 리소스를 같은 높이로)
//   열(x)    = 위 줄에서 받는 상자 바로 아래 (같은 줄은 왼쪽 → 오른쪽 흐름 순)
//   선       = 직각. 옆으로 가는 부분은 줄 사이 빈 칸(도착 상자마다 한 칸)이나 열 사이 통로로만 — 상자 · 글자를 가로지르지 않게.
//              같은 상자로 들어가는 선은 마지막 부분을 함께 쓴다 (선을 누르면 겹친 통신을 골라서 본다)

export const SZ = 52;
export const HALF = SZ / 2;
export const COLW = 160;
export const NAME_DY = HALF + 18;    // 아이콘 중심 → 이름 기준선
export const SUB_DY = HALF + 34;     // 아이콘 중심 → 종류 기준선
const BOTTOM = HALF + 42;            // 아이콘 중심 → 글자 아래
const TOP = HALF + 6;                // 아이콘 중심 → 화살촉 위치
const LANE = 8;                      // 같은 칸의 선 간격
const LAB_H = 13;
const BAND_HEAD = 30, BAND_PAD = 16, BAND_GAP = 14, VPC_HEAD = 58, VPC_PAD = 18, OUT_GAP = 70, TOP_PAD = 30;
const BAND_ORDER = { public: 0, mixed: 1, private_nat: 2, private: 3, unknown: 4 };
const ROW_OF = { gw: 0, lb: 0, compute: 0, data: 1 };
const RANK_KINDS = new Set(["sg", "traffic", "replica", "ghost"]);
const MAIN_KINDS = new Set(["sg", "traffic"]);

const fx = (v) => Number(Number(v).toFixed(1));
// 글자 폭 추정 (한글 · 한자는 글자 크기만큼, 나머지는 0.6배)
export const textW = (s, size = 12) => Math.ceil([...String(s || "")].reduce((w, ch) => w + (ch.codePointAt(0) > 0x2e80 ? size * 0.98 : size * 0.6), 0)) + 6;

function backEdges(ids, links) {
  const adj = {};
  links.forEach((l) => { (adj[l.src] = adj[l.src] || []).push(l.dst); });
  const st = {}, back = new Set();
  const dfs = (u) => {
    st[u] = 1;
    for (const v of adj[u] || []) {
      if (st[v] === 1) back.add(`${u}>${v}`);
      else if (!st[v]) dfs(v);
    }
    st[u] = 2;
  };
  ids.forEach((id) => { if (!st[id]) dfs(id); });
  return back;
}

// 선에 붙일 글자 (보안 그룹 · 원하는 구조 = 포트, 권한 = 동작, 역할 = 어떤 역할, 복제). items = 포트 하나하나 (위험 여부)
export function linkText(l) {
  const k = new Set(l.kinds);
  if ((k.has("sg") || k.has("ghost")) && (l.items || []).length) return `:${l.items.map((x) => x.text).join(", ")}`;
  if (k.has("perm")) { const t = String(l.label || ""); return t.length > 18 ? t.slice(0, 17) + "…" : t; }
  if (k.has("role")) return String(l.label || "");
  if (k.has("replica")) return "복제";
  return "";
}

// 같은 두 상자 사이의 보안 그룹 허용 · 요청 경로는 선 하나로 (포트 글자는 보안 그룹 쪽)
export function links(model, overlay = null) {
  const out = {};
  const all = [...((model && model.edges) || []), ...(((overlay || {}).ghost_edges) || [])];
  for (const e of all) {
    const main = MAIN_KINDS.has(e.kind);
    const key = main ? `${e.src}>${e.dst}>main` : `${e.src}>${e.dst}>${e.kind}>${e.id}`;
    const l = out[key] || (out[key] = { id: `l:${key}`, src: e.src, dst: e.dst, kinds: [], edges: [], ports: "", label: "", risk: null, ghost: false });
    l.kinds.push(e.kind);
    l.edges.push(e.id);
    if (e.kind === "sg" || e.kind === "ghost") {
      l.ports = l.ports ? `${l.ports}, ${e.ports}` : (e.ports || "");
      l.items = [...(l.items || []), ...(e.port_items || (e.ports ? [{ text: String(e.ports), risk: false }] : []))];
    }
    if (e.kind === "perm" || e.kind === "role") l.label = e.label || "";
    if (e.kind === "ghost") { l.ghost = true; l.state = e.state; }
    if (e.risk) l.risk = l.risk || e.risk;
    if (e.kind === "traffic" && !l.traffic) l.traffic = e.label || "요청 경로";
  }
  return Object.values(out).map((l) => ({ ...l, text: linkText(l) }));
}

export function layout(model, overlay = null) {
  const nodes = [...((model && model.nodes) || []), ...(((overlay || {}).ghost_nodes) || [])];
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const L = links(model, overlay).filter((l) => byId[l.src] && byId[l.dst] && l.src !== l.dst);
  const area = (n) => ((n.place || {}).area) || "outside";
  const isTop = (n) => area(n) === "external" || area(n) === "edge";

  // 1) 흐름 순위 = 외부에서 몇 번 거쳐 오는가 (가장 긴 경로, 되돌아가는 선 제외)
  const flowLinks = L.filter((l) => l.kinds.some((k) => RANK_KINDS.has(k)));
  const back = backEdges(nodes.filter(isTop).map((n) => n.id).concat(nodes.map((n) => n.id)), flowLinks);
  const fwd = flowLinks.filter((l) => !back.has(`${l.src}>${l.dst}`) && !isTop(byId[l.dst]));
  const rank = {};
  nodes.forEach((n) => { rank[n.id] = isTop(n) || area(n) === "vpc_src" ? 0 : 1; });
  for (let it = 0; it < nodes.length + 1; it++) {
    let ch = false;
    for (const l of fwd) { const r = rank[l.src] + 1; if (r > rank[l.dst]) { rank[l.dst] = r; ch = true; } }
    if (!ch) break;
  }
  const srcsOf = {};
  L.forEach((l) => { if (l.kinds.some((k) => RANK_KINDS.has(k))) (srcsOf[l.dst] = srcsOf[l.dst] || []).push(l); });

  // 2) 줄 구조: VPC 별 [띠 → 줄들]. 줄 = 같은 높이의 상자들
  const vpcs = ((model && model.vpcs) || []).map((v) => ({ ...v }));
  if (!vpcs.length && nodes.some((n) => ["subnet", "vpc", "vpc_gw"].includes(area(n)))) vpcs.push({ id: "vpc:?", label: "VPC", cidr: "" });
  const vpcOf = (n) => (n.place || {}).vpc || (vpcs[0] || {}).id;
  const bandsAll = ((model && model.bands) || []).slice().sort((a, b) => (BAND_ORDER[a.kind] ?? 9) - (BAND_ORDER[b.kind] ?? 9) || String(a.names).localeCompare(String(b.names)));
  const rows = [];                 // {id, nodes: [], band, vpc}
  const rowOf = {};
  const plan = [];
  for (const v of vpcs) {
    const groups = [];
    for (const b of bandsAll.filter((x) => (x.vpc || (vpcs[0] || {}).id) === v.id)) {
      const ins = nodes.filter((n) => area(n) === "subnet" && (n.place || {}).band === b.id);
      if (ins.length) groups.push({ band: b, rows: [ins.filter((n) => (ROW_OF[n.cat] ?? 0) === 0), ins.filter((n) => (ROW_OF[n.cat] ?? 0) === 1)].filter((r) => r.length) });
    }
    const loose = nodes.filter((n) => area(n) === "vpc" && vpcOf(n) === v.id);
    if (loose.length) groups.push({ band: { id: `band:loose:${v.id}`, kind: "unknown", label: loose.every((n) => n.ghost) ? "원하는 구조에만 있는 구성요소 (코드에 없음)" : "VPC 안 (서브넷 정보 없음)", names: [], azs: [] }, rows: [loose] });
    for (const g of groups) {
      g.rowIds = g.rows.map((r) => {
        const id = `r${rows.length}`;
        rows.push({ id, nodes: r, band: g.band, vpc: v.id });
        r.forEach((n) => { rowOf[n.id] = id; });
        return id;
      });
    }
    plan.push({ v, groups, gw: nodes.filter((n) => area(n) === "vpc_gw" && vpcOf(n) === v.id), src: nodes.filter((n) => area(n) === "vpc_src" && (vpcOf(n) === v.id || vpcs.length === 1)) });
  }
  const rowIdx = Object.fromEntries(rows.map((r, i) => [r.id, i]));

  // 3) 열: 위에서부터. 같은 줄 안의 흐름(앞 상자 → 다음 상자)은 바로 오른쪽, 위 줄에서 받는 상자는 그 바로 아래
  const col = {};
  let maxCol = 1;
  for (const r of rows) {
    const inRow = new Set(r.nodes.map((n) => n.id));
    const order = r.nodes.slice().sort((a, b) => (a.cat === "gw") - (b.cat === "gw") || rank[a.id] - rank[b.id] || String(a.label).localeCompare(String(b.label)));
    // 같은 줄 안의 선으로 이어진 상자는 붙여서 (앞 상자 다음에)
    const placedOrder = [];
    const used = new Set();
    const chainNext = (id) => L.filter((l) => l.src === id && inRow.has(l.dst) && l.kinds.some((k) => RANK_KINDS.has(k))).map((l) => byId[l.dst]).sort((a, b) => rank[a.id] - rank[b.id]);
    const visit = (n) => { if (used.has(n.id)) return; used.add(n.id); placedOrder.push(n); chainNext(n.id).forEach((m) => { if (rank[m.id] >= rank[n.id]) visit(m); }); };
    order.forEach(visit);
    let last = 0;
    for (const n of placedOrder) {
      let pref;
      const same = (srcsOf[n.id] || []).map((l) => l.src).filter((s) => inRow.has(s) && col[s]);
      const upper = (srcsOf[n.id] || []).map((l) => byId[l.src]).filter((s) => s && col[s.id] && !inRow.has(s.id) && rowOf[s.id] && rowIdx[rowOf[s.id]] < rowIdx[r.id]);
      if (same.length) pref = Math.max(...same.map((s) => col[s])) + 1;
      else if (upper.length) {
        const tr = upper.filter((s) => (L.find((l) => l.src === s.id && l.dst === n.id) || { kinds: [] }).kinds.includes("traffic"));
        const pick = (tr.length ? tr : upper).sort((a, b) => rank[b.id] - rank[a.id])[0];
        pref = col[pick.id];
      } else pref = n.cat === "gw" ? last + 1 : Math.max(1, rank[n.id]);
      const c = Math.max(pref, last + 1);
      col[n.id] = c; last = c; maxCol = Math.max(maxCol, c);
    }
  }

  // 4) 줄마다 위에서 꺾어 들어오는 선의 도착 상자 수 → 줄 위 칸 높이
  const P = {};
  const tmpRowY = {};             // 순서 비교용 (실제 y 전)
  rows.forEach((r, i) => { tmpRowY[r.id] = i + 1; });
  const orderY = (n) => (isTop(n) ? -2 : area(n) === "vpc_src" ? -1 : rowOf[n.id] ? tmpRowY[rowOf[n.id]] : 999);
  // 도착 묶음 = (도착 상자, 선 상태). 같은 상자로 들어와도 상태(원하는 구조대로 · 없음 · 위험 · 원하는 구조에만)가 다르면 따로 내려온다 — 빨간 선과 파란 선이 겹치지 않게
  const ovEdges = (overlay && overlay.edges) || {};
  const hasOv = Object.keys(ovEdges).length > 0;
  const GRP_ORDER = ["n", "r", "x", "gdesired", "gmissing", "gunknown", "gnew", "gremoved"];
  // 설계도 그림(선이 모두 같은 상태)은 출발 상자마다 따로 내려온다 — 어느 출발지의 포트인지 보이게 (6차 · D-34)
  const perSrc = !!(model && model.source === "design");
  const nodeIdx = Object.fromEntries(nodes.map((n, i) => [n.id, i]));
  const grp = (l) => (perSrc ? `s~${l.src}` : l.ghost ? `g${l.state || ""}` : l.edges.some((id) => (ovEdges[id] || {}).state === "excess") ? "x" : l.risk && !hasOv ? "r" : "n");
  const akey = (l) => `${l.dst}|${grp(l)}`;
  const groupsOf = {};            // 도착 상자 → 상태 묶음들
  L.forEach((l) => { const g = grp(l); const a = (groupsOf[l.dst] = groupsOf[l.dst] || []); if (!a.includes(g)) a.push(g); });
  const srcKey = (g) => { const id = g.slice(2); const n = byId[id]; return n && isTop(n) ? [0, nodeIdx[id] || 0] : [1, col[id] || 0, nodeIdx[id] || 0]; };
  const cmpKey = (a, b) => { for (let i = 0; i < Math.max(a.length, b.length); i++) { const d = (a[i] || 0) - (b[i] || 0); if (d) return d; } return 0; };
  Object.values(groupsOf).forEach((a) => a.sort((x, y) => (perSrc ? cmpKey(srcKey(x), srcKey(y)) : (GRP_ORDER.indexOf(x) + 99) % 99 - (GRP_ORDER.indexOf(y) + 99) % 99)));
  const arrOff = (l) => { const a = groupsOf[l.dst] || [grp(l)]; const i = a.indexOf(grp(l)); return (i - (a.length - 1) / 2) * 14; };
  const arrivals = {};            // 줄 → 위에서 꺾어 들어오는 도착 묶음들
  for (const l of L) {
    const s = byId[l.src], d = byId[l.dst];
    if (area(d) !== "outside" && rowOf[d.id] && orderY(s) <= orderY(d) && area(s) !== "outside") {
      const rid = rowOf[d.id];
      (arrivals[rid] = arrivals[rid] || new Set()).add(akey(l));
    }
  }
  const zoneH = (rid) => 26 + LANE * Math.max(0, ((arrivals[rid] && arrivals[rid].size) || 0) - 1) + 10;

  // 5) 세로 위치
  const topNodes = nodes.filter(isTop);
  const topY = topNodes.length ? TOP_PAD + HALF : 0;
  const topToVpc = new Set(L.filter((l) => isTop(byId[l.src]) && !isTop(byId[l.dst])).map((l) => akey(l)));
  const extZone = topNodes.length ? 22 + LANE * Math.max(0, topToVpc.size - 1) + 16 : 0;
  let y = topNodes.length ? topY + BOTTOM + extZone : 0;
  const boxes = { vpcs: [], bands: [], outside: null, top: topNodes.length ? { y: topY } : null };
  const x0 = 0;
  const colX = (c) => x0 + VPC_PAD + BAND_PAD + (c - 1) * COLW + COLW / 2;
  const srcCols = plan.reduce((m, p) => Math.max(m, p.src.length), 0);
  const headW = Math.max(0, ...plan.map((p) => 14 + p.gw.length * 46 + 30 + Math.max(textW(`${p.v.label || "VPC"}${p.v.cidr ? ` · ${p.v.cidr}` : ""}`, 14),
    p.gw.length ? textW(`인터넷 게이트웨이 ${p.gw.map((n) => n.label).join(" · ")} (VPC 경계)`, 11.5) : 0) + 12 - 2 * VPC_PAD - 2 * BAND_PAD),
    ...bandsAll.map((b) => 32 + textW([b.label, (b.names || []).join(" · "), (b.azs || []).length ? `가용 영역 ${(b.azs || []).join(" · ")}` : ""].filter(Boolean).join("   "), 12.5) + 10 - 2 * BAND_PAD));
  const innerW = Math.max((maxCol + srcCols) * COLW, headW);
  const rowY = {};
  for (const p of plan) {
    const vy0 = y;
    let cy = vy0 + VPC_HEAD;
    const vb = { id: p.v.id, label: p.v.label, cidr: p.v.cidr, x0, y0: vy0, x1: x0 + innerW + 2 * VPC_PAD + 2 * BAND_PAD, y1: 0, bands: [], gw: [] };
    p.gw.forEach((n, i) => { P[n.id] = { x: x0 + 34 + i * 46, y: vy0, gw: true }; vb.gw.push(n.id); });
    if (p.src.length) {
      const sy = cy + HALF;
      p.src.forEach((n, i) => { P[n.id] = { x: colX(maxCol + 1 + i), y: sy }; });
      cy = sy + BOTTOM + 10;
    }
    for (const g of p.groups) {
      const by0 = cy;
      cy += BAND_HEAD;
      const rowYs = [];
      g.rowIds.forEach((rid) => {
        const ry = cy + zoneH(rid) + HALF;
        rowYs.push(ry);
        rowY[rid] = ry;
        rows[rowIdx[rid]].nodes.forEach((n) => { P[n.id] = { x: colX(col[n.id]), y: ry }; });
        cy = ry + BOTTOM;
      });
      const bb = { id: g.band.id, kind: g.band.kind, label: g.band.label, names: g.band.names || [], azs: g.band.azs || [], x0: x0 + VPC_PAD, y0: by0, x1: vb.x1 - VPC_PAD, y1: cy + BAND_PAD, rowYs };
      boxes.bands.push(bb);
      vb.bands.push(bb.id);
      cy = bb.y1 + BAND_GAP;
    }
    vb.y1 = Math.max(cy, vy0 + VPC_HEAD + 40) + 4;
    boxes.vpcs.push(vb);
    y = vb.y1 + 40;
  }
  const vpcRight = boxes.vpcs.length ? Math.max(...boxes.vpcs.map((b) => b.x1)) : 0;
  const vpcTop = boxes.vpcs.length ? Math.min(...boxes.vpcs.map((b) => b.y0)) : y;

  // 6) 위 줄: 받는 상자 위에 (겹치면 오른쪽으로 비킨다). 위 줄끼리만 이어진 것(DNS → CloudFront)은 그 옆
  const want = topNodes.map((n, i) => {
    const ts = L.filter((l) => l.src === n.id && P[l.dst] && !isTop(byId[l.dst])).map((l) => P[l.dst].x);
    return { n, x: ts.length ? ts.reduce((s, v) => s + v, 0) / ts.length : null, i };
  });
  want.forEach((w) => {
    if (w.x != null) return;
    const peer = L.find((l) => l.src === w.n.id && isTop(byId[l.dst])) || L.find((l) => l.dst === w.n.id && isTop(byId[l.src]));
    const other = peer && want.find((o) => o.n.id === (peer.src === w.n.id ? peer.dst : peer.src));
    w.x = other && other.x != null ? other.x - 1 : -1e6 + w.i;
  });
  want.sort((a, b) => a.x - b.x || (area(a.n) === "external") - (area(b.n) === "external") || a.i - b.i);
  let lastX = -Infinity;
  want.forEach((w) => { const x = Math.max(w.x, lastX + COLW * 0.9, colX(1) - (w.x < 0 ? 0 : COLW)); P[w.n.id] = { x, y: topY }; lastX = x; });

  // 7) 오른쪽: VPC 밖 서비스. 역할(선의 출발) 열 + 그 역할이 가리키는 리소스를 같은 높이로 둔 열
  const outs = nodes.filter((n) => area(n) === "outside");
  if (outs.length) {
    const inOut = new Set(outs.map((n) => n.id));
    const oo = L.filter((l) => inOut.has(l.src) && inOut.has(l.dst));
    const srcSet = new Set(oo.map((l) => l.src));
    const users = (n) => L.filter((l) => l.dst === n.id && P[l.src]).map((l) => P[l.src]);
    const key = (n) => { const u = users(n); return u.length ? Math.min(...u.map((p) => p.y * 10 + p.x / 100)) : 1e9; };
    const fromIn = new Set(L.filter((l) => inOut.has(l.dst) && !inOut.has(l.src)).map((l) => l.dst));
    const colA = outs.filter((n) => srcSet.has(n.id) || (fromIn.has(n.id) && !oo.some((l) => l.dst === n.id)))
      .sort((a, b) => key(a) - key(b) || String(a.id).localeCompare(String(b.id)));
    const ox = (boxes.vpcs.length ? vpcRight + OUT_GAP : (topNodes.length ? x0 : x0)) + COLW / 2;
    const oy0 = boxes.vpcs.length ? vpcTop + 40 + HALF : y + HALF;
    const STEP = BOTTOM + HALF + 30;
    const slots = {};              // 열 → 쓰인 높이 칸
    const take = (c, want) => { const s = slots[c] = slots[c] || new Set(); let k = Math.max(0, want); while (s.has(k)) k++; s.add(k); return k; };
    const twoCols = colA.length > 0;
    colA.forEach((n) => { const k = take(0, 0); P[n.id] = { x: ox, y: oy0 + k * STEP }; });
    const rest = outs.filter((n) => !colA.includes(n));
    const linked = rest.filter((n) => oo.some((l) => l.dst === n.id)).sort((a, b) => key(a) - key(b));
    linked.forEach((n) => {
      const ss = oo.filter((l) => l.dst === n.id).map((l) => P[l.src]).filter(Boolean);
      const k = take(1, ss.length ? Math.round((Math.min(...ss.map((p) => p.y)) - oy0) / STEP) : 0);
      P[n.id] = { x: ox + COLW + 20, y: oy0 + k * STEP };
    });
    const loose = rest.filter((n) => !linked.includes(n)).sort((a, b) => key(a) - key(b) || String(a.cat).localeCompare(String(b.cat)) || String(a.id).localeCompare(String(b.id)));
    const vpcH = boxes.vpcs.length ? Math.max(...boxes.vpcs.map((b) => b.y1)) - oy0 : STEP * 4;
    const perCol = Math.max(2, Math.floor(vpcH / STEP) + 1);
    loose.forEach((n) => {
      // VPC 쪽에서 오는 선이 있으면 왼쪽 열(통로 쪽), 없으면 오른쪽 열부터 — 선이 다른 상자를 지나지 않게
      const c = fromIn.has(n.id) ? 0 : twoCols ? 1 : ((slots[0] || new Set()).size < perCol ? 0 : 1);
      const k = take(c, 0);
      P[n.id] = { x: ox + c * (COLW + 20), y: oy0 + k * STEP };
    });
    const xs = outs.map((n) => P[n.id].x), ys = outs.map((n) => P[n.id].y);
    boxes.outside = { x0: Math.min(...xs) - COLW / 2 + 4, y0: Math.min(...ys) - HALF - 34, x1: Math.max(...xs) + COLW / 2 - 4, y1: Math.max(...ys) + BOTTOM + 10 };
  }

  // 8) 선 (직각 경로)
  const placed = Object.fromEntries(nodes.filter((n) => P[n.id]).map((n) => [n.id, { ...n, x: P[n.id].x, y: P[n.id].y, rank: rank[n.id], gw: !!P[n.id].gw }]));
  const pn = Object.values(placed);
  const crosses = (x, y1, y2, skip) => {
    const lo = Math.min(y1, y2), hi = Math.max(y1, y2);
    return pn.some((n) => !skip.includes(n.id) && Math.abs(n.x - x) < 64 && n.y + BOTTOM > lo && n.y - HALF - 6 < hi);
  };
  const crossesH = (y, x1, x2, skip) => {
    const lo = Math.min(x1, x2), hi = Math.max(x1, x2);
    return pn.some((n) => !skip.includes(n.id) && n.x + HALF + 4 > lo && n.x - HALF - 4 < hi && y > n.y - HALF - 4 && y < n.y + BOTTOM);
  };
  // 도착 상자마다 칸 하나 (같은 상자로 가는 선은 같은 칸 → 마지막 부분을 함께 씀)
  const laneIdx = {};
  const kx = (k) => { const [d, g] = k.split("|"); return (P[d] ? P[d].x : 0) + (groupsOf[d] || []).indexOf(g); };
  rows.forEach((r) => {
    const ks = [...(arrivals[r.id] || [])].sort((a, b) => kx(a) - kx(b));
    ks.forEach((k, i) => { laneIdx[k] = i; });
  });
  const laneY = (l) => rowY[rowOf[l.dst]] - HALF - 22 - LANE * (laneIdx[akey(l)] || 0);
  const extIdx = {};
  [...topToVpc].filter((k) => P[k.split("|")[0]]).sort((a, b) => kx(a) - kx(b)).forEach((k, i) => { extIdx[k] = i; });
  const extY = (l) => vpcTop - 16 - LANE * (extIdx[akey(l)] || 0);
  const chanUse = {};
  const chan = (x) => { const k = (chanUse[Math.round(x)] = (chanUse[Math.round(x)] || 0) + 1) - 1; return x + (k % 2 ? -1 : 1) * Math.ceil(k / 2) * 6; };
  const channelNear = (d, fromX) => chan(d.x + (fromX < d.x ? -1 : 1) * COLW / 2);
  const belowUse = {};
  const below = (s) => { const k = (belowUse[s.id] = (belowUse[s.id] || 0) + 1) - 1; return s.y + BOTTOM + 8 + k * 6; };
  const outChanIdx = {};
  [...new Set(L.filter((l) => (area(byId[l.dst]) === "outside") !== (area(byId[l.src]) === "outside")).map((l) => (area(byId[l.dst]) === "outside" ? l.dst : l.src)))]
    .sort((a, b) => ((P[a] || {}).y || 0) - ((P[b] || {}).y || 0)).forEach((id, i) => { outChanIdx[id] = i; });
  const outChan = (o) => vpcRight + 18 + LANE * (outChanIdx[o.id] || 0);
  const topLaneUse = {};

  const routeDown = (s, d, l) => {
    const sy = s.y + (s.gw ? HALF + 4 : BOTTOM);
    const tip = d.y - TOP - 4;
    const ax = d.x + arrOff(l);
    const skip = [s.id, d.id];
    if (Math.abs(s.x - ax) < 1 && !crosses(s.x, sy, tip, skip)) return [[s.x, sy], [ax, tip]];
    if (isTop(s) && rowOf[d.id]) {
      const ey = extY(l);
      if (!crosses(ax, ey, tip, skip)) return [[s.x, sy], [s.x, ey], [ax, ey], [ax, tip]];
      const cx = channelNear(d, s.x);
      const ly = laneY(l);
      return [[s.x, sy], [s.x, ey], [cx, ey], [cx, ly], [ax, ly], [ax, tip]];
    }
    const ly = rowOf[d.id] ? laneY(l) : d.y - HALF - 22;
    if (!crosses(s.x, sy, ly, skip) && !crosses(ax, ly, tip, skip)) return [[s.x, sy], [s.x, ly], [ax, ly], [ax, tip]];
    const y1 = below(s);
    const cx = channelNear(d, s.x);
    return [[s.x, sy], [s.x, y1], [cx, y1], [cx, ly], [ax, ly], [ax, tip]];
  };
  const route = (l) => {
    const s = placed[l.src], d = placed[l.dst];
    const so = area(s) === "outside", dout = area(d) === "outside";
    if (so && dout) {
      const dir = d.x > s.x + 1 ? 1 : d.x < s.x - 1 ? -1 : 0;
      if (dir && Math.abs(s.y - d.y) < 1) return { pts: [[s.x + dir * (HALF + 6), s.y], [d.x - dir * (HALF + 10), d.y]], at: "side", dir };
      if (dir) { const mx = chan((s.x + d.x) / 2); return { pts: [[s.x + dir * (HALF + 6), s.y], [mx, s.y], [mx, d.y], [d.x - dir * (HALF + 10), d.y]], at: "side", dir }; }
      const rx = chan(s.x + COLW / 2 - 4);
      return { pts: [[s.x + HALF + 6, s.y], [rx, s.y], [rx, d.y], [d.x + HALF + 10, d.y]], at: "side", dir: -1 };
    }
    if (so !== dout) {
      // VPC 안 · 위 줄 ↔ VPC 밖: 오른쪽 통로(VPC 오른쪽 여백)로
      const [a, o] = dout ? [s, d] : [d, s];
      const cx = outChan(o);
      let start;
      if (isTop(a)) { const ey = vpcTop - 16 - LANE * (Object.keys(extIdx).length + (outChanIdx[o.id] || 0)); start = [[a.x, a.y + BOTTOM], [a.x, ey], [cx, ey]]; }
      else if (!crossesH(a.y, a.x + HALF + 6, cx, [a.id, o.id])) start = [[a.x + HALF + 6, a.y], [cx, a.y]];
      else { const y1 = below(a); start = [[a.x, a.y + (a.gw ? HALF + 4 : BOTTOM)], [a.x, y1], [cx, y1]]; }
      const pts = [...start, [cx, o.y], [o.x - HALF - 10, o.y]];
      return { pts: dout ? pts : pts.slice().reverse().map((p, i, arr) => (i === arr.length - 1 ? p : p)), at: dout ? "side" : "back", dir: 1 };
    }
    const ys = orderY(s), yd = orderY(d);
    if (ys === yd && Math.abs(s.y - d.y) < 2) {
      const lo = Math.min(s.x, d.x), hi = Math.max(s.x, d.x);
      const between = pn.some((n) => n.id !== s.id && n.id !== d.id && Math.abs(n.y - s.y) < 2 && n.x > lo && n.x < hi);
      const dir = d.x > s.x ? 1 : -1;
      if (!between) return { pts: [[s.x + dir * (HALF + 6), s.y], [d.x - dir * (HALF + 10), d.y]], at: "mid" };
      const ly = isTop(s) ? s.y - HALF - 14 - LANE * ((topLaneUse.n = (topLaneUse.n || 0) + 1) - 1) : laneY(l);
      const ax = d.x + arrOff(l);
      return { pts: [[s.x, s.y - TOP], [s.x, ly], [ax, ly], [ax, d.y - TOP - 4]], at: "top" };
    }
    if (ys < yd || (ys === yd && s.y < d.y)) return { pts: routeDown(s, d, l), at: "top" };
    // 위로 (드묾): 도착 상자 아래 칸으로
    const ly = d.y + BOTTOM + 10;
    const pts = [[s.x, s.y - TOP], [s.x, ly], [d.x, ly], [d.x, d.y + BOTTOM + 4]];
    if (Math.abs(s.x - d.x) < 1) pts.splice(1, 2);
    return { pts, at: "bottom" };
  };
  const paths = {};
  const labels = [];
  const dstLab = {};               // 도착 자리 → 다음 글자 x
  const sameLab = {};              // 도착 자리 + 글자 → 이미 놓은 글자 (같은 글자는 하나로)
  for (const l of L) {
    if (!placed[l.src] || !placed[l.dst]) continue;
    const r = route(l);
    const pts = r.pts.map((p) => [fx(p[0]), fx(p[1])]).filter((p, i, a) => i === 0 || p[0] !== a[i - 1][0] || p[1] !== a[i - 1][1]);
    paths[l.id] = { d: "M" + pts.map((p) => `${p[0]},${p[1]}`).join(" L"), pts, at: r.at };
    if (!l.text) continue;
    const d = placed[l.dst];
    const mono = l.kinds.includes("sg") || l.kinds.includes("ghost");
    const w = textW(l.text, mono ? 12 : 11.5);
    const end = pts[pts.length - 1];
    const spot = r.at === "top" ? `${l.dst}:top` : r.at === "side" ? `${l.dst}:side:${Math.round(end[1])}` : `${l.id}`;
    const ax = r.at === "top" ? end[0] : d.x;
    const skey = `${spot}|${l.text}|${grp(l)}|${(l.items || []).some((x) => x.risk)}`;
    const same = sameLab[skey];
    if (same) { same.links.push(l.id); if (l.risk) same.risk = true; continue; }
    let lab;
    const gs = groupsOf[l.dst] || [];
    if (r.at === "top" && gs.length === 2 && gs.indexOf(grp(l)) === 0) {
      // 두 묶음이 따로 내려오면: 왼쪽 묶음의 글자는 화살표 왼쪽, 오른쪽 묶음은 오른쪽 — 어느 선의 포트인지 보이게 (6차 · D-34)
      const lk = `${spot}:L`;
      const rx = dstLab[lk] === undefined ? ax - 6 : dstLab[lk];
      dstLab[lk] = rx - w - 4;
      lab = { x: rx, y: d.y - HALF - 9, anchor: "end" };
    } else if (r.at === "top") {
      const lx = dstLab[spot] === undefined ? Math.max(ax, d.x) + 6 : dstLab[spot];
      dstLab[spot] = lx + w + 4;
      lab = { x: lx, y: d.y - HALF - 9, anchor: "start" };
    } else if (r.at === "side") {
      const lx = dstLab[spot] === undefined ? end[0] - 4 : dstLab[spot];
      dstLab[spot] = lx - w - 4;
      lab = { x: lx, y: end[1] - 6, anchor: "end" };
    } else if (r.at === "back") {
      const a = pts[0];
      lab = { x: a[0] + 8, y: a[1] - 6, anchor: "start" };
    } else if (r.at === "mid") {
      lab = { x: (pts[0][0] + pts[pts.length - 1][0]) / 2, y: pts[0][1] - 7, anchor: "middle" };
    } else lab = { x: d.x + 6, y: d.y + BOTTOM + 16, anchor: "start" };
    const b = { link: l.id, links: [l.id], text: l.text, items: mono ? l.items || [] : null, risk: !!l.risk, x: fx(lab.x), y: fx(lab.y), anchor: lab.anchor, w };
    sameLab[skey] = b;
    labels.push(b);
  }
  // 글자끼리 겹치면 아래로 비킨다
  const box = (b) => { const x1 = b.anchor === "start" ? b.x : b.anchor === "end" ? b.x - b.w : b.x - b.w / 2; return [x1, b.y - LAB_H + 2, x1 + b.w, b.y + 2]; };
  const done = [];
  for (const b of labels) {
    for (let t = 0; t < 4; t++) {
      const [a1, b1, a2, b2] = box(b);
      if (!done.some((o) => { const [c1, d1, c2, d2] = box(o); return a1 < c2 && c1 < a2 && b1 < d2 && d1 < b2; })) break;
      b.y = fx(b.y + LAB_H);
    }
    done.push(b);
  }

  // 9) 보이는 범위 (글자 폭 포함)
  const xs = [], ys = [];
  pn.forEach((n) => { xs.push(n.x - COLW / 2 + 10, n.x + COLW / 2 - 10); ys.push(n.y - HALF - 8, n.y + BOTTOM + 6); });
  boxes.vpcs.forEach((b) => { xs.push(b.x0, b.x1); ys.push(b.y0 - HALF - 4, b.y1); });
  if (boxes.outside) { xs.push(boxes.outside.x0, boxes.outside.x1); ys.push(boxes.outside.y0, boxes.outside.y1); }
  Object.values(paths).forEach((p) => p.pts.forEach((q) => { xs.push(q[0]); ys.push(q[1]); }));
  labels.forEach((b) => { const [a1, b1, a2, b2] = box(b); xs.push(a1, a2); ys.push(b1, b2); });
  const vb = xs.length ? [fx(Math.min(...xs) - 12), fx(Math.min(...ys) - 12), fx(Math.max(...xs) - Math.min(...xs) + 24), fx(Math.max(...ys) - Math.min(...ys) + 24)] : [0, 0, 400, 120];
  return { viewBox: vb, nodes: placed, links: L, paths, labels, boxes, rank };
}
