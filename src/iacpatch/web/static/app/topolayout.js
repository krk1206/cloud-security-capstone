// 토폴로지 자동 배치 — 순수 함수 (DOM 없음, node 로 시험 가능). 그리기는 topo.js.
// 고정 좌표를 쓰지 않는다: 설계도(노드 · 설계 통신)와 후보 검사 결과(설계 밖 연결)에서 매번 계산한다 (2026-10-31).
//   열(x)  = 외부 출처에서 몇 번 거쳐 오는가 (설계 통신 기준 가장 긴 경로). 외부 출처가 0열.
//   행(y)  = 들어오는 첫 설계 통신의 출발 노드와 같은 높이를 바라고, 같은 열에서 겹치면 위아래로 벌린다.
//   선     = 바로 옆 열이면 곧은 선/부드러운 곡선, 다른 노드를 지나가면 꺾은 선(아래·위 통로)으로 피한다.
//   설계 밖 출처(VPC 내 모든 서버 · 설계 외 서버 등 설계도에 없는 출처)는 맨 위 줄에 따로 놓는다.

export const SZ = 64;
export const HALF = SZ / 2;
export const COLW = 185;          // 열 간격
export const ROWH = 140;          // 같은 열 노드 사이 최소 간격 (아이콘 + 이름 + 분류 글자)
export const EXT_GAP = 260;       // 외부 출처끼리 간격
export const NAME_DY = HALF + 23; // 아이콘 중심 → 이름 기준선
export const CAT_DY = HALF + 41;  // 아이콘 중심 → 분류 기준선
const UNDER = HALF + 52;          // 아래에서 올라오는 선은 분류 글자 밑에서 멈춤
const OVER = HALF + 9;            // 위에서 내려오는 선은 아이콘 위에서 멈춤

const fx = (v) => Number(v.toFixed(1));

function boxOf(n) { return [n.x - HALF - 8, n.y - HALF - 8, n.x + HALF + 8, n.y + HALF + 46]; }
function inBox(p, b) { return p[0] > b[0] && p[0] < b[2] && p[1] > b[1] && p[1] < b[3]; }

function sampleCubic(p0, c1, c2, p1, n = 28) {
  const out = [];
  for (let i = 1; i < n; i++) {
    const t = i / n, u = 1 - t;
    out.push([u * u * u * p0[0] + 3 * u * u * t * c1[0] + 3 * u * t * t * c2[0] + t * t * t * p1[0],
      u * u * u * p0[1] + 3 * u * u * t * c1[1] + 3 * u * t * t * c2[1] + t * t * t * p1[1]]);
  }
  return out;
}
function samplePoly(pts, step = 8) {
  const out = [];
  for (let i = 0; i + 1 < pts.length; i++) {
    const [a, b] = [pts[i], pts[i + 1]];
    const L = Math.hypot(b[0] - a[0], b[1] - a[1]), n = Math.max(1, Math.floor(L / step));
    for (let k = 1; k < n; k++) out.push([a[0] + (b[0] - a[0]) * k / n, a[1] + (b[1] - a[1]) * k / n]);
  }
  return out;
}

// 설계 통신 그래프에서 되돌아가는 선(순환)을 찾아 열 계산에서 뺀다
function backEdges(ids, flows) {
  const adj = {};
  flows.forEach((f) => { (adj[f.src] = adj[f.src] || []).push(f.dst); });
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

export function layout(model, extras = []) {
  const nodes = (model && model.nodes) || [];
  const flows = ((model && model.flows) || []).filter((f) => nodes.some((n) => n.id === f.src) && nodes.some((n) => n.id === f.dst));
  const isExt = (id) => (nodes.find((n) => n.id === id) || {}).kind === "external";
  const ids = nodes.map((n) => n.id);
  const order = Object.fromEntries(ids.map((id, i) => [id, i]));
  const back = backEdges(nodes.filter((n) => n.kind === "external").map((n) => n.id).concat(ids), flows);
  const fwd = flows.filter((f) => !back.has(`${f.src}>${f.dst}`) && !isExt(f.dst) && f.src !== f.dst);

  // 1) 열: 외부 출처 0, 나머지는 (앞 노드 열 + 1) 의 최댓값, 들어오는 선이 없으면 1
  const rank = {};
  nodes.forEach((n) => { rank[n.id] = n.kind === "external" ? 0 : 1; });
  for (let it = 0; it < nodes.length + 1; it++) {
    let changed = false;
    for (const f of fwd) {
      const r = rank[f.src] + 1;
      if (r > rank[f.dst]) { rank[f.dst] = r; changed = true; }
    }
    if (!changed) break;
  }
  // 코드에만 있는 리소스(설계도에 없는 리소스): 그쪽으로 들어오는 '설계 밖 연결' 이 있으면 그 출발 노드 다음 열에 (선이 다른 노드를
  // 가로지르지 않게). 들어오는 연결이 없으면 열 대신 맨 아래 줄 (2026-11-01 — 설계에서 뺀 Redis 가 API 옆에 남아 보이게)
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const freeIn = {};
  for (const e of extras || []) {
    const q = byId[e.dst], s = byId[e.src];
    if (!q || q.kind !== "unmapped" || !s || s.kind === "unmapped") continue;
    freeIn[q.id] = freeIn[q.id] || [];
    freeIn[q.id].push(s.id);
    rank[q.id] = Math.max(freeIn[q.id].length > 1 ? rank[q.id] : 0, rank[s.id] + 1);
  }
  const isFree = (n) => n.kind === "unmapped" && !freeIn[n.id];
  const maxRank = Math.max(0, ...nodes.filter((n) => !isFree(n)).map((n) => rank[n.id]));

  // 2) 행: 외부 출처는 차례로, 나머지는 첫 앞 노드의 높이를 바라고 겹치면 벌린다
  const pos = {};
  nodes.filter((n) => n.kind === "external").forEach((n, i) => { pos[n.id] = { x: 0, y: i * EXT_GAP }; });
  for (let r = 1; r <= maxRank; r++) {
    const col = nodes.filter((n) => n.kind !== "external" && !isFree(n) && rank[n.id] === r).map((n) => {
      const pre = fwd.find((f) => f.dst === n.id && pos[f.src]);
      const src = pre ? pre.src : (freeIn[n.id] || []).find((x) => pos[x]);
      return { id: n.id, pref: src ? pos[src].y : 0 };
    });
    col.sort((a, b) => a.pref - b.pref || order[a.id] - order[b.id]);
    const ys = [];
    col.forEach((c, i) => { ys.push(i === 0 ? c.pref : Math.max(c.pref, ys[i - 1] + ROWH)); });
    // 바라는 높이의 평균에 맞춰 묶음 전체를 옮긴다 (한쪽으로 쏠리지 않게)
    const shift = col.length ? (col.reduce((s, c) => s + c.pref, 0) - ys.reduce((s, y) => s + y, 0)) / col.length : 0;
    col.forEach((c, i) => { pos[c.id] = { x: r * COLW, y: ys[i] + shift }; });
  }
  const placedYs = Object.values(pos).map((p) => p.y);
  const bottom = (placedYs.length ? Math.max(...placedYs) : 0) + ROWH + 20;
  nodes.filter(isFree).forEach((n, i) => { pos[n.id] = { x: (1 + i) * COLW, y: bottom }; rank[n.id] = 1 + i; });
  const placed = Object.fromEntries(nodes.map((n) => [n.id, { ...n, x: pos[n.id].x, y: pos[n.id].y, rank: rank[n.id] }]));

  // 3) 영역: VPC(계층 전체) · 공개 · 비공개 서브넷. 두 서브넷 영역이 겹치면 노드마다 바탕판으로
  const tiers = Object.values(placed).filter((n) => n.kind !== "external");
  const bb = (list, pad, head) => {
    if (!list.length) return null;
    const xs = list.map((n) => n.x), ys = list.map((n) => n.y);
    return [Math.min(...xs) - HALF - 30 - pad, Math.min(...ys) - HALF - 18 - pad - head, Math.max(...xs) + HALF + 30 + pad, Math.max(...ys) + HALF + 58 + pad];
  };
  const pubBox = bb(tiers.filter((n) => n.zone === "public"), 0, 30);
  const privBox = bb(tiers.filter((n) => n.zone !== "public"), 0, 30);
  const overlap = pubBox && privBox && !(pubBox[2] + 8 <= privBox[0] || privBox[2] + 8 <= pubBox[0] || pubBox[3] + 8 <= privBox[1] || privBox[3] + 8 <= pubBox[1]);
  const vpcIn = [pubBox, privBox].filter(Boolean);
  const vpcBox = vpcIn.length ? [Math.min(...vpcIn.map((b) => b[0])) - 18, Math.min(...vpcIn.map((b) => b[1])) - 44, Math.max(...vpcIn.map((b) => b[2])) + 18, Math.max(...vpcIn.map((b) => b[3])) + 16] : null;

  // 4) 선 경로
  const others = (a, b) => Object.values(placed).filter((n) => n.id !== a && n.id !== b).map(boxOf);
  const clear = (pts, a, b) => { const bx = others(a, b); return !pts.some((p) => bx.some((q) => inBox(p, q))); };
  const allY = Object.values(placed).map((n) => n.y);
  // 노드 상자들이 차지하는 높이 구간을 합친 뒤, 구간 사이 빈 틈의 가운데 높이 (선을 지나가게 할 통로)
  const spans = Object.values(placed).map((n) => { const b = boxOf(n); return [b[1], b[3]]; }).sort((u, v) => u[0] - v[0]);
  const merged = [];
  spans.forEach((sp) => { const last = merged[merged.length - 1]; if (last && sp[0] <= last[1]) last[1] = Math.max(last[1], sp[1]); else merged.push([...sp]); });
  const rowGaps = [];
  for (let i = 0; i + 1 < merged.length; i++) if (merged[i + 1][0] - merged[i][1] > 28) rowGaps.push((merged[i][1] + merged[i + 1][0]) / 2);
  const laneUse = {};
  const route = (a, b, bend = 0) => {
    const p = placed[a], q = placed[b];
    const s = [p.x + HALF + 6, p.y + bend], e = [q.x - HALF - 9, q.y + bend];
    if (q.x > p.x) {
      if (Math.abs(q.y - p.y) < 1 && clear(samplePoly([s, e]), a, b)) {
        return { d: `M${fx(s[0])},${fx(s[1])} L${fx(e[0])},${fx(e[1])}`, lab: [fx((s[0] + e[0]) / 2), fx(s[1] - 11), "middle"] };
      }
      const k = (e[0] - s[0]) / 2;
      const c1 = [s[0] + k, s[1]], c2 = [e[0] - k, e[1]];
      if (clear(sampleCubic(s, c1, c2, e), a, b)) {
        return { d: `M${fx(s[0])},${fx(s[1])} C${fx(c1[0])},${fx(c1[1])} ${fx(c2[0])},${fx(c2[1])} ${fx(e[0])},${fx(e[1])}`,
          lab: [fx((s[0] + e[0]) / 2), fx((s[1] + e[1]) / 2 - 11), "middle"] };
      }
      // 꺾은 선: 출발 높이로 옆으로 간 뒤 도착 노드 아래(또는 위)로 들어간다. 같은 출발점 선끼리는 높이를 조금씩 비킨다
      const n = (laneUse[a] = (laneUse[a] || 0) + 1);
      const off = (n % 2 ? -1 : 1) * 12 * Math.ceil(n / 2);
      // 통로 후보: 출발 높이 → 노드 줄 사이 빈 틈(가까운 순) → 맨 아래 → 맨 위
      const gaps = rowGaps.map((g) => g + 10 * (n - 1)).sort((u, v) => Math.abs(u - p.y) - Math.abs(v - p.y));
      for (const ly of [p.y + off, ...gaps, Math.max(...allY) + HALF + 90 + 14 * n, Math.min(...allY) - HALF - 50 - 14 * n]) {
        const up = q.y < ly;
        const pts = [[s[0], ly], [q.x, ly], [q.x, up ? q.y + UNDER : q.y - OVER]];
        const start = Math.abs(ly - p.y) < 30 ? [s[0], ly] : [p.x, ly > p.y ? p.y + UNDER : p.y - OVER];
        const full = Math.abs(ly - p.y) < 30 ? pts : [start, [p.x, ly], ...pts.slice(1)];
        if (clear(samplePoly(full), a, b)) {
          const v0 = full[full.length - 2], v1 = full[full.length - 1];
          return { d: "M" + full.map((t) => `${fx(t[0])},${fx(t[1])}`).join(" L"), lab: [fx(v0[0] + 10), fx(v0[1] + (v1[1] - v0[1]) * 0.55), "start"] };
        }
      }
    }
    // 뒤로 가거나 같은 열: 위쪽 통로로 돌아간다
    const ly = Math.min(...allY) - HALF - 60 - 12 * ((laneUse.__top = (laneUse.__top || 0) + 1));
    const full = [[p.x, p.y - OVER], [p.x, ly], [q.x, ly], [q.x, q.y - OVER]];
    return { d: "M" + full.map((t) => `${fx(t[0])},${fx(t[1])}`).join(" L"), lab: [fx((p.x + q.x) / 2), fx(ly - 8), "middle"] };
  };
  const flowPaths = {};
  flows.forEach((f) => { flowPaths[f.id] = route(f.src, f.dst); });

  // 5) 설계 밖 연결: 설계도에 있는 노드면 그 노드에서, 없으면 맨 위 '출처' 칸에서
  const pseudo = {};
  const pseudoKeys = [];
  // '설계 외 서버 (주소…)' 출처가 그림에 있는 '설계도에 없는 리소스' 노드면 그 노드에서 선을 긋는다
  const srcOf = (e) => {
    if (placed[e.src]) return e.src;
    const hit = Object.values(placed).find((n) => n.kind === "unmapped" && (n.resources || []).some((a) => String(e.src_label || "").includes(a)));
    return hit ? hit.id : null;
  };
  (extras || []).forEach((e) => {
    if (!srcOf(e) && !pseudo[e.src || "unknown"]) { pseudo[e.src || "unknown"] = { label: e.src === "vpc" ? "VPC 내 모든 서버" : (e.src_label || "설계 밖 출처") }; pseudoKeys.push(e.src || "unknown"); }
  });
  const topY = (vpcBox ? vpcBox[1] : Math.min(...allY) - HALF) - 46;
  const span = vpcBox ? [vpcBox[0] + 120, vpcBox[2] - 60] : [0, maxRank * COLW];
  pseudoKeys.forEach((k, i) => { pseudo[k].x = fx(span[0] + (span[1] - span[0]) * (pseudoKeys.length === 1 ? 0.5 : i / (pseudoKeys.length - 1))); pseudo[k].y = fx(topY); });
  const pairCount = {};
  const pseudoUse = {};
  flows.forEach((f) => { pairCount[`${f.src}>${f.dst}`] = 1; });
  const extraPaths = (extras || []).map((e) => {
    const q = placed[e.dst];
    if (!q) return null;
    const sid = srcOf(e);
    if (sid) {
      const key = `${sid}>${e.dst}`;
      const bend = (pairCount[key] = (pairCount[key] || 0) + 1) > 1 ? 14 * (pairCount[key] - 1) : 0;   // 같은 두 노드 사이 선과 겹치지 않게
      return route(sid, e.dst, bend);
    }
    const p = pseudo[e.src || "unknown"];
    const s = [p.x, p.y + 13];
    // 1) 곡선으로 도착 노드 위에 들어가기 2) 안 되면 꺾은 선으로 도착 노드 오른쪽 · 왼쪽 틈을 타고 내려가 옆으로 들어가기
    const top = [q.x, q.y - OVER], c1 = [s[0], s[1] + 80], c2 = [q.x, q.y - OVER - 90];
    if (clear(sampleCubic(s, c1, c2, top), "", e.dst)) {
      return { d: `M${fx(s[0])},${fx(s[1])} C${fx(c1[0])},${fx(c1[1])} ${fx(c2[0])},${fx(c2[1])} ${fx(top[0])},${fx(top[1])}`, lab: [fx((s[0] + top[0]) / 2 + 6), fx((s[1] + top[1]) / 2), "start"] };
    }
    const k = (pseudoUse[e.dst] = (pseudoUse[e.dst] || 0) + 1);
    for (const side of [1, -1]) {
      const X = q.x + side * (HALF + 46 + 10 * k);
      const pts = [s, [s[0], s[1] + 14], [X, s[1] + 14], [X, q.y], [q.x + side * (HALF + 9), q.y]];
      if (clear(samplePoly(pts), "", e.dst)) {
        return { d: "M" + pts.map((t) => `${fx(t[0])},${fx(t[1])}`).join(" L"), lab: [fx(X + (side > 0 ? 6 : -6)), fx(q.y - 18), side > 0 ? "start" : "end"] };
      }
    }
    return { d: `M${fx(s[0])},${fx(s[1])} C${fx(c1[0])},${fx(c1[1])} ${fx(c2[0])},${fx(c2[1])} ${fx(top[0])},${fx(top[1])}`, lab: [fx((s[0] + top[0]) / 2 + 6), fx((s[1] + top[1]) / 2), "start"] };
  });

  // 6) 보이는 범위 — 실제로 그린 것(노드 · 영역 · 출처 칸 · 선의 모든 점)만큼
  const xs = [], ys = [];
  Object.values(placed).forEach((n) => { xs.push(n.x - HALF - 62, n.x + HALF + 62); ys.push(n.y - HALF - 14, n.y + HALF + 62); });
  [vpcBox].filter(Boolean).forEach((b) => { xs.push(b[0], b[2]); ys.push(b[1], b[3]); });
  Object.values(pseudo).forEach((p) => { xs.push(p.x - 80, p.x + 80); ys.push(p.y - 18, p.y + 18); });
  [...Object.values(flowPaths), ...extraPaths.filter(Boolean)].forEach((r) => {
    const nums = (r.d.match(/-?\d+(?:\.\d+)?/g) || []).map(Number);
    for (let i = 0; i + 1 < nums.length; i += 2) { xs.push(nums[i]); ys.push(nums[i + 1]); }
    xs.push(r.lab[0]); ys.push(r.lab[1] - 14);
  });
  const vb = [fx(Math.min(...xs) - 14), fx(Math.min(...ys) - 14), fx(Math.max(...xs) - Math.min(...xs) + 28), fx(Math.max(...ys) - Math.min(...ys) + 28)];
  return { viewBox: vb, nodes: placed, rank, maxRank, zones: { vpc: vpcBox, pub: overlap ? null : pubBox, priv: overlap ? null : privBox, plates: !!overlap },
    flows: flowPaths, extras: extraPaths, pseudo };
}
