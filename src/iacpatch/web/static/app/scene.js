// 시연 환경(scenarios/arch/webapp-2tier)을 3D 로: 인터넷·운영자 → 인터넷 게이트웨이 → 공개 서브넷의 웹 서버 → 비공개 서브넷의 앱 서버,
// 웹 서버 역할(IAM) → 자산 버킷. 요구사항마다 흐름 빛줄기가 있고, 판정(충족/위반/판단 불가)에 따라 색·도달 여부가 바뀐다.
// 장면은 판정을 만들지 않는다 — 서버가 계산한 요구사항 행(verdict)을 그대로 그린다.
import { Geo, hex, V3, pointAt } from "./engine.js";

const C = {
  cyan: "#46d9ff", violet: "#8f7bff", green: "#34ffa0", red: "#ff3456", orange: "#ff8a3d", amber: "#ffc94d",
  steel: "#86a0d6", ec2: "#ff9b3d", vpc: "#9b6bff", pub: "#8fe36b", priv: "#2fd6d0", s3: "#7be36b", iam: "#ff5c8a", white: "#e8f6ff",
};

const POS = {
  globe: [-19.5, 4.8, -3.2], op: [-18, 1.0, 6.4], igw: [-9.1, 2.3, 0], web: [-4.4, 1.95, 0], app: [3.9, 1.95, 0],
  role: [-4.4, 6.1, 0], bucket: [11.6, 1.4, -3.2], ghost: [[12.9, 1.0, 3.2], [10.6, 0.9, 5.2], [14.2, 0.85, 0.9]],
};
const SHIELD_R = 2.35;

// 요구사항 id → 흐름
export const REQ_FLOWS = {
  "keep:public-http": ["http"], "limit:ssh": ["ssh_net"], "limit:rdp": ["rdp_net"], "keep:admin-ssh": ["ssh_op"],
  "limit:app-8080": ["app_net", "app_int"], "limit:iam-0": ["iam_excess"],
  "keep:read-assets-objects": ["iam_read"], "keep:list-assets-bucket": ["iam_list"],
};

const FLOWS = [
  { id: "http", kind: "keep", set: "sg", target: "web", label: "HTTP 80 · 인터넷 사용자",
    pts: [POS.globe, [-14.5, 3.6, -1.6], [-9.1, 1.75, -0.65], [-6.9, 1.7, -0.6], [-4.4, 1.7, -0.45]] },
  { id: "ssh_net", kind: "limit", set: "sg", target: "web", label: "SSH 22 · 인터넷 전체",
    pts: [POS.globe, [-14.2, 4.9, -2.6], [-9.1, 2.35, 0.0], [-6.7, 2.35, 0.1], [-4.4, 2.3, 0.1]] },
  { id: "rdp_net", kind: "limit", set: "sg", target: "web", label: "RDP 3389 · 인터넷 전체",
    pts: [POS.globe, [-14.0, 6.2, -3.7], [-9.1, 2.95, 0.62], [-6.7, 2.95, 0.7], [-4.4, 2.85, 0.6]] },
  { id: "ssh_op", kind: "keep", set: "sg", target: "web", label: "SSH 22 · 운영자 10.0.0.0/8",
    pts: [POS.op, [-13.4, 1.9, 5.6], [-8.6, 1.7, 3.6], [-6.2, 1.55, 1.6], [-4.4, 1.5, 0.7]] },
  { id: "app_int", kind: "approved", set: "sg", target: "app", label: "8080 · 웹 서버 → 앱 서버",
    pts: [[-4.4, 1.3, 0.2], [-1.8, 1.55, 0.6], [0.5, 1.6, 0.6], [2.4, 1.45, 0.3], [3.9, 1.3, 0.2]] },
  { id: "app_net", kind: "limit", set: "sg", target: "app", label: "8080 · 인터넷 전체",
    pts: [POS.globe, [-14.6, 3.0, -4.6], [-9.1, 2.05, -1.0], [-6.0, 2.6, -3.6], [-1.0, 2.7, -3.9], [2.6, 2.3, -1.6], [3.9, 2.2, -0.5]] },
  { id: "iam_read", kind: "keep", set: "iam", target: "bucket", label: "s3:GetObject · 자산 버킷",
    pts: [POS.role, [0.5, 7.3, -1.3], [7.4, 5.6, -2.8], [11.6, 2.5, -3.1]] },
  { id: "iam_list", kind: "keep", set: "iam", target: "bucket", label: "s3:ListBucket · 자산 버킷",
    pts: [POS.role, [0.8, 6.6, -2.1], [7.8, 4.7, -3.4], [11.4, 2.2, -3.4]] },
  { id: "iam_excess", kind: "limit", set: "iam", target: "ghost", label: "승인 밖 권한 · 다른 버킷/동작",
    pts: [POS.role, [2.0, 7.6, 2.0], [9.0, 4.4, 3.6], POS.ghost[0]] },
  { id: "iam_excess2", kind: "limit", set: "iam", target: "ghost", label: "", parent: "iam_excess",
    pts: [POS.role, [1.5, 7.0, 3.4], [7.6, 3.6, 5.2], POS.ghost[1]] },
  { id: "iam_excess3", kind: "limit", set: "iam", target: "ghost", label: "", parent: "iam_excess",
    pts: [POS.role, [3.0, 7.9, 0.8], [10.6, 4.4, 1.4], POS.ghost[2]] },
];

const STATE_LOOK = {
  neutral_keep: { color: C.cyan, alpha: 0.75, width: 0.2, speed: 0.75, reach: true, text: "요구: 반드시 허용" },
  neutral_limit: { color: C.violet, alpha: 0.42, width: 0.16, speed: 0.55, reach: false, text: "요구: 막혀야 함" },
  neutral_approved: { color: C.cyan, alpha: 0.6, width: 0.17, speed: 0.7, reach: true, text: "요구: 웹 서버에서만" },
  ok: { color: C.green, alpha: 1.0, width: 0.22, speed: 0.95, reach: true, text: "열림 · 요구 충족" },
  violation: { color: C.red, alpha: 1.0, width: 0.36, speed: 1.7, reach: true, glow: 1.7, text: "뚫림 · 요구 위반" },
  blocked: { color: C.steel, alpha: 0.55, width: 0.15, speed: 0.6, reach: false, text: "막힘 · 요구 충족" },
  broken: { color: C.orange, alpha: 0.95, width: 0.24, speed: 1.2, reach: false, text: "끊김 · 필요한 접근이 막힘" },
  unknown: { color: C.amber, alpha: 0.6, width: 0.18, speed: 0.5, reach: false, text: "판단 불가" },
  hidden: { color: C.steel, alpha: 0, width: 0.12, speed: 0.5, reach: false, text: "" },
};

// 'a.b.c.d/n' 은 주소 순서로 (서버 목록은 글자 순서라 8.0.0.0/7 이 맨 뒤로 간다). CIDR 가 아닌 항목은 그대로 뒤에.
function sortCidrs(list) {
  const key = (s) => { const m = String(s).match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/); return m ? ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4] : Infinity; };
  return list.slice().sort((a, b) => key(a) - key(b));
}

function el(cls, html) {
  const d = document.createElement("div");
  d.className = cls; d.innerHTML = html;
  return d;
}

export class AwsScene {
  constructor(engine, arch) {
    this.E = engine;
    this.flows = {};
    this.parts = {};
    this.focusSet = "sg";
    this.highlightId = null;
    this.sparks = [];
    this.markers = {};
    this._build(arch || {});
    this.sparkSet = engine.addPoints(900);
    engine.onFrame.push((dt, t) => this._tick(dt, t));
    this.applyNeutral();
  }

  // ---------------------------------------------------------------- 만들기
  _build(arch) {
    const E = this.E;
    const sub = (arch.subnets || []);
    const pubC = (sub.find((s) => s.public) || {}).cidr, privC = (sub.find((s) => !s.public) || {}).cidr;
    const bucketName = ((arch.buckets || [])[0] || {}).name;

    // 바닥 구역: AWS 클라우드 · 리전 테두리
    E.addLines(Geo.rect(-12.5, -10, 16.5, 10, 0.03), { color: "#7d93b8", alpha: 0.5 });
    E.addLines(Geo.rect(-11.4, -8.9, 15.4, 8.9, 0.05), { color: C.priv, alpha: 0.55, dash: 1.6 });
    this._nodeLabel([-11.2, 0.2, -9.4], "AWS 클라우드 · 리전", "dim");

    // VPC · 서브넷 (유리 판)
    this.parts.vpc = E.addMesh(Geo.box(17.2, 0.3, 13.6), { color: C.vpc, alpha: 0.09, rim: 0.9, pos: [-0.6, 0.18, 0] });
    E.addLines(Geo.boxEdges(17.2, 0.3, 13.6), { color: C.vpc, alpha: 0.9, pos: [-0.6, 0.18, 0] });
    this._nodeLabel([-8.4, 0.5, 6.4], "VPC", "vpc");
    this.parts.pub = E.addMesh(Geo.box(7.6, 0.16, 11.6), { color: C.pub, alpha: 0.11, rim: 0.7, pos: [-4.4, 0.48, 0] });
    E.addLines(Geo.boxEdges(7.6, 0.16, 11.6), { color: C.pub, alpha: 0.75, pos: [-4.4, 0.48, 0] });
    this._nodeLabel([-4.4, 0.75, 5.3], `공개 서브넷${pubC ? " · " + pubC : ""}`, "pub");
    this.parts.priv = E.addMesh(Geo.box(7.0, 0.16, 11.6), { color: C.priv, alpha: 0.11, rim: 0.7, pos: [3.9, 0.48, 0] });
    E.addLines(Geo.boxEdges(7.0, 0.16, 11.6), { color: C.priv, alpha: 0.75, pos: [3.9, 0.48, 0] });
    this._nodeLabel([3.9, 0.75, 5.3], `비공개 서브넷${privC ? " · " + privC : ""}`, "priv");

    // 서버 (EC2) — 몸체 + 모서리 + 위에서 도는 고리
    const server = (key, p, name) => {
      const body = E.addMesh(Geo.box(1.9, 2.5, 1.9), { color: C.ec2, alpha: 0.5, rim: 1.8, pos: p });
      const core = E.addMesh(Geo.box(1.0, 1.7, 1.0), { color: "#ffd2a0", alpha: 0.35, rim: 2.2, pos: p });
      const edges = E.addLines(Geo.boxEdges(1.9, 2.5, 1.9), { color: C.ec2, alpha: 1, pos: p });
      const ring = E.addLines(Geo.circle(1.35, 64), { color: "#ffd2a0", alpha: 0.7, pos: [p[0], p[1] + 1.65, p[2]] });
      const ring2 = E.addLines(Geo.circle(1.05, 6), { color: C.ec2, alpha: 0.6, pos: [p[0], p[1] - 1.1, p[2]] });
      this.parts[key] = { body, core, edges, ring, ring2, pos: p, flash: 0 };
      this._nodeLabel([p[0], 0.9, p[2] + 2.75], name, "ec2");
    };
    server("web", POS.web, "웹 서버 · EC2");
    server("app", POS.app, "앱 서버 · EC2");

    // 보안 그룹 방패 (육각 기둥, 판정에 따라 색이 바뀐다)
    const shield = (key, p) => {
      const m = E.addMesh(Geo.prism(SHIELD_R, 3.7, 6), { color: C.cyan, alpha: 0.07, rim: 1.4, pos: [p[0], p[1] + 0.1, p[2]] });
      const e = E.addLines(Geo.prismEdges(SHIELD_R, 3.7, 6), { color: C.cyan, alpha: 0.75, pos: [p[0], p[1] + 0.1, p[2]] });
      this.parts[key] = { mesh: m, edges: e, pos: p, color: hex(C.cyan), goal: hex(C.cyan), alphaGoal: 0.07, flash: 0, state: "neutral" };
    };
    shield("webSG", POS.web);
    shield("appSG", POS.app);
    this._nodeLabel([POS.web[0] - 2.2, 4.25, POS.web[2] + 1.6], "web 보안 그룹", "sg");
    this._nodeLabel([POS.app[0] + 1.9, 4.25, POS.app[2] + 1.6], "app 보안 그룹", "sg");

    // 인터넷 게이트웨이 (세운 고리)
    this.parts.igw = E.addMesh(Geo.torus(1.55, 0.13, 64, 10), { color: C.vpc, alpha: 0.85, rim: 1.5, pos: POS.igw, rot: [0, 0, Math.PI / 2] });
    E.addLines(Geo.circle(1.15, 6), { color: "#c9b8ff", alpha: 0.7, pos: POS.igw, rot: [0, 0, Math.PI / 2] });
    this._nodeLabel([POS.igw[0], POS.igw[1] + 2.25, POS.igw[2]], "인터넷 게이트웨이", "igw");

    // 인터넷 (철망 구) · 운영자
    this.parts.globe = E.addLines(Geo.sphereWire(2.5, 10, 16, 64), { color: "#5aa8ff", alpha: 0.55, pos: POS.globe });
    this.parts.globeCore = E.addMesh(Geo.sphere(2.3, 18, 28), { color: "#1d5fff", alpha: 0.12, rim: 2.4, pos: POS.globe });
    this._nodeLabel([POS.globe[0], POS.globe[1] + 3.3, POS.globe[2]], "인터넷 · 0.0.0.0/0", "net");
    E.addMesh(Geo.box(1.8, 1.1, 0.25), { color: "#7fb6ff", alpha: 0.35, rim: 1.6, pos: [POS.op[0], POS.op[1] + 0.6, POS.op[2]], rot: [0, -0.5, 0] });
    E.addLines(Geo.boxEdges(1.8, 1.1, 0.25), { color: "#a9ceff", alpha: 0.9, pos: [POS.op[0], POS.op[1] + 0.6, POS.op[2]], rot: [0, -0.5, 0] });
    E.addLines(Geo.boxEdges(1.4, 0.12, 0.8), { color: "#a9ceff", alpha: 0.7, pos: [POS.op[0], POS.op[1] - 0.05, POS.op[2] + 0.4], rot: [0, -0.5, 0] });
    this._nodeLabel([POS.op[0], POS.op[1] + 1.8, POS.op[2]], "운영자 · 10.0.0.0/8", "net");

    // 웹 서버 역할 (IAM) — 떠 있는 결정
    this.parts.role = E.addMesh(Geo.octa(0.55), { color: C.iam, alpha: 0.75, rim: 2, pos: POS.role });
    this.parts.roleEdges = E.addLines(Geo.octaEdges(0.55), { color: "#ffb3c8", alpha: 1, pos: POS.role });
    E.addLines({ pos: new Float32Array([POS.web[0], 3.25, POS.web[2], POS.role[0], POS.role[1] - 0.8, POS.role[2]]) }, { color: C.iam, alpha: 0.6, dash: 3.0 });
    this._nodeLabel([POS.role[0] + 0.2, POS.role[1] + 1.25, POS.role[2]], "웹 서버 역할 · IAM", "iam");

    // 자산 버킷 (S3) + 승인 밖 '다른 버킷' 유령
    this.parts.bucket = E.addMesh(Geo.prism(1.05, 2.1, 28, 1.22, true), { color: C.s3, alpha: 0.42, rim: 1.8, pos: POS.bucket });
    E.addLines(Geo.circle(1.28, 48, 1.05), { color: "#c8ffb8", alpha: 0.9, pos: POS.bucket });
    E.addLines(Geo.circle(1.05, 48, -1.05), { color: "#c8ffb8", alpha: 0.6, pos: POS.bucket });
    this._nodeLabel([POS.bucket[0], POS.bucket[1] + 1.9, POS.bucket[2]], `자산 버킷 · S3${bucketName ? "<small>" + bucketName + "</small>" : ""}`, "s3");
    this.parts.ghosts = POS.ghost.map((p) => ({
      mesh: E.addMesh(Geo.prism(0.75, 1.5, 20, 1.2, true), { color: "#9aa7c7", alpha: 0.0, rim: 1.4, pos: p }),
      edges: E.addLines(Geo.circle(0.9, 36, 0.75), { color: "#c9d3ea", alpha: 0.0, pos: p }),
    }));
    this.parts.ghostLabel = this._nodeLabel([POS.ghost[0][0], 2.7, POS.ghost[0][2] + 0.4], "다른 버킷 · 모든 동작 (*)", "ghost");
    this.parts.ghostLabel.el.style.opacity = "0";

    // 흐름
    FLOWS.forEach((f) => {
      const rb = E.addRibbon(f.pts, { color: C.cyan, alpha: 0, width: 0.2 });
      const target = f.target === "web" ? POS.web : f.target === "app" ? POS.app : f.target === "bucket" ? POS.bucket : null;
      // 방패에 닿는 위치(u): 목표 서버 중심에서 수평 거리가 방패 반지름보다 작아지는 첫 점
      let uShield = 0.96;
      if (target && (f.target === "web" || f.target === "app")) {
        const i = rb.curve.pts.findIndex((p) => Math.hypot(p[0] - target[0], p[2] - target[2]) < SHIELD_R * 0.98);
        if (i > 0) uShield = rb.curve.u[i];
      } else if (f.target === "bucket") {
        const i = rb.curve.pts.findIndex((p) => Math.hypot(p[0] - target[0], p[2] - target[2]) < 1.5);
        if (i > 0) uShield = rb.curve.u[i];
      }
      const st = { def: f, rb, uShield, state: "neutral", look: null, cur: { color: hex(C.cyan), alpha: 0, end: 1, width: 0.2, speed: 0.7 }, goal: null, info: "" };
      if (f.label) {
        const U = { http: 0.2, ssh_net: 0.3, rdp_net: 0.4, ssh_op: 0.36, app_int: 0.5, app_net: 0.62, iam_read: 0.45, iam_list: 0.62, iam_excess: 0.55 };
        const anchor = V3.add(pointAt(rb.curve, U[f.id] ?? 0.4), [0, 0.7, 0]);
        st.label = this.E.addLabel(el("lbl flow", `<b>${f.label}</b><i></i>`), anchor);
        st.label.el.dataset.flow = f.id;
      }
      this.flows[f.id] = st;
    });
  }

  _nodeLabel(p, text, tone) {
    return this.E.addLabel(el(`lbl node ${tone}`, text), p);
  }

  // ---------------------------------------------------------------- 상태
  _setFlow(id, state, info = "") {
    const f = this.flows[id];
    if (!f) return;
    const kind = f.def.kind;
    let key = state;
    if (state === "neutral") key = kind === "keep" ? "neutral_keep" : kind === "approved" ? "neutral_approved" : "neutral_limit";
    if (f.def.id.startsWith("iam_excess") && state === "neutral") key = "hidden";
    const L = STATE_LOOK[key];
    f.state = state; f.look = L; f.info = info;
    f.goal = { color: hex(L.color), alpha: L.alpha, end: L.reach ? 1 : (state === "unknown" ? f.uShield * 0.94 : f.uShield), width: L.width, speed: L.speed, glow: L.glow || 1 };
    if (f.label) {
      f.label.el.className = `lbl flow s-${state}${id === this.highlightId ? " hl" : ""}`;
      f.label.el.querySelector("i").innerHTML = (L.text || "") + (info ? `<em>${info}</em>` : "");
      f.hiddenLook = key === "hidden";
      this._labelVis(f);
    }
  }

  // 흐름 라벨은 '강조된 것'과 '문제가 있는 것'(위반·끊김·판단 불가)만 보인다. showAll 이면 전부.
  _labelVis(f) {
    if (!f.label) return;
    const important = ["violation", "broken", "unknown"].includes(f.state);
    const hl = this.highlightId && (f.def.id === this.highlightId);
    f.label.visible = !f.hiddenLook && (this.showAll || important || hl);
  }

  setShowAllLabels(on) {
    this.showAll = on;
    Object.values(this.flows).forEach((f) => this._labelVis(f));
  }

  applyNeutral() {
    Object.keys(this.flows).forEach((id) => this._setFlow(id, "neutral"));
    this._shields();
    this.setTrivy(null);
  }

  // rows: [{id, verdict:'PASS'|'FAIL'|'UNKNOWN', excess:[], effective:[], reasons:[]}] — 서버가 계산한 값만 받는다
  applyRows(rows, setKey) {
    (rows || []).forEach((r) => {
      const ids = REQ_FLOWS[r.id] || [];
      ids.forEach((fid) => {
        const f = this.flows[fid];
        if (!f) return;
        let st;
        if (fid === "app_int") st = r.verdict === "UNKNOWN" ? "unknown" : "ok";
        else if (fid === "iam_excess") st = r.verdict === "FAIL" ? "violation" : r.verdict === "UNKNOWN" ? "unknown" : "hidden";
        else if (f.def.kind === "keep") st = r.verdict === "PASS" ? "ok" : r.verdict === "FAIL" ? "broken" : "unknown";
        else st = r.verdict === "PASS" ? "blocked" : r.verdict === "FAIL" ? "violation" : "unknown";
        let info = "";
        const exc = sortCidrs((r.excess || []).filter((x) => x));
        if (st === "violation" && exc.length) info = "승인 밖 출처: " + exc.slice(0, 3).join(", ") + (exc.length > 3 ? ` 외 ${exc.length - 3}개` : "");
        if (fid === "iam_excess" && st === "violation") info = exc.length ? exc.slice(0, 2).join(" · ") + (exc.length > 2 ? ` 외 ${exc.length - 2}개` : "") : "";
        this._setFlow(fid, st, fid === "app_int" ? "" : info);
        if (fid === "iam_excess") ["iam_excess2", "iam_excess3"].forEach((k) => this._setFlow(k, st));
      });
    });
    this._shields();
  }

  _shields() {
    const judge = (target) => {
      const fs = Object.values(this.flows).filter((f) => f.def.target === target);
      if (fs.some((f) => f.state === "violation")) return "violation";
      if (fs.some((f) => f.state === "broken")) return "broken";
      if (fs.some((f) => f.state === "unknown")) return "unknown";
      if (fs.every((f) => f.state === "neutral")) return "neutral";
      return "ok";
    };
    const look = { violation: [C.red, 0.17], broken: [C.orange, 0.13], unknown: [C.amber, 0.1], neutral: [C.cyan, 0.07], ok: [C.green, 0.09] };
    [["webSG", "web"], ["appSG", "app"]].forEach(([k, t]) => {
      const s = judge(t), sh = this.parts[k];
      sh.state = s; sh.goal = hex(look[s][0]); sh.alphaGoal = look[s][1];
    });
    // 역할·버킷: IAM 흐름 기준
    const iam = Object.values(this.flows).filter((f) => f.def.set === "iam");
    const ex = iam.some((f) => f.def.id === "iam_excess" && f.state === "violation");
    const gAlpha = ex ? 0.28 : 0;
    this.parts.ghosts.forEach((g) => { g.goal = gAlpha; });
    this.parts.ghostLabel.el.style.opacity = ex ? "1" : "0";
    this.parts.roleViolation = ex || iam.some((f) => f.state === "broken");
  }

  // Trivy 가 찾은 지적 표식: [{rule_id, severity, resource, title}] / mode: 'show' | 'resolved'(후보 재점검에서 사라짐) | null
  setTrivy(findings, resolvedRule = null) {
    const where = { "aws_security_group.web": [POS.web[0] - 2.6, 4.9, POS.web[2] - 1.4], "aws_iam_policy.web_assets": [POS.role[0] + 2.1, POS.role[1] + 0.6, POS.role[2] + 0.9],
      "aws_s3_bucket_policy.assets_public_read": [POS.bucket[0] + 1.6, 3.6, POS.bucket[2] + 1.2] };
    Object.values(this.markers).forEach((m) => { m.label.visible = false; m.mesh.visible = false; });
    if (!findings) return;
    findings.forEach((f) => {
      const p = where[f.resource];
      if (!p) return;
      let m = this.markers[f.resource];
      if (!m) {
        const mesh = this.E.addMesh(Geo.octa(0.3), { color: C.amber, alpha: 0.85, rim: 2, pos: p });
        const label = this.E.addLabel(el("lbl trivy", ""), [p[0], p[1] + 0.75, p[2]]);
        m = this.markers[f.resource] = { mesh, label, p };
      }
      const resolved = resolvedRule && resolvedRule === f.rule_id;
      m.resolved = resolved;
      m.mesh.visible = !resolved; m.label.visible = true;
      m.label.el.className = `lbl trivy${resolved ? " gone" : ""}`;
      m.label.el.innerHTML = resolved
        ? `<b>Trivy 재점검</b><i>${f.rule_id} 지적 사라짐 ✓</i>`
        : `<b>Trivy ${f.severity || ""}</b><i>${f.rule_id}</i>`;
    });
  }

  // ---------------------------------------------------------------- 보기
  setFocusSet(set) {
    this.focusSet = set;
    this.focus(set === "iam" ? "iam" : "sg");
  }

  // 보는 영역마다 꼭 들어와야 할 점들 (노드와 그 라벨 높이). 카메라는 이 점들이 패널 사이 빈 곳에 꼭 맞게 잡힌다.
  _keyPoints(name) {
    const g = POS.globe, o = POS.op, w = POS.web, a = POS.app, r = POS.role, b = POS.bucket;
    const net = [[g[0] - 2.6, g[1], g[2]], [g[0] + 2.6, g[1], g[2]], [g[0], g[1] + 3.7, g[2]], [g[0], g[1] - 2.6, g[2]], [o[0], o[1] + 2.1, o[2]], [o[0], 0, o[2] + 0.8]];
    const vpc = [[-9.2, 0, -6.8], [8.0, 0, -6.8], [-9.2, 0, 6.8], [8.0, 0, 6.8]];
    const sg = [[w[0] - 2.4, 4.9, w[2]], [w[0] + 2.4, 0, w[2]], [a[0] + 2.4, 4.6, a[2]], [w[0] - 2.6, 5.9, w[2] - 1.4], [POS.igw[0], POS.igw[1] + 2.6, 0]];
    const iam = [[r[0], r[1] + 1.9, r[2]], [r[0] + 2.1, r[1] + 1.6, r[2] + 0.9], [b[0] + 1.4, b[1] + 2.5, b[2]], [b[0], 0, b[2] - 1.4], ...POS.ghost.map((p) => [p[0], p[1] + 1.9, p[2]]), [w[0], 0, w[2]]];
    if (name === "sg") return [...net, ...sg, [-9.2, 0, 6.8], [-9.2, 0, -6.8]];
    if (name === "iam") return [...iam, [a[0], 0, a[2] + 5.8], [r[0] - 1.5, r[1], r[2]], [w[0] - 2.4, 0, w[2]], [w[0] - 2.4, 4.2, w[2]], [w[0], 0.9, w[2] + 2.9]];
    return [...net, ...vpc, ...sg, ...iam];
  }

  focus(name) {
    const pose = { overview: [-0.62, 0.6], sg: [-0.95, 0.5], iam: [-0.32, 0.56] }[name] || [-0.62, 0.6];
    this.E.flyTo(this.E.frame(this._keyPoints(name), pose[0], pose[1]), 1600);
  }

  highlight(reqId) {
    const ids = reqId ? (REQ_FLOWS[reqId] || []) : [];
    this.highlightId = ids[0] || null;
    Object.values(this.flows).forEach((f) => {
      f.dim = ids.length > 0 && !ids.includes(f.def.id) && !(ids.includes("iam_excess") && f.def.parent === "iam_excess");
      if (f.label) f.label.el.classList.toggle("hl", ids.includes(f.def.id));
      if (f.label) f.label.el.classList.toggle("dim", !!f.dim);
      this._labelVis(f);
    });
    clearTimeout(this._hlT);
    if (ids.length) {   // 마우스가 잠깐 머물면 그 흐름이 화면에 꼭 맞게 날아간다 (스쳐 지나가면 그대로)
      this._hlT = setTimeout(() => {
        const pts = [];
        ids.forEach((id) => { const f = this.flows[id]; if (f) for (let u = 0; u <= 1.0001; u += 0.125) pts.push(V3.add(pointAt(f.rb.curve, u), [0, 0.9, 0])); });
        if (!pts.length) return;
        const g = this.E.frame(pts, this.E.cam.yaw, 0.52, 60);
        g.radius = Math.max(g.radius, 30);      // 너무 가까이 붙지 않게 (주변 노드가 같이 보이도록)
        this.E.flyTo(g, 1100);
      }, 280);
    }
  }

  setScanning(on) {
    this.scanning = on; this.scanAcc = 0;
    [this.parts.vpc, this.parts.pub, this.parts.priv, this.parts.webSG.mesh, this.parts.appSG.mesh].forEach((m) => { m.scan = on ? 1 : 0; });
  }

  verdictFx(kind, target = "web") {
    const p = target === "iam" ? POS.role : target === "app" ? POS.app : POS.web;
    const color = kind === "pass" ? C.green : kind === "block" ? C.red : C.amber;
    this.E.waveAt([p[0], 0, p[2]], color);
    const sh = target === "app" ? this.parts.appSG : this.parts.webSG;
    sh.flash = 1;
    if (target === "iam") this.roleFlash = 1;
    this._burst(target === "iam" ? POS.role : [p[0], p[1] + 0.4, p[2]], hex(color), 140, 7);
  }

  // ---------------------------------------------------------------- 매 프레임
  _tick(dt, t) {
    const k = Math.min(1, dt * 3.2);
    // 흐름 전환 + 강조/흐림
    Object.values(this.flows).forEach((f) => {
      const g = f.goal; if (!g) return;
      const c = f.cur;
      for (let i = 0; i < 3; i++) c.color[i] += (g.color[i] - c.color[i]) * k;
      const setDim = this.focusSet && f.def.set !== this.focusSet ? 0.35 : 1;
      const hlDim = f.dim ? 0.2 : 1;
      const hlBoost = this.highlightId && (f.def.id === this.highlightId || (this.highlightId === "iam_excess" && f.def.parent === "iam_excess")) ? 1.35 : 1;
      c.alpha += (g.alpha * setDim * hlDim * hlBoost - c.alpha) * k;
      c.end += (g.end - c.end) * k;
      c.width += (g.width * (hlBoost > 1 ? 1.35 : 1) - c.width) * k;
      c.speed += (g.speed - c.speed) * k;
      c.glow = (c.glow ?? 1) + ((g.glow || 1) - (c.glow ?? 1)) * k;
      const rb = f.rb;
      rb.color = c.color; rb.alpha = c.alpha; rb.end = c.end; rb.width = c.width; rb.speed = c.speed; rb.glow = c.glow;
      if (f.label) f.label.el.style.opacity = String(Math.min(1, (g.alpha > 0 ? 1 : 0) * setDim * (f.dim ? 0.35 : 1)));
      // 막힘/끊김: 방패에서 불꽃 · 위반: 서버 안쪽에 붉은 입자
      if (c.alpha > 0.2 && (f.state === "blocked" || f.state === "broken" || f.state === "violation")) {
        f.acc = (f.acc || 0) + dt * (f.state === "violation" ? 26 : 14) * (setDim > 0.5 ? 1 : 0.3);
        while (f.acc > 1) {
          f.acc -= 1;
          const p = pointAt(rb.curve, Math.max(0, c.end - 0.004));
          const col = f.state === "violation" ? hex(C.red) : f.state === "broken" ? hex(C.orange) : hex("#bcd4ff");
          this._spark(p, col, f.state === "violation" ? 0.9 : 0.6);
        }
      }
    });
    // 방패 색·깜빡임
    ["webSG", "appSG"].forEach((key) => {
      const s = this.parts[key];
      for (let i = 0; i < 3; i++) s.color[i] += (s.goal[i] - s.color[i]) * k;
      const pulse = s.state === "violation" ? 0.06 * (0.5 + 0.5 * Math.sin(t * 6)) : 0;
      s.mesh.color = s.color; s.edges.color = s.color;
      s.mesh.alpha += (s.alphaGoal + pulse - s.mesh.alpha) * k;
      s.edges.alpha = 0.55 + (s.state === "violation" ? 0.45 * (0.5 + 0.5 * Math.sin(t * 6)) : 0.25);
      s.flash = Math.max(0, s.flash - dt * 1.6); s.mesh.flash = s.flash;
    });
    // 서버: 위반이면 붉게 깜빡임
    [["web", "webSG"], ["app", "appSG"]].forEach(([k2, sk]) => {
      const sv = this.parts[k2], sh = this.parts[sk];
      const bad = sh.state === "violation";
      sv.body.flash = bad ? 0.25 + 0.25 * Math.sin(t * 7) : 0;
      sv.ring.rot = [0, t * 0.8, 0];
      sv.ring2.rot = [0, -t * 0.5, 0];
      sv.edges.color = bad ? hex(C.red) : hex(C.ec2);
    });
    // 역할 결정 회전, 위반이면 붉게
    const r = this.parts.role;
    r.rot = [0, t * 0.9, 0]; this.parts.roleEdges.rot = r.rot;
    r.pos = [POS.role[0], POS.role[1] + Math.sin(t * 1.6) * 0.12, POS.role[2]]; this.parts.roleEdges.pos = r.pos;
    this.roleFlash = Math.max(0, (this.roleFlash || 0) - dt * 1.4);
    r.flash = this.roleFlash + (this.parts.roleViolation ? 0.2 + 0.2 * Math.sin(t * 6) : 0);
    this.parts.globe.rot = [0, t * 0.12, 0];
    this.parts.igw.rot = [t * 0.6, 0, Math.PI / 2];
    this.parts.ghosts.forEach((g) => {
      g.mesh.alpha += ((g.goal || 0) - g.mesh.alpha) * k;
      g.edges.alpha = g.mesh.alpha * 2.2;
      g.mesh.flash = g.mesh.alpha > 0.05 ? 0.15 + 0.15 * Math.sin(t * 5) : 0;
    });
    Object.values(this.markers).forEach((m) => { m.mesh.rot = [0, t * 1.5, 0]; m.mesh.pos = [m.p[0], m.p[1] + Math.sin(t * 2.2) * 0.12, m.p[2]]; });
    // 검증이 도는 동안: 대상 서버(또는 역할)에서 바닥으로 퍼지는 고리를 일정 간격으로
    if (this.scanning) {
      this.scanAcc = (this.scanAcc || 0) + dt;
      if (this.scanAcc > 1.7) { this.scanAcc = 0; const p = this.focusSet === "iam" ? POS.role : POS.web; this.E.waveAt([p[0], 0, p[2]], C.cyan); }
    }
    this._updateSparks(dt);
  }

  _spark(p, col, size = 0.7) {
    if (this.sparks.length > 850) return;
    const v = [(Math.random() - 0.5) * 2.6, Math.random() * 2.0 + 0.3, (Math.random() - 0.5) * 2.6];
    this.sparks.push({ p: p.slice(), v, life: 0, max: 0.45 + Math.random() * 0.5, col, size: size * (0.6 + Math.random() * 0.8) });
  }

  _burst(p, col, n, speed) {
    for (let i = 0; i < n; i++) {
      const th = Math.random() * Math.PI * 2, ph = Math.random() * Math.PI;
      const s = speed * (0.4 + Math.random() * 0.6);
      if (this.sparks.length > 880) break;
      this.sparks.push({ p: p.slice(), v: [Math.sin(ph) * Math.cos(th) * s, Math.cos(ph) * s * 0.7 + 1, Math.sin(ph) * Math.sin(th) * s],
        life: 0, max: 0.8 + Math.random() * 0.7, col, size: 0.7 + Math.random() * 0.9 });
    }
  }

  _updateSparks(dt) {
    const ps = this.sparkSet; let n = 0;
    this.sparks = this.sparks.filter((s) => (s.life += dt) < s.max);
    for (const s of this.sparks) {
      s.v[1] -= dt * 2.8;
      s.p[0] += s.v[0] * dt; s.p[1] += s.v[1] * dt; s.p[2] += s.v[2] * dt;
      const a = 1 - s.life / s.max;
      ps.pos.set(s.p, n * 3); ps.col.set([s.col[0], s.col[1], s.col[2], a], n * 4); ps.size[n] = s.size * (0.4 + a * 0.6);
      n++;
    }
    ps.count = n; ps.dirty = true;
  }
}
