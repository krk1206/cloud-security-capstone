"""구성도 배치 (web/static/app/archlayout.js) 단위 테스트 — node 로 순수 함수 layout 을 직접 부른다 (2026-11-01 갈아엎기 5차, D-33).

지켜야 하는 것 (B: "사용하기 어렵게 해 놨네" — 선이 상자 · 글자를 가로지르거나 글자끼리 겹치면 못 읽는다)
  - 상자끼리 겹치지 않는다
  - 선은 출발 · 도착 상자 말고 다른 상자의 아이콘을 지나가지 않는다
  - 선 글자(포트 등)끼리 겹치지 않는다
  - 보이는 범위(viewBox)가 상자 · 선 · 글자를 모두 담는다
  - 같은 상자로 들어오는 선이라도 상태가 다르면(원하는 구조대로 · 없음) 따로 내려온다 (빨강 · 파랑이 한 선으로 합쳐지지 않게)
  - (6차 · D-34) 설계도만 그린 그림 · '통신 관련만' 보기도 같은 규칙. 설계도 그림은 출발 상자마다 따로 내려오고,
    두 묶음이면 왼쪽 묶음의 포트 글자는 화살표 왼쪽 · 오른쪽 묶음은 오른쪽 (어느 출발지의 포트인지 보이게)
node 가 없으면 건너뛴다.
"""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from test_archmap import AUTO, arch_of, orders_plan
from test_product import two_tier_plan

from iacpatch.topology_intent import parse_topology_intent
from iacpatch.verify.v6 import v6_intent_oracle
from iacpatch.web import archmap

JS = ROOT / "src" / "iacpatch" / "web" / "static" / "app" / "archlayout.js"
NODE = shutil.which("node") or (shutil.which("/opt/node22/bin/node") if Path("/opt/node22/bin/node").exists() else None)
HARNESS = r"""
const A = await import(process.argv[2]);
const cases = JSON.parse(await new Promise((ok) => { let s = ""; process.stdin.on("data", (d) => { s += d; }); process.stdin.on("end", () => ok(s)); }));
const out = cases.map(({ model, overlay }) => {
  const L = A.layout(model, overlay);
  const H = A.HALF;
  const nodes = Object.values(L.nodes);
  const rect = (n) => (n.gw ? [n.x - 20, n.y - 20, n.x + 20, n.y + 20] : [n.x - H, n.y - H, n.x + H, n.y + H]);
  const overlap = (a, b) => a[0] < b[2] && b[0] < a[2] && a[1] < b[3] && b[1] < a[3];
  const nodeOverlaps = [];
  nodes.forEach((a, i) => nodes.slice(i + 1).forEach((b) => { if (overlap(rect(a), rect(b))) nodeOverlaps.push([a.id, b.id]); }));
  const segHits = (p, q, r) => {           // 직각 선분과 사각형 (경계에서 2px 안쪽)
    const [x0, y0, x1, y1] = [r[0] + 2, r[1] + 2, r[2] - 2, r[3] - 2];
    if (p[0] === q[0]) return p[0] > x0 && p[0] < x1 && Math.max(p[1], q[1]) > y0 && Math.min(p[1], q[1]) < y1;
    if (p[1] === q[1]) return p[1] > y0 && p[1] < y1 && Math.max(p[0], q[0]) > x0 && Math.min(p[0], q[0]) < x1;
    return false;
  };
  const crossings = [];
  for (const l of L.links) {
    const pth = L.paths[l.id];
    if (!pth) { crossings.push([l.id, "no path"]); continue; }
    for (const n of nodes) {
      if (n.id === l.src || n.id === l.dst) continue;
      for (let i = 1; i < pth.pts.length; i++) if (segHits(pth.pts[i - 1], pth.pts[i], rect(n))) { crossings.push([l.id, n.id]); break; }
    }
  }
  const box = (b) => { const x1 = b.anchor === "start" ? b.x : b.anchor === "end" ? b.x - b.w : b.x - b.w / 2; return [x1, b.y - 11, x1 + b.w, b.y + 2]; };
  const labOverlaps = [];
  L.labels.forEach((a, i) => L.labels.slice(i + 1).forEach((b) => { if (overlap(box(a), box(b))) labOverlaps.push([a.text, b.text]); }));
  const vb = L.viewBox;
  const inside = (x, y) => x >= vb[0] - 0.5 && y >= vb[1] - 0.5 && x <= vb[0] + vb[2] + 0.5 && y <= vb[1] + vb[3] + 0.5;
  const outside = [];
  nodes.forEach((n) => { const r = rect(n); if (!inside(r[0], r[1]) || !inside(r[2], r[3])) outside.push(n.id); });
  L.labels.forEach((b) => { const r = box(b); if (!inside(r[0], r[1]) || !inside(r[2], r[3])) outside.push(b.text); });
  const arrivals = {};
  for (const l of L.links) { const p = L.paths[l.id]; if (p) arrivals[l.id] = p.pts[p.pts.length - 1]; }
  const labels = L.labels.map((b) => ({ text: b.text, anchor: b.anchor, x: b.x, link: b.link }));
  return { nodeOverlaps, crossings, labOverlaps, outside, arrivals, labels, n: nodes.length, links: L.links.length };
});
process.stdout.write(JSON.stringify(out));
"""


def run(cases):
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "h.mjs"
        h.write_text(HARNESS, encoding="utf-8")
        r = subprocess.run([NODE, str(h), JS.as_uri()], input=json.dumps(cases), capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        return json.loads(r.stdout)


@unittest.skipUnless(NODE, "node 없음")
class ArchLayoutTests(unittest.TestCase):
    def setUp(self):
        self.orders, _ = arch_of(orders_plan())
        self.two, _ = arch_of(two_tier_plan())

    def test_readable_layout(self):
        lr = v6_intent_oracle(orders_plan(), {}, parse_topology_intent(AUTO))
        ov = archmap.overlay(self.orders, lr.details, AUTO)
        res = run([{"model": self.orders, "overlay": None}, {"model": self.two, "overlay": None},
                   {"model": self.orders, "overlay": {"edges": ov["edges"], "ghost_nodes": ov["ghost_nodes"], "ghost_edges": ov["ghost_edges"]}}])
        for name, r in zip(("주문 API", "2계층", "주문 API + 원하는 구조"), res, strict=True):
            with self.subTest(name):
                self.assertGreaterEqual(r["n"], 5)
                self.assertEqual(r["nodeOverlaps"], [], "상자끼리 겹침")
                self.assertEqual(r["crossings"], [], "선이 다른 상자를 지나감")
                self.assertEqual(r["labOverlaps"], [], "선 글자끼리 겹침")
                self.assertEqual(r["outside"], [], "보이는 범위 밖")

    def test_states_arrive_separately(self):
        lr = v6_intent_oracle(orders_plan(), {}, parse_topology_intent(AUTO))
        ov = archmap.overlay(self.orders, lr.details, AUTO)
        r = run([{"model": self.orders, "overlay": {"edges": ov["edges"], "ghost_nodes": [], "ghost_edges": []}}])[0]
        ok = r["arrivals"]["l:n:aws_ecs_service.api>n:aws_db_instance.orders>main"]
        bad = r["arrivals"]["l:x:vpc:10.20.0.0/16>n:aws_db_instance.orders>main"]
        self.assertEqual(ok[1], bad[1])
        self.assertGreaterEqual(abs(ok[0] - bad[0]), 10, "원하는 구조대로(파랑) · 없음(빨강) 선이 같은 자리로 들어옴")

    def test_design_view_simple_and_full(self):
        d = copy.deepcopy(AUTO)
        d["external"].append({"id": "office", "label": "운영팀 사무실", "cidrs_v4": ["203.0.113.0/24"]})
        d["flows"] += [{"id": "d", "from": "office", "to": "ops", "protocol": "tcp", "port": 22},
                       {"id": "e", "from": "internet", "to": "ops", "protocol": "tcp", "port": 80}]
        full = archmap.design_view(self.orders, d)
        keep = {n["id"] for n in full["nodes"] if n["core"]}            # 화면 m_map.simple 과 같은 규칙 ('통신 관련만')
        simple = {**full, "nodes": [n for n in full["nodes"] if n["core"]],
                  "edges": [e for e in full["edges"] if e["kind"] == "sg" and e["src"] in keep and e["dst"] in keep]}
        res = run([{"model": simple, "overlay": None}, {"model": full, "overlay": None}])
        for name, r in zip(("설계도 · 통신 관련만", "설계도 · 전체 보기"), res, strict=True):
            with self.subTest(name):
                self.assertEqual(r["nodeOverlaps"], [], "상자끼리 겹침")
                self.assertEqual(r["crossings"], [], "선이 다른 상자를 지나감")
                self.assertEqual(r["labOverlaps"], [], "선 글자끼리 겹침")
                self.assertEqual(r["outside"], [], "보이는 범위 밖")
        r = res[0]
        self.assertEqual(r["n"], 6)
        a_off = r["arrivals"]["l:g:ext:office>n:aws_instance.ops>main"]
        a_net = r["arrivals"]["l:x:internet>n:aws_instance.ops>main"]
        self.assertGreaterEqual(abs(a_off[0] - a_net[0]), 10, "설계도 그림: 출발지마다 따로 내려옴")
        lab = {b["link"]: b for b in r["labels"]}
        left, right = sorted([("l:g:ext:office>n:aws_instance.ops>main", a_off), ("l:x:internet>n:aws_instance.ops>main", a_net)], key=lambda t: t[1][0])
        self.assertEqual((lab[left[0]]["anchor"], lab[right[0]]["anchor"]), ("end", "start"))
        self.assertLess(lab[left[0]]["x"], left[1][0])
        self.assertGreater(lab[right[0]]["x"], right[1][0])


if __name__ == "__main__":
    unittest.main()
