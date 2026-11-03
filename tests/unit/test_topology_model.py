"""토폴로지 자동 그리기 (2026-10-31 — 고정 그림 제거): 그림 모델(web/topomodel.py) + 자동 배치(static/app/topolayout.js).

지켜야 하는 것
  - 노드 · 연결은 설계도에서 나온다. 설계도에 계층 · 통신을 더하면 그림에도 생긴다 (고정 좌표 없음)
  - 아이콘은 그 계층에 실제로 붙은 리소스 종류(후보 검사 결과)가 먼저다
  - 배치: 노드끼리 겹치지 않고, 설계 통신은 왼쪽(외부)에서 오른쪽으로 흐르고, 선이 다른 노드를 지나가지 않는다
  - 설계도에 없는 출처(VPC 내 모든 서버 등)는 맨 위 출처 칸으로 그린다
배치 시험은 node 가 없으면 건너뛴다.
"""
from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch.web.topomodel import model

INTENT = ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "intents" / "arch-3tier-flows.json"
DESIGN = json.loads(INTENT.read_text(encoding="utf-8"))
JS = ROOT / "src" / "iacpatch" / "web" / "static" / "app" / "topolayout.js"
NODE = shutil.which("node") or ("/opt/node22/bin/node" if Path("/opt/node22/bin/node").exists() else None)
HARNESS = """
import fs from 'node:fs';
const L = await import(process.argv[2]);
const cases = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(cases.map((c) => L.layout(c.model, c.extras || []))));
"""
TIERS = [{"id": "alb", "attached": ["aws_lb.alb"]}, {"id": "web", "attached": ["aws_launch_template.web"]}, {"id": "nlb", "attached": ["aws_lb.nlb"]},
         {"id": "api", "attached": ["aws_launch_template.api"]}, {"id": "bastion", "attached": ["aws_instance.bastion[0]"]},
         {"id": "redis", "attached": ["aws_elasticache_replication_group.redis"]}, {"id": "db", "attached": ["aws_db_instance.primary"], "extra_security_groups": ["aws_security_group.x"]}]


def with_cache_tier():
    d = copy.deepcopy(DESIGN)
    d["tiers"].append({"id": "queue", "label": "작업 큐 서버", "security_group": "aws_security_group.queue"})
    d["flows"].append({"id": "api-queue", "from": "api", "to": "queue", "protocol": "tcp", "port": 5672, "label": "작업 넣기"})
    d["flows"] = [f for f in d["flows"] if f["id"] != "bastion-api"]
    return d


class ModelTest(unittest.TestCase):
    def test_nodes_and_flows_come_from_the_design(self):
        m = model(DESIGN)
        self.assertTrue(m["ok"])
        self.assertEqual([n["id"] for n in m["nodes"]], ["internet", "admin", "alb", "web", "nlb", "api", "bastion", "redis", "db"])
        self.assertEqual(len(m["flows"]), 9)
        z = {n["id"]: n["zone"] for n in m["nodes"]}
        self.assertEqual({k for k, v in z.items() if v == "public"}, {"alb", "bastion"})      # 외부 출처가 바로 들어오는 계층
        icons = {n["id"]: (n["icon"], n.get("icon_source")) for n in m["nodes"]}
        self.assertEqual(icons["internet"][0], "users")
        self.assertEqual(icons["admin"][0], "client")
        self.assertEqual(icons["alb"], ("elb", "name"))
        self.assertEqual(icons["redis"], ("elasticache", "name"))
        self.assertEqual(icons["db"], ("rds", "name"))
        self.assertEqual(icons["web"], ("ec2", "default"))
        self.assertEqual(next(f for f in m["flows"] if f["id"] == "api-db")["ports"], "3306")

    def test_icons_follow_attached_resources_of_the_candidate(self):
        m = model(DESIGN, TIERS, "record")
        icons = {n["id"]: (n["icon"], n.get("icon_source")) for n in m["nodes"] if n["kind"] == "tier"}
        self.assertEqual(set(v[1] for v in icons.values()), {"attached"})
        self.assertEqual(icons["nlb"][0], "elb")
        self.assertEqual(icons["db"][0], "rds")
        db = next(n for n in m["nodes"] if n["id"] == "db")
        self.assertEqual(db["extra_security_groups"], ["aws_security_group.x"])      # 설계 밖 보안 그룹도 그림 자료로
        self.assertEqual(m["source"], "record")

    def test_design_change_changes_the_picture(self):
        m = model(with_cache_tier())
        self.assertIn("queue", [n["id"] for n in m["nodes"]])
        self.assertIn("api-queue", [f["id"] for f in m["flows"]])
        self.assertNotIn("bastion-api", [f["id"] for f in m["flows"]])

    def test_candidate_only_resources_become_nodes(self):
        m = model(DESIGN, TIERS, "record", [{"address": "aws_instance.debug", "type": "aws_instance", "security_groups": ["aws_security_group.debug"]}])
        n = next(x for x in m["nodes"] if x["kind"] == "unmapped")
        self.assertEqual((n["id"], n["icon"], n["sub"]), ("res:aws_instance.debug", "ec2", "설계도에 없는 리소스"))

    def test_unmapped_resources_skips_design_tiers(self):
        from iacpatch.web.topomodel import unmapped_resources
        self.assertEqual(unmapped_resources(None, TIERS), [])
        self.assertEqual(unmapped_resources({"planned_values": {}}, None), [])

    def test_non_topology_design_has_no_picture(self):
        self.assertFalse(model({"kind": "sg", "rules": []})["ok"])
        self.assertFalse(model(None)["ok"])


def _boxes(L):
    return {k: (n["x"] - 40, n["y"] - 40, n["x"] + 40, n["y"] + 78) for k, n in L["nodes"].items()}


def _sample_path(d, step=6.0):
    """SVG 경로(M · L · C)를 점들로."""
    toks = re.findall(r"[MLC]|-?\d+(?:\.\d+)?", d)
    pts, cur, i, cmd = [], None, 0, None
    while i < len(toks):
        t = toks[i]
        if t in "MLC":
            cmd = t
            i += 1
            continue
        if cmd == "M":
            cur = (float(toks[i]), float(toks[i + 1])); i += 2; pts.append(cur)
        elif cmd == "L":
            nxt = (float(toks[i]), float(toks[i + 1])); i += 2
            n = max(1, int(((nxt[0] - cur[0]) ** 2 + (nxt[1] - cur[1]) ** 2) ** 0.5 / step))
            pts += [(cur[0] + (nxt[0] - cur[0]) * k / n, cur[1] + (nxt[1] - cur[1]) * k / n) for k in range(1, n + 1)]
            cur = nxt
        elif cmd == "C":
            c1 = (float(toks[i]), float(toks[i + 1])); c2 = (float(toks[i + 2]), float(toks[i + 3])); p1 = (float(toks[i + 4]), float(toks[i + 5])); i += 6
            for k in range(1, 41):
                tt = k / 40; u = 1 - tt
                pts.append((u ** 3 * cur[0] + 3 * u * u * tt * c1[0] + 3 * u * tt * tt * c2[0] + tt ** 3 * p1[0],
                            u ** 3 * cur[1] + 3 * u * u * tt * c1[1] + 3 * u * tt * tt * c2[1] + tt ** 3 * p1[1]))
            cur = p1
        else:
            i += 1
    return pts


@unittest.skipUnless(NODE, "node 없음")
class LayoutTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        extras = [{"src": "web", "dst": "db", "ports": "3306"}, {"src": "bastion", "dst": "db", "ports": "3306"},
                  {"src": "vpc", "dst": "db", "ports": "3306", "src_label": "VPC 내 모든 서버"},
                  {"src": "unknown", "dst": "redis", "ports": "6379", "src_label": "설계 외 서버 (aws_instance.x)"},
                  {"src": "internet", "dst": "bastion", "ports": "22", "src_label": "인터넷 (IPv6)"}]
        unm = [{"address": "aws_instance.debug", "type": "aws_instance", "security_groups": ["aws_security_group.debug"]}]
        no_redis = copy.deepcopy(DESIGN)
        no_redis["tiers"] = [t for t in no_redis["tiers"] if t["id"] != "redis"]
        no_redis["flows"] = [f for f in no_redis["flows"] if "redis" not in (f["from"], f["to"])]
        und = [{"id": "res:aws_elasticache_replication_group.redis", "resources": ["aws_elasticache_replication_group.redis"],
                "security_group": "aws_security_group.redis", "inbound": 1}]
        cls.cases = [{"model": model(DESIGN)}, {"model": model(DESIGN, TIERS), "extras": extras}, {"model": model(with_cache_tier())},
                     {"model": model(DESIGN, TIERS, "record", unm),
                      "extras": [{"src": "unknown", "dst": "db", "ports": "3306", "src_label": "설계 외 서버 (aws_instance.debug)"}]},
                     {"model": model(no_redis, [t for t in TIERS if t["id"] != "redis"], "draft", undesigned=und),     # D-30: 설계에서 뺀 Redis 가 코드에 남음
                      "extras": [{"src": "api", "dst": "res:aws_elasticache_replication_group.redis", "ports": "6379", "kind": "undesigned_target"}]}]
        with tempfile.TemporaryDirectory() as td:
            h = Path(td) / "h.mjs"
            h.write_text(HARNESS, encoding="utf-8")
            r = subprocess.run([NODE, str(h), JS.as_uri()], input=json.dumps(cls.cases), capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        cls.out = json.loads(r.stdout)

    def test_nodes_do_not_overlap(self):
        for L in self.out:
            bx = list(_boxes(L).values())
            for i in range(len(bx)):
                for j in range(i + 1, len(bx)):
                    a, b = bx[i], bx[j]
                    self.assertFalse(a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3], (a, b))

    def test_flows_go_left_to_right_and_every_flow_has_a_path(self):
        for c, L in zip(self.cases, self.out):
            for f in c["model"]["flows"]:
                self.assertIn(f["id"], L["flows"])
                self.assertLess(L["rank"][f["src"]], L["rank"][f["dst"]], f)
        L = self.out[0]
        self.assertEqual([L["rank"][k] for k in ("internet", "alb", "web", "nlb", "api", "redis", "db", "admin", "bastion")], [0, 1, 2, 3, 4, 5, 5, 0, 1])

    def test_lines_do_not_cross_other_nodes(self):
        for c, L in zip(self.cases, self.out):
            boxes = _boxes(L)
            routes = [(f["src"], f["dst"], L["flows"][f["id"]]["d"]) for f in c["model"]["flows"]]
            def src_node(e):     # '설계 외 서버 (주소)' 출처는 그 주소의 '설계도에 없는 리소스' 노드에서 출발
                if e["src"] in L["nodes"]:
                    return e["src"]
                return next((k for k, n in L["nodes"].items() if n["kind"] == "unmapped" and any(a in e.get("src_label", "") for a in n["resources"])), e["src"])
            routes += [(src_node(e), e["dst"], r["d"]) for e, r in zip(c.get("extras") or [], L["extras"]) if r]
            for src, dst, d in routes:
                for p in _sample_path(d):
                    for k, b in boxes.items():
                        if k in (src, dst):
                            continue
                        self.assertFalse(b[0] < p[0] < b[2] and b[1] < p[1] < b[3], (src, dst, k, p))

    def test_outside_sources_and_new_tiers_appear(self):
        L = self.out[1]
        self.assertEqual(set(L["pseudo"]), {"vpc", "unknown"})               # 설계도에 없는 출처만 위 칸으로 (인터넷 IPv6 은 '사용자' 노드에서)
        self.assertEqual(L["pseudo"]["vpc"]["label"], "VPC 내 모든 서버")
        self.assertTrue(all(L["extras"]))
        vpc = L["zones"]["vpc"]
        for n in L["nodes"].values():
            if n["kind"] != "external":
                self.assertTrue(vpc[0] < n["x"] < vpc[2] and vpc[1] < n["y"] < vpc[3], n["id"])
        L4 = self.out[3]
        dbg = L4["nodes"]["res:aws_instance.debug"]
        self.assertGreater(dbg["y"], max(n["y"] for k, n in L4["nodes"].items() if k != "res:aws_instance.debug"))   # 맨 아래 줄
        self.assertEqual(L4["pseudo"], {})                                    # 출처가 그림에 있는 리소스라 위 칸 없이 그 노드에서
        self.assertTrue(L4["extras"][0]["d"].startswith(f"M{int(dbg['x'] + 38)}"), L4["extras"][0]["d"][:40])
        L3 = self.out[2]
        self.assertIn("queue", L3["nodes"])
        self.assertEqual(L3["rank"]["queue"], L3["rank"]["api"] + 1)        # 새 계층은 연결된 계층 다음 열
        L5 = self.out[4]
        r = "res:aws_elasticache_replication_group.redis"
        self.assertEqual(L5["rank"][r], L5["rank"]["api"] + 1)              # 설계에서 뺐는데 코드에 남은 리소스: 연결된 계층 다음 열
        self.assertTrue(L5["extras"][0]["d"].startswith(f"M{int(L5['nodes']['api']['x'] + 38)}"), L5["extras"][0]["d"][:40])


if __name__ == "__main__":
    unittest.main()
