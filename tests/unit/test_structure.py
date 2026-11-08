"""원하는 구조 = 자동 기준 + 그림에서 바꾼 것 (web/structure.py, 2026-11-01 갈아엎기 5차 · D-33).

지금 코드 = test_product 의 손으로 만든 2계층 plan (인터넷 → web 22 · 80, web → app 8080) — tofu 없이.
설계도 저장은 IACPATCH_DESIGNS_DIR 임시 폴더 (저장소 data/ 를 건드리지 않음). 비교 판정은 V6 오라클 그대로.
"""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from helpers import ROOT  # noqa: F401  (sys.path 설정)

from test_product import two_tier_plan

from iacpatch.verify.plan_model import build_world
from iacpatch.verify.sg_scan import scan
from iacpatch.web import archmap, cases, codetopo, designs, structure

PID = "webapp-2tier"


def cur_of(plan):
    sc = scan(build_world(plan, {}), codetopo.vpc_cidr(plan))
    return {"ok": True, "case": cases.get_case(PID), "plan": plan, "sources": {}, "plan_source": "시험", "sg_scan": sc,
            "arch": archmap.build(plan, {}, sc["findings"])}


class StructureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iacpatch-structure-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ["IACPATCH_DESIGNS_DIR"] = self.tmp
        self.addCleanup(os.environ.pop, "IACPATCH_DESIGNS_DIR", None)
        self.cur = cur_of(two_tier_plan())
        p = mock.patch.object(structure, "code", side_effect=lambda pid, *a, **k: self.cur)
        p.start()
        self.addCleanup(p.stop)
        e = {(x["src"], x["dst"]): x["id"] for x in self.cur["arch"]["edges"] if x["kind"] == "sg"}
        self.e_web = e[("x:internet", "n:aws_instance.web")]
        self.e_app = e[("n:aws_instance.web", "n:aws_instance.app")]

    def flows(self, d):
        names = {x["id"]: x["label"] for x in d["tiers"] + d["external"]}
        return sorted(f"{names[f['from']]}>{names[f['to']]}:{structure._port_txt(f)}" for f in d["flows"])

    def test_auto_design_is_code_minus_risky(self):
        a = structure.auto_design(PID)
        self.assertTrue(a["ok"])
        self.assertEqual(self.flows(a["design"]), ["web>app:8080", "사용자(인터넷)>web:80"])
        self.assertEqual(a["excluded"], [{"flow": "사용자(인터넷) → web 22", "why": "인터넷 전체 → 관리 포트 SSH(22)"}])

    def test_ensure_auto_saves_v1_once_and_marks_it_auto(self):
        r = structure.ensure_auto(PID)
        self.assertEqual((r["ok"], r["created"], r["version"]), (True, True, 1))
        again = structure.ensure_auto(PID)
        self.assertEqual((again["ok"], again["created"]), (True, False))
        key, _c = structure.design_key(PID)
        vs = designs.versions(key)
        self.assertEqual([(v["version"], v["auto"], v["by"]) for v in vs], [(1, True, "자동 (프로그램)")])
        d = designs.load(key, 1)
        self.assertEqual(d["auto"]["excluded"][0]["flow"], "사용자(인터넷) → web 22")
        self.assertIn("사람이 확인한 고객 설계 아님", d["description"])

    def test_preview_counts_follow_v6(self):
        p = structure.preview(PID, [])
        self.assertTrue(p["ok"], p)
        self.assertEqual((p["counts"]["excess"], p["counts"]["missing"], p["counts"]["ok"]), (1, 0, 2))
        self.assertEqual(p["overlay"]["edges"][self.e_web]["state"], "excess")          # 22 때문에 (80 은 원하는 구조)
        self.assertEqual(p["overlay"]["edges"][self.e_web]["ranges"], [["tcp", 22, 22]])

    def test_picture_edits(self):
        cases_ = [
            ([{"op": "keep", "edges": [self.e_web], "only": ["22"]}], ["web>app:8080", "사용자(인터넷)>web:22", "사용자(인터넷)>web:80"], 0, 0),
            ([{"op": "narrow", "edges": [self.e_web], "only": ["22"], "cidr": "203.0.113.0/24", "label": "운영팀"}],
             ["web>app:8080", "사용자(인터넷)>web:80", "운영팀>web:22"], 1, 0),
            ([{"op": "block", "edges": [self.e_web], "only": ["80"]}], ["web>app:8080"], 2, 0),            # 22 · 80 둘 다 원하는 구조 밖
            ([{"op": "port", "edges": [self.e_app], "port": "8443"}], ["web>app:8443", "사용자(인터넷)>web:80"], 2, 1),
            ([{"op": "gone", "node": "n:aws_instance.app"}], ["사용자(인터넷)>web:80"], 2, 0),
            ([{"op": "add", "from": "n:aws_instance.app", "to": "n:aws_instance.web", "port": "9000"}], ["app>web:9000", "web>app:8080", "사용자(인터넷)>web:80"], 1, 1),
        ]
        for edits, want, excess, missing in cases_:
            with self.subTest(op=edits[0]["op"]):
                p = structure.preview(PID, edits)
                self.assertTrue(p["ok"], p)
                self.assertEqual(self.flows(p["design"]), want)
                self.assertEqual((p["counts"]["excess"], p["counts"]["missing"]), (excess, missing))

    def test_drop_removes_a_design_only_flow(self):
        p = structure.preview(PID, [{"op": "add", "cidr": "198.51.100.0/24", "label": "협력사", "to": "n:aws_instance.app", "port": "8080"}])
        fid = next(f["id"] for f in p["design"]["flows"] if f["from"] != "web" and f["to"] == "app")
        p2 = structure.preview(PID, [{"op": "add", "cidr": "198.51.100.0/24", "label": "협력사", "to": "n:aws_instance.app", "port": "8080"},
                                     {"op": "drop", "flow": fid}])
        self.assertEqual(self.flows(p2["design"]), ["web>app:8080", "사용자(인터넷)>web:80"])

    def test_bad_edits_are_refused_with_reason(self):
        bad = [
            ([{"op": "narrow", "edges": [self.e_web], "cidr": "0.0.0.0/0"}], "좁히기"),
            ([{"op": "narrow", "edges": [self.e_web], "cidr": "2001:db8::/32"}], "IPv4"),
            ([{"op": "port", "edges": [self.e_app], "port": "abc"}], "포트가 숫자가 아님"),
            ([{"op": "keep", "edges": ["e99"]}], "그림에 없는 선"),
            ([{"op": "gone", "node": "n:aws_s3_bucket.assets"}], "보안 그룹이 없음"),
            ([{"op": "explode"}], "모르는 바꾸기"),
        ]
        for edits, why in bad:
            with self.subTest(why=why):
                p = structure.preview(PID, edits)
                self.assertFalse(p["ok"])
                self.assertIn(why, " ".join(p["errors"]))

    def test_save_keeps_auto_v1_and_adds_human_v2(self):
        r = structure.save(PID, [{"op": "narrow", "edges": [self.e_web], "only": ["22"], "cidr": "203.0.113.0/24", "label": "운영팀"}], "회의 11/1")
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["version"], r["auto_created"]), (2, True))
        key, _c = structure.design_key(PID)
        vs = designs.versions(key)
        self.assertEqual([(v["version"], v["auto"], v["active"]) for v in vs], [(1, True, False), (2, False, True)])
        v2 = designs.load(key, 2)
        self.assertNotIn("auto", v2, "사람이 바꾼 버전은 자동 기준 표시를 이어받지 않음")
        self.assertEqual(v2["edits"]["done"], ["출발지 좁히기: 인터넷 전체 → web :22 → 출발지 운영팀"])
        self.assertEqual(self.flows(v2), ["web>app:8080", "사용자(인터넷)>web:80", "운영팀>web:22"])
        # 바꾼 것이 없으면 저장 안 함
        self.assertFalse(structure.save(PID, [{"op": "keep", "edges": [self.e_app]}], "", 2)["ok"])
        self.assertFalse(structure.save(PID, [], "")["ok"])

    def test_result_says_auto_baseline_is_not_customer_confirmed(self):
        from iacpatch.web.problems import unchecked
        self.assertIn("자동 기준", unchecked("topology", None, False, True)[0])
        self.assertFalse(any("자동 기준" in x for x in unchecked("topology", None, False, False)))

    # ---------------------------------------------------------------- 6차 (D-34): ③ 통신 목록 · 설계도 그림
    def rowmap(self, p):
        return {(r["src"], r["dst"], r["port"]): r for r in p["rows"]}

    def test_rows_and_design_view(self):
        p = structure.preview(PID, [])
        self.assertTrue(p["ok"], p)
        rows = self.rowmap(p)
        self.assertEqual(set(rows), {("사용자(인터넷)", "web", "22"), ("사용자(인터넷)", "web", "80"), ("web", "app", "8080")})
        r22 = rows[("사용자(인터넷)", "web", "22")]
        self.assertEqual((r22["allow"], r22["fix"], r22["kind"], r22["edges"], r22["only"]), (False, True, "ip", [self.e_web], ["22"]))
        self.assertEqual(r22["note"], "위험해서 자동으로 막음 — 인터넷 전체 → 관리 포트 SSH(22)")
        self.assertEqual((rows[("사용자(인터넷)", "web", "80")]["allow"], rows[("web", "app", "8080")]["allow"]), (True, True))
        self.assertEqual(p["diff"], 1)
        # 설계도 그림 = 설계도의 통신만 (인터넷 → web 22 없음)
        v = p["view"]
        self.assertEqual(sorted((e["src"], e["dst"], e["ports"]) for e in v["edges"] if e["kind"] == "sg"),
                         [("n:aws_instance.web", "n:aws_instance.app", "8080"), ("x:internet", "n:aws_instance.web", "80")])

    def test_rows_after_edits(self):
        # 이 IP만 허용 → 인터넷 줄은 막힘 그대로 + 설계도에만 있는 줄(운영팀 → web 22) 이 생김. 사람이 바꾼 뒤엔 '자동으로' 라고 하지 않음
        p = structure.preview(PID, [{"op": "narrow", "edges": [self.e_web], "only": ["22"], "cidr": "203.0.113.0/24", "label": "운영팀"}])
        rows = self.rowmap(p)
        self.assertEqual(rows[("사용자(인터넷)", "web", "22")]["note"], "설계도에 없음 — 위험한 허용 (인터넷 전체 → 관리 포트 SSH(22))")
        office = rows[("운영팀", "web", "22")]
        self.assertEqual((office["allow"], office["kind"], office["fix"]), (True, "design", False))
        self.assertTrue(office["key"].startswith("flow|"))
        self.assertIn(("g:ext:ext", "n:aws_instance.web", "22"), [(e["src"], e["dst"], e["ports"]) for e in p["view"]["edges"]])
        # 막기 → 그 줄은 막힘 · 코드와 다름. 설계도에만 있는 줄을 막으면(drop) 목록에서 빠짐
        p2 = structure.preview(PID, [{"op": "block", "edges": [self.e_app], "only": ["8080"]}])
        r = self.rowmap(p2)[("web", "app", "8080")]
        self.assertEqual((r["allow"], r["fix"], r["note"]), (False, True, "설계도에 없음 → 코드에서 막을 대상"))
        p3 = structure.preview(PID, [{"op": "narrow", "edges": [self.e_web], "only": ["22"], "cidr": "203.0.113.0/24", "label": "운영팀"},
                                     {"op": "drop", "flow": office["key"].split("|", 1)[1]}])
        self.assertNotIn(("운영팀", "web", "22"), self.rowmap(p3))
        # 코드에 없는 통신 추가 → 설계도에만 있는 줄, 코드가 막고 있으니 '코드에서 열 대상'
        p4 = structure.preview(PID, [{"op": "add", "from": "n:aws_instance.app", "to": "n:aws_instance.web", "port": "9000"}])
        r4 = self.rowmap(p4)[("app", "web", "9000")]
        self.assertEqual((r4["allow"], r4["fix"], r4["note"]), (True, True, "코드에 허용 규칙이 없음 (지금은 막힘) → 코드에서 열 대상"))

    def test_rows_group_one_security_group(self):
        # 같은 보안 그룹이 붙은 상자 둘(app · app2) → 목록은 한 줄 (규칙 하나), 바꾸기는 두 선 모두
        plan = two_tier_plan()
        plan["planned_values"]["root_module"]["resources"].append({"address": "aws_instance.app2", "type": "aws_instance", "name": "app2", "mode": "managed", "values": {"ami": "ami-1"}})
        plan["resource_changes"].append({"address": "aws_instance.app2", "type": "aws_instance", "name": "app2", "mode": "managed", "change": {"actions": ["create"], "after_unknown": {}}})
        plan["configuration"]["root_module"]["resources"].append({"address": "aws_instance.app2", "type": "aws_instance", "name": "app2",
                                                                    "expressions": {"vpc_security_group_ids": {"references": ["aws_security_group.app.id", "aws_security_group.app"]}}})
        self.cur = cur_of(plan)
        p = structure.preview(PID, [])
        r = self.rowmap(p)[("web", "app · app2", "8080")]
        self.assertEqual(len(r["edges"]), 2)
        p2 = structure.preview(PID, [{"op": "block", "edges": r["edges"], "only": ["8080"]}])
        self.assertEqual(self.rowmap(p2)[("web", "app · app2", "8080")]["allow"], False)


if __name__ == "__main__":
    unittest.main()
