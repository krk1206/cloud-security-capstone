"""고객 설계도 버전 (D-30) — 화면에서 고친 설계도가 새 버전으로 저장되고 '지금 기준' 이 되는지, v1(평가 기준 파일)은 그대로인지.

저장 위치는 IACPATCH_DESIGNS_DIR 로 임시 폴더를 쓴다 (저장소 data/ 를 건드리지 않음).
"""
import copy
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import ROOT

from iacpatch.web import cases, designs

SET = "arch-3tier-sg"
BASE = ROOT / "experiments" / "candidate-sets" / SET / "intents" / "arch-3tier-flows.json"


def without_redis(d):
    d = copy.deepcopy(d)
    d["tiers"] = [t for t in d["tiers"] if t["id"] != "redis"]
    d["flows"] = [f for f in d["flows"] if "redis" not in (f["from"], f["to"])]
    return d


class DesignStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iacpatch-designs-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ["IACPATCH_DESIGNS_DIR"] = self.tmp
        self.addCleanup(os.environ.pop, "IACPATCH_DESIGNS_DIR", None)
        self.base_sha = hashlib.sha256(BASE.read_bytes()).hexdigest()

    def tearDown(self):
        self.assertEqual(hashlib.sha256(BASE.read_bytes()).hexdigest(), self.base_sha, "v1(평가 기준 파일)이 바뀌면 안 됨")

    def test_v1_is_manifest_file(self):
        vs = designs.versions(SET)
        self.assertEqual([(v["version"], v["source"], v["active"]) for v in vs], [(1, "manifest", True)])
        self.assertEqual(designs.active_path(SET).resolve(), BASE.resolve())

    def test_save_makes_v2_active_and_cases_follow(self):
        res = designs.save(SET, without_redis(designs.load(SET)), "Redis 안 씀")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["version"], 2)
        self.assertIn("Redis", res["changes"]["text"])
        self.assertEqual(designs.active_version(SET), 2)
        d2 = json.loads((Path(self.tmp) / SET / "v2.json").read_text(encoding="utf-8"))
        self.assertEqual((d2["intent_version"], d2["intent_id"], d2["status"], d2["kind"]), ("2", "arch-3tier-flows", "active", "topology"))
        self.assertEqual(d2["edited"]["from_version"], 1)
        case = cases.get_case("webapp-3tier")
        s = cases.load_set(case, case["sets"][0])
        self.assertTrue(s["intent_path"].endswith("v2.json"), s["intent_path"])
        self.assertEqual(s["design_version"], 2)
        self.assertNotIn("redis", [t["id"] for t in s["design"]["tiers"]])
        # 예전 버전으로 되돌리기
        self.assertTrue(designs.activate(SET, 1)["ok"])
        s = cases.load_set(case, case["sets"][0])
        self.assertEqual(s["design_version"], 1)
        self.assertIn("redis", [t["id"] for t in s["design"]["tiers"]])
        self.assertEqual([v["version"] for v in designs.versions(SET)], [1, 2])

    def test_unchanged_design_is_not_saved(self):
        res = designs.save(SET, designs.load(SET))
        self.assertFalse(res["ok"])
        self.assertEqual(designs.versions(SET)[-1]["version"], 1)

    def test_validation(self):
        d = designs.load(SET)
        cases_ = []
        bad = copy.deepcopy(d); bad["tiers"][0]["security_group"] = "web"; cases_.append(("보안 그룹", bad))
        bad = copy.deepcopy(d); bad["tiers"][1]["security_group"] = bad["tiers"][0]["security_group"]; cases_.append(("여러 개", bad))
        bad = copy.deepcopy(d); bad["flows"] = []; cases_.append(("통신이 하나 이상", bad))
        bad = copy.deepcopy(d); bad["flows"][0]["to"] = "internet"; cases_.append(("구성요소여야", bad))
        bad = copy.deepcopy(d); bad["flows"][0]["from"] = "ghost"; cases_.append(("없음", bad))
        bad = copy.deepcopy(d); bad["external"][1]["cidrs_v4"] = ["999.0.0.0/8"]; cases_.append(("", bad))
        bad = copy.deepcopy(d); bad["tiers"][0]["id"] = "Web Server"; cases_.append(("영문 소문자", bad))
        bad = copy.deepcopy(d); bad["flows"].append(dict(bad["flows"][0], id="dup")); cases_.append(("두 번", bad))
        for word, x in cases_:
            res = designs.save(SET, x)
            self.assertFalse(res["ok"], word)
            self.assertTrue(any(word in e for e in res["errors"]), (word, res["errors"]))
        self.assertEqual(len(designs.versions(SET)), 1)

    def test_new_component_and_flow(self):
        d = designs.load(SET)
        d["tiers"].append({"id": "pg", "label": "PostgreSQL", "security_group": "aws_security_group.pg", "type": "rds"})
        d["flows"].append({"from": "api", "to": "pg", "protocol": "tcp", "port": 5432})
        res = designs.save(SET, d, "PostgreSQL 추가")
        self.assertTrue(res["ok"], res)
        d2 = designs.load(SET)
        f = next(x for x in d2["flows"] if x["to"] == "pg")
        self.assertEqual((f["id"], f["port"]), ("api-pg-5432", 5432))
        self.assertIn("PostgreSQL", res["changes"]["text"])

    def test_preview_shows_removed_component_still_in_code(self):
        pv = designs.preview(SET, without_redis(designs.load(SET)))
        self.assertTrue(pv["ok"], pv)
        if not pv.get("computed"):
            self.skipTest("원본 plan 없음 — 그림만")
        und = [e for e in pv["topology"]["excess"] if e["kind"] == "undesigned_target"]
        self.assertEqual([(e["src"], e["ports"]) for e in und], [("api", "6379")])
        node = next(n for n in pv["model"]["nodes"] if n["id"] == und[0]["dst"])
        self.assertEqual((node["kind"], node["code"]), ("unmapped", "extra"))
        self.assertEqual(len(designs.versions(SET)), 1)        # 미리보기는 저장하지 않는다

    def test_review_uses_active_design(self):
        from iacpatch.web import server
        self.assertTrue(designs.save(SET, without_redis(designs.load(SET)), "Redis 안 씀")["ok"])
        seen = {}

        class Stop(Exception):
            pass

        def fake_run(settings, opt):
            seen["intent"] = str(opt.intent)
            raise Stop()
        with mock.patch("iacpatch.review.flow.run_review", fake_run), mock.patch("iacpatch.web.proof_api.ensure_calibration", lambda *a, **k: None):
            fn = server.job_candidate({"set_id": SET, "candidate_id": "correct-design"})
            with self.assertRaises(Stop):
                fn(lambda s: None, lambda i, n: None)
            self.assertTrue(seen["intent"].endswith("v2.json"), seen)
            fn = server.job_candidate({"set_id": SET, "candidate_id": "correct-design", "design_version": 1})
            with self.assertRaises(Stop):
                fn(lambda s: None, lambda i, n: None)
            self.assertEqual(Path(seen["intent"]).resolve(), BASE.resolve())
            with self.assertRaises(ValueError):
                server.job_candidate({"set_id": SET, "candidate_id": "correct-design", "design_version": 9})

    def test_bad_set_id_rejected(self):
        with self.assertRaises(ValueError):
            designs.store_dir("../../etc")


TWO_TIER = {"vpc_cidr": "10.0.0.0/16",
            "tiers": [{"id": "web", "label": "웹 서버", "security_group": "aws_security_group.web", "type": "ec2"},
                      {"id": "app", "label": "앱 서버", "security_group": "aws_security_group.app", "type": "ec2"}],
            "external": [{"id": "internet", "label": "사용자(인터넷)", "cidrs_v4": ["0.0.0.0/0"]},
                         {"id": "admin", "label": "관리자 대역", "cidrs_v4": ["10.0.0.0/8"]}],
            "flows": [{"from": "internet", "to": "web", "protocol": "tcp", "port": 80}, {"from": "admin", "to": "web", "protocol": "tcp", "port": 22},
                      {"from": "web", "to": "app", "protocol": "tcp", "port": 8080}],
            "draft_notes": ["화면용 — 저장하지 않음"], "draft_risky": {"x": "y"}}


class ProjectDesignTests(unittest.TestCase):
    """설계도가 없는 프로젝트(2계층)에서 지금 코드로 만든 초안을 사람이 고쳐 처음 확정(v1) — D-31."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iacpatch-designs-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ["IACPATCH_DESIGNS_DIR"] = self.tmp
        self.addCleanup(os.environ.pop, "IACPATCH_DESIGNS_DIR", None)

    def test_create_first_then_requirement_set_follows_project_design(self):
        self.assertEqual(designs._ref("arch-webapp-sg")[2], "requirement")
        r = designs.create_first("webapp-2tier", copy.deepcopy(TWO_TIER), "회의 11/1", "scenarios/arch/webapp-2tier")
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["version"], 1)
        saved = json.loads((Path(self.tmp) / "webapp-2tier" / "v1.json").read_text(encoding="utf-8"))
        self.assertNotIn("draft_notes", saved)                 # 화면용 칸은 저장하지 않는다
        self.assertNotIn("draft_risky", saved)
        self.assertEqual(saved["intent_version"], "1")
        key, base, kind = designs._ref("arch-webapp-sg")       # 보안 그룹 요구사항 묶음이 이제 프로젝트 설계도를 기준으로
        self.assertEqual((key, kind), ("webapp-2tier", "project"))
        case = cases.get_case("webapp-2tier")
        st = next(s for s in cases._sets(case) if s["set_id"] == "arch-webapp-sg")
        self.assertEqual(st["intent_kind"], "topology")
        self.assertEqual(len(st["design"]["flows"]), 3)

    def test_create_first_refuses_second_time_and_bad_input(self):
        self.assertTrue(designs.create_first("webapp-2tier", copy.deepcopy(TWO_TIER), "", "scenarios/arch/webapp-2tier")["ok"])
        again = designs.create_first("webapp-2tier", copy.deepcopy(TWO_TIER), "", "scenarios/arch/webapp-2tier")
        self.assertFalse(again["ok"])
        self.assertIn("이미 설계도가 있음", again["errors"][0])
        bad = copy.deepcopy(TWO_TIER)
        bad["tiers"][0]["security_group"] = "web"
        self.assertFalse(designs.create_first("other-project", bad, "", "x")["ok"])

    def test_manifest_topology_set_cannot_be_created_again(self):
        r = designs.create_first(SET, copy.deepcopy(TWO_TIER), "", "x")
        self.assertFalse(r["ok"])

    def test_confirmation_draft_then_human_then_draft_again(self):
        """D-38: 자동 v1 = 초안 → 이름 적고 확정 → 고쳐 저장한 v2 는 다시 초안 → 확정한 파일이 바뀌면 확정이 풀린다. 실험 세트는 '팀 작성 평가 기준'."""
        self.assertTrue(designs.create_first("webapp-2tier", copy.deepcopy(TWO_TIER), "", "scenarios/arch/webapp-2tier", {"auto": {"excluded": []}})["ok"])
        c = designs.confirmation("webapp-2tier")
        self.assertEqual((c["confirmed"], c["basis"], c["version"]), (False, "draft", 1))
        self.assertFalse(designs.confirm("webapp-2tier", 1, "", "")["ok"])                     # 이름 없이 확정 못 함
        r = designs.confirm("webapp-2tier", 1, "김보성", "고객 회의 11/2")
        self.assertTrue(r["ok"], r)
        c = designs.confirmation("webapp-2tier")
        self.assertEqual((c["confirmed"], c["basis"], c["by"], c["note"]), (True, "human", "김보성", "고객 회의 11/2"))
        self.assertTrue(designs.payload("arch-webapp-sg")["confirmation"]["confirmed"])        # 같은 프로젝트의 세트도 같은 확정 상태
        self.assertEqual(designs.versions("webapp-2tier")[0]["confirmation"]["basis"], "human")
        # 고쳐 저장 → v2 활성 · 초안
        d2 = designs.load("webapp-2tier"); d2["flows"] = d2["flows"][:-1]
        self.assertTrue(designs.save("webapp-2tier", d2, "한 줄 뺌")["ok"])
        c2 = designs.confirmation("webapp-2tier")
        self.assertEqual((c2["confirmed"], c2["version"]), (False, 2))
        self.assertTrue(designs.confirmation("webapp-2tier", 1)["confirmed"])                 # v1 확정 기록은 남아 있다
        # 확정한 v1 파일을 손으로 바꾸면 확정이 풀린다 (지문 불일치)
        p = Path(self.tmp) / "webapp-2tier" / "v1.json"
        p.write_text(p.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        c3 = designs.confirmation("webapp-2tier", 1)
        self.assertFalse(c3["confirmed"]); self.assertIn("풀림", c3["note"])
        # 실험 세트 설계도: 팀 작성 평가 기준 — 확정 대상 아님
        cm = designs.confirmation(SET)
        self.assertEqual((cm["confirmed"], cm["basis"]), (True, "manifest"))
        self.assertIn("고객이 확정한 설계도 아님", cm["by"])
        self.assertFalse(designs.confirm(SET, 1, "누구", "")["ok"])

    def test_can_approve_blocks_draft_design_records(self):
        from iacpatch.web.decision import can_approve
        base = {"state": "REVIEW_REQUIRED", "review_level": "FULL_REVIEW", "verification_status": "COMPLETE", "post_deploy": {"status": "VERIFIED"}}
        ok, _ = can_approve(dict(base, design={"intent_version": "1", "confirmation": {"confirmed": True, "basis": "human", "by": "x"}}))
        self.assertTrue(ok)
        ok, why = can_approve(dict(base, design={"intent_version": "1", "confirmation": {"confirmed": False, "basis": "draft"}}))
        self.assertFalse(ok); self.assertIn("초안", why)
        ok, _ = can_approve(dict(base, design={"intent_version": "1", "sha256": "x"}))      # 확정 정보 없는 예전 기록은 막지 않는다
        self.assertTrue(ok)


class RequirementVersionTests(unittest.TestCase):
    """요구사항 파일(IAM) 버전 (D-40): v1 = manifest 파일(팀 작성 평가 기준), 고친 JSON 올리기 → v2 초안 · 지금 기준, 확정 → 승인 기준.
    manifest 파일은 바뀌지 않는다. 검사 입력(active_path) · 사례(cases.load_set) 가 올린 판을 따라간다."""
    IAM = "arch-webapp-iam"
    IAM_BASE = ROOT / "experiments" / "candidate-sets" / "arch-webapp-iam" / "intents" / "arch-webapp-web-role.json"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iacpatch-designs-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ["IACPATCH_DESIGNS_DIR"] = self.tmp
        self.addCleanup(os.environ.pop, "IACPATCH_DESIGNS_DIR", None)
        self.base_sha = hashlib.sha256(self.IAM_BASE.read_bytes()).hexdigest()

    def tearDown(self):
        self.assertEqual(hashlib.sha256(self.IAM_BASE.read_bytes()).hexdigest(), self.base_sha, "manifest 요구사항 파일이 바뀌면 안 됨")

    def test_v1_is_manifest_and_team_basis(self):
        self.assertEqual(designs._ref(self.IAM)[2], "requirement")
        self.assertEqual(designs.active_path(self.IAM), self.IAM_BASE)
        vs = designs.versions(self.IAM)
        self.assertEqual([v["version"] for v in vs], [1])
        self.assertEqual((vs[0]["kind"], vs[0]["source"], vs[0]["n_rules"] > 0), ("iam", "manifest", True))
        c = designs.confirmation(self.IAM)
        self.assertEqual((c["confirmed"], c["basis"], c["kind"]), (True, "manifest", "iam"))
        self.assertFalse(designs.confirm(self.IAM, 1, "누구", "")["ok"])                     # 팀 작성 파일은 확정 대상 아님
        self.assertFalse(designs.save(self.IAM, json.loads(self.IAM_BASE.read_text(encoding="utf-8")), "x")["ok"])   # 편집기 없음

    def test_import_v2_draft_then_confirm_and_activate_back(self):
        raw = json.loads(self.IAM_BASE.read_text(encoding="utf-8"))
        # 거절: JSON 아님 · 다른 종류 · 다른 intent_id · 형식 오류 · 바뀐 것 없음
        self.assertIn("JSON", designs.import_version(self.IAM, "{not json", "")["errors"][0])
        self.assertIn("종류", designs.import_version(self.IAM, dict(raw, kind="topology"), "")["errors"][0])
        self.assertIn("intent_id", designs.import_version(self.IAM, dict(raw, intent_id="other"), "")["errors"][0])
        bad = copy.deepcopy(raw); bad["approved_permissions"] = "oops"
        self.assertIn("형식", designs.import_version(self.IAM, bad, "")["errors"][0])
        self.assertIn("바뀐 것이 없음", designs.import_version(self.IAM, copy.deepcopy(raw), "")["errors"][0])
        # v2: ListBucket 을 뺀 판
        new = copy.deepcopy(raw)
        new["approved_permissions"][0]["actions"] = ["s3:GetObject"]
        new["required_permissions"] = [p for p in new["required_permissions"] if p["action"] == "s3:GetObject"]
        r = designs.import_version(self.IAM, new, "고객이 ListBucket 을 뺌", "박지민")
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["version"], 2)
        self.assertIn("approved_permissions", r["changes"]["keys"])
        self.assertEqual(designs.active_version(self.IAM), 2)
        p2 = Path(self.tmp) / self.IAM / "v2.json"
        self.assertEqual(designs.active_path(self.IAM), p2)
        d2 = json.loads(p2.read_text(encoding="utf-8"))
        self.assertEqual((d2["intent_version"], d2["edited"]["from_version"], d2["edited"]["by"]), ("2", 1, "박지민"))
        c = designs.confirmation(self.IAM)
        self.assertEqual((c["confirmed"], c["basis"], c["version"], c["kind"]), (False, "draft", 2, "iam"))   # 올린 판 = 초안
        vs = designs.versions(self.IAM)
        self.assertEqual([(v["version"], v["active"], v["source"]) for v in vs], [(1, False, "manifest"), (2, True, "imported")])
        # 사례(화면)도 v2 를 따라간다 — 검사 입력 · 요구사항 표 · 버전
        case = cases.get_case("webapp-2tier")
        st = next(x for x in cases._sets(case) if x["set_id"] == self.IAM)
        self.assertEqual(st["design_version"], 2)
        self.assertTrue(str(st["intent_path"]).endswith("v2.json"))
        self.assertFalse(any("ListBucket" in r.get("text", "") for r in st["requirements"]))
        # 확정 → 승인 기준
        self.assertFalse(designs.confirm(self.IAM, 2, "", "")["ok"])
        self.assertTrue(designs.confirm(self.IAM, 2, "박지민", "고객 메일 11/2")["ok"])
        c = designs.confirmation(self.IAM)
        self.assertEqual((c["confirmed"], c["basis"], c["by"]), (True, "human", "박지민"))
        # 지금 기준을 v1 로 되돌리면 v1 = 팀 작성 평가 기준, v2 확정 기록은 그대로
        self.assertTrue(designs.activate(self.IAM, 1)["ok"])
        self.assertEqual(designs.active_path(self.IAM), self.IAM_BASE)
        self.assertEqual(designs.confirmation(self.IAM)["basis"], "manifest")
        self.assertTrue(designs.confirmation(self.IAM, 2)["confirmed"])
        self.assertEqual(designs.payload(self.IAM)["importable"], True)
        self.assertEqual(designs.payload(self.IAM, 2)["confirmable"], True)
        self.assertEqual(designs.payload(self.IAM, 1)["confirmable"], False)


if __name__ == "__main__":
    unittest.main()
