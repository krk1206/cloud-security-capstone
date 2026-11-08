"""고객 제안서 예제 (D-46, 2026-11-03) — '제안서가 들어왔다' 는 가정의 예제 board-saas.

지켜야 하는 것
  - 예제 case 가 있고 (scenarios/arch/board-saas · PROPOSAL.md · 세트 board-saas-sg), 설계도 v1 은 제안서 조건을 옮긴 토폴로지 형식
  - 설계도 종류 = 'proposal': v1 은 **초안**(확정 전) — '팀 작성 평가 기준' 으로 자동 확정하지 않는다. 담당자가 확정할 수 있다 (프로젝트처럼)
  - 설계도 v1 로 원본을 보면 제안서에 없는 통신 = 인터넷 → bastion :22 하나뿐
  - 규칙 기반 생성기가 설계도대로 bastion SSH 를 본사 사무실 대역으로 바꾼다 (D-45 와 이어짐)
  - 화면 자료: ③ payload 에 제안서 원문, ① 목록에 proposal 표시. 제안서 파일 · 설계도 파일은 시험이 바꾸지 않는다
저장 위치는 IACPATCH_DESIGNS_DIR 로 임시 폴더를 쓴다 (저장소 data/ 를 건드리지 않음).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch.web import cases, designs

SET = "board-saas-sg"
CASE = "board-saas"
TF_DIR = ROOT / "scenarios" / "arch" / "board-saas"
DESIGN = ROOT / "experiments" / "candidate-sets" / SET / "intents" / "board-flows.json"
PROPOSAL = TF_DIR / "PROPOSAL.md"


class ProposalExampleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iacpatch-proposal-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ["IACPATCH_DESIGNS_DIR"] = self.tmp
        self.addCleanup(os.environ.pop, "IACPATCH_DESIGNS_DIR", None)
        self.sha = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (DESIGN, PROPOSAL)}

    def tearDown(self):
        for p, h in self.sha.items():
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), h, f"{p.name} 이 바뀌면 안 됨")

    def test_case_and_files_exist(self):
        c = cases.get_case(CASE)
        self.assertIsNotNone(c)
        self.assertEqual(c["kind"], "example")
        self.assertEqual(c["proposal"], "scenarios/arch/board-saas/PROPOSAL.md")
        self.assertTrue(PROPOSAL.is_file() and DESIGN.is_file())
        self.assertTrue((ROOT / c["trivy_json"]).is_file())
        names = sorted(p.name for p in TF_DIR.glob("*.tf"))
        self.assertEqual(names, ["compute.tf", "db.tf", "network.tf", "outputs.tf", "provider.tf", "security_groups.tf", "versions.tf"])
        self.assertIn("203.0.113.0/24", PROPOSAL.read_text(encoding="utf-8"))
        man = json.loads((ROOT / "experiments" / "candidate-sets" / SET / "manifest.json").read_text(encoding="utf-8"))
        # 화면에 보이는 수정안 4개 (D-47): 각각 원본과 다르고 서로 다르다. 정답이 1번이 아니다
        self.assertEqual([c["id"] for c in man["candidates"]], ["fix-office", "fix-and-db-open", "split-cidr", "remove-rule"])
        self.assertEqual(man["featured"], ["split-cidr", "fix-and-db-open", "fix-office", "remove-rule"])
        orig = (TF_DIR / "security_groups.tf").read_text(encoding="utf-8")
        texts = {c["id"]: (ROOT / "experiments" / "candidate-sets" / SET / c["candidate"][7:]).read_text(encoding="utf-8") for c in man["candidates"]}
        self.assertEqual(len(set(texts.values())), 4)
        for cid, t in texts.items():
            self.assertNotEqual(t, orig, cid)
        self.assertIn('cidr_blocks = ["203.0.113.0/24"]', texts["fix-office"])
        self.assertIn('cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"]', texts["split-cidr"])
        self.assertNotIn("from_port   = 22", texts["remove-rule"].split('resource "aws_security_group" "web"')[0])
        self.assertEqual(texts["fix-and-db-open"].count("3306"), orig.count("3306") + 2)
        self.assertEqual((man["rule"], man["resource"]), ("AVD-AWS-0107", "aws_security_group.bastion"))

    def test_design_is_topology_from_proposal_and_parses(self):
        from iacpatch.topology_intent import load_topology_intent
        spec = load_topology_intent(DESIGN)
        self.assertEqual(spec.raw.get("source"), "proposal")
        self.assertEqual([t.security_group for t in spec.tiers], ["aws_security_group.bastion", "aws_security_group.web", "aws_security_group.db"])
        office = next(e for e in spec.external if e.id == "office")
        self.assertEqual(office.cidrs_v4, ["203.0.113.0/24"])
        self.assertEqual({(f.src, f.dst, f.from_port) for f in spec.flows},
                         {("internet", "web", 80), ("internet", "web", 443), ("office", "bastion", 22), ("bastion", "web", 22), ("web", "db", 3306)})

    def test_proposal_kind_is_draft_until_a_person_confirms(self):
        key, base, kind = designs._ref(SET)
        self.assertEqual((key, kind), (SET, "proposal"))
        self.assertEqual(base, DESIGN)
        c = designs.confirmation(SET)
        self.assertEqual((c["confirmed"], c["basis"], c.get("source")), (False, "draft", "proposal"))
        vs = designs.versions(SET)
        self.assertEqual((vs[0]["source"], vs[0]["version"]), ("proposal", 1))
        self.assertIn("고객 제안서에서 옮긴 설계도 초안", vs[0]["note"])
        pay = designs.payload(SET)
        self.assertTrue(pay["confirmable"])
        self.assertTrue(pay["editable"])
        # 이름 없이 확정 → 거절, 이름 있으면 확정 (사람 확정 기록은 임시 폴더에)
        self.assertFalse(designs.confirm(SET, None, "")["ok"])
        r = designs.confirm(SET, None, "김담당", "제안서 조건 1~4 와 같음")
        self.assertTrue(r["ok"], r)
        c2 = designs.confirmation(SET)
        self.assertEqual((c2["confirmed"], c2["basis"], c2["by"]), (True, "human", "김담당"))
        self.assertTrue((Path(self.tmp) / SET / "confirmed.json").is_file())
        # 실험 세트(3계층)는 그대로 '팀 작성 평가 기준' (회귀 없음)
        self.assertEqual(designs._ref("arch-3tier-sg")[2], "manifest")
        self.assertEqual(designs.confirmation("arch-3tier-sg")["basis"], "manifest")

    def test_proposal_text_and_screen_payloads(self):
        pt = designs.proposal_text(SET)
        self.assertEqual(pt["path"], "scenarios/arch/board-saas/PROPOSAL.md")
        self.assertIn("본사 사무실", pt["text"])
        self.assertIsNone(designs.proposal_text("arch-3tier-sg"))
        from iacpatch.web import product
        self.assertNotIn(CASE, [p["id"] for p in product.projects()["projects"]])     # 13차 (D-49): 화면 목록에서는 숨김 — id · ?all=1 로는 열림
        pj = product.projects(include_hidden=True)["projects"]
        me = next(p for p in pj if p["id"] == CASE)
        self.assertTrue(me["proposal"])
        self.assertFalse(next(p for p in pj if p["id"] == "webapp-3tier")["proposal"])
        self.assertEqual(me["design"], {"set_id": SET, "version": 1})

    def test_rule_based_fixes_bastion_ssh_to_office(self):
        from iacpatch.evidence import build_bundle
        from iacpatch.generator.rule_based import RuleBasedGenerator
        from iacpatch.review.inputs import list_findings, load_trivy_report
        from iacpatch.topology_intent import load_topology_intent
        pol = json.loads((ROOT / "policy" / "patch_policy.json").read_text(encoding="utf-8"))
        fs = list_findings(load_trivy_report(ROOT / "experiments" / "arch-board-saas" / "trivy-scan.json"))
        t = next(f for f in fs if f.rule_id == "AVD-AWS-0107")
        self.assertEqual(t.resource, "aws_security_group.bastion")
        files = {p.name: p.read_text(encoding="utf-8") for p in TF_DIR.glob("*.tf")}
        c = RuleBasedGenerator().generate(build_bundle("t", "scenarios/arch/board-saas", t, fs, files, load_topology_intent(DESIGN).to_dict(), pol, {}, {}))
        self.assertEqual(c.status, "PATCH", c.error)
        self.assertIn('cidr_blocks = ["203.0.113.0/24"]', c.files["security_groups.tf"])
        self.assertEqual(c.files["security_groups.tf"].count("0.0.0.0/0"), files["security_groups.tf"].count("0.0.0.0/0") - 1)   # egress 의 0.0.0.0/0 은 그대로
        self.assertIn("본사 사무실 → 점프 서버 (Bastion) :22", c.rationale)

    def test_review_flow_rule_based_matches_proposal_design(self):
        """⑤ 버튼이 부르는 길 그대로: run_review(rule_based, intent=제안서 설계도). 도구가 있으면 V6 = 설계도와 같음(PASS), 없으면 NOT_RUN."""
        from iacpatch.config import load_settings
        from iacpatch.review.flow import ReviewOptions, run_review
        tools = all(Path(os.environ.get(k, "")).is_file() for k in ("TRIVY_BIN", "TERRAFORM_BIN"))
        out = Path(tempfile.mkdtemp(prefix="iacpatch-proposal-run-"))
        self.addCleanup(shutil.rmtree, out, True)
        s = load_settings(str(ROOT))
        res = run_review(s, ReviewOptions(tf_dir="scenarios/arch/board-saas", trivy_json="experiments/arch-board-saas/trivy-scan.json", candidate="rule_based",
                                          scenario=f"ui/{SET}/rule-based-rb", rule="AVD-AWS-0107", resource="aws_security_group.bastion", out_dir=str(out),
                                          intent=str(DESIGN), local_tools=True, design_meta=designs.confirmation(SET)))
        st = json.loads((res.run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(st.get("candidate_origin"), "rule_based")
        self.assertFalse(((st.get("design") or {}).get("confirmation") or {}).get("confirmed"))      # 확정 전 기준으로 검사한 기록 — 승인 못 함 (D-38)
        self.assertTrue(json.loads((res.run_dir / "policy.json").read_text(encoding="utf-8")).get("ok"))
        v6 = res.validity.layer("V6")
        if tools:
            self.assertEqual(v6.verdict.value, "PASS", res.validity.to_dict())
            self.assertEqual(v6.details.get("excess"), [])
        else:
            self.assertEqual(v6.verdict.value, "NOT_RUN")


if __name__ == "__main__":
    unittest.main()
