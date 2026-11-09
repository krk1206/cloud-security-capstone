"""팀 저장소 3계층 예제 (D-49, 2026-11-04) — main 의 infrastructure/three-tier(팀장 A) 사본 + 시나리오 1.

지켜야 하는 것
  - 사본(scenarios/arch/three-tier-team)은 원본과 README 에 적은 곳만 다르다 (원본이 있으면 바이트 비교 — main 을 합친 뒤)
  - 일부러 넣은 설정 오류는 1개 (bastion_ssh_in 0.0.0.0/0 → Trivy AWS-0107 HIGH 1건), 실행 전 안전 점검 통과 (file() · AWS 조회 data 없음)
  - 설계도 v1 = 팀 설계 문서(DESIGN.md)의 허용 통신 5개 — 종류 proposal(초안, 사람이 확정), 이름 '팀 설계 문서'
  - 화면 수정안 4개(featured) — 서로 다르고, 정답이 1번이 아님. 규칙 삭제 후보는 정책이 plan 전에 막는다(POLICY_BLOCKED) → 화면 4개에서 뺐다
  - 규칙을 따로 쓴 코드(aws_vpc_security_group_ingress_rule)에서도: 규칙 → 보안 그룹을 알아 같은 문제를 한 줄로 합치고, 그림에서 그 선을 찾고,
    같은 이름의 상자(ALB · ASG 가 모두 'web')를 구분한다
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

SET = "three-tier-team-sg"
CASE = "three-tier-team"
TF_DIR = ROOT / "scenarios" / "arch" / "three-tier-team"
SET_DIR = ROOT / "experiments" / "candidate-sets" / SET
DESIGN = SET_DIR / "intents" / "three-tier-flows.json"
DOC = TF_DIR / "DESIGN.md"
ORIG = ROOT / "infrastructure" / "three-tier"
TF_NAMES = ["alb.tf", "bastion.tf", "iam.tf", "monitoring.tf", "network.tf", "outputs.tf", "provider.tf", "rds.tf", "s3.tf",
            "security_groups.tf", "variables.tf", "web_asg.tf"]


class TeamExampleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iacpatch-team-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ["IACPATCH_DESIGNS_DIR"] = self.tmp
        self.addCleanup(os.environ.pop, "IACPATCH_DESIGNS_DIR", None)
        self.sha = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (DESIGN, DOC, TF_DIR / "security_groups.tf")}

    def tearDown(self):
        for p, h in self.sha.items():
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), h, f"{p.name} 이 바뀌면 안 됨")

    def test_case_files_and_candidates(self):
        c = cases.get_case(CASE)
        self.assertEqual((c["kind"], c["proposal"], c["proposal_label"]), ("example", "scenarios/arch/three-tier-team/DESIGN.md", "팀 설계 문서"))
        self.assertEqual(sorted(p.name for p in TF_DIR.glob("*.tf")), TF_NAMES)
        # 화면 예제: 팀 3계층 → 3계층(AWS 시험 환경 실측). 게시판 · 2계층은 숨김 (id 로는 열림)
        # 15차: 요청 2 · 3 · 16차 (D-52): 요청 4 ~ 11 — 화면 목록에는 도착한 요청만 나온다 (web/inbox.py, test_inbox.py)
        self.assertEqual([x["id"] for x in cases.visible_cases()], ["three-tier-team", "three-tier-team-s3", "three-tier-team-iam", "three-tier-team-dbsg", "three-tier-team-dbpublic",
                                                                   "three-tier-team-upload", "three-tier-team-imds", "three-tier-team-dbenc", "three-tier-team-deletion",
                                                                   "three-tier-team-flowlog", "three-tier-team-backup", "webapp-3tier"])
        self.assertTrue(cases.get_case("board-saas").get("hidden"))
        man = json.loads((SET_DIR / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual((man["rule"], man["resource"], man["file"], man["line"]),
                         ("AVD-AWS-0107", "aws_vpc_security_group_ingress_rule.bastion_ssh_in", "security_groups.tf", 94))
        self.assertEqual(man["featured"], ["split-cidr", "fix-and-db-open", "fix-admin", "wrong-cidr"])
        self.assertNotEqual(man["featured"][0], "fix-admin")                              # 순서로 정답이 드러나지 않게
        orig = (TF_DIR / "security_groups.tf").read_text(encoding="utf-8")
        texts = {x["id"]: (SET_DIR / x["candidate"][7:]).read_text(encoding="utf-8") for x in man["candidates"]}
        self.assertEqual(len(set(texts.values())), 5)
        for cid, t in texts.items():
            self.assertNotEqual(t, orig, cid)
        self.assertIn("cidr_ipv4         = var.admin_cidr", texts["fix-admin"])
        self.assertIn('"0.0.0.0/1"', texts["split-cidr"])
        self.assertIn('"128.0.0.0/1"', texts["split-cidr"])
        self.assertIn('"198.51.100.0/24"', texts["wrong-cidr"])
        self.assertNotIn('"bastion_ssh_in"', texts["remove-rule"])
        self.assertIn('"db_from_internet"', texts["fix-and-db-open"])
        self.assertEqual(cases.display_labels(SET, man)["fix-admin"], "수정안 3")

    @unittest.skipUnless((ORIG / "security_groups.tf").is_file(), "팀 원본 infrastructure/three-tier 없음 (main 을 합치기 전 작업본)")
    def test_copy_differs_from_team_original_only_where_readme_says(self):
        for n in ("provider.tf", "network.tf", "alb.tf", "rds.tf", "s3.tf", "iam.tf", "monitoring.tf", "outputs.tf"):
            self.assertEqual((TF_DIR / n).read_bytes(), (ORIG / n).read_bytes(), n)
        o = (ORIG / "security_groups.tf").read_text(encoding="utf-8")
        o = o.replace("# SSH는 운영자 공인 IP /32 하나만. 0.0.0.0/0이면 AWS-0107(HIGH)이고 우리 연구의 시나리오 1이 된다.\n", "")
        o = o.replace('  description       = "SSH from admin only"\n  cidr_ipv4         = var.admin_cidr\n',
                      '  description       = "SSH from admin only"\n  cidr_ipv4         = "0.0.0.0/0"\n')
        self.assertEqual((TF_DIR / "security_groups.tf").read_text(encoding="utf-8"), o)

    def test_safety_check_passes_and_no_aws_lookups(self):
        from iacpatch.policy import exec_guard
        files = {p.name: p.read_text(encoding="utf-8") for p in TF_DIR.glob("*.tf")}
        self.assertEqual(exec_guard.check_files(files), [])
        code = "\n".join(exec_guard.code_view(t) for t in files.values())        # 주석 · 문자열 밖의 코드만
        self.assertNotIn("file(", code)
        self.assertNotIn('data "aws_ami"', code)

    def test_trivy_scan_has_the_one_intended_high(self):
        from iacpatch.review.inputs import list_findings, load_trivy_report
        fs = [f for f in list_findings(load_trivy_report(ROOT / "experiments" / "arch-three-tier-team" / "trivy-scan.json")) if f.status == "FAIL"]
        high = [f for f in fs if f.severity in ("HIGH", "CRITICAL")]
        self.assertEqual([(f.rule_id, f.resource, Path(f.filename).name, f.start_line) for f in high],
                         [("AVD-AWS-0107", "aws_vpc_security_group_ingress_rule.bastion_ssh_in", "security_groups.tf", 94)])
        self.assertEqual(sorted(f.severity for f in fs), ["HIGH", "LOW", "LOW", "LOW", "MEDIUM", "MEDIUM"])     # 원본 README 의 MEDIUM 2 · LOW 3 + 시나리오 1

    def test_design_from_team_doc_is_a_draft_until_confirmed(self):
        from iacpatch.topology_intent import load_topology_intent
        spec = load_topology_intent(DESIGN)
        self.assertEqual([t.security_group for t in spec.tiers],
                         ["aws_security_group.alb", "aws_security_group.web", "aws_security_group.bastion", "aws_security_group.db"])
        self.assertEqual(next(e for e in spec.external if e.id == "admin").cidrs_v4, ["203.0.113.10/32"])
        self.assertIn('default     = "203.0.113.10/32"', (TF_DIR / "variables.tf").read_text(encoding="utf-8"))   # 설계도의 운영자 IP = 사본의 admin_cidr 예시 값
        self.assertEqual({(f.src, f.dst, f.from_port) for f in spec.flows},
                         {("internet", "alb", 80), ("alb", "web", 80), ("admin", "bastion", 22), ("web", "db", 3306), ("bastion", "db", 3306)})
        self.assertEqual(designs._ref(SET)[2], "proposal")
        self.assertEqual(designs.proposal_label(SET), "팀 설계 문서")
        self.assertEqual(designs.proposal_label("board-saas-sg"), "고객 제안서")                  # 이름이 없는 세트는 전처럼
        self.assertIn("팀 설계 문서에서 옮긴 설계도 초안", designs.versions(SET)[0]["note"])
        c = designs.confirmation(SET)
        self.assertEqual((c["confirmed"], c.get("source"), c.get("source_label")), (False, "proposal", "팀 설계 문서"))
        pt = designs.proposal_text(SET)
        self.assertEqual((pt["path"], pt["label"]), ("scenarios/arch/three-tier-team/DESIGN.md", "팀 설계 문서"))
        self.assertIn("운영자 IP/32 →22→ Bastion SG", pt["text"])
        self.assertTrue(designs.confirm(SET, None, "김담당", "설계 문서 1.5절과 같음")["ok"])
        self.assertTrue(designs.confirmation(SET)["confirmed"])

    def test_rule_resource_maps_to_its_security_group(self):
        from iacpatch.web import archmap, product
        plan = {"configuration": {"root_module": {"resources": [
            {"address": "aws_vpc_security_group_ingress_rule.bastion_ssh_in", "mode": "managed", "type": "aws_vpc_security_group_ingress_rule",
             "expressions": {"security_group_id": {"references": ["aws_security_group.bastion.id", "aws_security_group.bastion"]}}},
            {"address": "aws_security_group.bastion", "mode": "managed", "type": "aws_security_group", "expressions": {}}]}}}
        self.assertEqual(product._rule_sg_map(plan), {"aws_vpc_security_group_ingress_rule.bastion_ssh_in": "aws_security_group.bastion"})
        self.assertEqual(product._rule_sg_map(None), {})
        model = {"nodes": [], "owners": {}, "sg_nodes": {"aws_security_group.bastion": ["n:b"]}, "edges": [
            {"id": "e1", "kind": "sg", "src": "x:internet", "dst": "n:b", "rules": ["aws_vpc_security_group_ingress_rule.bastion_ssh_in"]},
            {"id": "e2", "kind": "sg", "src": "x:internet", "dst": "n:w", "rules": ["aws_vpc_security_group_ingress_rule.alb_http_in"]}]}
        f = archmap.focus_for(model, {"resource": "aws_vpc_security_group_ingress_rule.bastion_ssh_in", "sources": ["trivy"], "rule": "AVD-AWS-0107"})
        self.assertEqual(f, {"nodes": ["n:b"], "edges": ["e1"]})
        nodes = [{"label": "web", "type": "aws_lb", "addresses": ["aws_lb.web"], "cat": "network", "sgs": ["aws_security_group.alb"]},
                 {"label": "web", "type": "aws_autoscaling_group", "addresses": ["aws_autoscaling_group.web"], "cat": "compute", "sgs": ["aws_security_group.web"]},
                 {"label": "web", "type": "aws_iam_role", "addresses": ["aws_iam_role.web"], "cat": "iam", "sgs": []},
                 {"label": "mysql", "type": "aws_db_instance", "addresses": ["aws_db_instance.mysql"], "cat": "data", "sgs": ["aws_security_group.db"]}]
        archmap._dedupe_labels(nodes, {"aws_lb.web": [{"values": {"load_balancer_type": "application"}}]})
        # 보안 그룹이 붙은 상자끼리만 구분 — 통신 그림에 없는 IAM 역할은 'web' 그대로
        self.assertEqual([n["label"] for n in nodes], ["web (ALB)", "web (ASG)", "web", "mysql"])

    def test_rule_based_fixes_bastion_ssh_to_admin_ip(self):
        from iacpatch.evidence import build_bundle
        from iacpatch.generator.rule_based import RuleBasedGenerator
        from iacpatch.review.inputs import list_findings, load_trivy_report
        from iacpatch.topology_intent import load_topology_intent
        pol = json.loads((ROOT / "policy" / "patch_policy.json").read_text(encoding="utf-8"))
        fs = list_findings(load_trivy_report(ROOT / "experiments" / "arch-three-tier-team" / "trivy-scan.json"))
        t = next(f for f in fs if f.rule_id == "AVD-AWS-0107")
        files = {p.name: p.read_text(encoding="utf-8") for p in TF_DIR.glob("*.tf")}
        c = RuleBasedGenerator().generate(build_bundle("t", "scenarios/arch/three-tier-team", t, fs, files, load_topology_intent(DESIGN).to_dict(), pol, {}, {}))
        self.assertEqual(c.status, "PATCH", c.error)
        sg = c.files["security_groups.tf"]
        self.assertIn('cidr_ipv4         = "203.0.113.10/32"', sg)
        self.assertEqual(sg.count('"0.0.0.0/0"'), files["security_groups.tf"].count('"0.0.0.0/0"') - 1)   # ALB 80 · egress 443 의 0.0.0.0/0 은 그대로

    def _review(self, cid: str):
        from iacpatch.config import load_settings
        from iacpatch.review.flow import ReviewOptions, run_review
        man = json.loads((SET_DIR / "manifest.json").read_text(encoding="utf-8"))
        c = next(x for x in man["candidates"] if x["id"] == cid)
        out = Path(tempfile.mkdtemp(prefix=f"iacpatch-team-{cid}-"))
        self.addCleanup(shutil.rmtree, out, True)
        return run_review(load_settings(str(ROOT)), ReviewOptions(
            tf_dir="scenarios/arch/three-tier-team", trivy_json="experiments/arch-three-tier-team/trivy-scan.json",
            candidate="manual:" + str(SET_DIR / c["candidate"][7:]), scenario=f"ui/{SET}/{cid}", rule="AVD-AWS-0107",
            filename="security_groups.tf", resource="aws_vpc_security_group_ingress_rule.bastion_ssh_in", line=94,
            out_dir=str(out), intent=str(DESIGN), local_tools=True, design_meta=designs.confirmation(SET)))

    def test_delete_candidate_is_blocked_by_policy_before_plan(self):
        res = self._review("remove-rule")
        st = json.loads((res.run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(st.get("state"), "POLICY_BLOCKED")
        pol = json.loads((res.run_dir / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(any("resource_delete:aws_vpc_security_group_ingress_rule.bastion_ssh_in" in v for v in pol.get("violations") or []), pol)

    def test_review_flow_correct_and_wrong_range(self):
        """도구가 있으면: 운영자 IP 로 되돌림 = V6 PASS, 다른 대역으로 좁힘 = V6 FAIL (설계도에 없는 통신 + 막힌 필요한 통신). 없으면 NOT_RUN."""
        tools = all(Path(os.environ.get(k, "")).is_file() for k in ("TRIVY_BIN", "TERRAFORM_BIN"))
        ok = self._review("fix-admin").validity.layer("V6")
        bad = self._review("wrong-cidr").validity.layer("V6")
        if not tools:
            self.assertEqual((ok.verdict.value, bad.verdict.value), ("NOT_RUN", "NOT_RUN"))
            return
        self.assertEqual(ok.verdict.value, "PASS", ok.details)
        self.assertEqual(ok.details.get("excess"), [])
        self.assertEqual(bad.verdict.value, "FAIL", bad.details)
        self.assertEqual([(e["src"], e["dst"], e["ports"], e["cidrs"]) for e in bad.details.get("excess") or []],
                         [("internet", "bastion", "22", ["198.51.100.0/24"])])                      # 설계도에 없는 통신
        self.assertEqual({f["id"]: f["status"] for f in bad.details.get("flows") or []}["admin-bastion-22"], "broken")   # 막힌 필요한 통신


if __name__ == "__main__":
    unittest.main()
