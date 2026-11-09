"""규칙 기반 생성기 × 설계도(topology) 어댑터 (D-45, 2026-11-03) — ⑤ '설계도대로 자동 수정' 의 바탕.

연결한 프로젝트의 설계도에는 포트별 승인 출처(guarded_services)가 없고 "누가 → 어느 계층 : 포트" 화살표(flows)만 있다.
생성기는 지목된 규칙이 속한 보안 그룹 → 그 보안 그룹을 단 계층 → 그 계층으로 **외부(external)에서** 들어오는 flows 의 cidrs_v4 를
포트별 허용 목록으로 바꿔 써서, 그 뒤는 기존 리터럴 CIDR 치환과 같다. 외부 도구 · AWS · LLM 없음.

지켜야 하는 것 (연구 질문 3 의 비교 기준 = 규칙 기반의 한계를 숨기지 않는다)
  - 설계도의 외부 → 계층 화살표가 있으면 PATCH: 0.0.0.0/0 → 그 화살표의 대역 (여러 외부면 합침, 순서 유지)
  - 그 포트로 들어오는 통신이 설계도에 없으면 NOT_SUPPORTED (삭제가 필요한데 규칙 기반은 지우지 않음)
  - 다른 계층(보안 그룹 참조)에서만 들어오면 NOT_SUPPORTED (IP 목록만 바꿀 수 있음)
  - 설계도가 이미 0.0.0.0/0 을 허용하면 NOT_SUPPORTED("이미 같음") — 고칠 곳은 ③ 설계도
  - 지목된 보안 그룹이 설계도의 어느 계층에도 없으면 INSUFFICIENT_INFO
  - 따로 쓴 규칙 리소스(aws_vpc_security_group_ingress_rule)는 security_group_id 참조로 보안 그룹을 찾는다
  - 옛 SG intent(guarded_services) 경로는 그대로 (회귀 없음)
"""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch.evidence import build_bundle
from iacpatch.generator.rule_based import RuleBasedGenerator, flagged_security_group
from iacpatch.models import Finding
from iacpatch.review.inputs import list_findings, load_trivy_report
from iacpatch.topology_intent import load_topology_intent

POLICY = json.loads((ROOT / "policy" / "patch_policy.json").read_text(encoding="utf-8"))
TF_DIR = ROOT / "scenarios" / "arch" / "webapp-3tier"
TRIVY = ROOT / "experiments" / "arch-webapp-3tier" / "trivy-scan.json"
DESIGN = ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "intents" / "arch-3tier-flows.json"


def _files():
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(TF_DIR.glob("*.tf"))}


def _target():
    fs = list_findings(load_trivy_report(TRIVY))
    return next(f for f in fs if f.rule_id == "AVD-AWS-0107"), fs


def _design():
    return load_topology_intent(DESIGN).to_dict()


def _gen(intent_raw, files=None, target=None):
    t, fs = _target()
    return RuleBasedGenerator().generate(build_bundle("t", "scenarios/arch/webapp-3tier", target or t, fs, files or _files(), intent_raw, POLICY, {}, {}))


def _changed_lines(before: str, after: str):
    return [(i + 1, o.strip(), n.strip()) for i, (o, n) in enumerate(zip(before.splitlines(), after.splitlines())) if o != n]


class TopologyAdapterTests(unittest.TestCase):
    def test_design_flow_from_external_becomes_literal_cidrs(self):
        d = _design()                       # admin(203.0.113.0/24, 198.51.100.0/24) → bastion :22
        c = _gen(d)
        self.assertEqual(c.status, "PATCH", c.error)
        self.assertEqual(c.origin, "rule_based")
        ch = _changed_lines(_files()["security_groups.tf"], c.files["security_groups.tf"])
        self.assertEqual(len(ch), 1, ch)
        self.assertEqual(ch[0][2], 'cidr_blocks = ["203.0.113.0/24", "198.51.100.0/24"]')
        self.assertIn("design flows", c.rationale)
        self.assertIn("관리자 접속 허용 목록 → Bastion :22", c.rationale)
        self.assertIn("approved sources = design flows from external entities only", c.assumptions)

    def test_two_externals_on_same_port_are_merged_in_order(self):
        d = _design()
        d["external"].append({"id": "office", "label": "본사", "cidrs_v4": ["192.0.2.0/24"]})
        d["flows"].append({"id": "office-bastion", "from": "office", "to": "bastion", "protocol": "tcp", "port": 22})
        c = _gen(d)
        self.assertEqual(c.status, "PATCH", c.error)
        self.assertIn('cidr_blocks = ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"]', c.files["security_groups.tf"])

    def test_no_flow_into_tier_is_not_supported_because_deletion_is_forbidden(self):
        d = _design()
        d["flows"] = [f for f in d["flows"] if f["to"] != "bastion"]
        c = _gen(d)
        self.assertEqual(c.status, "NOT_SUPPORTED")
        self.assertIn("포트 22", c.error)
        self.assertIn("규칙을 지우지 않음", c.error)
        self.assertEqual(c.files, {})

    def test_tier_only_source_is_not_supported(self):
        d = _design()
        d["flows"] = [f for f in d["flows"] if f["to"] != "bastion"] + [{"id": "web-bastion", "from": "web", "to": "bastion", "protocol": "tcp", "port": 22}]
        c = _gen(d)
        self.assertEqual(c.status, "NOT_SUPPORTED")
        self.assertIn("다른 계층(웹 서버)에서만", c.error)
        self.assertIn("보안 그룹 참조", c.error)

    def test_design_that_allows_internet_is_already_equal(self):
        d = _design()
        d["flows"] = [f for f in d["flows"] if f["to"] != "bastion"] + [{"id": "i-b", "from": "internet", "to": "bastion", "protocol": "tcp", "port": 22}]
        c = _gen(d)
        self.assertEqual(c.status, "NOT_SUPPORTED")
        self.assertIn("이미 같음", c.error)
        self.assertIn("③ 설계도", c.error)

    def test_security_group_missing_from_design_is_insufficient_info(self):
        d = _design()
        d["tiers"] = [t for t in d["tiers"] if t["id"] != "bastion"]
        d["flows"] = [f for f in d["flows"] if "bastion" not in (f["from"], f["to"])]
        c = _gen(d)
        self.assertEqual(c.status, "INSUFFICIENT_INFO")
        self.assertIn("aws_security_group.bastion", c.rationale)

    def test_protocol_all_flow_is_ignored_with_note(self):
        d = _design()
        d["flows"] = [f for f in d["flows"] if f["to"] != "bastion"] + [{"id": "a-b", "from": "admin", "to": "bastion", "protocol": "-1"}]
        c = _gen(d)
        self.assertEqual(c.status, "NOT_SUPPORTED")       # -1 은 포트 키가 없다 → 22 로 들어오는 통신 없음
        self.assertIn("포트 22", c.error)

    def test_separate_rule_resource_finds_sg_by_reference(self):
        tf = ('resource "aws_security_group" "bastion" {\n  name = "b"\n}\n\n'
              'resource "aws_vpc_security_group_ingress_rule" "ssh" {\n  security_group_id = aws_security_group.bastion.id\n'
              '  from_port         = 22\n  to_port           = 22\n  ip_protocol       = "tcp"\n  cidr_ipv4         = "0.0.0.0/0"\n}\n')
        f = Finding(rule_id="AVD-AWS-0107", severity="CRITICAL", resource="aws_vpc_security_group_ingress_rule.ssh", filename="sg.tf", start_line=10, end_line=10)
        self.assertEqual(flagged_security_group(None, tf.splitlines(), 9), "aws_security_group.bastion")
        d = _design()
        d["external"] = [{"id": "admin", "label": "관리자", "cidrs_v4": ["203.0.113.0/24"]}]
        d["flows"] = [{"id": "a-b", "from": "admin", "to": "bastion", "protocol": "tcp", "port": 22}]
        c = RuleBasedGenerator().generate(build_bundle("t", "x", f, [f], {"sg.tf": tf}, d, POLICY, {}, {}))
        self.assertEqual(c.status, "PATCH", c.error)
        self.assertIn('cidr_ipv4         = "203.0.113.0/24"', c.files["sg.tf"])

    def test_separate_rule_with_two_approved_sources_cannot_split(self):
        tf = ('resource "aws_security_group" "bastion" {\n  name = "b"\n}\n\n'
              'resource "aws_vpc_security_group_ingress_rule" "ssh" {\n  security_group_id = aws_security_group.bastion.id\n'
              '  from_port         = 22\n  to_port           = 22\n  ip_protocol       = "tcp"\n  cidr_ipv4         = "0.0.0.0/0"\n}\n')
        f = Finding(rule_id="AVD-AWS-0107", severity="CRITICAL", resource="aws_vpc_security_group_ingress_rule.ssh", filename="sg.tf", start_line=10, end_line=10)
        c = RuleBasedGenerator().generate(build_bundle("t", "x", f, [f], {"sg.tf": tf}, _design(), POLICY, {}, {}))
        self.assertEqual(c.status, "NOT_SUPPORTED")
        self.assertIn("cannot split", c.error)

    def test_legacy_guarded_services_path_unchanged(self):
        c = _gen({"kind": "sg", "guarded_services": [{"from_port": 22, "to_port": 22, "approved_sources": {"cidrs_v4": ["10.0.0.0/8"]}}]})
        self.assertEqual(c.status, "PATCH", c.error)
        self.assertIn('cidr_blocks = ["10.0.0.0/8"]', c.files["security_groups.tf"])
        self.assertTrue(c.rationale.startswith("rule-based literal replacement: "))

    def test_design_dict_is_not_mutated(self):
        d = _design()
        snap = copy.deepcopy(d)
        _gen(d)
        self.assertEqual(d, snap)


class RuleBasedTopologyFlowTests(unittest.TestCase):
    """run_review(candidate=rule_based, intent=설계도) — ⑤ 버튼이 부르는 길. 도구 없이(V1~V4 NOT_RUN) 후보 · 정책 · V6 까지."""

    def setUp(self):
        import os
        import tempfile
        self.out = Path(tempfile.mkdtemp(prefix="iacpatch-rbtopo-"))
        # 도구는 환경이 주는 대로 (CI = 없음 → V1~V6 NOT_RUN, 샌드박스 = 진짜 tofu · trivy → V6 까지). 결과는 둘 다 확인한다
        self.tools = all(Path(os.environ.get(k, "")).is_file() for k in ("TRIVY_BIN", "TERRAFORM_BIN"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.out, ignore_errors=True)

    def _run(self, intent_path: str):
        from iacpatch.config import load_settings
        from iacpatch.review.flow import ReviewOptions, run_review
        s = load_settings(str(ROOT))
        return run_review(s, ReviewOptions(tf_dir="scenarios/arch/webapp-3tier", trivy_json="experiments/arch-webapp-3tier/trivy-scan.json",
                                           candidate="rule_based", scenario="ui/arch-3tier-sg/rule-based-rb", rule="AVD-AWS-0107",
                                           resource="aws_security_group.bastion", out_dir=str(self.out), intent=intent_path, local_tools=True))

    def test_design_flow_makes_candidate_and_passes_policy(self):
        res = self._run(str(DESIGN))
        st = json.loads((res.run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(st.get("candidate_origin"), "rule_based")
        self.assertNotIn(res.state.value, ("CANDIDATE_INVALID", "INFO_INSUFFICIENT", "POLICY_BLOCKED"), res.message)
        pol = json.loads((res.run_dir / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(pol.get("ok"), pol)
        self.assertIn('cidr_blocks = ["203.0.113.0/24", "198.51.100.0/24"]', (res.run_dir / "candidate" / "security_groups.tf").read_text(encoding="utf-8"))
        v6 = res.validity.layer("V6")
        if self.tools:
            # 지목된 규칙(Bastion SSH)은 설계도대로 고쳐졌지만, 이 예제 원본에는 Trivy 가 보지 않는 설계 위반(웹 서버 → MySQL 3306)이
            # 하나 더 있다 — 규칙 기반은 지목된 줄만 바꾸므로 V6 는 그 1건으로 FAIL 이어야 한다 (숨기지 않는다)
            self.assertEqual(v6.verdict.value, "FAIL", res.validity.to_dict())
            det = v6.details
            self.assertEqual([(e["src"], e["dst"], e["ports"]) for e in det["excess"]], [("web", "db", "3306")])
            self.assertEqual(next(f for f in det["flows"] if f["id"] == "admin-bastion")["status"], "ok")
        else:
            self.assertEqual(v6.verdict.value, "NOT_RUN", res.validity.to_dict())  # plan 없이는 V6 를 판정하지 않는다 (추측 금지)

    def test_design_without_flow_records_origin_and_reason(self):
        d = _design()
        d["flows"] = [f for f in d["flows"] if f["to"] != "bastion"]
        p = self.out / "design-noflow.json"
        p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
        res = self._run(str(p))
        self.assertEqual(res.state.value, "INFO_INSUFFICIENT")
        st = json.loads((res.run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(st.get("candidate_origin"), "rule_based")          # 못 만든 기록에도 출처 (⑤ 문구가 이것으로 갈린다)
        self.assertIn("규칙을 지우지 않음", " ".join(st.get("errors") or []))
        self.assertFalse((res.run_dir / "candidate").exists())
        # 화면 결론 · 문제 문구
        from iacpatch.web import explain, problems
        cc = explain.conclusion(st, None, None, None, [])
        self.assertEqual(cc["title"], "규칙 기반으로는 이 문제를 고칠 수 없습니다")
        self.assertIn("포트 22", cc["reason"])
        self.assertNotIn("후보 상태", cc["reason"])
        pr = problems.problems(st, None, None, None)
        self.assertEqual(pr[0]["layer"], "생성")
        self.assertIn("③ 설계도", pr[0]["how"])


if __name__ == "__main__":
    unittest.main()
