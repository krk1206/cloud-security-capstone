"""결과 화면 (교수 피드백 2026-10-31): 발견된 문제(무엇 · 왜 · 어떻게) · 확인하지 않은 것 · 3단계 후보 구조 그림 자료.

판정은 기록 값 그대로다. 여기서는 (1) 실제 구조 검사(V6) 결과 모양에서 문장이 맞게 나오는지,
(2) 기록 화면이 그 기록에 저장한 설계도 사본으로 설명하는지, (3) 3단계 그림이 쓸 자료(후보의 최근 기록 → 구조)가
오는지를 본다. 도구(Trivy · Terraform) 없이 돈다 — V6 결과는 판정 규칙(topology_oracle)을 직접 돌려 만든다.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT
from test_topology_oracle import ADMIN, cidr_rule, original_world, set_rules, sg_rule

from iacpatch.topology_intent import load_topology_intent
from iacpatch.verify.topology_oracle import evaluate
from iacpatch.web.problems import _j, _rule_where, problems, unchecked

INTENT = ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "intents" / "arch-3tier-flows.json"
DESIGN = json.loads(INTENT.read_text(encoding="utf-8"))
SHA = hashlib.sha256(INTENT.read_bytes()).hexdigest()
DES_REC = {"intent_id": "arch-3tier-flows", "intent_version": "1", "kind": "topology",
           "path": "experiments/candidate-sets/arch-3tier-sg/intents/arch-3tier-flows.json", "sha256": SHA, "copy": "input/design.json"}


def _v6(world):
    rep = evaluate(world, load_topology_intent(INTENT))
    return {"layer": "V6", "verdict": rep.verdict.value, "summary": rep.summary, "details": rep.to_dict()}


def _ver(v6, **others):
    layers = [{"layer": f"V{i}", "verdict": others.get(f"V{i}", "PASS"), "summary": ""} for i in range(1, 6)] + [v6]
    return {"report": {"layers": layers, "validity": "COMPLETE"}}


def _flagged_only():
    """Trivy 가 지적한 Bastion 만 고치고 웹 → MySQL 직결은 남긴 수정 (설계도에 없는 통신 1개)."""
    return set_rules(original_world(), "bastion", [cidr_rule(22, ADMIN, "aws_security_group.bastion#ingress[0]")])


def _fixed():
    w = set_rules(original_world(), "bastion", [cidr_rule(22, ADMIN, "aws_security_group.bastion#ingress[0]")])
    return set_rules(w, "db", [sg_rule(3306, "api", "aws_security_group.db#ingress[0]")])


class ProblemCardTest(unittest.TestCase):
    """무엇 · 왜 · 어떻게 — 실제 판정 규칙 결과에서."""

    def test_pass_has_no_problem_cards(self):
        v6 = _v6(_fixed())
        self.assertEqual(v6["verdict"], "PASS")
        self.assertEqual(problems({"state": "REVIEW_REQUIRED"}, _ver(v6), {"ok": True}, DESIGN, DES_REC), [])

    def test_extra_flow_says_what_why_how_where(self):
        w = set_rules(_flagged_only(), "db", [sg_rule(3306, "api", "aws_security_group.db#ingress[0]"),
                                              sg_rule(3306, "web", "aws_security_group.db#ingress[1]")])
        v6 = _v6(w)
        self.assertEqual(v6["verdict"], "FAIL")
        ps = problems({"state": "VALIDATION_FAILED"}, _ver(v6), {"ok": True}, DESIGN, DES_REC)
        self.assertEqual([(p["kind"], p["layer"], p["tag"]) for p in ps], [("design_extra", "V6", "고객 설계에 없는 통신")])
        p = ps[0]
        self.assertEqual(p["what"], "웹 서버가 MySQL의 3306 포트에 접근할 수 있게 허용돼 있습니다.")
        # 왜: 그 기록의 고객 설계도가 MySQL 로 허용한 통신을 그대로 보여 준다
        self.assertEqual(p["why"], "고객 설계도(arch-3tier-flows v1)에서 MySQL로 들어오는 통신은 API 서버 → MySQL 3306 뿐입니다.")
        self.assertIn("aws_security_group.db", p["how"])
        self.assertIn("웹 서버에서 오는 3306 허용 규칙을 지우고 다시 검사", p["how"])
        self.assertEqual(p["where"], "aws_security_group.db 의 인바운드 규칙 2번째")
        self.assertEqual((p["flow"]["src_id"], p["flow"]["dst_id"]), ("web", "db"))     # 그림에 표시할 경로

    def test_vpc_wide_source_explains_why_ip_range_is_not_enough(self):
        w = set_rules(_flagged_only(), "db", [cidr_rule(3306, ["10.0.0.0/16"], "aws_security_group.db#ingress[0]")])
        ps = problems({"state": "VALIDATION_FAILED"}, _ver(_v6(w)), {"ok": True}, DESIGN, DES_REC)
        extra = [p for p in ps if p["kind"] == "design_extra"]
        self.assertEqual(len(extra), 1, ps)
        self.assertIn("VPC 대역(IP)으로 열면 어느 서버에서 오는지 구분할 수 없어", extra[0]["why"])
        self.assertIn("출발지를 설계도가 허용한 대상으로 좁히고", extra[0]["how"])
        self.assertIn("(허용: API 서버 → MySQL 3306)", extra[0]["how"])

    def test_missing_required_flow_is_rule_level_and_points_to_v8(self):
        w = set_rules(_fixed(), "alb", [cidr_rule(443, ADMIN, "aws_security_group.alb#ingress[0]")])     # 사용자 접속을 관리자 대역으로 좁힘
        ps = problems({"state": "VALIDATION_FAILED"}, _ver(_v6(w)), {"ok": True}, DESIGN, DES_REC)
        miss = [p for p in ps if p["kind"] == "design_missing"]
        self.assertEqual(len(miss), 1, ps)
        self.assertEqual(miss[0]["tag"], "허용 규칙 없는 필수 통신")
        self.assertEqual(miss[0]["what"], "사용자(인터넷) → ALB HTTPS(443) 통신을 허용하는 보안 그룹 규칙이 없습니다.")
        self.assertIn("규칙 기준 판정이며, 실제 연결은 AWS 시험 환경 검사(V8)에서 확인합니다.", miss[0]["why"])
        self.assertTrue(miss[0]["flow"]["missing"])

    def test_unknown_v6_is_its_own_card_not_a_pass(self):
        v6 = {"layer": "V6", "verdict": "UNKNOWN", "summary": "출발지 값이 plan 시점에 정해지지 않음", "details": {"kind": "topology", "flows": [], "excess": []}}
        ps = problems({"state": "REVIEW_REQUIRED"}, _ver(v6), {"ok": True}, DESIGN, DES_REC)
        self.assertEqual([p["tag"] for p in ps], ["판정 불가"])

    def test_policy_and_unsafe_code_cards(self):
        pol = {"ok": False, "violations": ['exec_guard:security_groups.tf: AWS 외 data 블록 (plan 중 파일 읽기·외부 접속 가능) 추가: data "local_file" "leak"',
                                           "resource_delete:aws_security_group.db: resource block removed"]}
        ps = problems({"state": "POLICY_BLOCKED"}, None, pol, DESIGN, DES_REC)
        self.assertEqual([p["kind"] for p in ps], ["unsafe_code", "policy"])
        self.assertIn("Trivy · Terraform 을 실행하지 않고 멈췄습니다", ps[0]["why"])
        self.assertEqual(ps[1]["tag"], "허용 범위 밖 수정")

    def test_reason_depends_on_violation_type(self):
        pol = {"ok": False, "violations": ["forbidden_tokens:security_groups.tf: introduced ['provisioner', 'local-exec']",
                                           "protected_blocks:security_groups.tf: terraform/provider blocks changed: body changed"]}
        ps = problems({"state": "POLICY_BLOCKED"}, None, pol, DESIGN, DES_REC)
        self.assertEqual([p["tag"] for p in ps], ["금지 코드", "설정 블록 변경"])
        self.assertIn("명령을 실행할 수 있어", ps[0]["why"])
        # V5: 영어 위반 문장 대신 화면 문장, 구분(허용 범위 밖 / 교체·삭제)은 tag 로
        ver = _ver(_v6(_fixed()), V5="FAIL")
        lay = {l["layer"]: l for l in ver["report"]["layers"]}
        lay["V5"]["details"] = {"violations": ["aws_security_group.bastion: attributes changed outside allowlist: name",
                                               "plan replaces (destroy+create) aws_security_group.bastion"]}
        ps = problems({"state": "VALIDATION_FAILED"}, ver, {"ok": True}, DESIGN, DES_REC)
        self.assertEqual([p["tag"] for p in ps], ["허용 범위 밖 수정", "교체 · 삭제 위험"])
        self.assertTrue(all("attributes changed" not in p["what"] and not p["what"].startswith("허용 범위 밖 변경") for p in ps), [p["what"] for p in ps])
        self.assertIn("교체", ps[1]["what"])

    def test_code_error_in_plain_words(self):
        ver = _ver(_v6(_fixed()), V3="FAIL")
        lay = {l["layer"]: l for l in ver["report"]["layers"]}
        lay["V3"]["details"] = {"diagnostics": [{"summary": "Reference to undeclared resource",
                                                 "detail": 'A managed resource "aws_security_group" "admin" has not been declared in the root module.',
                                                 "range": {"filename": "security_groups.tf", "start": {"line": 42}}}]}
        ps = problems({"state": "VALIDATION_FAILED"}, ver, {"ok": True}, DESIGN, DES_REC)
        self.assertEqual(ps[0]["what"], "Terraform 코드 오류: 선언되지 않은 리소스 참조 (aws_security_group.admin) (security_groups.tf 42행)")
        self.assertEqual(ps[0]["how"], "security_groups.tf 42행을 고치고 다시 검사하세요. 오류 원문은 V3 증거에 있습니다.")

    def test_v1_v2_v4_cards(self):
        ver = _ver(_v6(_fixed()), V1="FAIL", V2="FAIL", V4="FAIL")
        lay = {l["layer"]: l for l in ver["report"]["layers"]}
        lay["V1"]["summary"] = "AVD-AWS-0107 still present on aws_security_group.bastion"
        lay["V2"]["details"] = {"new": [{"rule_id": "AVD-AWS-0107", "resource": "aws_security_group.web", "filename": "security_groups.tf",
                                         "start_line": 40, "severity": "CRITICAL", "message": "x"}]}
        lay["V4"]["summary"] = "Error: loading configuration: failed to get shared config profile, capstone-tf"
        ps = problems({"state": "VALIDATION_FAILED"}, ver, {"ok": True}, DESIGN, DES_REC)
        by = {p["layer"]: p for p in ps}
        self.assertIn("SSH(22) · RDP(3389) 를 인터넷 전체", by["V1"]["what"])
        self.assertIn("고객 설계도(arch-3tier-flows v1)가 허용한 대상으로", by["V1"]["how"])
        self.assertEqual(by["V2"]["where"], "security_groups.tf:40")
        # AWS 프로필 오류는 코드 문제로 단정하지 않는다
        self.assertEqual(by["V4"]["kind"], "env_error")
        self.assertIn("검사 환경 문제일 수 있습니다", by["V4"]["why"])

    def test_rule_where_and_particles(self):
        self.assertEqual(_rule_where("aws_security_group.web#ingress[0]"), "aws_security_group.web 의 인바운드 규칙 1번째")
        self.assertEqual(_rule_where("a#egress[2]"), "a 의 아웃바운드 규칙 3번째")
        self.assertEqual([_j(w, "이가") for w in ("웹 서버", "Bastion", "MySQL", "ALB", "관리자 접속 허용 목록", "사용자(인터넷)")],
                         ["웹 서버가", "Bastion이", "MySQL이", "ALB가", "관리자 접속 허용 목록이", "사용자(인터넷)가"])
        self.assertEqual([_j(w, "으로") for w in ("MySQL", "Bastion", "웹 서버", "목록")], ["MySQL로", "Bastion으로", "웹 서버로", "목록으로"])


class UncheckedTest(unittest.TestCase):
    """확인하지 않은 것은 통과처럼 보이지 않게 따로 적는다."""

    def test_topology_before_real_aws(self):
        u = unchecked("topology", None)
        self.assertTrue(any("egress" in x and "NACL" in x for x in u))
        self.assertTrue(any("AWS 시험 환경 검사(V7 · V8) 전" in x for x in u))
        self.assertTrue(any("운영 AWS" in x for x in u))
        self.assertTrue(any("Trivy 규칙에 없는" in x for x in u))

    def test_after_real_aws_the_v7_v8_line_goes(self):
        u = unchecked("topology", "VERIFIED")
        self.assertFalse(any("V7 · V8" in x for x in u))
        self.assertTrue(any("egress" in x for x in u))        # 실제 AWS 검사 뒤에도 설계 비교 범위(인바운드)는 그대로


class RecordViewTest(unittest.TestCase):
    """기록 화면 = 그 기록의 설계도 사본으로 설명 + 3단계 그림 자료 (후보의 최근 기록 → 구조)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ["IACPATCH_REVIEWS_DIR"] = self.tmp
        self.addCleanup(os.environ.pop, "IACPATCH_REVIEWS_DIR", None)

    def _record(self, rid, cid, v6, design_bytes, design_sha):
        d = Path(self.tmp) / rid
        (d / "input").mkdir(parents=True)
        st = {"run_id": rid, "scenario": f"ui/arch-3tier-sg/{cid}", "state": "VALIDATION_FAILED" if v6["verdict"] != "PASS" else "REVIEW_REQUIRED",
              "history": [], "errors": [], "started_at": "2026-10-31T07:00:00+00:00", "finished_at": "2026-10-31T07:01:00+00:00",
              "verification_status": "FAILED" if v6["verdict"] != "PASS" else "PASSED", "review_level": "BLOCKED" if v6["verdict"] != "PASS" else "FULL_REVIEW",
              "tf_dir": "scenarios/arch/webapp-3tier", "candidate_sha256": "0" * 64, "design": {**DES_REC, "sha256": design_sha}}
        (d / "state.json").write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")
        (d / "verification.json").write_text(json.dumps(_ver(v6), ensure_ascii=False), encoding="utf-8")
        (d / "policy.json").write_text(json.dumps({"ok": True, "violations": [], "checks": []}), encoding="utf-8")
        (d / "input" / "design.json").write_bytes(design_bytes)
        return d

    def test_explains_with_the_records_own_design_copy(self):
        from iacpatch.web.server import record_view
        w = set_rules(_flagged_only(), "db", [sg_rule(3306, "api", "aws_security_group.db#ingress[0]"),
                                              sg_rule(3306, "web", "aws_security_group.db#ingress[1]")])
        # 기록 당시 설계도 사본에서 API 서버 이름이 달랐다고 하자 → 설명은 사본 기준이어야 한다 (지금 설계도로 다시 해석하지 않음)
        old = copy.deepcopy(DESIGN)
        next(t for t in old["tiers"] if t["id"] == "api")["label"] = "API 서버(이전 이름)"
        raw = json.dumps(old, ensure_ascii=False).encode("utf-8")
        self._record("20261031-070000-aaaaaa", "flagged-only-fix", _v6(w), raw, hashlib.sha256(raw).hexdigest())
        rec = record_view("20261031-070000-aaaaaa")
        self.assertNotIn("error", rec)
        self.assertEqual(rec["conclusion"]["title"], "수정한 코드가 고객 설계와 일치하지 않습니다")
        self.assertEqual(rec["conclusion"]["status"], "검증 실패 · 승인 불가")
        self.assertFalse(rec["conclusion"]["can_approve"])
        self.assertIn("API 서버(이전 이름) → MySQL 3306", rec["problems"][0]["why"])
        self.assertIs(rec["design"]["same_as_current"], False)          # 화면이 '이전 설계도 기준 결과' 로 표시
        self.assertEqual(rec["requirements"], [r for r in rec["requirements"] if r["before"] is None])   # 다른 설계도의 '수정 전' 과 섞지 않음
        self.assertTrue(any("V7 · V8" in x for x in rec["unchecked"]))

    def test_step3_diagram_data_comes_from_candidates_latest_record(self):
        from iacpatch.web import cases as cs
        from iacpatch.web.server import record_view
        w = set_rules(_flagged_only(), "db", [sg_rule(3306, "api", "aws_security_group.db#ingress[0]"),
                                              sg_rule(3306, "web", "aws_security_group.db#ingress[1]")])
        self._record("20261031-070100-bbbbbb", "flagged-only-fix", _v6(w), INTENT.read_bytes(), SHA)
        self._record("20261031-070200-cccccc", "correct-design", _v6(_fixed()), INTENT.read_bytes(), SHA)
        sets = cs.candidates("webapp-3tier")["sets"]
        cands = {c["id"]: c for c in sets[0]["candidates"]}
        self.assertEqual(cands["flagged-only-fix"]["latest"]["id"], "20261031-070100-bbbbbb")
        self.assertEqual(cands["correct-design"]["latest"]["id"], "20261031-070200-cccccc")
        self.assertIsNone(cands["db-only-fix"]["latest"])              # 검사 전 후보 → 화면은 원본 구조 + '검사 전' 안내
        # 후보마다 그림이 달라야 한다: 웹 → MySQL 이 남은 후보는 빨간 점선 1곳, 설계대로 고친 후보는 0곳
        t1 = record_view("20261031-070100-bbbbbb")["topology"]
        t2 = record_view("20261031-070200-cccccc")["topology"]
        self.assertEqual([(e["src"], e["dst"]) for e in t1["excess"]], [("web", "db")])
        self.assertEqual(t2["excess"], [])
        self.assertEqual(len(t1["flows"]), 9)
        self.assertTrue(all(f["status"] == "ok" for f in t2["flows"]))
        self.assertTrue(record_view("20261031-070200-cccccc")["design"]["same_as_current"])
        # 그림 모델: 그 기록의 설계도 + 이 후보 코드의 V6 결과(붙은 리소스) — 고정 그림이 아님
        tm = record_view("20261031-070100-bbbbbb")["topology_model"]
        self.assertEqual(tm["source"], "record")
        icons = {n["id"]: (n["icon"], n["icon_source"]) for n in tm["nodes"] if n["kind"] == "tier"}
        self.assertEqual(icons["db"], ("rds", "attached"))
        self.assertEqual(icons["nlb"], ("elb", "attached"))
        self.assertEqual(len(tm["flows"]), 9)


if __name__ == "__main__":
    unittest.main()
