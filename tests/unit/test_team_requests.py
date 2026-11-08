"""팀 3계층 요청 2 (S3, 정책 밖) · 요청 3 (IAM) (15차, D-51 — B 2026-11-06 "시나리오 고객 요청 건을 좀 더 늘리자").

지켜야 하는 것
  - 요청 3 사본: 원본과 README 표에 적은 곳만 다르다 (SSH 는 원본 그대로, iam.tf 의 정책 · 답이 되는 주석만). Trivy 지적 = AWS-0345 1건 (HIGH)
  - 요청 3 수정안 7개의 expected 는 실행 전 고정값 그대로 (correct 1 · deceptive 2 · breaks_required 2 · unapproved 1 · unsupported 1), 화면 4개(featured)의 정답은 1번이 아님
  - 요청 3 요구사항 v1 = 팀 설계 문서(DESIGN.md)에서 옮긴 **초안** (req_proposal) — 확정 전에는 '고객 요구 충족' 이 아니고, 사람이 확정할 수 있다
  - 요청 3 조건: V6 IAM 이 FAIL 이면 어느 조건이든 '어김' (excess · missing · 신뢰 정책이 조건 하나씩에 들어감). 초안이면 '지킴' 대신 '초안 기준'
  - 요청 2 사본: 공개 차단 4개만 false · Trivy HIGH 4건. 고칠 묶음이 없고(정책 밖), '사람에게 넘김' 칸은 정책 파일 · Trivy 결과를 그대로 옮긴다 — 정책 파일은 바꾸지 않는다
  - 권한 그림: 권한 선마다 (동작, 리소스) 짝, 겹침은 V6 IAM 결과 그대로 (요구사항 밖 → excess, 꼭 필요한데 없음 → 유령 선)
저장 위치는 IACPATCH_DESIGNS_DIR 로 임시 폴더를 쓴다 (저장소 data/ 를 건드리지 않음).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest

from helpers import ROOT

from iacpatch.iam_intent import parse_iam_intent
from iacpatch.review.inputs import list_findings, load_trivy_report
from iacpatch.web import archmap, cases, designs, request

IAM_CASE, S3_CASE = "three-tier-team-iam", "three-tier-team-s3"
IAM_DIR = ROOT / "scenarios" / "arch" / "three-tier-team-iam"
S3_DIR = ROOT / "scenarios" / "arch" / "three-tier-team-s3"
SET_DIR = ROOT / "experiments" / "candidate-sets" / "three-tier-team-iam"
ORIG = ROOT / "infrastructure" / "three-tier"
POLICY = ROOT / "policy" / "patch_policy.json"


def findings(case_id):
    c = cases.get_case(case_id)
    return [f for f in list_findings(load_trivy_report(ROOT / c["trivy_json"])) if f.status == "FAIL"]


def v6_iam(excess=(), missing=(), unknown=(), verdict=None):
    v = verdict or ("FAIL" if excess or missing else "UNKNOWN" if unknown else "PASS")
    return {"verdict": v, "summary": "", "details": {"kind": "iam", "info": [], "scopes": [
        {"scope_id": "aws_iam_role.web", "verdict": v, "excess": list(excess), "missing": list(missing), "unknown_reasons": list(unknown)}]}}


class IamExampleTests(unittest.TestCase):
    def test_copy_differs_only_where_readme_says(self):
        self.assertEqual(sorted(p.name for p in IAM_DIR.iterdir()),
                         sorted(["DESIGN.md", "README.md", "alb.tf", "bastion.tf", "iam.tf", "monitoring.tf", "network.tf", "outputs.tf", "provider.tf", "rds.tf",
                                 "s3.tf", "security_groups.tf", "variables.tf", "web_asg.tf"]))
        iam = (IAM_DIR / "iam.tf").read_text(encoding="utf-8")
        self.assertIn('actions   = ["s3:*"]', iam)
        self.assertIn('resources = ["*"]', iam)
        self.assertNotIn("시나리오 3", iam)                     # 답이 되는 주석은 README 에만 (D-32)
        self.assertNotIn("최소 권한", iam)
        self.assertIn("cidr_ipv4         = var.admin_cidr", (IAM_DIR / "security_groups.tf").read_text(encoding="utf-8"))   # 요청 1 은 고친 상태
        team = ROOT / "scenarios" / "arch" / "three-tier-team"
        for name in ("alb.tf", "bastion.tf", "monitoring.tf", "network.tf", "outputs.tf", "provider.tf", "rds.tf", "s3.tf", "variables.tf", "web_asg.tf"):
            self.assertEqual((IAM_DIR / name).read_bytes(), (team / name).read_bytes(), name)     # 요청 1 사본과 같은 파일
        if ORIG.is_dir():                                       # main 을 합친 트리에서만 (팀 원본과 바이트 비교)
            self.assertEqual((IAM_DIR / "security_groups.tf").read_bytes(), (ORIG / "security_groups.tf").read_bytes())

    def test_trivy_one_high_on_policy_document(self):
        high = [(f.rule_id, f.resource, f.start_line) for f in findings(IAM_CASE) if f.severity in ("HIGH", "CRITICAL")]
        self.assertEqual(high, [("AVD-AWS-0345", "data.aws_iam_policy_document.web_s3_read", 22)])
        man = json.loads((SET_DIR / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual((man["rule"], man["resource"], man["file"], man["line"]), ("AVD-AWS-0345", "data.aws_iam_policy_document.web_s3_read", "iam.tf", 22))
        self.assertIn("AVD-AWS-0345", json.loads(POLICY.read_text(encoding="utf-8"))["supported_target_rules"])

    def test_candidates_and_expected_fixed(self):
        man = json.loads((SET_DIR / "manifest.json").read_text(encoding="utf-8"))
        exp = {c["id"]: c["expected"] for c in man["candidates"]}
        self.assertEqual(exp, {"fix-least": "correct", "action-star": "deceptive", "enum-star": "deceptive", "remove-read": "breaks_required",
                               "wrong-bucket": "breaks_required", "trust-open": "unapproved", "rule-based": "unsupported"})
        self.assertEqual(man["featured"], ["action-star", "fix-least", "remove-read", "enum-star"])
        self.assertNotEqual(exp[man["featured"][0]], "correct")             # 정답이 1번이 아님
        self.assertIs(man["week4_label_replay"], False)
        for c in man["candidates"]:
            if c["candidate"].startswith("manual:"):
                text = (SET_DIR / c["candidate"].split(":", 1)[1]).read_text(encoding="utf-8")
                self.assertIn('data "aws_iam_policy_document" "web_s3_read"', text, c["id"])
        star = (SET_DIR / "candidates" / "action-star.tf").read_text(encoding="utf-8")
        self.assertIn('actions   = ["*"]', star)                            # 팀 README 시나리오 3 의 모양 — Trivy 0.74 는 못 잡는다

    def test_requirement_from_team_document(self):
        raw = json.loads((SET_DIR / "intents" / "web-role.json").read_text(encoding="utf-8"))
        spec = parse_iam_intent(raw)
        self.assertEqual(spec.target_roles, ["aws_iam_role.web"])
        self.assertEqual([(a.actions, a.resources) for a in spec.approved],
                         [(["s3:GetObject"], ["tf:aws_s3_bucket.assets.arn/*"]), (["s3:ListBucket"], ["tf:aws_s3_bucket.assets.arn"])])
        self.assertEqual(spec.approved_managed_policy_arns, ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"])
        doc = (IAM_DIR / "DESIGN.md").read_text(encoding="utf-8")
        self.assertIn("권한 정책(무엇을: assets 버킷 GetObject/ListBucket, SSM 관리형 정책). 리소스를 버킷 ARN으로 못 박았다.", doc)
        if (ROOT / "docs" / "architecture" / "three-tier-design.md").is_file():     # main 을 합친 트리: 원문 문장이 그대로인지
            src = (ROOT / "docs" / "architecture" / "three-tier-design.md").read_text(encoding="utf-8")
            for line in doc.splitlines():
                if line.startswith(("1.12절 IAM: \"", "3.3절 실행 기록: \"")):
                    self.assertIn(line.split(": \"", 1)[1].rstrip("\"").split(" | ")[0], src)


class RequirementDraftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iacpatch-req-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ["IACPATCH_DESIGNS_DIR"] = self.tmp
        self.addCleanup(os.environ.pop, "IACPATCH_DESIGNS_DIR", None)
        self.intent = SET_DIR / "intents" / "web-role.json"
        self.sha = hashlib.sha256(self.intent.read_bytes()).hexdigest()

    def tearDown(self):
        self.assertEqual(hashlib.sha256(self.intent.read_bytes()).hexdigest(), self.sha, "요구사항 파일이 바뀌면 안 됨")

    def test_v1_is_draft_then_confirmed_by_a_person(self):
        sid = "three-tier-team-iam"
        c = designs.confirmation(sid)
        self.assertEqual((c["confirmed"], c["basis"], c.get("source"), c.get("source_label")), (False, "draft", "proposal", "팀 설계 문서"))
        self.assertTrue(designs.payload(sid)["confirmable"])
        self.assertTrue(designs.payload(sid)["importable"])
        self.assertFalse(designs.confirm(sid, 1, "")["ok"])                      # 이름 없으면 거절
        r = designs.confirm(sid, 1, "김담당", "팀 설계 문서 1.12절과 같음")
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["confirmation"]["confirmed"], r["confirmation"]["basis"], r["confirmation"]["by"]), (True, "human", "김담당"))
        # 2계층(팀 작성 평가 기준 manifest)은 그대로 — 확정 대상 아님
        self.assertEqual(designs.confirmation("arch-webapp-iam")["basis"], "manifest")


class IamRequestTests(unittest.TestCase):
    TRUST = "aws_iam_role.web.assume_role_policy#0: trust policy allows Principal '*' without Condition (anyone can assume the role)"

    def check(self, v6, draft=False, **kw):
        good_q = [{"key": "scope", "tone": "good"}, {"key": "new", "tone": "good"}]          # ⑥ 질문(V5 · V2)은 통과로 두고 V6 IAM 만 바꿔 본다
        ctx = {"v1": "PASS", "v6": v6, "rule": "AVD-AWS-0345", "questions": kw.get("questions", good_q), "decision": {}, "post": {}, "draft": draft}
        return request.check(IAM_CASE, ctx)

    def test_meta_seq_kind(self):
        m = request.meta(IAM_CASE)
        self.assertEqual((m["seq"], m["kind"], len(m["items"])), (3, "iam", 4))
        self.assertIn("요청 3", m["text"].splitlines()[0])

    def test_pass_is_kept_and_fail_always_breaks_one_condition(self):
        ok = self.check(v6_iam())
        self.assertEqual([x["tone"] for x in ok["items"]][:3], ["good", "good", "good"])
        cases_ = {
            "excess": v6_iam(excess=["data.aws_iam_policy_document.web_s3_read#0: * on *"]),
            "missing": v6_iam(missing=["read-assets-objects: s3:GetObject on ${aws_s3_bucket.assets.arn}/* not allowed by any evaluated Allow statement"]),
            "trust": v6_iam(excess=[self.TRUST]),
        }
        want = {"excess": 0, "missing": 1, "trust": 2}
        for k, v6 in cases_.items():
            res = self.check(v6)
            tones = [x["tone"] for x in res["items"]]
            self.assertIn("bad", tones, k)
            self.assertEqual(tones[want[k]], "bad", (k, tones))
        r = self.check(cases_["excess"])
        self.assertIn("요구사항 밖 권한: * → 모든 리소스(*)", r["items"][0]["why"])

    def test_unknown_and_draft(self):
        u = self.check(v6_iam(unknown=["aws_iam_role_policy.web_s3_read: policy value unknown at plan time (computed)"]))
        self.assertEqual(u["items"][0]["tone"], "unknown")
        self.assertIn("정책 값이 plan 에 없고 코드에서도 읽지 못함", " ".join(u["items"][0]["why"]))
        d = self.check(v6_iam(), draft=True)
        self.assertEqual([x["word"] for x in d["items"]][:3], ["지킴 — 초안 기준"] * 3)
        self.assertIn("요구사항", d["note"])
        self.assertIn("초안", d["note"])
        no = self.check({"verdict": "NOT_RUN", "summary": "", "details": {}})       # V6 전에 멈춘 수정안 — 조건은 판정 불가 (지킴 아님)
        self.assertEqual(no["items"][0]["tone"], "unknown")


class S3HandoffTests(unittest.TestCase):
    def test_copy_and_trivy(self):
        s3 = (S3_DIR / "s3.tf").read_text(encoding="utf-8")
        for a in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
            self.assertRegex(s3, rf"{a}\s+= false")
        self.assertNotIn("시나리오 2", s3)
        high = sorted((f.rule_id, f.resource) for f in findings(S3_CASE) if f.severity == "HIGH")
        self.assertEqual(high, [(r, "aws_s3_bucket_public_access_block.assets") for r in ("AVD-AWS-0086", "AVD-AWS-0087", "AVD-AWS-0091", "AVD-AWS-0093")])
        self.assertEqual(cases.get_case(S3_CASE)["sets"], [])

    def test_handoff_reads_policy_file_as_is(self):
        pol = json.loads(POLICY.read_text(encoding="utf-8"))
        h = request.meta(S3_CASE)["handoff"]
        self.assertEqual([f["rule"] for f in h["found"]], ["AVD-AWS-0086", "AVD-AWS-0087", "AVD-AWS-0091", "AVD-AWS-0093"])
        sup_has = any(r in pol["supported_target_rules"] for r in ("AVD-AWS-0086", "AVD-AWS-0087", "AVD-AWS-0091", "AVD-AWS-0093"))
        type_ok = "aws_s3_bucket_public_access_block" in pol["allowed_change_resource_types"]
        self.assertEqual(any("자동 수정 대상 규칙에 없음" in w for w in h["why"]), not sup_has)
        self.assertEqual(any("allowed_change_resource_types" in w for w in h["why"]), not type_ok)
        self.assertTrue(any("V6" in w for w in h["why"]))
        self.assertTrue(h["todo"] and h["verify"] and "사람" in h["policy_note"])


class PermPictureTests(unittest.TestCase):
    def setUp(self):
        from test_iam_hcl import INTENT, TEAM_CFG, TEAM_IAM, mk_plan
        self.INTENT, self.IAM = INTENT, TEAM_IAM
        plan = mk_plan(TEAM_CFG)
        plan["planned_values"]["root_module"]["resources"] += [
            {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets", "values": {}},
            {"address": "aws_iam_instance_profile.web", "mode": "managed", "type": "aws_iam_instance_profile", "name": "web", "values": {}},
            {"address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web", "values": {"instance_type": "t3.micro"}}]
        plan["configuration"]["root_module"]["resources"] += [
            {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets", "expressions": {}},
            {"address": "aws_iam_instance_profile.web", "mode": "managed", "type": "aws_iam_instance_profile", "name": "web",
             "expressions": {"role": {"references": ["aws_iam_role.web.name", "aws_iam_role.web"]}}},
            {"address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web",
             "expressions": {"iam_instance_profile": {"references": ["aws_iam_instance_profile.web.name", "aws_iam_instance_profile.web"]}}}]
        self.plan = plan

    def test_edges_pairs_overlay_design_diff(self):
        from iacpatch.verify.v6 import v6_intent_oracle
        m = archmap.build(self.plan, {"iam.tf": self.IAM}, [])
        lab = {n["id"]: n["label"] for n in m["nodes"]}
        perm = [e for e in m["edges"] if e["kind"] == "perm"]
        self.assertEqual([(lab[e["dst"]], e["pairs"]) for e in perm],
                         [("assets", [["s3:GetObject", "tf:aws_s3_bucket.assets.arn/*"], ["s3:ListBucket", "tf:aws_s3_bucket.assets.arn"]])])
        self.assertEqual(perm[0]["docs"], ["data.aws_iam_policy_document.web_s3_read"])
        ov = archmap.iam_overlay(m, v6_intent_oracle(self.plan, {"iam.tf": self.IAM}, self.INTENT).details)
        self.assertEqual({k: v["state"] for k, v in ov["edges"].items()}, {perm[0]["id"]: "ok"})
        # 요구사항 밖 · 꼭 필요한데 없음은 오라클 결과 그대로 옮긴다 (다시 판정하지 않음)
        det = v6_iam(excess=["data.aws_iam_policy_document.web_s3_read#0: s3:GetObject on ${aws_s3_bucket.assets.arn}/*"],
                     missing=["list-assets-bucket: s3:ListBucket on ${aws_s3_bucket.assets.arn} not allowed by any evaluated Allow statement"])["details"]
        ov2 = archmap.iam_overlay(m, det)
        self.assertEqual(ov2["edges"][perm[0]["id"]]["state"], "excess")
        self.assertEqual([(lab[g["src"]], lab[g["dst"]], g["label"], g["state"]) for g in ov2["ghost_edges"]], [("web", "assets", "s3:ListBucket", "missing")])
        dv = archmap.iam_design_view(m, json.loads((SET_DIR / "intents" / "web-role.json").read_text(encoding="utf-8")))
        dl = {n["id"]: n["label"] for n in dv["nodes"]}
        self.assertEqual(sorted((dl[e["src"]], dl[e["dst"]], e["label"]) for e in dv["edges"] if e["kind"] == "perm"), [("web", "assets", "s3:GetObject · s3:ListBucket")])
        role = next(n for n in dv["nodes"] if n["id"] == "n:aws_iam_role.web")
        self.assertIn(("붙여도 되는 AWS 관리형 정책", "AmazonSSMManagedInstanceCore"), [tuple(f) for f in role["facts"]])
        # 적용 전(s3:* on *) → 후(assets 읽기): 권한 선 비교
        before = json.loads(json.dumps(m))
        star = {**perm[0], "id": "e99", "dst": "x:allres", "pairs": [["s3:*", "*"]], "label": "s3:*"}
        before["edges"] = [e for e in before["edges"] if e["kind"] != "perm"] + [star]
        before["nodes"] = before["nodes"] + [{"id": "x:allres", "label": "모든 리소스 (*)"}]
        d = archmap.perm_diff(before, m)
        self.assertEqual(sorted((x["kind"], x["what"]) for x in d), [("added", "assets"), ("removed", "모든 리소스 (*)")])



class RiskFamilyTests(unittest.TestCase):
    """요청 3 의 대상은 data 소스(data.aws_iam_policy_document) — 위험도의 '대상 가족' 이 IAM 이어야 한다 (D-51).
    예전에는 주소의 첫 조각 'data' 를 타입으로 써서 네트워크 가족이 됐고, IAM 정책을 고친 정답 수정안도 '대상 외 종류' +2 를 받았다
    (policy/risk_rubric.json _target_family_note: 'IAM 정책을 고치는 것은 가족 안이라 0점')."""

    def test_target_type_skips_data_and_module(self):
        from iacpatch.policy.risk import target_resource_type
        self.assertEqual(target_resource_type("data.aws_iam_policy_document.web_s3_read"), "aws_iam_policy_document")
        self.assertEqual(target_resource_type("module.ops.aws_iam_policy.worker"), "aws_iam_policy")
        self.assertEqual(target_resource_type("module.a.module.b.data.aws_iam_policy_document.x"), "aws_iam_policy_document")
        self.assertEqual(target_resource_type("aws_vpc_security_group_ingress_rule.bastion_ssh_in"), "aws_vpc_security_group_ingress_rule")
        self.assertIsNone(target_resource_type(""))

    def test_iam_fix_on_data_target_is_inside_family(self):
        from iacpatch.policy.risk import score_risk, target_resource_type
        rubric = json.loads((ROOT / "policy" / "risk_rubric.json").read_text(encoding="utf-8"))
        v5 = {"changed": {"aws_iam_role_policy.web_s3_read": ["policy"]}}
        r = score_risk(rubric, v5, None, {"files": 1}, None, target_type=target_resource_type("data.aws_iam_policy_document.web_s3_read"))
        out = [f for f in r.factors if f["factor"] == "outside_target_family_touched"][0]
        self.assertEqual((out["value"], out["points"]), ([], 0))
        self.assertEqual(r.risk_level.value, "MEDIUM")   # IAM medium floor (점수가 아니라 바닥 규칙으로)
        old = score_risk(rubric, v5, None, {"files": 1}, None, target_type="data")   # 고치기 전에 넘기던 값
        self.assertEqual([f["points"] for f in old.factors if f["factor"] == "outside_target_family_touched"], [2])


if __name__ == "__main__":
    unittest.main()
