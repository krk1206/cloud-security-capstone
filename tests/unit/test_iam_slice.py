"""IAM Tier-1 슬라이스 — intent 로더, IAM Intent Oracle(V6), 규칙 기반 생성기, V6 분기. 외부 도구·AWS 없음.

plan fixture 는 tests/fixtures/plans/iam-*/plan.json — scenarios/eval/iam-report-worker 원본 + eval-seeded-iam 후보를
OpenTofu 1.10.6 + AWS provider 5.100.0 오프라인 plan 으로 만든 **실제 plan JSON** 이다 (2026-09-22, 샌드박스). trivy.json 은 같은 후보의 Trivy 0.74.0 스캔.
"""
import json
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch.config import load_json
from iacpatch.evidence import build_bundle
from iacpatch.generator.rule_based import RuleBasedGenerator
from iacpatch.iam_intent import IamIntentSpec, IntentError, load_iam_intent, parse_iam_intent, try_load_any_intent
from iacpatch.models import Verdict
from iacpatch.review.inputs import list_findings, load_trivy_report
from iacpatch.verify.iam_oracle import build_iam_world, evaluate, pattern_subset
from iacpatch.verify.v6 import v6_intent_oracle

PLANS = ROOT / "tests" / "fixtures" / "plans"
INTENT = ROOT / "experiments" / "candidate-sets" / "eval-seeded-iam" / "intent.json"
SCEN = ROOT / "scenarios" / "eval" / "iam-report-worker"
POLICY = load_json(ROOT / "policy" / "patch_policy.json")


def plan(name):
    return json.loads((PLANS / f"iam-{name}" / "plan.json").read_text(encoding="utf-8"))


class PatternTests(unittest.TestCase):
    def test_subset_semantics(self):
        self.assertTrue(pattern_subset("s3:GetObject", "s3:Get*", True))
        self.assertTrue(pattern_subset("s3:Get*", "s3:Get*", True))
        self.assertTrue(pattern_subset("S3:GETOBJECT", "s3:GetObject", True))          # action 은 대소문자 무시
        self.assertFalse(pattern_subset("s3:*", "s3:Get*", True))                       # 더 넓은 패턴은 포함 안 됨
        self.assertFalse(pattern_subset("*", "s3:*", True))
        self.assertTrue(pattern_subset("*", "*", True))
        self.assertTrue(pattern_subset("arn:aws:s3:::app-data/*", "arn:aws:s3:::app-data/*", False))
        self.assertFalse(pattern_subset("arn:aws:s3:::App-Data/*", "arn:aws:s3:::app-data/*", False))  # resource 는 구분
        self.assertFalse(pattern_subset("arn:aws:s3:::*", "arn:aws:s3:::app-data/*", False))


class IntentTests(unittest.TestCase):
    def test_load_and_kind_dispatch(self):
        spec, kind, err = try_load_any_intent(INTENT)
        self.assertEqual(kind, "iam"); self.assertIsNone(err); self.assertIsInstance(spec, IamIntentSpec)
        self.assertEqual(spec.target_policies, ["aws_iam_policy.worker"])
        self.assertEqual(len(spec.required), 2)
        sg, kind2, _ = try_load_any_intent(ROOT / "policy" / "intent" / "sg-baseline.json")
        self.assertEqual(kind2, "sg"); self.assertIsNotNone(sg)

    def test_rejects_bad_intents(self):
        base = json.loads(INTENT.read_text(encoding="utf-8"))
        with self.assertRaises(IntentError):
            parse_iam_intent(dict(base, approved_permissions=[]))            # 빈 승인 집합 금지
        with self.assertRaises(IntentError):
            parse_iam_intent(dict(base, targets={}))
        with self.assertRaises(IntentError):
            parse_iam_intent(dict(base, kind="sg"))
        bad = dict(base); bad["approved_permissions"] = [{"actions": ["<FILL>"], "resources": ["*"]}]
        with self.assertRaises(IntentError):
            parse_iam_intent(bad)                                             # 자리표시자


class OracleOnRealPlansTests(unittest.TestCase):
    """seeded 13 + 원본 1 의 실제 plan 에 대한 오라클 판정 — 라벨은 manifest 의 expected 와 같은 근거로 고정."""
    EXPECT = {
        "00-report-worker": Verdict.FAIL, "correct-least-privilege": Verdict.PASS,
        "deceptive-star-action": Verdict.FAIL, "deceptive-enumerated-actions": Verdict.FAIL, "deceptive-resource-star": Verdict.FAIL,
        "deceptive-notaction": Verdict.UNKNOWN, "deceptive-condition-s3star": Verdict.UNKNOWN,
        "deceptive-inline-role-policy": Verdict.FAIL, "deceptive-second-policy": Verdict.FAIL,
        "unapproved-managed-policy": Verdict.UNKNOWN, "breaks-required-missing-list": Verdict.FAIL,
        "breaks-required-wrong-bucket": Verdict.FAIL, "invalid-identical": Verdict.FAIL,
        "unapproved-trust-policy-open": Verdict.FAIL,   # 09-22 교차검증 후: Principal '*' 무조건 신뢰는 EXCESS 로 FAIL (이전엔 PASS, V5·기준표에만 의존)
    }
    ATTACKS = ["b1-ref-launder", "b2-inline-unknown", "b3-module", "b4-attachments-exclusive", "b5-policy-attachment", "b9c", "b13-two-refs"]

    def setUp(self):
        self.intent = load_iam_intent(INTENT)

    def test_all_cases(self):
        for name, exp in self.EXPECT.items():
            rep = evaluate(build_iam_world(plan(name)), self.intent)
            self.assertEqual(rep.verdict, exp, f"{name}: {rep.summary}")

    def test_role_aggregation_and_reasons(self):
        rep = evaluate(build_iam_world(plan("deceptive-inline-role-policy")), self.intent)
        by = {s.scope_id: s for s in rep.scopes}
        self.assertEqual(by["aws_iam_policy.worker"].verdict, Verdict.PASS)          # 대상 정책만 보면 정상
        self.assertEqual(by["aws_iam_role.worker"].verdict, Verdict.FAIL)            # 역할 합산에서 inline * 가 EXCESS
        self.assertTrue(any("inline_policy" in e for e in by["aws_iam_role.worker"].excess))
        rep2 = evaluate(build_iam_world(plan("deceptive-second-policy")), self.intent)
        self.assertTrue(any("worker_ops" in e for s in rep2.scopes for e in s.excess))
        rep3 = evaluate(build_iam_world(plan("breaks-required-missing-list")), self.intent)
        self.assertTrue(any("ListBucket" in m for s in rep3.scopes for m in s.missing))
        rep4 = evaluate(build_iam_world(plan("unapproved-managed-policy")), self.intent)
        self.assertTrue(any("AmazonS3ReadOnlyAccess" in u for s in rep4.scopes for u in s.unknown_reasons))
        self.assertFalse(any(s.excess or s.missing for s in rep4.scopes))            # UNKNOWN 이지 FAIL 이 아니다

    def test_scanner_blind_cases_are_caught_by_oracle(self):
        """스캐너 PASS ∧ 오라클 FAIL 원자료: 실제 trivy.json + 실제 plan."""
        blind = []
        for name in ("deceptive-star-action", "deceptive-enumerated-actions", "deceptive-resource-star", "deceptive-inline-role-policy", "deceptive-second-policy"):
            fails = list_findings(load_trivy_report(PLANS / f"iam-{name}" / "trivy.json"))
            self.assertEqual(fails, [], f"{name}: scanner should be blind, got {[f.rule_id for f in fails]}")
            self.assertEqual(evaluate(build_iam_world(plan(name)), self.intent).verdict, Verdict.FAIL)
            blind.append(name)
        self.assertEqual(len(blind), 5)
        # 원본은 스캐너도 잡는다 (AVD-AWS-0345), 그리고 중복 finding 은 하나로 합쳐진다
        fails = list_findings(load_trivy_report(SCEN / "trivy-scan.json"))
        self.assertEqual([f.rule_id for f in fails], ["AVD-AWS-0345"])

    def test_cross_verification_attacks_never_pass(self):
        """docs/CROSS_VERIFICATION_2026-09-22.md 의 false-PASS 7건 (tests/fixtures/plans/iam-x-*). 수정 후 PASS 가 나오면 회귀."""
        for name in self.ATTACKS:
            rep = evaluate(build_iam_world(plan(f"x-{name}")), self.intent)
            self.assertNotEqual(rep.verdict, Verdict.PASS, f"{name}: {rep.summary}")
        self.assertEqual(evaluate(build_iam_world(plan("x-b3-module")), self.intent).verdict, Verdict.FAIL)

    def test_document_tricks_never_pass(self):
        """중복 키·유니코드 대소문자·공백·모듈 접두 — 교차검증 #7/#8."""
        import copy
        base = plan("correct-least-privilege")
        def with_policy(text):
            p = copy.deepcopy(base)
            for r in p["planned_values"]["root_module"]["resources"]:
                if r["address"] == "aws_iam_policy.worker":
                    r["values"]["policy"] = text
            return p
        dup = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::report-archive","arn:aws:s3:::report-archive/*"]}]}'
        self.assertEqual(evaluate(build_iam_world(with_policy(dup)), self.intent).verdict, Verdict.UNKNOWN)
        homoglyph = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["\u017f3:GetObject", "s3:ListBucKet".replace("K", "\u212a")],
                                                                        "Resource": ["arn:aws:s3:::report-archive", "arn:aws:s3:::report-archive/*"]}]})
        self.assertNotEqual(evaluate(build_iam_world(with_policy(homoglyph)), self.intent).verdict, Verdict.PASS)
        self.assertFalse(pattern_subset("s3:GetObject\n", "s3:GetObject", True))
        self.assertFalse(pattern_subset("\u017f3:GetObject", "s3:GetObject", True))

    def test_v6_layer_dispatches_to_iam(self):
        lr = v6_intent_oracle(plan("deceptive-star-action"), {}, self.intent)
        self.assertEqual(lr.layer, "V6"); self.assertEqual(lr.verdict, Verdict.FAIL)
        self.assertEqual(lr.details.get("kind"), "iam"); self.assertEqual(lr.tool, "iacpatch.iam_oracle")
        lr2 = v6_intent_oracle(plan("correct-least-privilege"), {}, self.intent)
        self.assertEqual(lr2.verdict, Verdict.PASS)


class RuleBasedIamTests(unittest.TestCase):
    def _bundle(self, files_override=None, intent_override=None):
        report = load_trivy_report(SCEN / "trivy-scan.json")
        findings = list_findings(report)
        target = findings[0]
        files = {"main.tf": (SCEN / "main.tf").read_text(encoding="utf-8")}
        if files_override:
            files = dict(files, **files_override)
        intent = intent_override if intent_override is not None else json.loads(INTENT.read_text(encoding="utf-8"))
        return build_bundle("iam-t", "scenarios/eval/iam-report-worker", target, findings, files, intent, POLICY, {}, {})

    def test_single_statement_literal_is_rewritten(self):
        c = RuleBasedGenerator().generate(self._bundle())
        self.assertEqual(c.status, "PATCH", c.error)
        new = c.files["main.tf"]
        self.assertIn('Action   = ["s3:GetObject", "s3:ListBucket"]', new)
        self.assertIn('Resource = ["arn:aws:s3:::report-archive", "arn:aws:s3:::report-archive/*"]', new)
        self.assertNotIn('"s3:*"', new)
        self.assertIn("rule-based IAM", c.rationale)

    def test_unsupported_shapes_abstain(self):
        orig = (SCEN / "main.tf").read_text(encoding="utf-8")
        two_stmts = orig.replace('    }]\n  })\n}\n\nresource "aws_iam_role_policy_attachment"',
                                 '    }, {\n      Effect   = "Allow"\n      Action   = ["s3:ListAllMyBuckets"]\n      Resource = "*"\n    }]\n  })\n}\n\nresource "aws_iam_role_policy_attachment"')
        self.assertNotEqual(two_stmts, orig)
        c = RuleBasedGenerator().generate(self._bundle({"main.tf": two_stmts}))
        self.assertEqual(c.status, "NOT_SUPPORTED")
        cond = orig.replace('      Resource = "*"', '      Resource = "*"\n      Condition = { IpAddress = { "aws:SourceIp" = "10.0.0.0/8" } }')
        c2 = RuleBasedGenerator().generate(self._bundle({"main.tf": cond}))
        self.assertEqual(c2.status, "NOT_SUPPORTED")
        var = orig.replace('Action   = ["s3:*"]', 'Action   = var.actions')
        c3 = RuleBasedGenerator().generate(self._bundle({"main.tf": var}))
        self.assertEqual(c3.status, "NOT_SUPPORTED")
        intent = json.loads(INTENT.read_text(encoding="utf-8"))
        intent["approved_permissions"].append({"actions": ["sqs:SendMessage"], "resources": ["arn:aws:sqs:ap-northeast-2:123456789012:q"]})
        c4 = RuleBasedGenerator().generate(self._bundle(intent_override=intent))
        self.assertEqual(c4.status, "NOT_SUPPORTED")                                 # 문을 나눠야 하는 경우


if __name__ == "__main__":
    unittest.main()
