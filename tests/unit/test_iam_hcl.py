"""IAM 정책을 코드(HCL)에서 읽기 (15차, D-51) — plan 에 정책 값이 없을 때만, plan 의 configuration 과 맞을 때만.

팀 3계층(infrastructure/three-tier)의 권한 정책은 data "aws_iam_policy_document" 이고 Resource 가 버킷 ARN 을 참조한다.
버킷 이름이 apply 때 정해져서(bucket_prefix) plan 에 policy 값이 없다 → 전에는 V6(IAM) 가 늘 '판정 불가'.
여기서 지키는 것
  - 팀 원본 코드: 코드에서 읽어 참조끼리 비교 → 요구사항(같은 버킷 GetObject · ListBucket)대로면 PASS
  - 코드를 못 믿는 모양(변수 · 함수 · dynamic · 다른 정책 합치기 · 같은 이름 블록 둘 · plan 과 다른 값)은 읽지 않는다 → UNKNOWN (PASS 아님)
  - 토큰 흉내: plan 에 값이 있는 정책에 'tf:...' 글자를 적어도 승인 목록과 같다고 보지 않는다 (UNKNOWN)
  - 코드를 주지 않으면 전과 같다 (UNKNOWN)
plan 은 실제 OpenTofu 1.10.6 plan(2026-11-06 샌드박스, 팀 사본)과 같은 모양을 손으로 줄여 만든다 — tests/fixtures 는 사람만 고치므로 여기 둔다.
"""
from __future__ import annotations

import json
import unittest

from helpers import ROOT

from iacpatch.iam_intent import parse_iam_intent
from iacpatch.models import Verdict
from iacpatch.verify import iam_hcl
from iacpatch.verify.iam_oracle import build_iam_world, evaluate
from iacpatch.verify.v6 import v6_intent_oracle

TEAM_IAM = (ROOT / "scenarios" / "arch" / "three-tier-team" / "iam.tf").read_text(encoding="utf-8")
SSM = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
TRUST = '{"Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}],"Version":"2012-10-17"}'
DOC_START = 'data "aws_iam_policy_document" "web_s3_read" {'
REFS = ["aws_s3_bucket.assets.arn", "aws_s3_bucket.assets"]
TEAM_CFG = [
    {"actions": {"constant_value": ["s3:GetObject"]}, "resources": {"references": REFS}, "sid": {"constant_value": "ReadAssetsObjects"}},
    {"actions": {"constant_value": ["s3:ListBucket"]}, "resources": {"references": REFS}, "sid": {"constant_value": "ListAssetsBucket"}},
]
INTENT = parse_iam_intent({
    "kind": "iam", "intent_id": "t-web-role", "status": "active", "targets": {"roles": ["aws_iam_role.web"]},
    "approved_permissions": [{"actions": ["s3:GetObject"], "resources": ["${aws_s3_bucket.assets.arn}/*"]},
                             {"actions": ["s3:ListBucket"], "resources": ["${aws_s3_bucket.assets.arn}"]}],
    "required_permissions": [{"label": "read-assets", "action": "s3:GetObject", "resource": "${aws_s3_bucket.assets.arn}/*"},
                             {"label": "list-assets", "action": "s3:ListBucket", "resource": "${aws_s3_bucket.assets.arn}"}],
    "approved_managed_policy_arns": [SSM]})


def with_doc(body: str) -> str:
    """팀 iam.tf 에서 web_s3_read data 블록만 바꾼 글자."""
    a = TEAM_IAM.index(DOC_START)
    b = TEAM_IAM.index('resource "aws_iam_role_policy" "web_s3_read"')
    return TEAM_IAM[:a] + DOC_START + "\n" + body + "\n}\n\n" + TEAM_IAM[b:]


def mk_plan(stmt_cfg, policy_known=None, policy_refs=None):
    pol_vals = {"name": "capstone-three-tier-web-s3-read"}
    if policy_known is not None:
        pol_vals["policy"] = policy_known
    return {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": [
            {"address": "aws_iam_role.web", "mode": "managed", "type": "aws_iam_role", "name": "web",
             "values": {"name": "capstone-three-tier-web-role", "assume_role_policy": TRUST}},
            {"address": "aws_iam_role_policy.web_s3_read", "mode": "managed", "type": "aws_iam_role_policy", "name": "web_s3_read", "values": pol_vals},
            {"address": "aws_iam_role_policy_attachment.web_ssm", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "web_ssm",
             "values": {"policy_arn": SSM, "role": "capstone-three-tier-web-role"}},
        ]}},
        "resource_changes": [
            {"address": "aws_iam_role.web", "mode": "managed", "type": "aws_iam_role", "change": {"actions": ["create"], "after_unknown": {"arn": True, "id": True}}},
            {"address": "aws_iam_role_policy.web_s3_read", "mode": "managed", "type": "aws_iam_role_policy",
             "change": {"actions": ["create"], "after_unknown": {"id": True, "role": True, **({"policy": True} if policy_known is None else {})}}},
            {"address": "aws_iam_role_policy_attachment.web_ssm", "mode": "managed", "type": "aws_iam_role_policy_attachment",
             "change": {"actions": ["create"], "after_unknown": {"id": True}}},
        ],
        "configuration": {"root_module": {"resources": [
            {"address": "aws_iam_role.web", "mode": "managed", "type": "aws_iam_role", "name": "web",
             "expressions": {"assume_role_policy": {"references": ["data.aws_iam_policy_document.ec2_assume.json", "data.aws_iam_policy_document.ec2_assume"]}}},
            {"address": "aws_iam_role_policy.web_s3_read", "mode": "managed", "type": "aws_iam_role_policy", "name": "web_s3_read",
             "expressions": {"policy": {"references": policy_refs or ["data.aws_iam_policy_document.web_s3_read.json", "data.aws_iam_policy_document.web_s3_read"]},
                             "role": {"references": ["aws_iam_role.web.id", "aws_iam_role.web"]}}},
            {"address": "aws_iam_role_policy_attachment.web_ssm", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "web_ssm",
             "expressions": {"policy_arn": {"constant_value": SSM}, "role": {"references": ["aws_iam_role.web.name", "aws_iam_role.web"]}}},
            {"address": "data.aws_iam_policy_document.web_s3_read", "mode": "data", "type": "aws_iam_policy_document", "name": "web_s3_read",
             "expressions": {"statement": stmt_cfg}},
        ]}},
    }


def run(iam_text, stmt_cfg=None, policy_known=None, sources=True, policy_refs=None):
    plan = mk_plan(TEAM_CFG if stmt_cfg is None else stmt_cfg, policy_known, policy_refs)
    world = build_iam_world(plan, {"iam.tf": iam_text} if sources else None)
    return evaluate(world, INTENT), world


class SymbolTests(unittest.TestCase):
    def test_symbolize_and_display(self):
        self.assertEqual(iam_hcl.symbolize_pattern("${aws_s3_bucket.assets.arn}/*"), "tf:aws_s3_bucket.assets.arn/*")
        self.assertEqual(iam_hcl.symbolize_pattern("arn:aws:s3:::${aws_s3_bucket.assets.id}/*"), "tf:aws_s3_bucket.assets.arn/*")
        self.assertEqual(iam_hcl.symbolize_pattern("arn:aws:s3:::${aws_s3_bucket.assets.bucket}"), "tf:aws_s3_bucket.assets.arn")
        self.assertEqual(iam_hcl.symbolize_pattern("arn:aws:s3:::literal/*"), "arn:aws:s3:::literal/*")
        self.assertEqual(iam_hcl.symbolize_pattern("${var.bucket}/*"), "${var.bucket}/*")          # 리소스 참조가 아니면 그대로
        self.assertEqual(iam_hcl.display("tf:aws_s3_bucket.assets.arn/*"), "${aws_s3_bucket.assets.arn}/*")
        self.assertEqual(INTENT.required[0].resource, "tf:aws_s3_bucket.assets.arn/*")


class TeamCodeTests(unittest.TestCase):
    def test_team_original_reads_from_code_and_passes(self):
        stmts, via, why = iam_hcl.policy_doc_from_source("aws_iam_role_policy.web_s3_read", mk_plan(TEAM_CFG), {"iam.tf": TEAM_IAM})
        self.assertEqual(why, [])
        self.assertEqual(via, "data.aws_iam_policy_document.web_s3_read")
        self.assertEqual([(s["sid"], s["actions"], s["resources"]) for s in stmts],
                         [("ReadAssetsObjects", ["s3:GetObject"], ["tf:aws_s3_bucket.assets.arn/*"]),
                          ("ListAssetsBucket", ["s3:ListBucket"], ["tf:aws_s3_bucket.assets.arn"])])
        rep, world = run(TEAM_IAM)
        self.assertEqual(rep.verdict, Verdict.PASS, rep.summary)
        self.assertTrue(any("코드의 data.aws_iam_policy_document.web_s3_read 에서 읽음" in x for x in rep.info))
        self.assertEqual(world.notes, [])                                    # 알림(info)은 판정에 붙지 않는다

    def test_without_sources_stays_unknown(self):
        rep, _ = run(TEAM_IAM, sources=False)
        self.assertEqual(rep.verdict, Verdict.UNKNOWN)

    def test_v6_passes_sources_through(self):
        lr = v6_intent_oracle(mk_plan(TEAM_CFG), {"iam.tf": TEAM_IAM}, INTENT)
        self.assertEqual(lr.verdict, Verdict.PASS, lr.summary)
        self.assertIn("info", lr.details)

    def test_s3_arn_from_bucket_id_is_same_bucket(self):
        body = '''  statement {
    sid       = "ReadAssetsObjects"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.assets.id}/*"]
  }

  statement {
    sid       = "ListAssetsBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.assets.arn] # 주석
  }'''
        cfg = [{**TEAM_CFG[0], "resources": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}, TEAM_CFG[1]]
        rep, _ = run(with_doc(body), cfg)
        self.assertEqual(rep.verdict, Verdict.PASS, rep.summary)

    def test_excess_and_missing_are_fail(self):
        body = '''  statement {
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]
  }'''
        cfg = [{"actions": {"constant_value": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]}, "resources": {"references": REFS}}]
        rep, _ = run(with_doc(body), cfg)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        excess = rep.scopes[0].excess
        self.assertTrue(any("s3:PutObject on ${aws_s3_bucket.assets.arn}/*" in x for x in excess), excess)   # 메시지는 코드 모양
        self.assertTrue(any("list-assets" in m for m in rep.scopes[0].missing))

    def test_star_resource_from_code_is_excess(self):
        body = '''  statement {
    actions   = ["s3:GetObject"]
    resources = ["*", "${aws_s3_bucket.assets.arn}/*"]
  }
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.assets.arn]
  }'''
        cfg = [{"actions": {"constant_value": ["s3:GetObject"]}, "resources": {"references": REFS}},
               {"actions": {"constant_value": ["s3:ListBucket"]}, "resources": {"references": REFS}}]
        rep, _ = run(with_doc(body), cfg)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertTrue(any("s3:GetObject on *" in x for x in rep.scopes[0].excess))


class NotTrustedTests(unittest.TestCase):
    """읽지 않는(믿지 않는) 모양 — 모두 UNKNOWN, PASS 가 되면 안 된다."""

    def assert_unknown(self, iam_text, cfg=None, policy_refs=None, why_part=""):
        rep, world = run(iam_text, cfg, policy_refs=policy_refs)
        self.assertEqual(rep.verdict, Verdict.UNKNOWN, rep.summary)
        if why_part:
            self.assertTrue(any(why_part in x for x in world.info), world.info)

    def test_code_and_plan_disagree(self):
        body = '''  statement {
    sid       = "ReadAssetsObjects"
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
  statement {
    sid       = "ListAssetsBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.assets.arn]
  }'''
        self.assert_unknown(with_doc(body), why_part="참조한 리소스와 plan 이 다름")         # plan 은 참조라고 하는데 코드는 '*'
        self.assert_unknown(with_doc(body.split("  statement {")[0] + "  statement {" + body.split("  statement {")[1]), why_part="statement 수")

    def test_dynamic_variable_function_template(self):
        dyn = '''  dynamic "statement" {
    for_each = var.stmts
    content {
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }'''
        self.assert_unknown(with_doc(dyn), why_part="dynamic")
        var = TEAM_IAM.replace('resources = ["${aws_s3_bucket.assets.arn}/*"]', 'resources = ["${var.bucket_arn}/*"]')
        self.assert_unknown(var, why_part="지원하지 않는 보간")
        fn = TEAM_IAM.replace('resources = ["${aws_s3_bucket.assets.arn}/*"]', 'resources = [format("%s/*", aws_s3_bucket.assets.arn)]')
        self.assert_unknown(fn, why_part="값을 읽을 수 없음")
        tpl = TEAM_IAM.replace('resources = ["${aws_s3_bucket.assets.arn}/*"]', 'resources = ["%{ if true }${aws_s3_bucket.assets.arn}/*%{ endif }"]')
        self.assert_unknown(tpl, why_part="템플릿 지시자")

    def test_merging_other_documents_and_duplicates(self):
        merged = TEAM_IAM.replace(DOC_START, DOC_START + "\n  source_policy_documents = [data.aws_iam_policy_document.ec2_assume.json]")
        self.assert_unknown(merged, why_part="source_policy_documents")
        dup = TEAM_IAM + "\n" + TEAM_IAM[TEAM_IAM.index(DOC_START):TEAM_IAM.index('resource "aws_iam_role_policy" "web_s3_read"')]
        self.assert_unknown(dup, why_part="블록이 2개")

    def test_policy_attribute_must_be_the_document_json(self):
        wrapped = TEAM_IAM.replace("policy = data.aws_iam_policy_document.web_s3_read.json",
                                   'policy = replace(data.aws_iam_policy_document.web_s3_read.json, "GetObject", "*")')
        self.assert_unknown(wrapped, why_part="그대로 쓰는 경우만")
        self.assert_unknown(TEAM_IAM, policy_refs=["data.aws_iam_policy_document.web_s3_read.json", "var.extra"], why_part="하나만 참조하지 않음")

    def test_condition_and_principal_are_unknown_not_pass(self):
        cond = TEAM_IAM.replace('    resources = ["${aws_s3_bucket.assets.arn}/*"]\n',
                                '    resources = ["${aws_s3_bucket.assets.arn}/*"]\n    condition {\n      test     = "Bool"\n      variable = "aws:SecureTransport"\n      values   = ["true"]\n    }\n')
        cfg = [{**TEAM_CFG[0], "condition": [{"test": {"constant_value": "Bool"}}]}, TEAM_CFG[1]]
        rep, _ = run(cond, cfg)
        self.assertEqual(rep.verdict, Verdict.UNKNOWN, rep.summary)
        self.assertTrue(any("Condition" in x for x in rep.scopes[0].unknown_reasons))

    def test_token_literal_in_code_or_plan_is_not_trusted(self):
        lit = TEAM_IAM.replace('resources = ["${aws_s3_bucket.assets.arn}/*"]', 'resources = ["tf:aws_s3_bucket.assets.arn/*"]')
        cfg = [{**TEAM_CFG[0], "resources": {"constant_value": ["tf:aws_s3_bucket.assets.arn/*"]}}, TEAM_CFG[1]]
        rep, _ = run(lit, cfg)
        self.assertEqual(rep.verdict, Verdict.UNKNOWN, rep.summary)
        # plan 에 값이 있는 정책(JSON)에 토큰을 흉내 낸 글자 — 승인 목록과 같다고 보지 않는다
        spoof = json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "tf:aws_s3_bucket.assets.arn/*"},
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "tf:aws_s3_bucket.assets.arn"}]})
        rep2, _ = run(TEAM_IAM, policy_known=spoof)
        self.assertNotEqual(rep2.verdict, Verdict.PASS, rep2.summary)
        self.assertTrue(any("internal reference token" in x for x in rep2.scopes[0].unknown_reasons))

    def test_known_policy_ignores_code(self):
        """plan 에 값이 있으면 코드를 읽지 않는다 — 망가뜨린 상태(s3:* on *)는 plan 값으로 FAIL."""
        broad = json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "WebS3All", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
        rep, world = run(TEAM_IAM, policy_known=broad)
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertEqual(world.info, [])


if __name__ == "__main__":
    unittest.main()
