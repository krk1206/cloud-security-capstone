"""팀 3계층 요청 4 ~ 11 (16차, D-52 — B 2026-11-06 "4개도 너무 적음 … 실시간으로 … 실제 기반처럼").

지켜야 하는 것
  - 새 사본 8개 = 요청 1 · 3 을 고친 코드(요청 3 사본의 .tf + 팀 원본 iam.tf)에서 README 표에 적은 곳만 다르다 (요청 9 · 10 은 같음 — 원래 있던 지적)
  - Trivy: 넣은 설정 오류마다 정해 둔 지적 1건만 늘고, 나머지 지적(MEDIUM 2 · LOW 3)은 그대로. 요청 9 · 10 의 대상은 원래 있던 지적
  - 수정안 세트 2개(요청 4 DB 보안 그룹 · 요청 6 업로드): expected 는 실행 전 고정값 그대로 · 화면 1번이 정답이 아님 · 파일이 모두 있음
  - 사람에게 넘김 6건(요청 5 · 7 ~ 11): Trivy 결과 · plan 값 · 정책 파일만 옮긴다 — 지금 값 · 요청한 값 · 정책 이유 · 할 일 · 확인 방법. 정책 파일은 바꾸지 않는다
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import ROOT

from iacpatch.review.inputs import list_findings, load_trivy_report
from iacpatch.web import cases, request

A = ROOT / "scenarios" / "arch"
SETS = ROOT / "experiments" / "candidate-sets"
POLICY = ROOT / "policy" / "patch_policy.json"
TF = ["alb.tf", "bastion.tf", "iam.tf", "monitoring.tf", "network.tf", "outputs.tf", "provider.tf", "rds.tf", "s3.tf", "security_groups.tf", "variables.tf", "web_asg.tf"]
BASE_FINDINGS = {("AVD-AWS-0017", "aws_cloudwatch_log_group.web"), ("AVD-AWS-0089", "aws_s3_bucket.assets"), ("AVD-AWS-0133", "aws_db_instance.mysql"),
                 ("AVD-AWS-0177", "aws_db_instance.mysql"), ("AVD-AWS-0178", "aws_vpc.main")}
# 사본마다: 원본(고친 코드)과 다른 곳 = (파일, 원본 글자, 바뀐 글자) — README 표와 같은 것
CHANGES = {
    "dbsg": [("security_groups.tf", '''  security_group_id            = aws_security_group.db.id
  description                  = "MySQL from bastion"
  referenced_security_group_id = aws_security_group.bastion.id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
}''', '''  security_group_id = aws_security_group.db.id
  description       = "MySQL from bastion"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}''')],
    "dbpublic": [("rds.tf", "publicly_accessible    = false", "publicly_accessible    = true ")],
    "upload": [("iam.tf", "# iam.tf - WEB 인스턴스가 쓰는 IAM 역할. 최소 권한: 이 버킷 읽기 + SSM 접속만.\n# 우리 연구의 시나리오 3(IAM 과다 권한)은 이 정책이 \"Action\": \"*\", \"Resource\": \"*\"인 상태를 뜻한다.\n",
                "# iam.tf - WEB 인스턴스가 쓰는 IAM 역할.\n"),
               ("iam.tf", "# 권한 정책: 무엇을 할 수 있나 -> assets 버킷 객체 읽기, 목록 조회. 리소스를 ARN으로 못 박는다.", "# 권한 정책: 무엇을 할 수 있나"),
               ("iam.tf", '''    resources = [aws_s3_bucket.assets.arn]
  }
}''', '''    resources = [aws_s3_bucket.assets.arn]
  }

  statement {
    sid       = "UploadAssets"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]
  }
}''')],
    "imds": [("web_asg.tf", 'http_tokens                 = "required"', 'http_tokens                 = "optional"')],
    "dbenc": [("rds.tf", "storage_encrypted = true", "storage_encrypted = false")],
    "deletion": [],
    "flowlog": [],
    "backup": [("rds.tf", "backup_retention_period             = 7 ", "backup_retention_period             = 1 ")],
}
INTENDED = {"dbsg": ("AVD-AWS-0107", "aws_vpc_security_group_ingress_rule.db_from_bastion"), "dbpublic": ("AVD-AWS-0180", "aws_db_instance.mysql"),
            "upload": ("AVD-AWS-0345", "data.aws_iam_policy_document.web_s3_read"), "imds": ("AVD-AWS-0130", "aws_launch_template.web"),
            "dbenc": ("AVD-AWS-0080", "aws_db_instance.mysql"), "deletion": ("AVD-AWS-0177", "aws_db_instance.mysql"),
            "flowlog": ("AVD-AWS-0178", "aws_vpc.main"), "backup": ("AVD-AWS-0077", "aws_db_instance.mysql")}
HANDOFF = ["dbpublic", "imds", "dbenc", "deletion", "flowlog", "backup"]
DBSG, UPLOAD = "three-tier-team-dbsg", "three-tier-team-upload"


def base_text(name: str) -> str:
    src = A / ("three-tier-team" if name == "iam.tf" else "three-tier-team-iam") / name
    return src.read_text(encoding="utf-8")


def fails(cid: str):
    c = cases.get_case(cid)
    return {(f.rule_id, f.resource) for f in list_findings(load_trivy_report(ROOT / c["trivy_json"])) if f.status == "FAIL"}


class CopyTests(unittest.TestCase):
    def test_copies_differ_only_where_readme_says(self):
        for x, changes in CHANGES.items():
            d = A / f"three-tier-team-{x}"
            extra = ["DESIGN.md"] if x in ("dbsg", "upload") else []
            self.assertEqual(sorted(p.name for p in d.iterdir()), sorted(TF + ["README.md"] + extra), x)
            readme = (d / "README.md").read_text(encoding="utf-8")
            self.assertIn("가상", readme)
            for name in TF:
                want = base_text(name)
                for f, old, new in changes:
                    if f == name:
                        self.assertEqual(want.count(old), 1, (x, f, old[:40]))
                        want = want.replace(old, new)
                        self.assertIn(f"`{f}`", readme, x)               # 다른 곳은 README 표에 있다
                self.assertEqual((d / name).read_text(encoding="utf-8"), want, (x, name))
        self.assertNotIn("시나리오 3", (A / "three-tier-team-upload" / "iam.tf").read_text(encoding="utf-8"))   # 답이 되는 주석은 README 에만 (D-32)

    def test_trivy_adds_only_the_intended_finding(self):
        for x, (rule, res) in INTENDED.items():
            got = fails(f"three-tier-team-{x}")
            self.assertTrue(BASE_FINDINGS <= got, x)
            self.assertEqual(got - BASE_FINDINGS, set() if x in ("deletion", "flowlog") else {(rule, res)}, x)
            self.assertIn((rule, res), got, x)


class CandidateSetTests(unittest.TestCase):
    WANT = {"three-tier-team-dbsg": ({"open-3306": "deceptive", "split-cidr": "deceptive", "fix-bastion": "correct", "vpc-all": "unapproved",
                                      "remove-rule": "breaks_required", "rule-based": "unsupported"},
                                     ["open-3306", "split-cidr", "fix-bastion", "vpc-all"], ("AVD-AWS-0107", "aws_vpc_security_group_ingress_rule.db_from_bastion", "security_groups.tf", 134)),
            "three-tier-team-upload": ({"put-star": "deceptive", "fix-put": "correct", "remove-upload": "breaks_required", "put-delete": "unapproved",
                                        "get-put-star": "deceptive", "rule-based": "unsupported"},
                                       ["put-star", "fix-put", "remove-upload", "put-delete"], ("AVD-AWS-0345", "data.aws_iam_policy_document.web_s3_read", "iam.tf", 22))}

    def test_expected_fixed_before_running(self):
        sup = json.loads(POLICY.read_text(encoding="utf-8"))["supported_target_rules"]
        for sid, (exp, featured, target) in self.WANT.items():
            man = json.loads((SETS / sid / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual({c["id"]: c["expected"] for c in man["candidates"]}, exp, sid)
            self.assertEqual(man["featured"], featured, sid)
            self.assertNotEqual(exp[featured[0]], "correct", sid)           # 정답이 1번이 아님
            self.assertEqual((man["rule"], man["resource"], man["file"], man["line"]), target, sid)
            self.assertIn(man["rule"], sup, sid)                             # 자동 수정 대상 규칙
            self.assertIs(man["week4_label_replay"], False)
            self.assertEqual(man["tf_dir"], f"scenarios/arch/{sid}")
            self.assertTrue((ROOT / man["intent"]).is_file(), sid)
            texts = []
            for c in man["candidates"]:
                if c["candidate"].startswith("manual:"):
                    p = SETS / sid / c["candidate"].split(":", 1)[1]
                    self.assertTrue(p.is_file(), (sid, c["id"]))
                    texts.append(p.read_text(encoding="utf-8"))
                else:
                    self.assertEqual(c["candidate"], "rule_based", (sid, c["id"]))
            self.assertEqual(len(set(texts)), len(texts), sid)               # 수정안끼리 서로 다름
            case = cases.get_case(sid)
            self.assertEqual([s["set_id"] for s in case["sets"]], [sid])
            self.assertEqual(request.case_for_set(sid), sid)

    def test_correct_fixes(self):
        fix = (SETS / "three-tier-team-dbsg" / "candidates" / "fix-bastion.tf").read_text(encoding="utf-8")
        self.assertIn(base_text("security_groups.tf").split('resource "aws_vpc_security_group_ingress_rule" "db_from_bastion"')[1].split("}")[0], fix)   # 팀 원본 규칙 그대로
        put = (SETS / "three-tier-team-upload" / "candidates" / "fix-put.tf").read_text(encoding="utf-8")
        self.assertIn('actions   = ["s3:PutObject"]', put)
        self.assertNotIn('"s3:*"', put)


def _plan(resources):
    return {"format_version": "1.2", "planned_values": {"root_module": {"resources": resources}}, "resource_changes": [], "configuration": {"root_module": {"resources": []}}}


class HandoffTests(unittest.TestCase):
    """요청 5 · 7 ~ 11 — '사람에게 넘김' 칸은 기록을 옮길 뿐이다."""

    def setUp(self):
        self.pol_sha = hashlib.sha256(POLICY.read_bytes()).hexdigest()
        self.pol = json.loads(POLICY.read_text(encoding="utf-8"))

    def tearDown(self):
        self.assertEqual(hashlib.sha256(POLICY.read_bytes()).hexdigest(), self.pol_sha, "정책 파일이 바뀌면 안 됨")

    def test_found_why_todo_verify(self):
        for x in HANDOFF:
            cid = f"three-tier-team-{x}"
            case = cases.get_case(cid)
            self.assertEqual((case["sets"], case.get("fix_scope")), ([], "out_of_policy"), x)
            spec = request.REQUESTS[cid]["handoff"]
            rule, res = INTENDED[x]
            self.assertEqual((spec["rules"], spec["resource"]), ([rule], res), x)
            h = request.handoff(cid)
            self.assertEqual([(f["rule"], f["file"]) for f in h["found"]], [(rule, spec["file"])], x)
            self.assertEqual(any("자동 수정 대상 규칙에 없음" in w for w in h["why"]), rule not in self.pol["supported_target_rules"], x)
            rtype = h["resource"].split(".")[0]
            self.assertEqual(any("allowed_change_resource_types" in w for w in h["why"]),
                             rtype not in self.pol["allowed_change_resource_types"] and not spec.get("absent"), x)
            self.assertTrue(any("V6" in w for w in h["why"]), x)
            self.assertIn(rule.replace("AVD-", ""), h["verify"][0], x)            # 확인 첫 줄 = 다시 점검해서 그 지적이 없어졌는지
            self.assertIn("PR", h["todo"][-1], x)
            self.assertIn("사람", h["policy_note"], x)
        flow = request.handoff("three-tier-team-flowlog")
        need = [t for t in request.REQUESTS["three-tier-team-flowlog"]["handoff"]["create"] if t not in self.pol.get("allowed_create_resource_types", [])]
        self.assertEqual(any("새 리소스를 만들어야 함" in w for w in flow["why"]), bool(need))
        enc = request.handoff("three-tier-team-dbenc")
        self.assertIn(request.REQUESTS["three-tier-team-dbenc"]["handoff"]["replace"], enc["why"])

    def test_now_rows_from_plan(self):
        vals = {"publicly_accessible": True, "storage_encrypted": False, "deletion_protection": False, "skip_final_snapshot": True, "backup_retention_period": 1}
        lt = {"metadata_options": [{"http_tokens": "optional", "http_endpoint": "enabled"}]}
        res = [{"address": "aws_db_instance.mysql", "type": "aws_db_instance", "values": vals},
               {"address": "aws_launch_template.web", "type": "aws_launch_template", "values": lt},
               {"address": "aws_vpc.main", "type": "aws_vpc", "values": {}}]
        with tempfile.TemporaryDirectory() as td:
            pp = Path(td) / "plan.json"
            pp.write_text(json.dumps(_plan(res)), encoding="utf-8")
            with mock.patch("iacpatch.web.cases._baseline_plan_path", return_value=(pp, "시험 plan")):
                rows = {x: request.handoff(f"three-tier-team-{x}")["now"] for x in HANDOFF}
                note = request.handoff("three-tier-team-backup")["plan_note"]
            pp.write_text(json.dumps(_plan(res + [{"address": "aws_flow_log.vpc", "type": "aws_flow_log", "values": {}}])), encoding="utf-8")
            with mock.patch("iacpatch.web.cases._baseline_plan_path", return_value=(pp, "시험 plan")):
                flow_ok = request.handoff("three-tier-team-flowlog")["now"]
            pp.write_text(json.dumps(_plan([])), encoding="utf-8")
            with mock.patch("iacpatch.web.cases._baseline_plan_path", return_value=(pp, "시험 plan")):
                gone = request.handoff("three-tier-team-backup")
        self.assertEqual(rows["dbpublic"], [{"attr": "publicly_accessible", "value": "true", "want": "false", "ok": False}])
        self.assertEqual(rows["imds"], [{"attr": "metadata_options.0.http_tokens", "value": "optional", "want": "required", "ok": False}])
        self.assertEqual(rows["dbenc"], [{"attr": "storage_encrypted", "value": "false", "want": "true", "ok": False}])
        self.assertEqual(rows["deletion"], [{"attr": "deletion_protection", "value": "false", "want": "true", "ok": False},
                                            {"attr": "skip_final_snapshot", "value": "true", "want": "false", "ok": False}])
        self.assertEqual(rows["backup"], [{"attr": "backup_retention_period", "value": "1", "want": "7", "ok": False}])
        self.assertEqual([(r["value"], r["ok"]) for r in rows["flowlog"]], [("0개 (코드에 없음)", False)])
        self.assertEqual([(r["value"], r["ok"]) for r in flow_ok], [("1개", True)])
        self.assertEqual(note, "원본 plan 의 값 (AWS 접속 없이 코드에서 계산)")
        self.assertEqual((gone["now"], gone["plan_note"]), ([], "원본 plan 에 aws_db_instance.mysql 가 없음"))

    def test_s3_still_works_with_generic_rows(self):
        with tempfile.TemporaryDirectory() as td:
            pp = Path(td) / "plan.json"
            vals = {a: False for a in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")}
            pp.write_text(json.dumps(_plan([{"address": "aws_s3_bucket_public_access_block.assets", "type": "aws_s3_bucket_public_access_block", "values": vals}])), encoding="utf-8")
            with mock.patch("iacpatch.web.cases._baseline_plan_path", return_value=(pp, "시험 plan")):
                now = request.handoff("three-tier-team-s3")["now"]
        self.assertEqual([(r["attr"], r["value"], r["want"], r["ok"]) for r in now],
                         [(a, "false", "true", False) for a in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")])


class RequestCheckTests(unittest.TestCase):
    """요청 4 (DB 보안 그룹) · 요청 6 (업로드) 의 조건 결과 = 기록 값(V1 · V6 · ⑥ 질문)을 조건대로 모은 것."""

    def test_dbsg_conditions(self):
        from test_request import _ctx, _tones
        self.assertEqual(_tones(request.check(DBSG, _ctx())), ["good", "good", "good", "good", "wait"])
        for ex, want in [([{"src": "internet", "dst": "db", "ports": "TCP 전체 포트", "kind": "not_designed"}], 0),          # DB 를 인터넷에 (조건 1)
                         ([{"src": "vpc", "dst": "db", "ports": "3306", "kind": "not_designed"}], 0),                        # VPC 전체에서 DB (조건 1)
                         ([{"src": "internet", "dst": "bastion", "ports": "22", "kind": "outside_approved"}], 2),             # SSH 를 다시 엶 (조건 3)
                         ([{"src": "internet", "dst": "web", "ports": "8080", "kind": "not_designed"}], 3)]:                 # 그 밖 (조건 4)
            tones = _tones(request.check(DBSG, _ctx(v6="FAIL", excess=ex)))
            self.assertEqual(tones.index("bad"), want, (ex, tones))
            self.assertEqual(tones.count("bad"), 1, (ex, tones))

    def test_upload_conditions(self):
        from test_team_requests import v6_iam
        good_q = [{"key": "scope", "tone": "good"}, {"key": "new", "tone": "good"}]
        ctx = {"v1": "PASS", "v6": v6_iam(), "rule": "AVD-AWS-0345", "questions": good_q, "decision": {}, "post": {}, "draft": False}
        r = request.check(UPLOAD, ctx)
        self.assertEqual([x["tone"] for x in r["items"]], ["good", "good", "good", "wait"])
        self.assertIn("읽기 · 목록 · 올리기", " ".join(x["text"] for x in r["items"][1]["lines"]))
        miss = v6_iam(missing=["upload-assets: s3:PutObject on ${aws_s3_bucket.assets.arn}/* not allowed by any evaluated Allow statement"])
        self.assertEqual([x["tone"] for x in request.check(UPLOAD, {**ctx, "v6": miss})["items"]][:3], ["good", "bad", "good"])
        wide = v6_iam(excess=["data.aws_iam_policy_document.web_s3_read#2: s3:* on ${aws_s3_bucket.assets.arn}/*"])
        self.assertEqual([x["tone"] for x in request.check(UPLOAD, {**ctx, "v6": wide})["items"]][:3], ["bad", "good", "good"])


class V5NoChangeTests(unittest.TestCase):
    """요청 6 에서 드러난 표시 오류 (16차): V5 WARN(plan 에서 바뀐 리소스 없음)을 ⑥ 이 '예, 범위 밖 변경'(빨강)으로 보였다 — 결론('모두 통과')과 어긋남."""

    def view(self, v5):
        from iacpatch.web import product
        layers = [{"layer": f"V{i}", "verdict": "PASS", "summary": ""} for i in (1, 2, 3, 4, 6)] + [v5]
        rv = {"layers": layers, "policy": {"ok": True}, "design": {}, "set": {"set_id": "nope"}, "problems": []}
        with tempfile.TemporaryDirectory() as td, mock.patch.dict("os.environ", {"IACPATCH_REVIEWS_DIR": td}), \
                mock.patch("iacpatch.web.server.record_view", return_value=rv):
            return {q["key"]: q for q in product.verdict_view("r1")["questions"]}

    def test_no_change_is_not_out_of_scope(self):
        q = self.view({"layer": "V5", "verdict": "WARN", "summary": "no resource-level change between baseline and candidate plans"})
        self.assertEqual((q["scope"]["answer"], q["scope"]["tone"]), ("아니오 — plan 에서 바뀐 리소스 없음", "good"))
        self.assertIn("적용 후 결정", q["scope"]["note"])
        q = self.view({"layer": "V5", "verdict": "FAIL", "summary": "plan deletes aws_db_instance.mysql"})
        self.assertEqual((q["scope"]["answer"], q["scope"]["tone"]), ("예, 범위 밖 변경", "bad"))
        q = self.view({"layer": "V5", "verdict": "PASS", "summary": "changes within policy"})
        self.assertEqual((q["scope"]["answer"], q["scope"]["tone"], q["scope"].get("note")), ("아니오, 허용 범위 안", "good", None))


class SameRuleOneLineTests(unittest.TestCase):
    """17차 (D-53): 요청 4 의 규칙 하나(DB 보안 그룹 · 인터넷 · 모든 포트)가 ④ 에 세 줄(Trivy · 자체 검사 · 설계 위반)로 나오고
    'Trivy 는 못 보고 이 프로그램만 찾은 문제 2' 로 셌다 — Trivy 0107 은 모든 포트 규칙에도 나온다 (22 · 3389 포함). 같은 규칙이면 한 줄."""

    @staticmethod
    def plan():
        ref = {"references": ["aws_security_group.db.id", "aws_security_group.db"]}
        rule_v = {"cidr_ipv4": "0.0.0.0/0", "from_port": None, "ip_protocol": "-1", "referenced_security_group_id": None, "to_port": None}
        pv = [{"address": "aws_db_instance.mysql", "mode": "managed", "type": "aws_db_instance", "name": "mysql", "values": {}},
              {"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db", "values": {"name": "db-sg"}},
              {"address": "aws_vpc_security_group_ingress_rule.db_from_bastion", "mode": "managed", "type": "aws_vpc_security_group_ingress_rule", "name": "db_from_bastion", "values": rule_v}]
        cf = [{"address": "aws_db_instance.mysql", "mode": "managed", "type": "aws_db_instance", "name": "mysql", "expressions": {"vpc_security_group_ids": ref}},
              {"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db", "expressions": {}},
              {"address": "aws_vpc_security_group_ingress_rule.db_from_bastion", "mode": "managed", "type": "aws_vpc_security_group_ingress_rule", "name": "db_from_bastion",
               "expressions": {"cidr_ipv4": {"constant_value": "0.0.0.0/0"}, "ip_protocol": {"constant_value": "-1"}, "security_group_id": ref}}]
        return {"format_version": "1.2", "planned_values": {"root_module": {"resources": pv}}, "resource_changes": [], "configuration": {"root_module": {"resources": cf}}}

    def test_all_ports_rule_is_one_line_with_trivy(self):
        from iacpatch.web import product
        with tempfile.TemporaryDirectory() as td:
            pp = Path(td) / "plan.json"
            pp.write_text(json.dumps(self.plan()), encoding="utf-8")
            with mock.patch("iacpatch.web.cases._baseline_plan_path", return_value=(pp, "시험 plan")):
                r = product.issues("three-tier-team-dbsg")
        rule = [x for x in r["issues"] if x["resource"] == "aws_vpc_security_group_ingress_rule.db_from_bastion"]
        self.assertEqual(len(rule), 1, rule)
        self.assertEqual((sorted(rule[0]["sources"]), rule[0]["title"], rule[0]["severity"], rule[0]["rule"]),
                         (["design", "sg", "trivy"], "모든 포트가 인터넷 전체에 열림", "CRITICAL", "AVD-AWS-0107"))
        self.assertTrue(rule[0]["trivy_why"])                                       # Trivy 원문 설명은 따로 남김
        self.assertFalse([x["title"] for x in r["issues"] if x["resource"] == "aws_security_group.db"])     # DB 보안 그룹 이름으로 따로 나온 줄 없음 (전: 자체 검사 · 설계 위반 두 줄)
        self.assertNotIn(rule[0], [x for x in r["issues"] if "trivy" not in x["sources"]])

    def test_helpers(self):
        from iacpatch.web import product
        self.assertEqual(product._rule_base("aws_security_group.bastion#ingress[0]"), "aws_security_group.bastion")
        self.assertEqual(product._rule_base("aws_vpc_security_group_ingress_rule.r[1]"), "aws_vpc_security_group_ingress_rule.r")
        self.assertTrue(all(product._all_ports_txt(x) for x in ("모든 프로토콜·포트", "모든 프로토콜 · 포트", "전체", "-1", "0-65535")))
        self.assertFalse(any(product._all_ports_txt(x) for x in ("3306", "MySQL(3306)", "22-23", "")))


class ConfirmNoteTests(unittest.TestCase):
    """⑥ 고객 기준 질문의 설명 글 (16차): '김담당 가 확정한' · 'IAM 요구사항가' · 'IAM 요구사항와' 처럼 받침과 안 맞는 조사가 나오지 않게."""

    def note(self, conf):
        from iacpatch.web import product
        layers = [{"layer": f"V{i}", "verdict": "PASS", "summary": ""} for i in range(1, 7)]
        rv = {"layers": layers, "policy": {"ok": True}, "design": {"recorded": {"confirmation": conf}}, "set": {"set_id": "nope"}, "problems": []}
        with tempfile.TemporaryDirectory() as td, mock.patch.dict("os.environ", {"IACPATCH_REVIEWS_DIR": td}), \
                mock.patch("iacpatch.web.server.record_view", return_value=rv):
            return {q["key"]: q for q in product.verdict_view("r1")["questions"]}["design"].get("note") or ""

    def test_particles(self):
        self.assertEqual(self.note({"confirmed": True, "kind": "iam", "by": "김담당", "version": 1, "at": "2026-11-06T15:34:00+09:00"}),
                         "비교 기준 = IAM 요구사항 v1 — 확정한 사람 김담당 · 2026-11-06 15:34")
        self.assertEqual(self.note({"confirmed": True, "by": "이보안", "version": 2}), "비교 기준 = 설계도 v2 — 확정한 사람 이보안")
        self.assertIn("비교 기준인 IAM 요구사항이 아직 초안", self.note({"confirmed": False, "kind": "iam", "version": 2}))
        self.assertIn("비교 기준인 설계도가 아직 초안", self.note({"confirmed": False, "version": 1}))
        self.assertIn("고객이 확정한 IAM 요구사항과 구분", self.note({"confirmed": True, "kind": "iam", "basis": "manifest", "version": 1}))


class BroadPermTests(unittest.TestCase):
    def test_wildcard_action_on_one_bucket_is_broad(self):
        """넓은 권한 = 와일드카드 동작 (리소스가 버킷 하나여도) — 요청 6 의 ② 그림에 빨간 선 (16차). 팀 원본(읽기 · 목록)은 빨강 아님."""
        from iacpatch.web import archmap
        from test_iam_hcl import REFS, TEAM_CFG, TEAM_IAM, mk_plan

        def perm_edges(cfg, src):
            plan = mk_plan(cfg)
            plan["planned_values"]["root_module"]["resources"].append(
                {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets", "values": {}})
            plan["configuration"]["root_module"]["resources"].append(
                {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets", "expressions": {}})
            return [e for e in archmap.build(plan, {"iam.tf": src}, [])["edges"] if e["kind"] == "perm"]
        up = TEAM_CFG + [{"actions": {"constant_value": ["s3:*"]}, "resources": {"references": REFS}, "sid": {"constant_value": "UploadAssets"}}]
        e = perm_edges(up, (A / "three-tier-team-upload" / "iam.tf").read_text(encoding="utf-8"))
        self.assertTrue(any(x["dst"] == "n:aws_s3_bucket.assets" and x["risk"] == "broad_perm" and "s3:*" in x["label"] for x in e), e)
        self.assertEqual([x["risk"] for x in perm_edges(TEAM_CFG, TEAM_IAM)], [None])


if __name__ == "__main__":
    unittest.main()
