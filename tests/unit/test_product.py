"""새 프로그램 화면 자료 (2026-11-01 갈아엎기 3차, D-31) — 코드에서 그린 현재 인프라(codetopo) · 설계도 초안 · 문제 목록 도우미.

plan 은 손으로 만든 작은 2계층 plan JSON (tofu 없이). 판정은 verify/sg_scan · topology_oracle 테스트가 맡고,
여기서는 '코드 → 그림 · 초안 · 화면 글' 변환이 맞는지만 본다.
"""
import unittest

from helpers import ROOT  # noqa: F401  (sys.path 설정)

from iacpatch.tools.github import public_name
from iacpatch.verify.plan_model import build_world
from iacpatch.verify.sg_scan import scan
from iacpatch.web import codetopo, product
from iacpatch.web.cases import is_ai_run


def _rule(port, cidrs, desc, with_sg=False):
    r = {"cidr_blocks": list(cidrs), "description": desc, "from_port": port, "ipv6_cidr_blocks": [], "prefix_list_ids": [],
         "protocol": "tcp", "self": False, "to_port": port}
    if not with_sg:
        r["security_groups"] = []
    return r


def two_tier_plan(ssh=("0.0.0.0/0",)):
    """인터넷 → web (22 · 80), web → app (8080) + 그림 밖 리소스(S3 · IAM). 인스턴스의 보안 그룹은 설정 참조로만 보인다."""
    res = [
        ("aws_vpc", "main", {"cidr_block": "10.0.0.0/16"}),
        ("aws_security_group", "web", {"name": "web", "ingress": [_rule(22, ssh, "SSH"), _rule(80, ["0.0.0.0/0"], "HTTP")], "egress": []}),
        ("aws_security_group", "app", {"name": "app", "ingress": [_rule(8080, [], "app from web", with_sg=True)], "egress": []}),
        ("aws_instance", "web", {"ami": "ami-12345678"}),
        ("aws_instance", "app", {"ami": "ami-12345678"}),
        ("aws_s3_bucket", "assets", {"bucket": "assets"}),
        ("aws_iam_role", "web", {"name": "web"}),
    ]
    planned = [{"address": f"{t}.{n}", "type": t, "name": n, "mode": "managed", "values": v} for t, n, v in res]
    unknown = {"aws_security_group.app": {"ingress": [{"security_groups": True}]}}
    rc = [{"address": p["address"], "type": p["type"], "name": p["name"], "mode": "managed",
           "change": {"actions": ["create"], "after_unknown": unknown.get(p["address"], {})}} for p in planned]
    ref = lambda sg: {"references": [f"aws_security_group.{sg}.id", f"aws_security_group.{sg}"]}  # noqa: E731
    cfg = [{"address": "aws_security_group.app", "type": "aws_security_group", "name": "app", "expressions": {"ingress": ref("web")}},
           {"address": "aws_instance.web", "type": "aws_instance", "name": "web", "expressions": {"vpc_security_group_ids": ref("web")}},
           {"address": "aws_instance.app", "type": "aws_instance", "name": "app", "expressions": {"vpc_security_group_ids": ref("app")}}]
    return {"format_version": "1.2", "planned_values": {"root_module": {"resources": planned}}, "resource_changes": rc,
            "configuration": {"root_module": {"resources": cfg}}}


def model_of(plan):
    sc = scan(build_world(plan, {}), codetopo.vpc_cidr(plan))
    return codetopo.build(plan, {}, sc["findings"]), sc


class CodeTopologyTests(unittest.TestCase):
    def test_picture_from_code(self):
        m, sc = model_of(two_tier_plan())
        self.assertTrue(m["ok"])
        self.assertEqual(m["vpc_cidr"], "10.0.0.0/16")
        tiers = {n["label"]: n for n in m["nodes"] if n["kind"] == "tier"}
        self.assertEqual(sorted(tiers), ["app", "web"])
        self.assertEqual(tiers["web"]["zone"], "public")      # 외부 출처가 바로 들어옴
        self.assertEqual(tiers["app"]["zone"], "private")
        flows = {(f["src"], f["dst"]): f for f in m["flows"]}
        web, app = tiers["web"]["id"], tiers["app"]["id"]
        inet = next(f for (s, d), f in flows.items() if d == web)
        self.assertEqual(inet["ports"], "22, 80")
        self.assertEqual(inet["risk"], "mgmt_public")         # 자체 검사가 위험으로 본 규칙 → 빨간 선
        self.assertEqual(flows[(web, app)]["ports"], "8080")
        self.assertIsNone(flows[(web, app)]["risk"])
        self.assertEqual([f["kind"] for f in sc["findings"]], ["mgmt_public"])

    def test_inventory_lists_what_is_not_drawn(self):
        m, _ = model_of(two_tier_plan())
        inv = m["inventory"]
        self.assertEqual(inv["total"], 7)
        grp = {r["address"]: r["group"] for r in inv["rows"]}
        self.assertEqual(grp["aws_instance.web"], "picture")
        self.assertEqual(grp["aws_security_group.web"], "sg")
        self.assertEqual(grp["aws_s3_bucket.assets"], "s3")
        self.assertEqual(grp["aws_iam_role.web"], "iam")
        self.assertEqual(grp["aws_vpc.main"], "network")

    def test_draft_design_flags_internet_to_ssh(self):
        m, _ = model_of(two_tier_plan())
        d = codetopo.draft_design(m, "p-design", "scenarios/x")
        self.assertEqual(sorted((f["from"], f["to"], f.get("port")) for f in d["flows"]),
                         [("internet", "web", 22), ("internet", "web", 80), ("web", "app", 8080)])
        self.assertEqual(list(d["draft_risky"].values()), ["인터넷 전체 → 관리 포트 SSH(22)"])
        self.assertTrue(d["draft_notes"][0].startswith("⚠ 사용자(인터넷) → web :22"))

    def test_draft_without_risk_when_ssh_is_limited(self):
        m, _ = model_of(two_tier_plan(ssh=("10.0.0.0/8",)))
        d = codetopo.draft_design(m, "p-design", "scenarios/x")
        self.assertEqual(d["draft_risky"], {})
        self.assertFalse(any(n.startswith("⚠") for n in d["draft_notes"]))


class ScreenTextTests(unittest.TestCase):
    def test_trivy_groups(self):
        self.assertEqual(product.trivy_group("AVD-AWS-0107")[0], "public_mgmt")
        self.assertEqual(product.trivy_group("AVD-AWS-0104", "A security group rule should not allow unrestricted egress to any IP address.")[0], "network")
        # 'CloudWatch log groups should be encrypted' 은 로그가 아니라 암호화 문제
        self.assertEqual(product.trivy_group("AVD-AWS-0017", "CloudWatch log groups should be encrypted using CMK")[0], "encryption")
        self.assertEqual(product.trivy_group("AVD-AWS-0089", "S3 Bucket Logging")[0], "storage")

    def test_plain_http_is_encryption_and_ecs_is_its_own_kind(self):
        from iacpatch.web import designs, topomodel
        self.assertEqual(product.trivy_group("AVD-AWS-0054", "Use of plain HTTP.")[0], "encryption")
        self.assertEqual(topomodel._icon_from_types(["aws_ecs_service.api"]), "ecs")     # 컨테이너 서비스를 '서버 (EC2)' 라고 부르지 않는다
        self.assertIn("ecs", designs.TYPES)

    def test_korean_title_falls_back_to_original(self):
        self.assertEqual(product.title_ko("AVD-AWS-0107", "x"), "보안 그룹이 SSH · RDP 를 모든 IP 에서 받음")
        self.assertEqual(product.title_ko("AVD-AWS-9999", "Original title"), "Original title")

    def test_port_text(self):
        self.assertEqual([product._port_txt(x) for x in ("MySQL(3306)", "3306", "8080-8090", "전체")], [":3306", ":3306", ":8080-8090", "전체"])

    def test_trivy_description_lookup(self):
        rep = {"Results": [{"Misconfigurations": [{"ID": "AWS-0107", "Description": "desc",
                                                   "CauseMetadata": {"Resource": "aws_security_group.web", "StartLine": 3}}]}]}
        self.assertEqual(product._trivy_text(rep), {("AVD-AWS-0107", "aws_security_group.web", 3): "desc"})

    def test_pr_name_hides_candidate_id(self):
        self.assertEqual(public_name("ui/arch-3tier-sg/correct-design"), "arch-3tier-sg")
        self.assertEqual(public_name("pr-t"), "pr-t")

    def test_ai_run_ids(self):
        self.assertTrue(is_ai_run("ai-20261101-044210-0a1b2c-a2"))
        self.assertFalse(is_ai_run("ai-claude-r1"))      # manifest 의 팀 후보 이름
        self.assertFalse(is_ai_run("upload-20261031-194951-0da5c6"))


if __name__ == "__main__":
    unittest.main()


class ClosingTests(unittest.TestCase):
    """⑧ 끝맺음 세 줄 (D-42): 확인한 것 · 결정 · 남은 것 — 새로 판정하지 않고 결론 · 결정 기록 · 미검증 목록을 옮긴다."""

    def test_no_decision_yet(self):
        vv = {"conclusion": {"status": "다음: AWS 시험 환경 검사", "next": ["AWS 시험 환경 검사: 시험 환경 반영 → V7 · V8 측정 → 시험 환경 삭제", "수정 요청", "폐기"]}, "decision": {}}
        c = product._closing(vv, ["Trivy: x"], [], None, [], ["AWS 에서의 실제 연결 · 차단 — AWS 시험 환경 검사(V7 · V8) 전"], {"text": "미검증 — AWS 시험 환경 검사(V7 · V8)를 하지 않음"})
        self.assertIn("해결 1개", c["checked"]); self.assertIn("새 문제 검사 못 함", c["checked"]); self.assertIn("미검증", c["checked"])
        self.assertIn("아직 결정 없음", c["decided"])
        self.assertTrue(any("V7 · V8" in x for x in c["left"]))
        self.assertFalse(any("폐기" in x for x in c["left"]))                    # 다음 할 일에서 '폐기' 는 남은 것이 아니다
        self.assertNotIn("수정 요청", c["left"])                                  # 17차: 결정 이름 한 단어는 '남은 것' 이 아니다 ('결정' 줄에 있음)

    def test_approved_with_ack(self):
        vv = {"conclusion": {"status": "승인 판단 가능 · 실제 AWS 미검증"}, "decision": {"decision": "APPROVED", "by": "김보성", "at": "2026-11-02T15:00:00+0900", "reason": "설계 일치", "aws_unverified_ack": True},
              "decision_ko": "적용 승인 — PR 초안 생성"}
        c = product._closing(vv, [], [], [], [], ["시험 환경 없음"], {"text": "미검증 — 이 프로젝트에는 AWS 시험 환경이 없음 · 승인한 사람이 미검증을 확인하고 승인함"})
        self.assertIn("김보성", c["decided"]); self.assertIn("2026-11-02 15:00", c["decided"]); self.assertIn("실제 AWS 미검증을 알고 승인", c["decided"])
        self.assertTrue(any("운영 반영은 이 프로그램 밖" in x for x in c["left"]))
        self.assertIn("시험 환경 없음", c["left"][0])
