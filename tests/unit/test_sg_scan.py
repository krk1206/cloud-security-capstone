"""자체 보안 그룹 검사(verify/sg_scan) — 설계도 없이 코드만으로 보는 규칙 (2026-11-01, D-31).

SGWorld 를 손으로 만들어 판정 규칙만 확인한다: 관리 포트 · 고위험 포트(AWS Security Hub EC2.19 목록) · 모든 포트 · 쪼갠 대역 · IPv6 · VPC 전체 ·
출처 미확정. '인터넷에 열렸지만 위험 포트 목록 밖(443)' 은 문제로 세지 않는다 — 고객이 원하는지는 설계 비교가 판단한다.
"""
import unittest

from helpers import ROOT  # noqa: F401  (sys.path 설정)

from iacpatch.verify.sg_scan import EC2_19_PORTS, MGMT_PORTS, scan
from iacpatch.verify.sgmodel import AttachmentPoint, Rule, SecurityGroupModel, SGWorld, Source


def rule(port, cidrs, origin="r#0", proto="tcp", kind="cidr4", hi=None):
    return Rule("ingress", proto, port, port if hi is None else hi, [Source(kind, c) for c in cidrs], origin)


def world(rules, extra_attach=True, unknown_ingress=None):
    m = SecurityGroupModel("aws_security_group.app", rules=rules)
    if unknown_ingress:
        m.inline_unknown["ingress"] = unknown_ingress
    sgs = {"aws_security_group.app": m}
    att = [AttachmentPoint("aws_instance.app", "aws_instance", ["aws_security_group.app"])] if extra_attach else []
    return SGWorld("plan", sgs, attachments=att)


def kinds(res):
    return sorted(f["kind"] for f in res["findings"])


class SgScanTests(unittest.TestCase):
    def test_ssh_open_to_internet_is_mgmt_public(self):
        res = scan(world([rule(22, ["0.0.0.0/0"])]), "10.0.0.0/16")
        self.assertEqual(kinds(res), ["mgmt_public"])
        f = res["findings"][0]
        self.assertEqual((f["severity"], f["from_port"], f["to_port"]), ("CRITICAL", 22, 22))
        self.assertEqual(f["resources"], ["aws_instance.app"])
        self.assertIn("22 SSH", f["detail"])

    def test_public_https_is_not_a_problem(self):
        self.assertEqual(scan(world([rule(443, ["0.0.0.0/0"])]), "10.0.0.0/16")["findings"], [])

    def test_highrisk_port_uses_ec2_19_list(self):
        res = scan(world([rule(3306, ["0.0.0.0/0"])]), "10.0.0.0/16")
        self.assertEqual(kinds(res), ["highrisk_public"])
        self.assertIn("3306 MySQL", res["findings"][0]["detail"])
        self.assertTrue({22, 3389} <= set(EC2_19_PORTS) and set(MGMT_PORTS) == {22, 3389})

    def test_all_ports_open(self):
        res = scan(world([rule(0, ["0.0.0.0/0"], proto="-1")]), "10.0.0.0/16")
        self.assertEqual(kinds(res), ["all_ports_public"])

    def test_split_ranges_are_unioned(self):
        res = scan(world([rule(22, ["0.0.0.0/1", "128.0.0.0/1"])]), "10.0.0.0/16")
        self.assertEqual(kinds(res), ["mgmt_public", "split_any"])
        split = next(f for f in res["findings"] if f["kind"] == "split_any")
        self.assertIn("0.0.0.0/0", split["detail"])

    def test_split_public_entry_is_not_counted_twice(self):
        # 443 을 쪼갠 대역으로 연 것은 공개 입구와 같은 뜻 — 세지 않는다
        self.assertEqual(scan(world([rule(443, ["0.0.0.0/1", "128.0.0.0/1"])]), "10.0.0.0/16")["findings"], [])

    def test_ipv6_any(self):
        res = scan(world([rule(22, ["::/0"], kind="cidr6")]), "10.0.0.0/16")
        self.assertEqual(kinds(res), ["ipv6_any"])

    def test_vpc_wide_on_highrisk_port(self):
        res = scan(world([rule(3306, ["10.0.0.0/16"])]), "10.0.0.0/16")
        self.assertEqual(kinds(res), ["vpc_wide"])
        self.assertEqual(res["findings"][0]["severity"], "MEDIUM")
        # VPC 대역을 모르면 검사하지 않는다
        self.assertEqual(scan(world([rule(3306, ["10.0.0.0/16"])]), None)["findings"], [])

    def test_admin_range_is_fine(self):
        self.assertEqual(scan(world([rule(22, ["203.0.113.0/24"])]), "10.0.0.0/16")["findings"], [])

    def test_unknown_ingress_is_undecidable_not_safe(self):
        res = scan(world([], unknown_ingress="computed"), "10.0.0.0/16")
        self.assertEqual(kinds(res), ["undecidable"])
        self.assertEqual(res["findings"][0]["severity"], "UNKNOWN")

    def test_unattached_group_is_noted_not_scanned(self):
        res = scan(world([rule(22, ["0.0.0.0/0"])], extra_attach=False), "10.0.0.0/16")
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["unattached_security_groups"], ["aws_security_group.app"])
        self.assertTrue(res["notes"])


if __name__ == "__main__":
    unittest.main()
