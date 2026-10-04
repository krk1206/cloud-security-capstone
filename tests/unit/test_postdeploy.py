"""V7 (AWS 응답 → 오라클) 와 V8 (통신 확인) 테스트. 실제 AWS 는 호출하지 않는다.

V7 입력 fixture 는 worklog 2026-09-11 에 기록된 describe-security-groups 응답 형태를 따라 손으로 만든 것이다
(실제 계정 응답이 아님). 구조: SecurityGroups[].IpPermissions[].{IpProtocol,FromPort,ToPort,IpRanges,Ipv6Ranges,PrefixListIds,UserIdGroupPairs}
"""
import socket
import threading
import unittest
from typing import Any, Dict, List

from helpers import intent_for

from iacpatch.models import Verdict
from iacpatch.postdeploy import v7_aws_state, v8_connectivity
from iacpatch.tools.awscli import AwsCli, build_world_from_aws
from iacpatch.verify.sg_oracle import evaluate


class FakeCli(AwsCli):
    """AwsCli 와 같은 인터페이스로 canned 응답을 돌려준다."""

    def __init__(self, sgs: List[Dict[str, Any]], enis: Dict[str, List[Dict[str, Any]]] = None, pls: Dict[str, List[str]] = None):
        super().__init__(binary="aws-fake", profile="x", region="ap-northeast-2")
        self._sgs, self._enis, self._pls = sgs, enis or {}, pls or {}

    def available(self):
        return True

    def describe_security_groups(self, ids):
        return [s for s in self._sgs if s["GroupId"] in ids]

    def describe_network_interfaces_by_sg(self, sg_id):
        return self._enis.get(sg_id, [])

    def prefix_list_entries(self, pl_id):
        from iacpatch.tools.awscli import AwsError
        if pl_id not in self._pls:
            raise AwsError("not found")
        return self._pls[pl_id]


def perm(proto="tcp", fp=22, tp=22, v4=(), v6=(), pls=(), sgs=()):
    return {"IpProtocol": proto, "FromPort": fp, "ToPort": tp,
            "IpRanges": [{"CidrIp": c} for c in v4], "Ipv6Ranges": [{"CidrIpv6": c} for c in v6],
            "PrefixListIds": [{"PrefixListId": p} for p in pls], "UserIdGroupPairs": [{"GroupId": g} for g in sgs]}


class V7Tests(unittest.TestCase):
    def test_worklog_shape_open_to_world(self):
        cli = FakeCli([{"GroupId": "sg-aaa", "GroupName": "capstone-vuln-ssh", "IpPermissions": [perm(v4=["0.0.0.0/0"])], "IpPermissionsEgress": []}])
        world, raw = build_world_from_aws(cli, ["sg-aaa"])
        rep = evaluate(world, intent_for("aws_security_group.vulnerable_ssh"), aliases={"aws_security_group.vulnerable_ssh": "sg-aaa"})
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertEqual(world.source, "aws")

    def test_fixed_state_passes(self):
        cli = FakeCli([{"GroupId": "sg-aaa", "GroupName": "x", "IpPermissions": [perm(v4=["10.0.0.0/8"])], "IpPermissionsEgress": []}])
        world, _ = build_world_from_aws(cli, ["sg-aaa"])
        rep = evaluate(world, intent_for("aws_security_group.x"), aliases={"aws_security_group.x": "sg-aaa"})
        self.assertEqual(rep.verdict, Verdict.PASS, rep.summary)

    def test_prefix_list_expanded_and_split(self):
        cli = FakeCli([{"GroupId": "sg-aaa", "GroupName": "x", "IpPermissions": [perm(pls=["pl-1"])], "IpPermissionsEgress": []}],
                      pls={"pl-1": ["0.0.0.0/1", "128.0.0.0/1"]})
        world, _ = build_world_from_aws(cli, ["sg-aaa"])
        rep = evaluate(world, intent_for("aws_security_group.x"), aliases={"aws_security_group.x": "sg-aaa"})
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertTrue(rep.targets[0].scopes[0].services[0].covers_entire_internet_v4)

    def test_prefix_list_expansion_failure_is_unknown(self):
        cli = FakeCli([{"GroupId": "sg-aaa", "GroupName": "x", "IpPermissions": [perm(pls=["pl-missing"])], "IpPermissionsEgress": []}])
        world, _ = build_world_from_aws(cli, ["sg-aaa"])
        rep = evaluate(world, intent_for("aws_security_group.x", required=[]), aliases={"aws_security_group.x": "sg-aaa"})
        self.assertEqual(rep.verdict, Verdict.UNKNOWN)

    def test_eni_level_aggregation_finds_other_sg(self):
        sgs = [{"GroupId": "sg-app", "GroupName": "app", "IpPermissions": [perm(v4=["10.0.0.0/8"])], "IpPermissionsEgress": []},
               {"GroupId": "sg-legacy", "GroupName": "legacy", "IpPermissions": [perm(v4=["0.0.0.0/0"])], "IpPermissionsEgress": []}]
        enis = {"sg-app": [{"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-app"}, {"GroupId": "sg-legacy"}]}]}
        world, _ = build_world_from_aws(FakeCli(sgs, enis), ["sg-app"])
        self.assertEqual(world.attachments[0].sg_refs, ["sg-app", "sg-legacy"])
        rep = evaluate(world, intent_for("aws_security_group.app"), aliases={"aws_security_group.app": "sg-app"})
        self.assertEqual(rep.verdict, Verdict.FAIL)
        self.assertEqual(rep.targets[0].scopes[0].scope_id, "eni:eni-1")

    def test_sg_reference_source(self):
        sgs = [{"GroupId": "sg-app", "GroupName": "app", "IpPermissions": [perm(sgs=["sg-bastion"])], "IpPermissionsEgress": []}]
        world, _ = build_world_from_aws(FakeCli(sgs), ["sg-app"])
        rep = evaluate(world, intent_for("aws_security_group.app", required=[]), aliases={"aws_security_group.app": "sg-app"})
        self.assertEqual(rep.verdict, Verdict.FAIL)
        rep2 = evaluate(world, intent_for("aws_security_group.app", sg_refs=["sg-bastion"], required=[]), aliases={"aws_security_group.app": "sg-app"})
        self.assertEqual(rep2.verdict, Verdict.PASS, rep2.summary)

    def test_v7_layer_preview_and_unmapped(self):
        cli = FakeCli([])
        lr, _ = v7_aws_state(cli, intent_for("aws_security_group.x"), {}, execute=False)
        self.assertEqual(lr.verdict, Verdict.UNKNOWN)  # 주소→ID 매핑 없음
        lr, _ = v7_aws_state(cli, intent_for("aws_security_group.x"), {"aws_security_group.x": "sg-aaa"}, execute=False)
        self.assertEqual(lr.verdict, Verdict.SKIPPED)
        self.assertFalse(lr.executed)


class _Listener:
    def __enter__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()
        return self

    def _serve(self):
        try:
            c, _ = self.sock.accept()
            c.sendall(b"SSH-2.0-test\r\n")
            c.close()
        except OSError:
            pass

    def __exit__(self, *a):
        self.sock.close()


class V8Tests(unittest.TestCase):
    def _closed_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    def test_allowed_open_and_forbidden_closed(self):
        intent = intent_for("aws_security_group.x")
        with _Listener() as l:
            spec = {"checks": [
                {"label": "ssh from approved", "host": "127.0.0.1", "port": l.port, "expect": "open", "vantage": "local", "source_class": "approved", "service_label": "ssh", "timeout_s": 2},
                {"label": "ssh from unapproved", "host": "127.0.0.1", "port": self._closed_port(), "expect": "closed", "vantage": "local", "source_class": "unapproved", "service_label": "ssh", "timeout_s": 2},
                {"label": "rdp from unapproved", "host": "127.0.0.1", "port": self._closed_port(), "expect": "closed", "vantage": "local", "source_class": "unapproved", "service_label": "rdp", "timeout_s": 2},
            ]}
            r = v8_connectivity(spec, intent, execute=True)
        self.assertEqual(r.verdict, Verdict.PASS, r.summary)

    def test_required_access_broken_fails(self):
        intent = intent_for("aws_security_group.x")
        spec = {"checks": [{"label": "ssh", "host": "127.0.0.1", "port": self._closed_port(), "expect": "open", "vantage": "local", "source_class": "approved", "service_label": "ssh", "timeout_s": 2}]}
        r = v8_connectivity(spec, intent, execute=True)
        self.assertEqual(r.verdict, Verdict.FAIL)

    def test_missing_unapproved_vantage_is_unknown_not_pass(self):
        intent = intent_for("aws_security_group.x")
        with _Listener() as l:
            spec = {"checks": [{"label": "ssh", "host": "127.0.0.1", "port": l.port, "expect": "open", "vantage": "local", "source_class": "approved", "service_label": "ssh", "timeout_s": 2}]}
            r = v8_connectivity(spec, intent, execute=True)
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertIn("ssh", r.details["services_without_unapproved_check"])

    def test_forbidden_reachable_fails(self):
        intent = intent_for("aws_security_group.x", required=[])
        with _Listener() as l:
            spec = {"checks": [{"label": "ssh from unapproved", "host": "127.0.0.1", "port": l.port, "expect": "closed", "vantage": "local", "source_class": "unapproved", "service_label": "ssh", "timeout_s": 2}]}
            r = v8_connectivity(spec, intent, execute=True)
        self.assertEqual(r.verdict, Verdict.FAIL)

    def test_closed_from_approved_source_is_inconclusive(self):
        intent = intent_for("aws_security_group.x", required=[])
        spec = {"checks": [{"label": "x", "host": "127.0.0.1", "port": self._closed_port(), "expect": "closed", "vantage": "local", "source_class": "approved", "service_label": "ssh", "timeout_s": 1}]}
        r = v8_connectivity(spec, intent, execute=True)
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertEqual(r.details["results"][0]["outcome"], "INCONCLUSIVE")

    def test_remote_vantage_observed_value(self):
        intent = intent_for("aws_security_group.x", required=[])
        spec = {"checks": [
            {"label": "ssh from hotspot", "host": "203.0.113.10", "port": 22, "expect": "closed", "vantage": "hotspot", "source_class": "unapproved", "service_label": "ssh", "observed": "timeout"},
            {"label": "rdp from hotspot", "host": "203.0.113.10", "port": 3389, "expect": "closed", "vantage": "hotspot", "source_class": "unapproved", "service_label": "rdp", "observed": "timeout"},
        ]}
        r = v8_connectivity(spec, intent, execute=True)
        self.assertEqual(r.verdict, Verdict.PASS, r.summary)
        spec["checks"][0].pop("observed")
        r = v8_connectivity(spec, intent, execute=True)
        self.assertEqual(r.verdict, Verdict.UNKNOWN)

    def test_not_executed_or_no_spec(self):
        intent = intent_for("aws_security_group.x")
        self.assertEqual(v8_connectivity(None, intent, execute=True).verdict, Verdict.UNKNOWN)
        self.assertEqual(v8_connectivity({"checks": []}, intent, execute=False).verdict, Verdict.SKIPPED)


if __name__ == "__main__":
    unittest.main()
