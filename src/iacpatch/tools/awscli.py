"""AWS CLI 어댑터 (V7 실측용). boto3 없이 `aws` CLI 를 subprocess 로 호출한다.

모든 호출은 읽기 전용(describe/get)이다. 이 모듈은 리소스를 만들거나 바꾸지 않는다.
자격증명은 CLI 프로필/환경변수에서만 온다 (코드/기록에 저장하지 않음).
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from ..verify.sgmodel import AttachmentPoint, PrefixListModel, Rule, SGWorld, SecurityGroupModel, Source, normalize_protocol
from .runner import ToolNotFound, run, which


class AwsError(RuntimeError):
    pass


class AwsCli:
    def __init__(self, binary: Optional[str] = None, profile: Optional[str] = None, region: Optional[str] = None):
        self.binary = binary or os.environ.get("AWS_BIN") or "aws"
        self.profile = profile or os.environ.get("AWS_PROFILE") or ""
        self.region = region or os.environ.get("AWS_REGION") or ""

    def available(self) -> bool:
        return which(self.binary) is not None

    def _base(self) -> List[str]:
        argv = [self.binary]
        if self.profile:
            argv += ["--profile", self.profile]
        if self.region:
            argv += ["--region", self.region]
        argv += ["--output", "json"]
        return argv

    def call(self, *args: str, timeout: int = 120) -> Any:
        argv = self._base() + list(args)
        try:
            r = run(argv, timeout=timeout)
        except ToolNotFound as e:
            raise AwsError(str(e))
        if not r.ok:
            raise AwsError(f"aws {' '.join(args[:3])} failed: {(r.stderr or r.stdout).strip()[:800]}")
        try:
            return json.loads(r.stdout or "null")
        except json.JSONDecodeError as e:
            raise AwsError(f"aws output not JSON: {e}")

    def command_preview(self, *args: str) -> str:
        return " ".join(self._base() + list(args))

    # -- 읽기 전용 API -----------------------------------------------------
    def describe_security_groups(self, ids: List[str]) -> List[Dict[str, Any]]:
        if not ids:
            return []
        return self.call("ec2", "describe-security-groups", "--group-ids", *ids).get("SecurityGroups", [])

    def describe_network_interfaces_by_sg(self, sg_id: str) -> List[Dict[str, Any]]:
        return self.call("ec2", "describe-network-interfaces", "--filters", f"Name=group-id,Values={sg_id}").get("NetworkInterfaces", [])

    def prefix_list_entries(self, pl_id: str) -> List[str]:
        d = self.call("ec2", "get-managed-prefix-list-entries", "--prefix-list-id", pl_id)
        return [e["Cidr"] for e in d.get("Entries", []) if e.get("Cidr")]

    def caller_identity(self) -> Dict[str, Any]:
        return self.call("sts", "get-caller-identity")


# ---------------------------------------------------------------------------
# describe-security-groups JSON → SGWorld (오라클 공통 모델)
# ---------------------------------------------------------------------------
def _perm_to_rule(direction: str, perm: Dict[str, Any], owner: str, idx: int, prefix_lists: Dict[str, PrefixListModel]) -> Rule:
    proto = normalize_protocol(perm.get("IpProtocol"))
    fp, tp = perm.get("FromPort"), perm.get("ToPort")
    srcs: List[Source] = []
    for r in perm.get("IpRanges", []) or []:
        if r.get("CidrIp"):
            srcs.append(Source("cidr4", r["CidrIp"]))
    for r in perm.get("Ipv6Ranges", []) or []:
        if r.get("CidrIpv6"):
            srcs.append(Source("cidr6", r["CidrIpv6"]))
    for r in perm.get("PrefixListIds", []) or []:
        pid = r.get("PrefixListId")
        if pid:
            pl = prefix_lists.get(pid)
            if pl is None or pl.cidrs is None:
                srcs.append(Source("prefix_list", pid, None, note=(pl.note if pl else "not expanded")))
            else:
                srcs.append(Source("prefix_list", pid, list(pl.cidrs), note="expanded via get-managed-prefix-list-entries"))
    for r in perm.get("UserIdGroupPairs", []) or []:
        gid = r.get("GroupId")
        if gid:
            srcs.append(Source("self", owner) if gid == owner else Source("sg", gid))
    if proto == "-1":
        fp = tp = None
    return Rule(direction, proto, fp if isinstance(fp, int) else None, tp if isinstance(tp, int) else None, srcs, f"{owner}#{direction}[{idx}]")


def build_world_from_aws(cli: AwsCli, sg_ids: List[str], expand_attachments: bool = True) -> "tuple[SGWorld, Dict[str, Any]]":
    """대상 SG ID 들로부터 (같은 ENI 에 붙은 다른 SG 포함) SGWorld 를 만든다. 원문 응답도 함께 돌려준다."""
    raw: Dict[str, Any] = {"security_groups": [], "network_interfaces": {}, "prefix_lists": {}}
    world = SGWorld(source="aws", security_groups={}, meta={"region": cli.region, "profile": cli.profile})
    to_fetch = list(dict.fromkeys(sg_ids))
    eni_groups: Dict[str, List[str]] = {}
    if expand_attachments:
        for sid in list(to_fetch):
            try:
                enis = cli.describe_network_interfaces_by_sg(sid)
            except AwsError as e:
                world.notes.append(f"{sid}: describe-network-interfaces failed: {e}")
                continue
            raw["network_interfaces"][sid] = enis
            for eni in enis:
                eid = eni.get("NetworkInterfaceId", "?")
                gids = [g.get("GroupId") for g in eni.get("Groups", []) if g.get("GroupId")]
                eni_groups[eid] = gids
                for g in gids:
                    if g not in to_fetch:
                        to_fetch.append(g)
    sgs = cli.describe_security_groups(to_fetch)
    raw["security_groups"] = sgs
    # prefix list 전개
    pl_ids: List[str] = []
    for sg in sgs:
        for perm in (sg.get("IpPermissions", []) or []) + (sg.get("IpPermissionsEgress", []) or []):
            for p in perm.get("PrefixListIds", []) or []:
                if p.get("PrefixListId") and p["PrefixListId"] not in pl_ids:
                    pl_ids.append(p["PrefixListId"])
    for pid in pl_ids:
        try:
            cidrs = cli.prefix_list_entries(pid)
            raw["prefix_lists"][pid] = cidrs
            world.prefix_lists[pid] = PrefixListModel(pid, cidrs, "IPv4" if all(":" not in c for c in cidrs) else "IPv6", "expanded")
        except AwsError as e:
            world.prefix_lists[pid] = PrefixListModel(pid, None, "IPv4", f"expansion failed: {e}")
    for sg in sgs:
        gid = sg.get("GroupId", "?")
        m = SecurityGroupModel(address=gid, name=sg.get("GroupName"), aws_id=gid)
        for i, perm in enumerate(sg.get("IpPermissions", []) or []):
            m.rules.append(_perm_to_rule("ingress", perm, gid, i, world.prefix_lists))
        for i, perm in enumerate(sg.get("IpPermissionsEgress", []) or []):
            m.rules.append(_perm_to_rule("egress", perm, gid, i, world.prefix_lists))
        world.security_groups[gid] = m
    for eid, gids in eni_groups.items():
        world.attachments.append(AttachmentPoint(address=f"eni:{eid}", resource_type="network_interface", sg_refs=list(gids)))
    return world, raw
