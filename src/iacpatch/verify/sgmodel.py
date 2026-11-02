"""Security Group 규칙의 공통 모델.

plan JSON(V6, 배포 전)과 describe-security-groups 결과(V7, 배포 후)를 **같은 구조**로 정규화해서
Intent Oracle 이 동일한 계산을 하게 한다. 이 파일은 순수 데이터 구조와 프로토콜/포트 정규화만 담당한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

PROTOCOL_ALIASES = {
    "-1": "-1", "all": "-1", "ALL": "-1",
    "6": "tcp", "tcp": "tcp", "TCP": "tcp",
    "17": "udp", "udp": "udp", "UDP": "udp",
    "1": "icmp", "icmp": "icmp", "ICMP": "icmp",
    "58": "icmpv6", "icmpv6": "icmpv6", "ICMPV6": "icmpv6",
}


def normalize_protocol(p) -> str:
    if p is None:
        return "-1"
    s = str(p).strip()
    return PROTOCOL_ALIASES.get(s, PROTOCOL_ALIASES.get(s.lower(), s.lower()))


@dataclass
class Source:
    """규칙의 출처(어디서 오는 트래픽을 허용하는가) 하나.

    kind:
      cidr4 / cidr6      : 값이 CIDR 문자열
      sg                 : 참조 보안그룹 (리소스 주소 'aws_security_group.x' 또는 실제 ID 'sg-...').
                           **참조 SG 의 인바운드 규칙을 상속하지 않는다.** 의미는 "그 SG 가 붙은 ENI 에서 오는 트래픽 허용".
      self               : 같은 SG 가 붙은 ENI 에서 오는 트래픽
      prefix_list        : managed prefix list. resolved_cidrs 가 채워지면 전개 완료, None 이면 전개 불가(UNKNOWN)
      unknown            : plan 시점에 값이 확정되지 않았고 참조로도 해석할 수 없음
    """
    kind: str
    value: str = ""
    resolved_cidrs: Optional[List[str]] = None
    note: str = ""


@dataclass
class Rule:
    direction: str                     # "ingress" | "egress"
    protocol: str                      # normalize_protocol() 결과
    from_port: Optional[int]           # protocol == "-1" 이면 None (전체)
    to_port: Optional[int]
    sources: List[Source]
    origin: str                        # 규칙을 선언한 위치 (예: "aws_security_group.x#ingress[0]")
    unknown_fields: List[str] = field(default_factory=list)   # 값이 확정되지 않은 필드 이름들

    def matches_service(self, direction: str, protocol: str, from_port: int, to_port: int) -> str:
        """서비스(방향/프로토콜/포트범위)와의 관계.

        returns: "full"    규칙이 서비스 포트 범위를 전부 덮음
                 "partial" 일부 포트만 겹침
                 "none"    무관
        """
        if self.direction != direction:
            return "none"
        if self.protocol == "-1":
            return "full"
        if self.protocol != protocol:
            return "none"
        if protocol in ("icmp", "icmpv6"):
            # icmp 의 from/to 는 type/code 이므로 포트 비교 대상이 아니다. 같은 프로토콜이면 관련 있다고 본다.
            return "full"
        if self.from_port is None or self.to_port is None:
            return "full"
        lo, hi = self.from_port, self.to_port
        if lo == 0 and hi == 0:
            # aws_security_group 의 관례: from=0,to=0 + protocol 지정 → 그 프로토콜 전체 포트
            return "full"
        if hi < from_port or lo > to_port:
            return "none"
        if lo <= from_port and hi >= to_port:
            return "full"
        return "partial"


@dataclass
class SecurityGroupModel:
    address: str                                   # plan 주소 또는 AWS GroupId
    name: Optional[str] = None
    rules: List[Rule] = field(default_factory=list)
    inline_unknown: Dict[str, str] = field(default_factory=dict)   # {"ingress": 이유} inline 블록 전체가 미확정일 때
    caveats: List[str] = field(default_factory=list)
    aws_id: Optional[str] = None


@dataclass
class PrefixListModel:
    address: str
    cidrs: Optional[List[str]]         # None 이면 항목이 미확정
    address_family: str = "IPv4"
    note: str = ""


@dataclass
class AttachmentPoint:
    """SG 가 붙는 지점 (인스턴스/ENI 등). 실효 규칙은 같은 지점에 붙은 SG 들의 합집합이다."""
    address: str
    resource_type: str
    sg_refs: List[str]                 # plan 주소 또는 sg-... ID
    external_sg_ids: List[str] = field(default_factory=list)   # plan 에 없는 실제 ID (규칙을 볼 수 없음)
    unknown: bool = False
    note: str = ""


@dataclass
class SGWorld:
    """오라클 입력 전체. plan 이든 AWS 실측이든 이 형태로 만든다."""
    source: str                                        # "plan" | "aws"
    security_groups: Dict[str, SecurityGroupModel]
    prefix_lists: Dict[str, PrefixListModel] = field(default_factory=dict)
    attachments: List[AttachmentPoint] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)

    def attachments_of(self, sg_ref: str) -> List[AttachmentPoint]:
        return [a for a in self.attachments if sg_ref in a.sg_refs]
