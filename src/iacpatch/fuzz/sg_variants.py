"""Security Group 변형 생성기 — SSH(22) 를 어떤 출처에 여는가를 겉모습만 바꿔가며 만든다.

정답(truth):
  open        실효적으로 0.0.0.0/0 (전 인터넷) 이 22 에 닿는다            → 스캐너·오라클 모두 FAIL 이어야 함
  unapproved  전 인터넷은 아니지만 승인 출처(10.0.0.0/8) 밖이 닿는다       → 오라클 FAIL 이어야 함 (Trivy 0107 은 원래 안 본다)
  approved    승인 출처만 닿는다 (정상 수정)                              → 둘 다 PASS 여야 함 (오탐 검사)
family 는 "어떤 재주로 겉모습을 바꿨나" 다. 변형은 결정론적이다(난수 없음) — 같은 목록이 항상 나온다.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List

APPROVED = "10.0.0.0/8"
TARGET = "aws_security_group.t"
PROVIDER = 'provider "aws" {\n  region = "ap-northeast-2"\n}\n\n'


@dataclass
class Variant:
    name: str
    family: str
    truth: str                 # open | unapproved | approved
    hcl: str
    note: str = ""
    target: str = TARGET
    intent_kwargs: Dict = field(default_factory=dict)   # 예: {"v6": ["2001:db8::/32"]}


def split_cidr(cidr: str, k: int) -> List[str]:
    """cidr 를 k(2의 거듭제곱) 조각으로. 합집합은 원래 cidr."""
    net = ipaddress.ip_network(cidr)
    bits = k.bit_length() - 1
    return [str(s) for s in net.subnets(prefixlen_diff=bits)]


def _sg(rules: str, name: str = "t", extra: str = "") -> str:
    return PROVIDER + f'resource "aws_security_group" "{name}" {{\n  name        = "fuzz-{name}"\n  description = "fuzz"\n{rules}}}\n' + extra


def _ingress(cidrs: List[str] | None = None, from_port: int = 22, to_port: int = 22, protocol: str = "tcp", v6: List[str] | None = None,
             raw: str = "") -> str:
    lines = ["  ingress {", "    description = \"SSH\"", f"    from_port   = {from_port}", f"    to_port     = {to_port}", f"    protocol    = \"{protocol}\""]
    if cidrs is not None:
        lines.append("    cidr_blocks = [" + ", ".join(f'"{c}"' for c in cidrs) + "]")
    if v6 is not None:
        lines.append("    ipv6_cidr_blocks = [" + ", ".join(f'"{c}"' for c in v6) + "]")
    if raw:
        lines.append(raw)
    lines.append("  }")
    return "\n".join(lines) + "\n"


def _hcl_list(items: List[str]) -> str:
    return "[" + ", ".join(f'"{c}"' for c in items) + "]"


def variants() -> List[Variant]:
    V: List[Variant] = []
    world = "0.0.0.0/0"

    # ---- 대조군
    V.append(Variant("control-open", "control", "open", _sg(_ingress([world])), "취약 대조군: 0.0.0.0/0 그대로"))
    V.append(Variant("control-approved", "control", "approved", _sg(_ingress([APPROVED])), "정상 수정: 승인 출처만"))
    V.append(Variant("control-unapproved-8", "control", "unapproved", _sg(_ingress(["8.0.0.0/8"])), "승인 밖 대역 하나"))

    # ---- A. CIDR 분할 (합집합 = 전체)
    for k in (2, 4, 8, 16, 64):
        V.append(Variant(f"split-{k}", "cidr-split", "open", _sg(_ingress(split_cidr(world, k))), f"0.0.0.0/0 을 {k} 조각으로 한 규칙에"))
    V.append(Variant("split-uneven", "cidr-split", "open", _sg(_ingress(["0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/3"])), "크기가 다른 조각"))
    V.append(Variant("split-overlap", "cidr-split", "open", _sg(_ingress(["0.0.0.0/2", "0.0.0.0/1", "128.0.0.0/1", "64.0.0.0/2"])), "겹치는 조각 (중복 포함)"))
    V.append(Variant("split-two-rules", "cidr-split", "open", _sg(_ingress(["0.0.0.0/1"]) + _ingress(["128.0.0.0/1"])), "두 ingress 블록에 반씩"))
    V.append(Variant("split-with-approved", "cidr-split", "open", _sg(_ingress([APPROVED, "0.0.0.0/1", "128.0.0.0/1"])), "승인 출처 옆에 조각을 끼움"))
    V.append(Variant("superset-of-approved", "cidr-split", "unapproved", _sg(_ingress(["0.0.0.0/4"])), "승인 대역을 포함하는 더 큰 대역"))
    V.append(Variant("approved-split", "cidr-split", "approved", _sg(_ingress(split_cidr(APPROVED, 4))), "승인 대역을 조각낸 정상 수정"))

    # ---- B. 별도 규칙 리소스
    for k in (2, 4):
        parts = split_cidr(world, k)
        rules = "".join(f'resource "aws_vpc_security_group_ingress_rule" "r{i}" {{\n  security_group_id = aws_security_group.t.id\n  cidr_ipv4         = "{c}"\n  from_port         = 22\n  to_port           = 22\n  ip_protocol       = "tcp"\n}}\n' for i, c in enumerate(parts))
        V.append(Variant(f"vpc-rule-split-{k}", "separate-rule", "open", _sg("", extra=rules), f"aws_vpc_security_group_ingress_rule {k}개로 분할"))
    legacy = "".join(f'resource "aws_security_group_rule" "l{i}" {{\n  type              = "ingress"\n  security_group_id = aws_security_group.t.id\n  cidr_blocks       = ["{c}"]\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n}}\n' for i, c in enumerate(split_cidr(world, 2)))
    V.append(Variant("legacy-rule-split-2", "separate-rule", "open", _sg("", extra=legacy), "aws_security_group_rule(레거시) 2개로 분할"))
    one_ok = 'resource "aws_vpc_security_group_ingress_rule" "ok" {\n  security_group_id = aws_security_group.t.id\n  cidr_ipv4         = "10.0.0.0/8"\n  from_port         = 22\n  to_port           = 22\n  ip_protocol       = "tcp"\n}\n'
    V.append(Variant("vpc-rule-approved", "separate-rule", "approved", _sg("", extra=one_ok), "별도 규칙 리소스로 승인 출처만"))
    mixed = one_ok + 'resource "aws_vpc_security_group_ingress_rule" "bad" {\n  security_group_id = aws_security_group.t.id\n  cidr_ipv4         = "8.0.0.0/8"\n  from_port         = 22\n  to_port           = 22\n  ip_protocol       = "tcp"\n}\n'
    V.append(Variant("vpc-rule-mixed-unapproved", "separate-rule", "unapproved", _sg("", extra=mixed), "인라인 없음 + 별도 규칙 승인 1 · 미승인 1"))

    # ---- C. 값을 간접적으로 만들기 (plan 에서만 해소)
    V.append(Variant("var-default-split", "indirection", "open",
                     PROVIDER + 'variable "allowed" {\n  type    = list(string)\n  default = ' + _hcl_list(split_cidr(world, 2)) + '\n}\n\n' + _sg(_ingress(raw="    cidr_blocks = var.allowed")).replace(PROVIDER, ""), "변수 기본값에 조각"))
    V.append(Variant("local-concat", "indirection", "open",
                     PROVIDER + 'locals {\n  a = ["0.0.0.0/1"]\n  b = ["128.0.0.0/1"]\n}\n\n' + _sg(_ingress(raw="    cidr_blocks = concat(local.a, local.b)")).replace(PROVIDER, ""), "locals + concat()"))
    V.append(Variant("cidrsubnet-fn", "indirection", "open", _sg(_ingress(raw='    cidr_blocks = [cidrsubnet("0.0.0.0/0", 1, 0), cidrsubnet("0.0.0.0/0", 1, 1)]')), "cidrsubnet() 로 조각을 계산"))
    V.append(Variant("format-fn", "indirection", "open", _sg(_ingress(raw='    cidr_blocks = [format("%s/%d", "0.0.0.0", 0)]')), "format() 으로 0.0.0.0/0 조합"))
    V.append(Variant("join-fn", "indirection", "open", _sg(_ingress(raw='    cidr_blocks = [join("/", ["0.0.0.0", "0"])]')), "join() 으로 조합"))
    V.append(Variant("for-expr", "indirection", "open", _sg(_ingress(raw='    cidr_blocks = [for p in ["0.0.0.0/1", "128.0.0.0/1"] : p]')), "for 식"))
    V.append(Variant("var-approved", "indirection", "approved",
                     PROVIDER + 'variable "allowed" {\n  type    = list(string)\n  default = ["10.0.0.0/8"]\n}\n\n' + _sg(_ingress(raw="    cidr_blocks = var.allowed")).replace(PROVIDER, ""), "변수 경유 정상 수정"))
    V.append(Variant("cidrsubnets-approved", "indirection", "approved", _sg(_ingress(raw='    cidr_blocks = cidrsubnets("10.0.0.0/8", 1, 1)')), "cidrsubnets() 로 승인 대역 조각"))

    # ---- D. dynamic / for_each / count
    dyn = ('  dynamic "ingress" {\n    for_each = ["0.0.0.0/1", "128.0.0.0/1"]\n    content {\n      description = "SSH"\n      from_port   = 22\n      to_port     = 22\n'
           '      protocol    = "tcp"\n      cidr_blocks = [ingress.value]\n    }\n  }\n')
    V.append(Variant("dynamic-split", "iteration", "open", _sg(dyn), "dynamic 블록 + 조각"))
    fe = ('resource "aws_vpc_security_group_ingress_rule" "r" {\n  for_each          = toset(["0.0.0.0/1", "128.0.0.0/1"])\n  security_group_id = aws_security_group.t.id\n'
          '  cidr_ipv4         = each.value\n  from_port         = 22\n  to_port           = 22\n  ip_protocol       = "tcp"\n}\n')
    V.append(Variant("for-each-rules", "iteration", "open", _sg("", extra=fe), "for_each 규칙 리소스"))
    cnt = ('resource "aws_vpc_security_group_ingress_rule" "r" {\n  count             = 2\n  security_group_id = aws_security_group.t.id\n'
           '  cidr_ipv4         = cidrsubnet("0.0.0.0/0", 1, count.index)\n  from_port         = 22\n  to_port           = 22\n  ip_protocol       = "tcp"\n}\n')
    V.append(Variant("count-cidrsubnet", "iteration", "open", _sg("", extra=cnt), "count + cidrsubnet()"))

    # ---- E. 참조 (prefix list, SG 참조, self)
    pl = ('resource "aws_ec2_managed_prefix_list" "p" {\n  name           = "fuzz-pl"\n  address_family = "IPv4"\n  max_entries    = 4\n'
          '  entry {\n    cidr = "0.0.0.0/1"\n  }\n  entry {\n    cidr = "128.0.0.0/1"\n  }\n}\n')
    V.append(Variant("prefix-list-split", "reference", "open", _sg(_ingress(raw="    prefix_list_ids = [aws_ec2_managed_prefix_list.p.id]"), extra=pl), "prefix list 안에 조각"))
    pl_ok = 'resource "aws_ec2_managed_prefix_list" "p" {\n  name           = "fuzz-pl"\n  address_family = "IPv4"\n  max_entries    = 1\n  entry {\n    cidr = "10.0.0.0/8"\n  }\n}\n'
    V.append(Variant("prefix-list-approved", "reference", "approved", _sg(_ingress(raw="    prefix_list_ids = [aws_ec2_managed_prefix_list.p.id]"), extra=pl_ok), "prefix list 안에 승인 대역만"))
    other = 'resource "aws_security_group" "other" {\n  name        = "fuzz-other"\n  description = "other"\n}\n'
    V.append(Variant("sg-ref-unapproved", "reference", "unapproved", _sg(_ingress(raw="    security_groups = [aws_security_group.other.id]"), extra=other), "다른 SG 참조 (승인 안 됨)"))
    V.append(Variant("self-ref", "reference", "unapproved", _sg(_ingress(raw="    self = true")), "self 참조"))

    # ---- F. 포트·프로토콜
    V.append(Variant("port-range-cover", "port", "open", _sg(_ingress([world], 20, 30)), "포트 범위 20-30 이 22 포함"))
    V.append(Variant("all-ports", "port", "open", _sg(_ingress([world], 0, 65535)), "0-65535"))
    V.append(Variant("all-protocols", "port", "open", _sg(_ingress([world], 0, 0, "-1")), "protocol -1"))
    V.append(Variant("udp-only-22", "port", "approved", _sg(_ingress([APPROVED]) + _ingress([world], 22, 22, "udp")), "UDP 22 만 전체 개방 (SSH 는 TCP)"))

    # ---- G. IPv6
    V.append(Variant("ipv6-open", "ipv6", "unapproved", _sg(_ingress([APPROVED], v6=["::/0"])), "IPv4 는 승인, IPv6 ::/0 추가 (승인된 v6 없음)"))
    V.append(Variant("ipv6-split", "ipv6", "unapproved", _sg(_ingress([APPROVED], v6=["::/1", "8000::/1"])), "IPv6 조각"))
    V.append(Variant("ipv6-approved", "ipv6", "approved", _sg(_ingress([APPROVED], v6=["2001:db8::/32"])), "승인된 IPv6 만", intent_kwargs={"v6": ["2001:db8::/32"]}))

    # ---- H. 다른 SG 를 같은 인스턴스에
    second = ('resource "aws_security_group" "legacy" {\n  name        = "fuzz-legacy"\n  description = "legacy"\n' + _ingress(["0.0.0.0/1", "128.0.0.0/1"]) + '}\n'
              'resource "aws_instance" "app" {\n  ami           = "ami-0c9c942bd7bf113a2"\n  instance_type = "t3.micro"\n  vpc_security_group_ids = [aws_security_group.t.id, aws_security_group.legacy.id]\n}\n')
    V.append(Variant("second-sg-split", "aggregation", "open", _sg(_ingress([APPROVED]), extra=second), "대상 SG 는 정상, 같은 인스턴스의 다른 SG 가 조각 개방"))
    return V
