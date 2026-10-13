"""CIDR 집합 계산 (Python 표준 라이브러리 ipaddress 만 사용).

Intent Oracle(V6)과 AWS 실측(V7)이 공통으로 쓰는 "집합" 연산.
문자열 비교를 하지 않는다. 0.0.0.0/1 + 128.0.0.0/1 은 collapse 하면 0.0.0.0/0 이 된다.

IPv4 와 IPv6 는 별도 집합으로 다룬다 (NetSet 하나에 섞지 않는다).
"""
from __future__ import annotations

import ipaddress
from typing import Iterable, List, Sequence, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

ALL_V4 = ipaddress.ip_network("0.0.0.0/0")
ALL_V6 = ipaddress.ip_network("::/0")


class CidrParseError(ValueError):
    pass


def parse_cidr(text: str) -> IPNetwork:
    """'a.b.c.d/n' 을 네트워크로. 호스트 비트가 켜져 있으면(예: 10.0.0.1/8) 오류로 취급한다.

    strict=True 를 쓰는 이유: AWS 는 SG 규칙에 호스트 비트가 켜진 CIDR 을 넣으면 정규화하거나 거부한다.
    어느 쪽인지 코드에서 추측하지 않고, 파이프라인 입력 단계에서 명시적으로 걸러낸다.
    """
    if not isinstance(text, str) or not text.strip():
        raise CidrParseError(f"empty cidr: {text!r}")
    t = text.strip()
    try:
        return ipaddress.ip_network(t, strict=True)
    except ValueError as e:
        raise CidrParseError(f"invalid cidr {text!r}: {e}") from e


class NetSet:
    """같은 IP 버전의 네트워크 집합. 항상 collapse 된 정규형으로 유지한다."""

    def __init__(self, version: int, networks: Iterable[IPNetwork] = ()):
        if version not in (4, 6):
            raise ValueError("version must be 4 or 6")
        self.version = version
        nets: List[IPNetwork] = []
        for n in networks:
            if n.version != version:
                raise ValueError(f"mixed ip version: {n} in v{version} set")
            nets.append(n)
        self.networks: List[IPNetwork] = list(ipaddress.collapse_addresses(nets)) if nets else []

    # -- 생성 ------------------------------------------------------------
    @classmethod
    def from_cidrs(cls, version: int, cidrs: Sequence[str]) -> "NetSet":
        nets = []
        for c in cidrs:
            n = parse_cidr(c)
            if n.version != version:
                raise CidrParseError(f"{c} is not IPv{version}")
            nets.append(n)
        return cls(version, nets)

    @classmethod
    def all(cls, version: int) -> "NetSet":
        return cls(version, [ALL_V4 if version == 4 else ALL_V6])

    # -- 성질 ------------------------------------------------------------
    def is_empty(self) -> bool:
        return not self.networks

    def covers_everything(self) -> bool:
        """공인 인터넷 전체(0.0.0.0/0 또는 ::/0)를 덮는가. 분할된 CIDR 도 collapse 되므로 잡힌다."""
        return len(self.networks) == 1 and self.networks[0].prefixlen == 0

    def num_addresses(self) -> int:
        return sum(n.num_addresses for n in self.networks)

    def contains_network(self, net: IPNetwork) -> bool:
        """net 전체가 이 집합에 포함되는가 (집합 차이가 비면 포함)."""
        return NetSet(self.version, [net]).difference(self).is_empty()

    # -- 연산 ------------------------------------------------------------
    def union(self, other: "NetSet") -> "NetSet":
        self._check(other)
        return NetSet(self.version, self.networks + other.networks)

    def difference(self, other: "NetSet") -> "NetSet":
        """self − other. CIDR 은 서로 포함 관계이거나 서로소이므로 address_exclude 로 정확히 계산된다."""
        self._check(other)
        remaining: List[IPNetwork] = list(self.networks)
        for b in other.networks:
            nxt: List[IPNetwork] = []
            for r in remaining:
                if not _overlaps(r, b):
                    nxt.append(r)
                elif b.supernet_of(r) or b == r:  # r ⊆ b → 전부 제거
                    continue
                else:  # b ⊂ r → r 에서 b 를 뺀 조각들
                    nxt.extend(r.address_exclude(b))
            remaining = nxt
        return NetSet(self.version, remaining)

    def intersection(self, other: "NetSet") -> "NetSet":
        self._check(other)
        out: List[IPNetwork] = []
        for a in self.networks:
            for b in other.networks:
                if _overlaps(a, b):
                    out.append(a if b.supernet_of(a) or a == b else b)
        return NetSet(self.version, out)

    def _check(self, other: "NetSet") -> None:
        if other.version != self.version:
            raise ValueError("ip version mismatch")

    # -- 표현 ------------------------------------------------------------
    def to_list(self) -> List[str]:
        return [str(n) for n in self.networks]

    def __repr__(self) -> str:  # pragma: no cover
        return f"NetSet(v{self.version}, {self.to_list()})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, NetSet) and other.version == self.version and other.networks == self.networks


def _overlaps(a: IPNetwork, b: IPNetwork) -> bool:
    return a.overlaps(b)


def split_by_version(cidrs: Sequence[str]) -> "tuple[NetSet, NetSet, List[str]]":
    """문자열 CIDR 목록을 (v4 집합, v6 집합, 파싱 실패 목록) 으로 나눈다."""
    v4: List[IPNetwork] = []
    v6: List[IPNetwork] = []
    bad: List[str] = []
    for c in cidrs:
        try:
            n = parse_cidr(c)
        except CidrParseError:
            bad.append(c)
            continue
        (v4 if n.version == 4 else v6).append(n)
    return NetSet(4, v4), NetSet(6, v6), bad
