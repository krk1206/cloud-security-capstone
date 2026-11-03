"""대역 계산 교차 확인 — 오라클(V6·V7)의 CIDR 집합 계산을 '다른 방식' 으로 다시 해서 결과가 같은지 본다.

오라클(verify/netset.py)은 파이썬 표준 라이브러리 ipaddress 의 collapse_addresses 로 계산한다.
여기서는 ipaddress 를 쓰지 않고 IPv4 주소를 직접 정수로 바꿔 [시작, 끝] 구간을 정렬·병합한다. 두 구현이 같은 답을 내야 한다.
(IPv6 는 이 확인에서 다루지 않는다 — 화면에 '대상 아님' 으로 표시.)
"""
from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

Interval = Tuple[int, int]
FULL_V4: Interval = (0, 2 ** 32 - 1)


def v4_interval(cidr: str) -> Optional[Interval]:
    """'a.b.c.d/n' → (첫 주소, 끝 주소). 호스트 비트가 켜져 있거나 형식이 틀리면 None."""
    try:
        addr, _, plen_s = cidr.strip().partition("/")
        parts = addr.split(".")
        if len(parts) != 4 or not plen_s:
            return None
        octets = [int(p) for p in parts]
        if any(o < 0 or o > 255 for o in octets):
            return None
        plen = int(plen_s)
        if plen < 0 or plen > 32:
            return None
        value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        size = 1 << (32 - plen)
        if value % size != 0:
            return None
        return value, value + size - 1
    except ValueError:
        return None


def merge(ivs: Sequence[Interval]) -> List[Interval]:
    out: List[Interval] = []
    for s, e in sorted(ivs):
        if out and s <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def subtract(a: Sequence[Interval], b: Sequence[Interval]) -> List[Interval]:
    res: List[Interval] = []
    for s, e in merge(a):
        cur = [(s, e)]
        for bs, be in merge(b):
            nxt: List[Interval] = []
            for cs, ce in cur:
                if be < cs or bs > ce:
                    nxt.append((cs, ce))
                else:
                    if bs > cs:
                        nxt.append((cs, bs - 1))
                    if be < ce:
                        nxt.append((be + 1, ce))
            cur = nxt
        res.extend(cur)
    return merge(res)


def ip_text(v: int) -> str:
    return ".".join(str((v >> s) & 255) for s in (24, 16, 8, 0))


def interval_text(iv: Interval) -> str:
    return f"{ip_text(iv[0])} ~ {ip_text(iv[1])}"


def count(ivs: Sequence[Interval]) -> int:
    return sum(e - s + 1 for s, e in merge(ivs))


def union_check(cidrs: Sequence[str], allowed: Sequence[str] = ()) -> Dict[str, Any]:
    """대역 목록의 합집합과 '허용 대역 밖 부분' 을 정수 구간으로 계산."""
    ivs = [v4_interval(c) for c in cidrs]
    if any(iv is None for iv in ivs):
        return {"ok": False, "reason": "IPv4 CIDR 이 아닌 값 포함", "cidrs": list(cidrs)}
    u = merge([iv for iv in ivs if iv])
    al = [v4_interval(c) for c in allowed]
    rest = subtract(u, [iv for iv in al if iv])
    return {"ok": True, "cidrs": list(cidrs), "union": [interval_text(iv) for iv in u], "union_addresses": count(u),
            "covers_internet": u == [FULL_V4], "outside_allowed": [interval_text(iv) for iv in rest],
            "outside_addresses": count(rest)}


def compare_with_netset(cidrs: Sequence[str], allowed: Sequence[str] = ()) -> Dict[str, Any]:
    """오라클의 NetSet 결과와 정수 구간 결과를 나란히."""
    from ..verify.netset import NetSet
    mine = union_check(cidrs, allowed)
    if not mine.get("ok"):
        return {"same": None, "mine": mine}
    ns = NetSet.from_cidrs(4, list(cidrs))
    rest = ns.difference(NetSet.from_cidrs(4, list(allowed))) if allowed else ns
    oracle = {"union": [str(n) for n in ns.networks], "union_addresses": ns.num_addresses(), "covers_internet": ns.covers_everything(),
              "outside_allowed": rest.to_list(), "outside_addresses": rest.num_addresses()}
    same = (oracle["union_addresses"] == mine["union_addresses"] and oracle["covers_internet"] == mine["covers_internet"]
            and oracle["outside_addresses"] == mine["outside_addresses"])
    return {"same": same, "mine": mine, "oracle": oracle}


def _rand_cidr(rng: random.Random) -> str:
    plen = rng.choice([0, 1, 1, 2, 2, 3, 4, 8, 8, 12, 16, 24, 31, 32, rng.randint(0, 32)])
    addr = rng.getrandbits(32)
    size = 1 << (32 - plen)
    addr -= addr % size
    return f"{ip_text(addr)}/{plen}"


def differential(n: int = 2000, seed: Optional[int] = None) -> Dict[str, Any]:
    """무작위 대역 목록 n 건: 오라클(NetSet) vs 정수 구간 구현. 불일치 건수와 첫 불일치 예."""
    from ..verify.netset import NetSet
    seed = int(time.time()) if seed is None else seed
    rng = random.Random(seed)
    t0 = time.time()
    mism: List[Dict[str, Any]] = []
    whole = 0
    for _ in range(n):
        a = [_rand_cidr(rng) for _ in range(rng.randint(1, 6))]
        b = [_rand_cidr(rng) for _ in range(rng.randint(0, 3))]
        ns_a = NetSet.from_cidrs(4, a)
        ns_b = NetSet.from_cidrs(4, b) if b else NetSet(4)
        ref_a = merge([v4_interval(c) for c in a])            # type: ignore[misc]
        ref_b = merge([v4_interval(c) for c in b])            # type: ignore[misc]
        got = (ns_a.num_addresses(), ns_a.covers_everything(), ns_a.difference(ns_b).num_addresses())
        exp = (count(ref_a), ref_a == [FULL_V4], count(subtract(ref_a, ref_b)))
        whole += 1 if exp[1] else 0
        if got != exp and len(mism) < 3:
            mism.append({"a": a, "b": b, "oracle": got, "reference": exp})
        elif got != exp:
            mism.append({})
    return {"cases": n, "seed": seed, "mismatches": len(mism), "examples": [m for m in mism if m][:3],
            "cases_covering_internet": whole, "elapsed_s": round(time.time() - t0, 2)}
