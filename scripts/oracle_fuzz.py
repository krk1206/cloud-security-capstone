#!/usr/bin/env python3
"""오라클 자체의 차등 검증(differential testing) — 오라클이 쓰는 집합 연산을 '다른 방식으로 짠 기준 구현' 과 무작위 입력 수만 건으로 대조한다.

    python3 scripts/oracle_fuzz.py               # 기본 20,000 건 → experiments/ORACLE_FUZZ.md
    python3 scripts/oracle_fuzz.py --n 100000 --seed 7

무엇을 대조하나:
  1. NetSet (SG 오라클의 CIDR 합집합·차집합·포함·전체 개방 판정, ipaddress.collapse_addresses 기반)
     vs 정수 구간 [start, end] 리스트로 짠 기준 구현 (merge / subtract / cover). IPv4·IPv6 모두, 무작위 CIDR 목록.
  2. pattern_subset (IAM 오라클의 '*' 글롭 포함 관계, 센티널 치환 방식)
     vs 작은 알파벳 위의 문자열을 전부 나열해 L(P) ⊆ L(Q) 를 직접 확인하는 기준 구현.
왜: V6 가 틀리면 전체가 틀린다. 교차검증 1회차는 사람이 찾은 7종이었고, 이건 기계가 무작위로 찾는 방식이다. 불일치가 0 이어야 한다.
숫자는 만들어내지 않는다 — 실행 때마다 seed 와 건수를 결과에 적는다. 도구·네트워크·AWS 불필요 (표준 라이브러리만).
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import argparse
import datetime as _dt
import ipaddress
import itertools
import random
import time
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parents[1]
_sys.path.insert(0, str(ROOT / "src"))

from iacpatch.verify.iam_oracle import pattern_matches, pattern_subset  # noqa: E402
from iacpatch.verify.netset import NetSet  # noqa: E402

Interval = Tuple[int, int]


# --------------------------------------------------------------------------- 기준 구현 1: 정수 구간
def _iv(cidr: str) -> Interval:
    n = ipaddress.ip_network(cidr)
    return int(n.network_address), int(n.broadcast_address)


def merge(ivs: List[Interval]) -> List[Interval]:
    out: List[Interval] = []
    for s, e in sorted(ivs):
        if out and s <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def subtract(a: List[Interval], b: List[Interval]) -> List[Interval]:
    out: List[Interval] = []
    for s, e in merge(a):
        cur = [(s, e)]
        for bs, be in merge(b):
            nxt = []
            for cs, ce in cur:
                if be < cs or bs > ce:
                    nxt.append((cs, ce))
                else:
                    if bs > cs:
                        nxt.append((cs, bs - 1))
                    if be < ce:
                        nxt.append((be + 1, ce))
            cur = nxt
        out.extend(cur)
    return merge(out)


def count(ivs: List[Interval]) -> int:
    return sum(e - s + 1 for s, e in merge(ivs))


def netset_intervals(ns: NetSet) -> List[Interval]:
    return merge([(int(n.network_address), int(n.broadcast_address)) for n in ns.networks])


def rand_cidr(rng: random.Random, v: int) -> str:
    bits = 32 if v == 4 else 128
    # 짧은 prefix(큰 대역)가 자주 나오게 — 겹침·전체 개방이 실제로 생기도록
    plen = rng.choice([0, 1, 1, 2, 2, 3, 4, 8, 8, 12, 16, 24, bits - 1, bits, rng.randint(0, bits)])
    addr = rng.getrandbits(bits)
    net = ipaddress.ip_network((addr, plen), strict=False)
    return str(net)


def fuzz_netset(rng: random.Random, n: int) -> dict:
    stats = {"cases": 0, "mismatch": [], "covers_all": 0, "v6_cases": 0}
    for i in range(n):
        v = 4 if rng.random() < 0.7 else 6
        a = [rand_cidr(rng, v) for _ in range(rng.randint(1, 6))]
        b = [rand_cidr(rng, v) for _ in range(rng.randint(0, 4))]
        A, B = NetSet.from_cidrs(v, a), NetSet.from_cidrs(v, b)
        ia, ib = [_iv(c) for c in a], [_iv(c) for c in b]
        full = (1 << (32 if v == 4 else 128)) - 1
        checks = {
            "union": (netset_intervals(A.union(B)), merge(ia + ib)),
            "difference": (netset_intervals(A.difference(B)), subtract(ia, ib)),
            "intersection_count": (A.intersection(B).num_addresses(), count(ia) - count(subtract(ia, ib))),
            "covers_everything": (A.covers_everything(), merge(ia) == [(0, full)]),
            "num_addresses": (A.num_addresses(), count(ia)),
            "contains_first_b": (A.contains_network(ipaddress.ip_network(b[0])) if b else True, (subtract([ib[0]], ia) == []) if b else True),
        }
        stats["cases"] += 1
        stats["v6_cases"] += int(v == 6)
        stats["covers_all"] += int(checks["covers_everything"][1])
        for name, (got, want) in checks.items():
            if got != want:
                stats["mismatch"].append({"case": i, "check": name, "a": a, "b": b, "got": str(got)[:200], "want": str(want)[:200]})
    return stats


# --------------------------------------------------------------------------- 기준 구현 2: 글롭 포함을 전수 나열로
ALPHABET = "ab"
MAXLEN = 6
UNIVERSE = [""] + ["".join(t) for L in range(1, MAXLEN + 1) for t in itertools.product(ALPHABET, repeat=L)]


def rand_pattern(rng: random.Random) -> str:
    return "".join(rng.choice("ab*") for _ in range(rng.randint(1, 4))) or "*"


def fuzz_patterns(rng: random.Random, n: int) -> dict:
    stats = {"cases": 0, "mismatch": [], "subset_true": 0}
    known = [("a*b", "a*", True), ("a*", "a*b", False), ("*", "a*", False), ("ab", "a*b", True), ("a*a*", "a*", True), ("a*b*c", "a*c", True),
             ("a*c", "a*b*c", False), ("*a", "*", True), ("*a*", "a*", False), ("a*", "*a*", True), ("a*b", "a*b*b", False), ("s3:Get*", "s3:*", True),
             ("s3:*", "s3:Get*", False), ("S3:GETOBJECT", "s3:getobject", True)]
    for p, q, want in known:
        got = pattern_subset(p, q, ignore_case=True)
        stats["cases"] += 1
        if got != want:
            stats["mismatch"].append({"check": "known", "p": p, "q": q, "got": got, "want": want})
    for i in range(n):
        p, q = rand_pattern(rng), rand_pattern(rng)
        got = pattern_subset(p, q, ignore_case=False)
        # 기준: L(P) 의 모든 문자열(길이 ≤ MAXLEN)이 Q 에 매치되는가
        want = all(pattern_matches(q, s, False) for s in UNIVERSE if pattern_matches(p, s, False))
        stats["cases"] += 1
        stats["subset_true"] += int(want)
        if got != want and not (got is False and want is True):
            # got False / want True 는 길이 제한 유니버스가 못 보는 반례가 있을 수 있어 별도 재검사
            stats["mismatch"].append({"case": i, "check": "random", "p": p, "q": q, "got": got, "want": want})
        elif got is False and want is True:
            # 길이 MAXLEN+3 까지 넓혀 반례를 찾는다 — 그래도 없으면 불일치로 기록
            bigger = ["".join(t) for L in range(MAXLEN + 1, MAXLEN + 4) for t in itertools.product(ALPHABET, repeat=L)]
            if all(pattern_matches(q, s, False) for s in bigger if pattern_matches(p, s, False)):
                stats["mismatch"].append({"case": i, "check": "random(extended)", "p": p, "q": q, "got": got, "want": want})
    return stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=20260922)
    ap.add_argument("--out", default="experiments/ORACLE_FUZZ.md")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    t0 = time.time()
    ns = fuzz_netset(rng, a.n)
    t1 = time.time()
    pt = fuzz_patterns(rng, max(2000, a.n // 10))
    t2 = time.time()
    L = ["# 오라클 차등 검증 (자동 생성) — 무작위 입력으로 기준 구현과 대조", "",
         f"- 생성 {_dt.datetime.now().isoformat(timespec='seconds')} · seed {a.seed} · `python3 scripts/oracle_fuzz.py --n {a.n} --seed {a.seed}`",
         "- 불일치 0 이어야 한다. 0 이 아니면 그 입력이 곧 오라클 버그의 재현 케이스다 (`docs/CROSS_VERIFICATION_*.md` 로).", "",
         "## 1. NetSet (SG 오라클의 CIDR 집합 연산) vs 정수 구간 기준 구현", "",
         f"- 무작위 케이스 {ns['cases']:,}건 (IPv6 {ns['v6_cases']:,}건 포함, 전체 개방이 되는 케이스 {ns['covers_all']:,}건) · {t1 - t0:.1f}s",
         "- 대조 항목: 합집합, 차집합, 교집합 크기, 전체 개방 여부, 주소 수, 포함 여부",
         f"- **불일치: {len(ns['mismatch'])}건**", ""]
    for m in ns["mismatch"][:20]:
        L.append(f"  - {m}")
    L += ["", "## 2. pattern_subset (IAM 오라클의 '*' 포함 관계) vs 전수 나열 기준 구현", "",
          f"- 알려진 쌍 14 + 무작위 패턴 쌍 {pt['cases'] - 14:,}건 (알파벳 {{a,b}}, 문자열 길이 ≤ {MAXLEN}; P ⊆ Q 가 참인 경우 {pt['subset_true']:,}건) · {t2 - t1:.1f}s",
          f"- **불일치: {len(pt['mismatch'])}건**", ""]
    for m in pt["mismatch"][:20]:
        L.append(f"  - {m}")
    L += ["", "## 3. 이 검증이 말하지 않는 것", "",
          "- 집합 연산과 글롭 포함이 맞다는 것이지, plan JSON 을 읽어 세계를 만드는 부분(참조 해소·prefix list 전개·ENI 합산·정책 문서 파싱)이 맞다는 것은 아니다. 그쪽은 `scripts/fuzz_scanner.py`(변형 생성)와 fixture 회귀 테스트가 맡는다.",
          "- IAM 은 Tier 1('*' 글롭·Allow) 범위 안에서만 검증한다."]
    out = ROOT / a.out
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L)); print(f"\n→ {out}")
    return 0 if not ns["mismatch"] and not pt["mismatch"] else 1


if __name__ == "__main__":
    _sys.exit(main())
