#!/usr/bin/env python3
"""스캐너 사각 탐색 실험 — 뜻은 같고 겉모습만 다른 변형을 자동 생성해 Trivy 와 오라클(V6)에 나란히 넣는다.

    python3 scripts/fuzz_scanner.py                 # SG + IAM 전부 → experiments/FUZZ_RESULTS.md (+ experiments/fuzz/<시각>/…/원문)
    python3 scripts/fuzz_scanner.py --kind sg --limit 5
    python3 scripts/fuzz_scanner.py --only cidr-split indirection   # family 나 이름으로 고르기

답하는 질문:
  1. Trivy 0.74.0 은 어떤 겉모습의 '전 인터넷 개방 / 과다 권한' 을 못 보는가 (스캐너 사각 목록).
  2. 오라클(V6)은 그 변형들을 잡는가 — 못 잡으면 그것이 오라클 버그다 (교차검증 재료).
  3. 정상 수정을 오탐하지 않는가.
정답은 변형을 만들 때 구조적으로 정해지므로 사람이 라벨을 적지 않는다 (src/iacpatch/fuzz/*_variants.py).
하지 않는 것: AWS 접속, apply, LLM 호출. 변형 파일은 실험 재료이며 배포용이 아니다.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import argparse
import datetime as _dt
import json
import platform
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_sys.path.insert(0, str(ROOT / "src"))

from iacpatch.config import load_settings  # noqa: E402
from iacpatch.fuzz.runner import run_variants  # noqa: E402
from iacpatch.tools.terraform import TerraformAdapter  # noqa: E402
from iacpatch.tools.trivy import TrivyAdapter  # noqa: E402


def _md(kind: str, rs) -> list:
    title = {"sg": "Security Group (SSH 22, 승인 출처 10.0.0.0/8)", "iam": "IAM (report-worker, 승인 = s3:GetObject/ListBucket on report-archive)"}[kind]
    L = [f"## {title} — 변형 {len(rs)}개", ""]
    want_fail = [r for r in rs if r.expected == "FAIL"]
    want_pass = [r for r in rs if r.expected == "PASS"]
    want_unk = [r for r in rs if r.expected == "UNKNOWN"]
    blind = [r for r in want_fail if r.trivy_flagged is False]
    blind_caught = [r for r in blind if r.oracle == "FAIL"]
    blind_unknown = [r for r in blind if r.oracle == "UNKNOWN"]
    oracle_miss = [r for r in want_fail if r.oracle == "PASS"]
    plan_fail = [r for r in rs if r.plan_ok is False]
    L += [f"- 잡혀야 하는 변형 {len(want_fail)}개 중 **Trivy 가 못 본 것 {len(blind)}개** → 그중 오라클이 잡은 것 **{len(blind_caught)}개**, 사람에게 넘긴 것(UNKNOWN) {len(blind_unknown)}개, "
          f"**오라클도 놓친 것 {len(oracle_miss)}개**" + (" ← 버그 후보, 교차검증 대상" if oracle_miss else ""),
          f"- 정상 수정 {len(want_pass)}개: 오라클 오탐 {sum(1 for r in want_pass if r.oracle != 'PASS' and r.plan_ok is not False)}개, 스캐너 오탐 {sum(1 for r in want_pass if r.trivy_flagged)}개",
          f"- Tier 1 밖 구조 {len(want_unk)}개: UNKNOWN(설계대로) {sum(1 for r in want_unk if r.oracle == 'UNKNOWN')}개, FAIL(보수적) {sum(1 for r in want_unk if r.oracle == 'FAIL')}개, PASS 로 샘 {sum(1 for r in want_unk if r.oracle == 'PASS')}개" if want_unk else "",
          f"- plan 실패(V4 에서 걸림) {len(plan_fail)}개" + (": " + ", ".join(r.name for r in plan_fail) if plan_fail else ""), ""]
    L = [x for x in L if x != ""] + [""]
    fam = defaultdict(list)
    for r in rs:
        fam[r.family].append(r)
    L += ["| 재주(family) | 변형 | 잡혀야 함 | Trivy 사각 | 오라클 탐지 | 오라클 사각 |", "|---|---|---|---|---|---|"]
    for f, items in fam.items():
        wf = [r for r in items if r.expected == "FAIL"]
        L.append(f"| {f} | {len(items)} | {len(wf)} | {sum(1 for r in wf if r.trivy_flagged is False)} | {sum(1 for r in wf if r.oracle == 'FAIL')} | {sum(1 for r in wf if r.oracle == 'PASS')} |")
    L += ["", "| 변형 | 재주 | 정답 | Trivy | Trivy 룰 | plan | 오라클 | 판정 | 설명 |", "|---|---|---|---|---|---|---|---|---|"]
    for r in rs:
        tv = "FAIL" if r.trivy_flagged else ("PASS" if r.trivy_flagged is False else "-")
        L.append(f"| {r.name} | {r.family} | {r.truth} | {tv} | {', '.join(r.trivy_rules) or '-'} | {'OK' if r.plan_ok else ('FAIL' if r.plan_ok is False else '-')} | {r.oracle} | {r.verdict} | {r.note} |")
    L.append("")
    return L


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=["sg", "iam", "all"], default="all")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--out", default="experiments/FUZZ_RESULTS.md")
    ap.add_argument("--fresh", action="store_true", help="변형·코드·도구가 같아도 다시 돌린다")
    a = ap.parse_args()
    s = load_settings(str(ROOT))
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = ROOT / "experiments" / "fuzz" / f"{stamp}-{platform.node() or 'host'}"
    trivy = TrivyAdapter(s.trivy_bin)
    info = TerraformAdapter(s.terraform_bin, s.aws_region).info()
    env = f"host={platform.node()}, trivy={trivy.version() if trivy.available() else '없음'}, terraform={(info.kind + ' ' + info.version) if info.available else '없음'}"
    print(env)
    kinds = ["sg", "iam"] if a.kind == "all" else [a.kind]
    # 지문: 변형 목록 + 판정 코드 + 도구 버전이 같으면 (전체 실행일 때) 이전 결과를 그대로 둔다 — 한 번 클릭 실행기가 매번 10분을 쓰지 않게
    from iacpatch.fingerprint import code_digest, combine
    from iacpatch.fuzz import iam_variants, sg_variants
    fp = combine({"v": 1, "env": env, "code": code_digest(ROOT), "kinds": kinds, "limit": a.limit, "only": a.only,
                  "sg": [v.hcl for v in sg_variants.variants()], "iam": [v.hcl for v in iam_variants.variants()]})
    latest = ROOT / "experiments" / "fuzz" / "latest.json"
    if not a.fresh and latest.exists() and (ROOT / a.out).exists():
        try:
            prev = json.loads(latest.read_text(encoding="utf-8"))
            if prev.get("fingerprint") == fp and Path(prev.get("results", "")).exists():
                print(f"재사용: 변형·코드·도구가 같다 → {a.out} 유지 (원 실행 {prev.get('stamp')}). 다시 돌리려면 --fresh")
                return 0
        except (OSError, ValueError):
            pass
    L = ["# 스캐너 사각 탐색 실험 (자동 생성) — 겉모습만 다른 변형을 Trivy 와 오라클(V6)에 나란히", "",
         f"- 생성: {stamp} · {env} · 원문: `{base.relative_to(ROOT)}/` (변형 main.tf, trivy.json, plan.json)",
         "- 정답(truth)은 변형을 만들 때 구조적으로 정해진다 (`src/iacpatch/fuzz/*_variants.py`). 사람이 라벨을 적지 않았다.",
         "- Trivy 열: SG 는 AVD-AWS-0107 이 FAIL 인가, IAM 은 aws_iam_* 리소스에 FAIL finding 이 하나라도 있는가. 오라클 열: V6 판정 (plan JSON 기준).",
         "- 이 숫자는 '스캐너가 못 보는 겉모습이 몇 종인가' 이지 'LLM 이 이런 패치를 얼마나 내는가' 가 아니다.", ""]
    all_rs = {}
    for kind in kinds:
        rs = run_variants(s, kind, base / kind, limit=a.limit, only=a.only)
        all_rs[kind] = rs
        L += _md(kind, rs)
    tot_fail = [r for k in all_rs for r in all_rs[k] if r.expected == "FAIL"]
    tot_blind = [r for r in tot_fail if r.trivy_flagged is False]
    L.insert(6, f"**합계**: 잡혀야 하는 변형 {len(tot_fail)}개 중 Trivy 사각 **{len(tot_blind)}개**, 그중 오라클 탐지 **{sum(1 for r in tot_blind if r.oracle == 'FAIL')}개** · UNKNOWN {sum(1 for r in tot_blind if r.oracle == 'UNKNOWN')}개 · 오라클도 놓침 **{sum(1 for r in tot_fail if r.oracle == 'PASS')}개**\n")
    out = ROOT / a.out
    out.write_text("\n".join(L), encoding="utf-8")
    (base / "results.json").write_text(json.dumps({"env": env, "stamp": stamp, "fingerprint": fp, "results": {k: [r.to_dict() for r in v] for k, v in all_rs.items()}}, ensure_ascii=False, indent=1), encoding="utf-8")
    latest.write_text(json.dumps({"fingerprint": fp, "stamp": stamp, "results": str(base / "results.json"), "out": a.out}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"→ {out}\n→ {base / 'results.json'}")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
