#!/usr/bin/env python3
"""기업용 한 장 — "스캐너만 쓰면 무엇이 통과하고, 이 게이트는 무엇을 막았나" 를 실측 기록에서만 만든다.

    python3 scripts/why_this_gate.py   → experiments/WHY_THIS_GATE.md

입력(전부 저장소 안의 실측 기록):
  - tests/fixtures/plans/*  + tests/fixtures/trivy/*  (SG, A 의 Trivy 스캔 + 실제 plan)  → scripts/oracle_experiment.py 와 같은 계산
  - tests/fixtures/plans/iam-* (IAM, 실제 plan + trivy.json)
  - experiments/candidate-sets/eval-seeded-*/results.md 의 최신 실행 (파이프라인 전체: 정책·V1~V6·검토 수준)
숫자를 만들어내지 않는다. 기록이 없으면 "기록 없음" 으로 적는다. LLM 후보가 0 이면 0 이라고 적는다.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_sys.path.insert(0, str(ROOT / "src"))
_sys.path.insert(0, str(ROOT / "scripts"))

from oracle_experiment import CASES, IAM_CASES, IAM_INTENT, PLANS, SRC, intent_for, scanner_0107, scanner_any  # noqa: E402
from iacpatch.iam_intent import load_iam_intent  # noqa: E402
from iacpatch.verify.iam_oracle import build_iam_world  # noqa: E402
from iacpatch.verify.iam_oracle import evaluate as evaluate_iam  # noqa: E402
from iacpatch.verify.plan_model import build_world  # noqa: E402
from iacpatch.verify.sg_oracle import evaluate  # noqa: E402


def sg_rows():
    out = []
    for case, tgt, kw, exp, desc in CASES:
        p = PLANS / case / "plan.json"
        if not p.exists():
            continue
        world = build_world(json.loads(p.read_text(encoding="utf-8")), {q.name: q.read_text(encoding="utf-8") for q in (SRC / case).glob("*.tf")})
        out.append((case, scanner_0107(case), evaluate(world, intent_for(tgt, kw)).verdict.value, exp, desc))
    return out


def iam_rows():
    intent = load_iam_intent(IAM_INTENT)
    out = []
    for case, exp, desc in IAM_CASES:
        d = PLANS / f"iam-{case}"
        if not (d / "plan.json").exists():
            continue
        v = evaluate_iam(build_iam_world(json.loads((d / "plan.json").read_text(encoding="utf-8"))), intent).verdict.value
        out.append((case, scanner_any(d / "trivy.json"), v, exp, desc))
    return out


def latest_set_summary(set_id: str):
    """results.md 의 머리 숫자 (있으면)."""
    p = ROOT / "experiments" / "candidate-sets" / set_id / "results.md"
    if not p.exists():
        return None
    t = p.read_text(encoding="utf-8")
    m = re.search(r"V1 만으로 통과시켰을 건수 (\d+) vs V1\+V6 통과 (\d+)", t)
    env = re.search(r"실행 환경: (.+)", t)
    lab = re.search(r"라벨 있는 실행 (\d+)건 중 기대대로 판정 (\d+)건", t)
    return {"v1_only": int(m.group(1)) if m else None, "v1_v6": int(m.group(2)) if m else None,
            "env": env.group(1).strip() if env else "?", "labeled": (int(lab.group(1)), int(lab.group(2))) if lab else None}


def main() -> int:
    sg, iam = sg_rows(), iam_rows()
    sg_blind = [r for r in sg if r[1] == "PASS" and r[2] == "FAIL"]
    iam_blind = [r for r in iam if r[1] == "PASS" and r[2] == "FAIL"]
    cc_manifest = json.loads((ROOT / "experiments/candidate-sets/eval-claude-code/manifest.json").read_text(encoding="utf-8"))
    n_llm = len(cc_manifest.get("candidates") or [])
    L = ["# 왜 스캐너만으로는 안 되고, 이 게이트가 무엇을 더 하나 — 실측 한 장 (자동 생성)", "",
         "> 대상 독자: 기업 엔지니어. 아래 숫자는 전부 이 저장소의 기록에서 다시 계산한 것이며, 스캐너는 Trivy 0.74.0(내장 체크) 이다.",
         "> 후보는 사람/AI 세션이 만든 **알려진 우회 패턴** 이다. 'LLM 이 실제로 이런 패치를 얼마나 내는가' 는 별도 측정 항목이며 현재 LLM 후보 수는 아래에 적는다.", "",
         "## 1. 스캐너가 통과시키는데 실제 보안 상태는 그대로인 패치 (스캐너 PASS ∧ 오라클 FAIL)", "",
         f"- Security Group: 실제 plan {len(sg)}개 중 **{len(sg_blind)}개** — " + ", ".join(r[0] for r in sg_blind),
         f"- IAM (Tier 1): 실제 plan {len(iam)}개 중 **{len(iam_blind)}개** — " + ", ".join(r[0] for r in iam_blind), "",
         "이 패치들은 `trivy config` 를 통과한다. 재스캔만으로 '고쳐졌다' 고 판단하는 CI 는 이 패치를 그대로 병합한다.", "",
         "| 유형 | 우회 방식 | Trivy | 이 게이트(V6) |", "|---|---|---|---|"]
    for r in sg_blind + iam_blind:
        L.append(f"| {'SG' if r in sg_blind else 'IAM'} | {r[4]} | 통과 | 차단 |")
    L += ["", "## 2. 정상 패치는 통과시키나 (오탐)", ""]
    for name, rows in (("SG", sg), ("IAM", iam)):
        ok = [r for r in rows if r[3] == "PASS"]
        L.append(f"- {name}: 정상으로 설계된 후보 {len(ok)}개 중 오라클 PASS {sum(1 for r in ok if r[2] == 'PASS')}개")
    fuzz_md = (ROOT / "experiments" / "FUZZ_RESULTS.md").read_text(encoding="utf-8") if (ROOT / "experiments" / "FUZZ_RESULTS.md").exists() else ""
    fz = re.search(r"잡혀야 하는 변형 (\d+)개 중 Trivy 사각 \*\*(\d+)개\*\*, 그중 오라클 탐지 \*\*(\d+)개\*\* · UNKNOWN (\d+)개 · 오라클도 놓침 \*\*(\d+)개\*\*", fuzz_md)
    L += ["", "## 2b. 겉모습만 바꾼 변형을 자동으로 만들어 넣었을 때 (스캐너 사각 탐색, `scripts/fuzz_scanner.py`)", ""]
    if fz:
        L += [f"- 잡혀야 하는 변형 {fz.group(1)}종 중 Trivy 가 못 본 것 **{fz.group(2)}종** → 오라클이 잡은 것 **{fz.group(3)}종**, 사람에게 넘긴 것 {fz.group(4)}종, 오라클도 놓친 것 **{fz.group(5)}종** (`experiments/FUZZ_RESULTS.md`)",
              "- 재주별(CIDR 분할·별도 규칙 리소스·변수/함수 경유·dynamic/for_each·prefix list·인접 SG·IAM 나열·Resource *·신뢰 정책 …)로 어떤 겉모습이 스캐너를 통과하는지가 표로 남는다. 정답은 변형을 만들 때 구조적으로 정해지므로 사람 라벨이 없다."]
    else:
        L.append("- 기록 없음 (scripts/fuzz_scanner.py 미실행)")
    L += ["", "## 3. 파이프라인 전체(정책 → V1~V6 → 검토 수준)를 돌렸을 때", ""]
    for set_id in ("eval-seeded-sg", "eval-seeded-iam"):
        s = latest_set_summary(set_id)
        if not s:
            L.append(f"- {set_id}: 기록 없음"); continue
        L.append(f"- {set_id}: 재스캔(V1)만 믿었으면 통과 {s['v1_only']}건 → 게이트 통과 {s['v1_v6']}건"
                 + (f" (기대 라벨 일치 {s['labeled'][1]}/{s['labeled'][0]})" if s["labeled"] else "") + f" — 실행 환경: {s['env']}")
    L += ["", "## 4. 이 게이트가 하지 않는 것 (정직하게)", "",
          "- 스캐너를 대체하지 않는다. Trivy 결과가 입력이고, 그 위에 실효 상태 검사(V6)·plan 차이(V5)·위험도 게이트를 얹는다.",
          "- 배포 후 실제 상태 확인(V7/V8)은 코드는 있으나 이 저장소 기록에는 **실행 0회** 다.",
          f"- LLM 이 실제로 기만적 패치를 내는 비율은 아직 측정 전이다 (Claude Code 후보 {n_llm}건).",
          "- IAM 은 Tier 1(Allow 문, `*` 와일드카드, 역할 합산)만 판정한다. Deny/Condition/NotAction/관리형 정책은 '판단 불가 → 사람 검토' 다.",
          "- 오라클 자체의 집합 연산은 무작위 입력으로 기준 구현과 대조했다 (`experiments/ORACLE_FUZZ.md`, 불일치 0 이어야 함). plan 을 읽어 세계를 만드는 부분은 변형 생성 실험과 fixture 회귀 테스트가 맡는다.",
          "- 같은 검사를 OPA/Sentinel 정책 코드로 직접 작성할 수도 있다. 이 게이트의 가치는 '미리 구현된 실효 상태 오라클 + intent 비교 + 위험도 게이트 + 근거 기록' 을 한 묶음으로 CI 에 붙이는 데 있다.", "",
          "## 5. 기업이 쓴다면 어디에", "",
          "- PR 체크: AI 도구(Copilot/Claude Code/Q Developer 등)가 제안한 IaC 수정 PR 에 이 게이트를 required check 로. 통과 못 하면 근거 표와 함께 차단.",
          "- 도구 도입 평가: '우리 AI 도구가 스캐너를 속이는 패치를 얼마나 내는가' 를 seeded 세트 + 이 게이트로 측정.",
          "- 교육: 스캐너 사각 사례집(`experiments/ORACLE_RESULTS.md`)."]
    out = ROOT / "experiments" / "WHY_THIS_GATE.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L)); print(f"\n→ {out}")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
