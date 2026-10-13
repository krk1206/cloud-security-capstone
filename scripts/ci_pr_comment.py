#!/usr/bin/env python3
"""CI 용 요약 마크다운 — PR 댓글 / Actions 작업 요약에 붙는 검증 표.

    python3 scripts/ci_pr_comment.py [--out experiments/CI_SUMMARY.md]

숫자는 전부 이 실행의 기록(data/reviews, experiments/*.md)과 도구 없는 재계산(rubric_demo)에서만 온다. 없는 것은 '없음/미실행' 으로 적는다.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import argparse
import os
import platform
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_sys.path.insert(0, str(ROOT / "src"))

MARKER = "<!-- iacpatch-ci-summary -->"


def _tool(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr).strip() else "?"
    except (OSError, subprocess.TimeoutExpired):
        return "없음"


def build() -> str:
    from iacpatch import rubric_demo as rd
    from iacpatch.report_html import summarize
    S = summarize()
    lm = rd.labeled_matrix(ROOT, Path(tempfile.mkdtemp(prefix="ci-rubric-")))
    cap = rd.cap_enforcement_check()
    trivy = _tool([os.environ.get("TRIVY_BIN", "trivy"), "--version"])
    tf = _tool([os.environ.get("TERRAFORM_BIN", "terraform"), "version"])
    L = [MARKER, "## IaCPatch 검증 표 (이 커밋, GitHub Actions 에서 실행)", "",
         f"실행 환경: `{platform.node()}` · python {platform.python_version()} · {trivy} · {tf} · offline plan (AWS 자격증명 없음) · LLM API 호출 0 · terraform apply 0",
         ""]
    L += ["### 후보 세트 (V1~V6, 실제 도구)", "", "| 세트 | 후보 | 라벨 일치 | 재스캔(V1)만 통과 | V1+V6 통과 | 스캐너 통과∧오라클 FAIL | 미검증 계층 |", "|---|---|---|---|---|---|---|"]
    for s in S["sets"]:
        if not s.get("n"):
            L.append(f"| {s['id']} | 0 | – | – | – | – | 미실행 |")
            continue
        L.append(f"| {s['id']} | {s['n']} | {s.get('agree', 0)}/{s.get('labeled', 0)} | {s.get('v1_only', 0)} | {s.get('gate', 0)} | **{s.get('spof', 0)}** | {s.get('not_run', 0)} |")
    L += ["", f"합계: 라벨 일치 **{S['label_agree']}/{S['label_total']}** · 스캐너 통과∧오라클 FAIL **{S['spof_total']}** · 미검증 계층 {S['not_run_total']} · LLM 후보 {S['n_llm']}{' (미측정)' if not S['n_llm'] else ''} · AWS 배포 후 검증 {S['aws_runs']}회", ""]
    if S.get("blind_sg") or S.get("blind_iam"):
        bs, bi = S.get("blind_sg") or (0, 0), S.get("blind_iam") or (0, 0)
        L += [f"오라클 실험(실제 plan): 스캐너 통과∧V6 FAIL — SG {bs[0]}/{bs[1]} · IAM {bi[0]}/{bi[1]} (experiments/ORACLE_RESULTS.md)", ""]
    if S.get("fuzz"):
        f = S["fuzz"]
        L += [f"스캐너 사각 탐색: 잡혀야 하는 변형 {f['should']} 중 Trivy 사각 {f['trivy_blind']} → 오라클 탐지 {f['oracle_caught']} · UNKNOWN {f['unknown']} · 놓침 **{f['oracle_miss']}** (experiments/FUZZ_RESULTS.md)", ""]
    L += ["### 4주차 — 위험도 기준표 (도구 없이 재계산)", "",
          f"- 라벨 25건을 실제 검토 흐름으로 다시 돌린 결과: 기대 등급 = 코드 등급 **{lm['agree']}/{lm['judged']}** (분포 LOW {lm['distribution']['LOW']} / MEDIUM {lm['distribution']['MEDIUM']} / HIGH {lm['distribution']['HIGH']}) · 사람 손 검산 {lm['human_verified']}/{lm['total']}",
          f"- 상한 강제 전수 검사: {cap['total']} 조합 중 위반 **{len(cap['violations'])}** 건 (정책 위반/검증 실패 → 차단, 검증 통과 → 최종 자율성 = min(상한, LLM 제안))",
          "",
          "### 어디서 걸렸나 (세트별 최신 실행)", ""]
    stops = S["stops"]
    L += ["| 걸린 곳 | 건수 |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sorted(stops.items(), key=lambda kv: -kv[1])]
    L += ["", "리포트 전체(report/index.html)와 후보별 review.md 는 이 워크플로의 아티팩트에 있다. "
             "이 표는 검증 결과 '표시' 이며 병합 판단은 사람이 한다 — 자동 병합·자동 apply 없음 (D-5).", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="experiments/CI_SUMMARY.md")
    a = ap.parse_args()
    md = build()
    out = ROOT / a.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(md)
    print(f"→ {out}")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
