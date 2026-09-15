#!/usr/bin/env python3
"""A 의 Trivy 우회 실험 결과(experiments/trivy-sg-probe/results-verify/*.json) 를 우리 로더로 읽고,
trivy 가 있으면 같은 케이스를 로컬에서 다시 스캔해 FAIL 룰 집합이 같은지 확인한다.

    TRIVY_BIN=trivy python3 experiments/candidate-sets/a-probe-dev/check_a_results.py  →  A_RESULTS_CHECK.md

- 비교 대상: A 의 RESULTS.md / VERIFY.md 표 (2026-09-08, Trivy 0.74.0, WSL2)
- 로컬 스캔은 trivy 가 없으면 건너뛰고 "미실행" 으로 적는다. 숫자를 지어내지 않는다.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
from iacpatch.review.inputs import list_findings, load_trivy_report  # noqa: E402

HERE = Path(__file__).resolve().parent
CASES = ["00-baseline", "01-cidr-split", "01b-control", "02-var-default", "03-string-build", "04-dynamic",
         "05-separate", "06-prefix-list", "07-ipv6-only", "08-second-sg"]
A_RESULTS = ROOT / "experiments/trivy-sg-probe/results-verify"
A_CASES = ROOT / "experiments/trivy-sg-probe/cases"


def fail_rules(report) -> list[str]:
    return sorted(f.rule_id for f in list_findings(report))


def summary(report) -> tuple[int, int]:
    s = f = 0
    for r in report.get("Results") or []:
        ms = r.get("MisconfSummary") or {}
        s += int(ms.get("Successes") or 0)
        f += int(ms.get("Failures") or 0)
    return s, f


def local_scan(case_dir: Path, trivy: str):
    out = HERE / "local-rescan" / (case_dir.name + ".json")
    out.parent.mkdir(exist_ok=True)
    argv = [trivy, "config", str(case_dir), "--format", "json", "--include-non-failures", "--quiet", "--output", str(out)]
    if os.environ.get("TRIVY_SKIP_CHECK_UPDATE", "1") == "1":
        argv.append("--skip-check-update")
    r = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout)[:300]
    return json.loads(out.read_text(encoding="utf-8")), ""


def main() -> int:
    trivy = os.environ.get("TRIVY_BIN", "trivy")
    have_trivy = subprocess.run([trivy, "--version"], capture_output=True, text=True).returncode == 0 if _which(trivy) else False
    ver = subprocess.run([trivy, "--version"], capture_output=True, text=True).stdout.strip().splitlines()[0] if have_trivy else "없음"
    rows = []
    all_same = True
    for c in CASES:
        ap = A_RESULTS / f"{c}.json"
        if not ap.exists():
            rows.append((c, "A 파일 없음", "", "", "", ""))
            continue
        a = load_trivy_report(ap)
        a_rules, (a_s, a_f) = fail_rules(a), summary(a)
        a_0107 = "FAIL" if "AVD-AWS-0107" in a_rules else "PASS"
        if have_trivy and (A_CASES / c).is_dir():
            l, err = local_scan(A_CASES / c, trivy)
            if l is None:
                rows.append((c, f"{a_s}/{a_f}", a_0107, ",".join(a_rules) or "-", f"스캔 실패: {err}", "?"))
                all_same = False
                continue
            l_rules, (l_s, l_f) = fail_rules(l), summary(l)
            same = (l_rules == a_rules) and (l_s, l_f) == (a_s, a_f)
            all_same &= same
            rows.append((c, f"{a_s}/{a_f}", a_0107, ",".join(a_rules) or "-", f"{l_s}/{l_f} " + (",".join(l_rules) or "-"), "동일" if same else "**다름**"))
        else:
            rows.append((c, f"{a_s}/{a_f}", a_0107, ",".join(a_rules) or "-", "미실행 (trivy 없음)" if not have_trivy else "케이스 폴더 없음", "-"))
    lines = ["# A 의 Trivy 우회 실험 결과 — 우리 로더 판독 + 로컬 재스캔 대조", "",
             f"- A 의 결과 파일: `experiments/trivy-sg-probe/results-verify/*.json` (A: Trivy 0.74.0, 2026-09-08)",
             f"- 로컬 재스캔: {ver} (내장 체크 번들, `--skip-check-update`), 실행 환경: 이 저장소를 돌린 컴퓨터",
             "- 판독: `iacpatch.review.inputs.list_findings` (검토 흐름이 쓰는 것과 같은 로더). '통과/실패' 는 MisconfSummary 합계", "",
             "| 케이스 | A 통과/실패 | A AWS-0107 | A FAIL 룰 | 로컬 재스캔 통과/실패 + FAIL 룰 | 일치 |", "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| " + " | ".join(r) + " |")
    lines += ["", ("**전 케이스 일치** — A 의 표(RESULTS.md/VERIFY.md)가 다른 컴퓨터·내장 체크 번들로 재현됐다." if have_trivy and all_same
                   else ("불일치 항목이 있다. 체크 번들 버전 차이일 수 있으니 A 의 실행 기록(VERIFY.md 의 번들 시각)과 비교할 것." if have_trivy
                         else "로컬 재스캔은 실행하지 않았다 (trivy 없음). 표의 A 열은 A 파일을 그대로 읽은 값이다."))]
    out = HERE / "A_RESULTS_CHECK.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"→ {out}")
    return 0


def _which(b: str) -> bool:
    from shutil import which
    return which(b) is not None or os.path.exists(b)


if __name__ == "__main__":
    sys.exit(main())
