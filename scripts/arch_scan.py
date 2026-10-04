#!/usr/bin/env python3
"""아키텍처 Terraform → Trivy 점검 → 결과물 (지도교수 9/29 지시 흐름의 2단계).

    python3 scripts/arch_scan.py                                   # scenarios/arch/webapp-2tier 점검 → data/arch/<실행 ID>/
    python3 scripts/arch_scan.py --dir scenarios/arch/webapp-2tier --no-plan
    IaCPatch-console.exe --exec scripts/arch_scan.py               # 팀 PC (python 없이, tools\\ 의 trivy·terraform 사용)

하는 것: *.tf 목록·리소스 집계 → terraform fmt/validate/오프라인 plan (자격증명 없음, 아무것도 만들지 않음) → trivy config →
         findings.md(표) · summary.json · interpret_prompt.md(AI 해석용 프롬프트).
하지 않는 것: 모델 호출, AWS 접속, 원본 수정. 도구가 없으면 NOT_RUN 으로 적는다.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from iacpatch.archscan import run_scan  # noqa: E402
from iacpatch.config import package_root  # noqa: E402


def main(argv=None) -> int:
    root = package_root() if (package_root() / "policy" / "patch_policy.json").exists() else ROOT
    ap = argparse.ArgumentParser(description="아키텍처 Terraform 점검 (fmt/validate/plan + trivy config)")
    ap.add_argument("--dir", default="scenarios/arch/webapp-2tier", help="Terraform 폴더 (저장소 루트 기준)")
    ap.add_argument("--out", default=None, help="결과 폴더 (기본 data/arch/<YYYYmmdd-HHMMSS>)")
    ap.add_argument("--no-plan", action="store_true", help="terraform 단계 생략 (trivy 만)")
    a = ap.parse_args(argv)
    tf_dir = (root / a.dir) if not Path(a.dir).is_absolute() else Path(a.dir)
    if not tf_dir.is_dir():
        print(f"폴더가 없다: {tf_dir}", file=sys.stderr)
        return 2
    out = Path(a.out) if a.out else root / "data" / "arch" / time.strftime("%Y%m%d-%H%M%S")
    res = run_scan(tf_dir, out, root=root, do_plan=not a.no_plan)
    bad = res["scan"].get("status") not in ("PASS",) or res["plan"].get("status") == "FAIL"
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
