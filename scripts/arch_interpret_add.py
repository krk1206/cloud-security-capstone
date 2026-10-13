#!/usr/bin/env python3
"""AI 해석 응답을 스캔 기록에 등록한다 (지도교수 9/29 지시 3단계).

    python3 scripts/arch_interpret_add.py data/arch/20261002-120000 응답.json --note "2026-10-03 Claude Code 세션, 모델 표시 ..."
    IaCPatch-console.exe --exec scripts/arch_interpret_add.py data\\arch\\20261002-120000 응답.json --note "..."

- 응답.json: Claude Code(또는 Claude 앱)에 interpret_prompt.md 를 붙여 넣고 받은 JSON (```json 블록째 저장해도 된다).
- 이 스크립트는 모델을 호출하지 않는다. 응답을 실제 Trivy 결과·팀 CIS 매핑표와 **기계 대조**하고 결과를 interpretation.md 에 쓴다.
- 지어낸 finding·누락·CIS 불일치는 숨기지 않고 그대로 표시한다.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from iacpatch.archinterp import InterpretationError, register  # noqa: E402
from iacpatch.config import load_json, package_root  # noqa: E402


def main(argv=None) -> int:
    root = package_root() if (package_root() / "policy" / "patch_policy.json").exists() else ROOT
    ap = argparse.ArgumentParser(description="AI 해석 응답 등록 (실제 스캔 결과와 대조)")
    ap.add_argument("scan_dir", help="scripts/arch_scan.py 결과 폴더 (summary.json 이 있는 곳)")
    ap.add_argument("response", help="응답 JSON 파일 (.json / .md)")
    ap.add_argument("--note", default="", help="날짜·세션·모델 표시 (화면에 보이는 대로)")
    ap.add_argument("--source", default="claude-code-manual", help="출처 표시 (기본 claude-code-manual)")
    a = ap.parse_args(argv)
    scan_dir = Path(a.scan_dir) if Path(a.scan_dir).is_absolute() else root / a.scan_dir
    try:
        rec = register(scan_dir, Path(a.response), load_json(root / "policy" / "cis_mapping.json"), note=a.note, source=a.source)
    except (InterpretationError, OSError) as e:
        print(f"등록 실패: {e}", file=sys.stderr)
        return 2
    ch = rec["checks"]
    print(f"등록됨: {scan_dir / 'interpretation.md'}")
    print(f"  해석된 실제 finding {ch['coverage']} · 지어낸 finding {len(ch['fabricated'])}건 · 누락 {len(ch['missing'])}건 · CIS 불일치 {ch['cis_mismatch']}건")
    for w in rec.get("warnings") or []:
        print(f"  경고: {w}")
    return 0 if not ch["fabricated"] else 1


if __name__ == "__main__":
    sys.exit(main())
