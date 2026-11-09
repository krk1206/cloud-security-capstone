#!/usr/bin/env python3
"""PR 게이트 (iac-scan.yml): 이 PR 이 HIGH · CRITICAL 설정 오류를 "새로" 만들었는가.

    python scripts/ci_scan_gate.py --head head.json [--base base.json] [--severity HIGH,CRITICAL]

- 두 Trivy JSON(trivy config --format json) 에서 FAIL 이고 심각도가 기준 안인 finding 을 센다.
- 열쇠 = (규칙 ID, 리소스 주소). 같은 열쇠가 기준(base)보다 많아졌으면 그만큼이 "새 finding" 이다.
  (같은 보안 그룹에 나쁜 규칙을 하나 더 넣으면 개수가 늘어서 잡힌다. 줄 번호는 열쇠에 넣지 않는다 — 편집으로 줄이 밀려도 새것으로 안 본다.)
- --base 가 없으면 (새 폴더) 모든 finding 이 새것이다.
- 새 finding 이 있으면 종료 코드 1. 원래 있던 finding 만 남아 있으면 0 (예: 패치가 SSH 는 고쳤지만 원래 있던 egress 지적은 남은 경우).

이유: main 에는 일부러 넣은 설정 오류가 있다. "HIGH 가 하나라도 있으면 실패" 면 그 오류를 하나만 고친 정상 패치 PR 도 막힌다.
표준 라이브러리만 쓴다.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

Key = Tuple[str, str]


def findings(path: Optional[str], severities: set) -> Tuple[Counter, Dict[Key, dict]]:
    cnt: Counter = Counter()
    sample: Dict[Key, dict] = {}
    if not path or not Path(path).exists():
        return cnt, sample
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    for res in doc.get("Results") or []:
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL" or str(m.get("Severity", "")).upper() not in severities:
                continue
            rid = str(m.get("AVDID") or m.get("ID") or "?")
            resource = str((m.get("CauseMetadata") or {}).get("Resource") or res.get("Target") or "?")
            k = (rid, resource)
            cnt[k] += 1
            sample.setdefault(k, {"severity": m.get("Severity"), "title": m.get("Title"), "target": res.get("Target"),
                                  "line": (m.get("CauseMetadata") or {}).get("StartLine")})
    return cnt, sample


def new_findings(base: Counter, head: Counter) -> List[Tuple[Key, int]]:
    return sorted(((k, n - base.get(k, 0)) for k, n in head.items() if n > base.get(k, 0)), key=lambda x: x[0])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--head", required=True)
    ap.add_argument("--base")
    ap.add_argument("--severity", default="HIGH,CRITICAL")
    ap.add_argument("--label", default="", help="출력에 붙일 폴더 이름")
    a = ap.parse_args()
    sev = {s.strip().upper() for s in a.severity.split(",") if s.strip()}
    base_cnt, _ = findings(a.base, sev)
    head_cnt, sample = findings(a.head, sev)
    new = new_findings(base_cnt, head_cnt)
    fixed = sorted(k for k, n in base_cnt.items() if head_cnt.get(k, 0) < n)
    tag = f"[{a.label}] " if a.label else ""
    print(f"{tag}기준(base) {sum(base_cnt.values())}건 · 이번(head) {sum(head_cnt.values())}건 · 새로 생김 {sum(n for _, n in new)}건 · 줄어듦 {len(fixed)}종")
    for (rid, resource), n in new:
        s = sample.get((rid, resource), {})
        print(f"  새 finding: {rid} ({s.get('severity')}) {resource} x{n} — {s.get('title')} [{s.get('target')}:{s.get('line')}]")
    for rid, resource in fixed:
        print(f"  줄어든 finding: {rid} {resource}")
    if not a.base:
        print("  (기준 없음: 새 폴더 — 모든 finding 을 새것으로 본다)")
    return 1 if new else 0


if __name__ == "__main__":
    raise SystemExit(main())
