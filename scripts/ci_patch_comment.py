#!/usr/bin/env python3
"""iacpatch predeploy 기록(data/runs/<id>/run.json) → PR 댓글용 마크다운 한 장.

사용: python scripts/ci_patch_comment.py data/runs/<id> [--target-dir DIR] > comment.md
표준 라이브러리만 쓴다. 판정은 만들지 않는다 — 기록에 있는 값을 그대로 옮긴다.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ICON = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "UNKNOWN": "❔", "SKIPPED": "⏭️", "ERROR": "💥", "NOT_RUN": "⏸️"}
GATE_KO = {
    "CREATE_PR_AUTO": "패치 PR 자동 생성 (병합 전 경량 확인)",
    "CREATE_PR_APPROVAL": "패치 PR 생성 — 승인 필수",
    "REPORT_ONLY": "리포트만 — 위험도 HIGH 또는 근거 부족, 패치 PR 만들지 않음",
    "HOLD_FOR_HUMAN": "검증 미완료(INCOMPLETE) — 자동 조치 없음, 사람이 판단",
    "BLOCK": "차단 — 검증 FAIL 또는 정책 위반, 패치 PR 만들지 않음",
}


def _load(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def main(argv) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    run_dir = Path(argv[1])
    target_dir = argv[argv.index("--target-dir") + 1] if "--target-dir" in argv else None
    run = _load(run_dir / "run.json")
    if run is None:
        print(f"## iacpatch\n\n기록 없음: `{run_dir}`")
        return 1
    pr = _load(run_dir / "pr.json") or {}
    tgt = target_dir or run.get("target_dir") or "-"
    status = run.get("status", "-")
    out = [f"## iacpatch 패치 단계 — `{tgt}`", ""]
    out.append(f"- run: `{run.get('run_id', run_dir.name)}` · 시나리오 `{run.get('scenario_id', '-')}` · 생성기 `{run.get('generator', '-')}` · 상태 `{status}`")

    if status != "DONE":
        out += ["", f"> {run.get('note') or '패치 단계가 끝까지 가지 않았다.'}", ""]
        print("\n".join(out))
        return 0

    tf = run.get("target_finding") or {}
    out.append(f"- 대상 결함: `{tf.get('rule_id', '-')}` {tf.get('severity', '')} on `{tf.get('resource', '-')}` ({tf.get('filename', '-')}:{tf.get('start_line', '-')})")
    gate = run.get("gate") or {}
    risk = run.get("risk") or {}
    policy = run.get("policy") or {}
    action = gate.get("action", "-")
    out += ["", f"### 게이트: **{action}** — {GATE_KO.get(action, '')}", ""]
    out.append(f"- 검증(Validity): **{gate.get('validity', '-')}**")
    out.append(f"- 위험도(Risk): **{(risk or {}).get('level') or gate.get('risk_level') or '-'}**" + (f" — {risk.get('summary')}" if risk and risk.get("summary") else ""))
    out.append(f"- 정책(Policy): **{'OK' if policy.get('ok') else 'VIOLATION'}**" + (f" — {', '.join(policy.get('violations') or [])}" if policy.get("violations") else ""))
    for r in gate.get("reasons") or []:
        out.append(f"  - {r}")
    if pr.get("url"):
        out += ["", f"➡️ **패치 PR**: {pr['url']}"]
    out += ["", "| 계층 | 내용 | 판정 | 요약 |", "|---|---|---|---|"]
    for l in (run.get("validity") or {}).get("layers") or []:
        v = l.get("verdict", "-")
        s = (l.get("summary") or "").replace("|", "\\|").replace("\n", " ")
        out.append(f"| {l.get('layer')} | {l.get('name', '')} | {ICON.get(v, '')} {v} | {s[:160]} |")
    out += ["", "> 검증 축과 위험도 축은 별개다. 검증이 FAIL/INCOMPLETE 면 위험도와 무관하게 자동 조치하지 않는다. apply 는 이 단계에서 하지 않는다.",
            f"> 전체 기록(diff·plan·Trivy 원문)은 이 워크플로 실행의 artifact 안 `data/runs/{run.get('run_id', run_dir.name)}/` 에 있다."]
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
