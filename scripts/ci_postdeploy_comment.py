#!/usr/bin/env python3
"""iacpatch postdeploy 기록(data/runs/<id>/verification_post.json) → PR 댓글용 마크다운.

사용: python scripts/ci_postdeploy_comment.py --before data/runs/<id1> --after data/runs/<id2> \
          [--plan-check BLOCKED|OK|SKIPPED] [--timings apply_base=12,apply_patch=5,destroy=20] [--target-dir DIR] > comment.md
--before 는 원본(패치 전) 측정, --after 는 패치 후 측정. 둘 중 하나만 있어도 된다.
표준 라이브러리만 쓴다. 판정은 만들지 않는다 — 기록에 있는 값을 그대로 옮긴다.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ICON = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "UNKNOWN": "❔", "SKIPPED": "⏭️", "ERROR": "💥", "NOT_RUN": "⏸️"}
STATUS_KO = {"VERIFIED": "V7·V8 모두 PASS", "DEPLOY_FAILED": "FAIL 있음", "UNVERIFIED": "통과 아님 (UNKNOWN/ERROR 남음)"}


def _load(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _status(report: dict) -> str:
    vs = [l.get("verdict") for l in report.get("layers") or []]
    if any(v == "FAIL" for v in vs):
        return "DEPLOY_FAILED"
    if vs and all(v == "PASS" for v in vs):
        return "VERIFIED"
    return "UNVERIFIED"


def section(title: str, run_dir: Path) -> list:
    run = _load(run_dir / "run.json") or {}
    rep = _load(run_dir / "verification_post.json")
    out = [f"### {title} — run `{run.get('run_id', run_dir.name)}`", ""]
    if rep is None:
        out += ["> 측정 기록 없음 (postdeploy 가 끝까지 가지 않았다)", ""]
        return out
    st = _status(rep)
    out.append(f"- 결과: **{st}** — {STATUS_KO.get(st, '')} · validity `{rep.get('validity', '-')}`")
    out += ["", "| 계층 | 내용 | 판정 | 요약 |", "|---|---|---|---|"]
    for l in rep.get("layers") or []:
        v = l.get("verdict", "-")
        s = (l.get("summary") or "").replace("|", "\\|").replace("\n", " ")
        out.append(f"| {l.get('layer')} | {l.get('name', '')} | {ICON.get(v, '')} {v} | {s[:200]} |")
    v8 = next((l for l in rep.get("layers") or [] if l.get("layer") == "V8"), None)
    rows = ((v8 or {}).get("details") or {}).get("results") or []
    if rows:
        out += ["", "<details><summary>V8 통신 검사 상세</summary>", "", "| 검사 | 포트 | 기대 | 출처 | 실제 | 결과 |", "|---|---|---|---|---|---|"]
        for r in rows:
            probe = (r.get("probe") or {}).get("result", r.get("outcome", "-"))
            out.append(f"| {r.get('label')} | {r.get('port')} | {r.get('expect')} | {r.get('source_class')} | {probe} | {r.get('outcome')} |")
        out += ["", "</details>"]
    out.append("")
    return out


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--before"); ap.add_argument("--after")
    ap.add_argument("--plan-check", default="SKIPPED")
    ap.add_argument("--timings", default="")
    ap.add_argument("--target-dir", default="-")
    ap.add_argument("--destroyed", default="unknown", help="clean|leftover|unknown")
    a = ap.parse_args(argv[1:])
    out = [f"## iacpatch 임시 시험 환경 (V7·V8) — `{a.target_dir}`", "",
           "> 격리된 임시 VPC 에 원본을 올려 측정하고, 패치를 올려 다시 측정한 뒤, 환경을 지웠다. 사람 승인 없이 도는 단계이며 상시 환경은 건드리지 않는다.", ""]
    pc = {"OK": "✅ 교체·삭제 없음 (제자리 수정만)", "BLOCKED": "❌ 교체 또는 삭제가 포함됨 → 패치 apply 하지 않음", "SKIPPED": "⏭️ 확인 안 함"}
    out.append(f"- 패치 plan 점검(실제 state 기준): {pc.get(a.plan_check, a.plan_check)}")
    if a.timings:
        out.append("- 소요: " + ", ".join(f"{k} {v}s" for k, v in (kv.split('=', 1) for kv in a.timings.split(',') if '=' in kv)))
    out.append({"clean": "- 임시 환경 삭제 완료 (남은 리소스 0)", "leftover": "- ⚠️ **임시 환경에 리소스가 남아 있음 — 사람이 정리 필요**"}.get(a.destroyed, "- 임시 환경 삭제 여부 미확인"))
    out.append("")
    if a.before:
        out += section("패치 전 (원본)", Path(a.before))
    if a.after:
        out += section("패치 후", Path(a.after))
    out += ["> 러너(인터넷) 가 승인 밖 관측 지점이다. 승인 출처 안에서의 접속(required_access) 은 V7 규칙 실측으로만 확인한다.",
            "> 전체 기록(aws_raw·verification_post·plan)은 이 워크플로 실행의 artifact 에 있다."]
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
