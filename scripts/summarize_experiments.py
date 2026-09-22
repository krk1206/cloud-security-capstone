#!/usr/bin/env python3
"""평가용 세트들의 최신 실행 결과를 한 장으로 합친다 → experiments/RESULTS_SUMMARY.md

    python3 scripts/summarize_experiments.py [--sets eval-a-probe-rule eval-seeded-sg eval-claude-code] [--out data/reviews]

- 각 세트의 labels.json + data/reviews 의 **가장 최근 실행**(세트별 scenario 접두어로 찾음) 을 집계한다.
- 숫자를 만들어내지 않는다: NOT_RUN/ERROR 계층은 그대로 세어 표시하고, 후보 출처(규칙 기반/seeded/claude-code)를 항상 같이 적는다.
- E1(출처별) 은 세 세트를 합쳐서, E2(오라클 유무) 는 세트마다 따로 낸다.
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
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from iacpatch.metrics import collect, summarize  # noqa: E402

DEFAULT_SETS = ["eval-a-probe-rule", "eval-seeded-sg", "eval-iam-rule", "eval-seeded-iam", "eval-claude-code"]


def latest_rows_for_set(rows, set_id):
    """같은 후보 id 가 여러 번 실행됐으면 가장 최근 run 만 남긴다."""
    by_scn = {}
    for r in rows:
        scn = str(r.get("scenario") or "")
        if not scn.startswith(set_id + "/"):
            continue
        if scn not in by_scn or str(r["run_id"]) > str(by_scn[scn]["run_id"]):
            by_scn[scn] = r
    return list(by_scn.values())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sets", nargs="*", default=DEFAULT_SETS)
    ap.add_argument("--out", default="data/reviews")
    ap.add_argument("--write", default="experiments/RESULTS_SUMMARY.md")
    args = ap.parse_args()
    all_rows = collect([ROOT / args.out])
    L = ["# 실험 결과 요약 (자동 생성)", "",
         f"- 생성: {_dt.datetime.now().isoformat(timespec='seconds')} @ {platform.node() or '?'}",
         "- 이 파일은 **이 컴퓨터의 `data/reviews/`** 만 합산한다. 다른 컴퓨터에서 돌린 기록은 각 세트의 `results-history/<시각>-<호스트>.md` 를 볼 것 "
         "(예: `DESKTOP-*` = B 의 PC(Terraform 1.16.1), `vm` = 개발 샌드박스(OpenTofu 1.10.6 오프라인 plan). 두 환경의 SG 결과는 2026-09-21/22 에 일치했다).",
         "- 후보 출처가 `claude-code` 가 아닌 숫자는 LLM 성능이 아니다 (규칙 기반 = 기준선, seeded = 알려진 패턴 탐지 능력).",
         "- NOT_RUN/ERROR 는 검증이 안 된 것이지 통과가 아니다. 그 계층이 남아 있으면 해당 세트의 E2 는 미완이다.", ""]
    e1 = defaultdict(lambda: {"total": 0, "candidate_produced": 0, "as_expected": 0})
    for set_id in args.sets:
        sdir = ROOT / "experiments" / "candidate-sets" / set_id
        man = sdir / "manifest.json"
        if not man.exists():
            L += [f"## {set_id}", "", "- manifest 없음", ""]
            continue
        m = json.loads(man.read_text(encoding="utf-8"))
        labels = {f"{set_id}/{c['id']}": {"expected": c.get("expected", ""), "source": c.get("source", "")} for c in m.get("candidates", [])}
        rows = latest_rows_for_set(all_rows, set_id)
        L += [f"## {set_id} — {m.get('_note', '')[:120]}", ""]
        if not m.get("candidates"):
            L += ["- 후보 0건 (아직 채우지 않음)", ""]
            continue
        if not rows:
            L += [f"- manifest 에 후보 {len(m['candidates'])}건이 있지만 실행 기록이 없다 → `python3 scripts/run_candidate_set.py {man.relative_to(ROOT)}`", ""]
            continue
        s = summarize(rows, labels)
        not_run = {k: v.get("NOT_RUN", 0) + v.get("ERROR", 0) + v.get("SKIPPED", 0) for k, v in s["layer_verdicts"].items()}
        L += [f"- 실행 {s['runs']}건 (manifest {len(m['candidates'])}건). 최종 상태 {s['by_state']}",
              f"- 계층별 미검증(NOT_RUN/ERROR/SKIPPED): {not_run}",
              f"- E2: V1 만 통과 {s['gate_v1_only_pass']} / V1+V6 통과 {s['gate_v1_and_v6_pass']} / V1 통과했지만 V6 미실행 {s['gate_v6_not_run']}",
              f"- 스캐너 통과 ∧ 오라클 실패 (기만 탐지 원자료): {s['scanner_pass_oracle_fail']}건, 오라클 UNKNOWN: {s['oracle_unknown']}건"]
        durs = [r["duration_s"] for r in rows if r.get("duration_s") is not None]
        if durs:
            L.append(f"- 자동 처리 시간(사람 승인 대기 제외): 평균 {sum(durs)/len(durs):.1f}s, 최대 {max(durs):.0f}s ({len(durs)}건; 도구 없이 돈 기록이 섞이면 무의미)")
        if "labeled" in s:
            lb = s["labeled"]
            L.append(f"- 기대 라벨 대비 일치: {lb['as_expected']}/{lb['total']} — " + ", ".join(f"{k} {v['as_expected']}/{v['total']}" for k, v in lb["by_label"].items()))
            for src, v in lb.get("by_source", {}).items():
                for k in e1[src]:
                    e1[src][k] += v[k]
        L.append("")
        L += ["| 후보 | 출처 | 상태 | 검토수준 | V1 | V2 | V3 | V4 | V5 | V6 | 기대 |", "|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in sorted(rows, key=lambda x: str(x["scenario"])):
            ly = r["layers"]
            lab = labels.get(str(r["scenario"]), {})
            L.append(f"| {str(r['scenario']).split('/', 1)[1]} | {lab.get('source') or r['origin']} | {r['state']} | {r['review_level']} | "
                     + " | ".join(str(ly.get(x, "-")) for x in ["V1", "V2", "V3", "V4", "V5", "V6"]) + f" | {lab.get('expected', '')} |")
        L.append("")
    L += ["## E1 — 후보 출처별 (세트 합산)", "", "| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |", "|---|---|---|---|"]
    for src, v in e1.items():
        L.append(f"| {src} | {v['total']} | {v['candidate_produced']} | {v['as_expected']} |")
    if "claude-code" not in e1:
        L.append("| claude-code | 0 | 0 | 0 |")
    L += ["", "> 'claude-code' 행이 0 이면 LLM 축은 아직 측정 전이다. 'seeded' 의 기대대로 판정 수는 검증 계층의 탐지 능력이지 LLM 이 그런 패치를 내는 빈도가 아니다.", ""]
    out = ROOT / args.write
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))
    print(f"→ {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
