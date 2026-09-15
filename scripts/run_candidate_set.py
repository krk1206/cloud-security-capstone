#!/usr/bin/env python3
"""후보 세트 일괄 실행 — 실험 프로토콜의 실행 도구.

    python3 scripts/run_candidate_set.py experiments/candidate-sets/<set>/manifest.json [--out data/reviews]

manifest.json 형식 (docs/EXPERIMENT_GUIDE.md):
{
  "set_id": "example-dev",
  "tf_dir": "scenarios/dev/case00-baseline",
  "trivy_json": "scenarios/dev/case00-baseline/trivy-scan.json",
  "rule": "AVD-AWS-0107", "resource": "aws_security_group.baseline", "line": null,
  "intent": "examples/bc/case00/intent.json",
  "baseline_plan": "tests/fixtures/plans/00-baseline/plan.json",
  "verification": null,
  "candidates": [
    {"id": "fixed-01", "candidate": "manual:examples/bc/case00/candidate_fixed", "expected": "correct", "source": "seeded",
     "note": "개발 중 작성한 예제", "candidate_plan": "tests/fixtures/plans/00b-baseline-fixed/plan.json", "verification": null}
  ]
}
- 경로는 저장소 루트 기준. 후보마다 candidate_plan / verification 을 따로 줄 수 있다 (없으면 세트 공통 값, 그것도 없으면 NOT_RUN).
- expected ∈ correct | deceptive | breaks_required | unapproved | unknown | invalid  (사람이 케이스 내용을 보고 적는다)
- source ∈ claude-code | rule_based | seeded | human ...  (후보를 누가/무엇이 만들었는지. 집계 표의 E1 비교 축)
- 결과: <set 폴더>/labels.json, <set 폴더>/results.md, 기록은 data/reviews/<id>/ (scenario = "<set_id>/<candidate id>")
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iacpatch.config import load_settings  # noqa: E402
from iacpatch.metrics import collect, render_table  # noqa: E402
from iacpatch.review.flow import ReviewOptions, run_review  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--out", default="data/reviews")
    args = ap.parse_args()
    mpath = ROOT / args.manifest if not Path(args.manifest).is_absolute() else Path(args.manifest)
    m = json.loads(mpath.read_text(encoding="utf-8"))
    set_dir = mpath.parent
    s = load_settings(str(ROOT))
    out_root = ROOT / args.out
    labels = {}
    run_ids = []
    for c in m["candidates"]:
        cid = c["id"]
        scenario = f"{m['set_id']}/{cid}"
        cand = c["candidate"]
        if cand.startswith("manual:") and not Path(cand[7:]).is_absolute():
            p = Path(cand[7:])
            cand = "manual:" + str((set_dir / p) if (set_dir / p).exists() else (ROOT / p))
        opt = ReviewOptions(
            tf_dir=m["tf_dir"], trivy_json=m["trivy_json"], candidate=cand, scenario=scenario,
            rule=m.get("rule", "AVD-AWS-0107"), filename=m.get("file"), resource=m.get("resource"), line=m.get("line"),
            candidate_note=c.get("note", ""), verification=c.get("verification") or m.get("verification"),
            baseline_plan=c.get("baseline_plan") or m.get("baseline_plan"), candidate_plan=c.get("candidate_plan"),
            intent=m.get("intent"), out_dir=str(out_root))
        res = run_review(s, opt)
        run_ids.append(res.run_id)
        labels[scenario] = {"expected": c.get("expected", ""), "source": c.get("source", "")}
        lvl = res.level.value if res.level else "-"
        v6 = next((l.verdict.value for l in (res.validity.layers if res.validity else []) if l.layer == "V6"), "-")
        print(f"{cid:20s} {res.state.value:20s} level={lvl:13s} V6={v6:8s} risk={res.risk.risk_level.value if res.risk else '-'}")
    (set_dir / "labels.json").write_text(json.dumps(labels, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    rows = [r for r in collect([out_root]) if r["run_id"] in run_ids]
    table = render_table(rows, title=f"세트 {m['set_id']} 결과 ({len(rows)}건)", labels=labels)
    (set_dir / "results.md").write_text(table, encoding="utf-8")
    print(table)
    print(f"→ {set_dir / 'results.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
