#!/usr/bin/env python3
"""후보 세트 일괄 실행 — 실험 프로토콜의 실행 도구.

    python3 scripts/run_candidate_set.py experiments/candidate-sets/<set>/manifest.json [--out data/reviews] [--local-tools]

manifest.json 형식 (docs/EXPERIMENT_GUIDE.md):
{
  "set_id": "example-dev",
  "tf_dir": "scenarios/dev/case00-baseline",
  "trivy_json": "scenarios/dev/case00-baseline/trivy-scan.json",
  "rule": "AVD-AWS-0107", "resource": "aws_security_group.baseline", "line": null,
  "intent": "examples/bc/case00/intent.json",
  "baseline_plan": "tests/fixtures/plans/00-baseline/plan.json",
  "verification": null,
  "local_tools": false,
  "candidates": [
    {"id": "fixed-01", "candidate": "manual:examples/bc/case00/candidate_fixed", "expected": "correct", "source": "seeded",
     "note": "개발 중 작성한 예제", "candidate_plan": "tests/fixtures/plans/00b-baseline-fixed/plan.json", "verification": null}
  ]
}
- 경로는 저장소 루트 기준(세트 폴더 기준 경로도 허용). 후보마다 tf_dir / trivy_json / intent / rule / resource / line / file /
  baseline_plan / candidate_plan / verification 을 따로 줄 수 있다 (없으면 세트 공통 값, 그것도 없으면 NOT_RUN).
- expected ∈ correct | deceptive | breaks_required | unapproved | unknown | invalid | not_triggered | unsupported  (사람이 케이스 내용을 보고 적는다)
- source ∈ claude-code | rule_based | seeded | human ...  (후보를 누가/무엇이 만들었는지. 집계 표의 E1 비교 축)
- local_tools (세트 또는 --local-tools): trivy/terraform 이 있으면 V1~V4 를 로컬 실행. 없는 계층은 NOT_RUN
- 결과: <set 폴더>/labels.json, <set 폴더>/results.md (+ results-history/<시각>-<호스트>.md 누적), 기록은 data/reviews/<id>/ (scenario = "<set_id>/<candidate id>")
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iacpatch.config import load_settings  # noqa: E402
from iacpatch.metrics import collect, render_table  # noqa: E402
from iacpatch.review.flow import ReviewOptions, run_review  # noqa: E402


def _resolve(p, set_dir: Path):
    """세트 폴더 기준 경로가 있으면 그것, 아니면 저장소 루트 기준 그대로."""
    if not p or Path(p).is_absolute():
        return p
    return str(set_dir / p) if (set_dir / p).exists() else p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--out", default="data/reviews")
    ap.add_argument("--local-tools", dest="local_tools", action="store_true", help="trivy/terraform 이 있으면 V1~V4 로컬 실행")
    ap.add_argument("--results-dir", dest="results_dir", help="results.md / results-history 를 쓸 폴더 (기본: 세트 폴더). 테스트는 임시 폴더를 준다")
    args = ap.parse_args()
    mpath = ROOT / args.manifest if not Path(args.manifest).is_absolute() else Path(args.manifest)
    m = json.loads(mpath.read_text(encoding="utf-8"))
    set_dir = mpath.parent
    s = load_settings(str(ROOT))
    out_root = ROOT / args.out
    local_tools = bool(args.local_tools or m.get("local_tools"))
    labels = {}
    run_ids = []

    def pick(c, key, default=None):
        return c[key] if key in c else m.get(key, default)

    for c in m["candidates"]:
        cid = c["id"]
        scenario = f"{m['set_id']}/{cid}"
        cand = c["candidate"]
        if cand.startswith("manual:"):
            cand = "manual:" + str(_resolve(cand[7:], set_dir))
        opt = ReviewOptions(
            tf_dir=pick(c, "tf_dir"), trivy_json=_resolve(pick(c, "trivy_json"), set_dir), candidate=cand, scenario=scenario,
            rule=pick(c, "rule", "AVD-AWS-0107"), filename=pick(c, "file"), resource=pick(c, "resource"), line=pick(c, "line"),
            candidate_note=c.get("note", ""), verification=_resolve(pick(c, "verification"), set_dir),
            baseline_plan=_resolve(pick(c, "baseline_plan"), set_dir), candidate_plan=_resolve(c.get("candidate_plan"), set_dir),
            intent=_resolve(pick(c, "intent"), set_dir), out_dir=str(out_root), local_tools=local_tools)
        res = run_review(s, opt)
        run_ids.append(res.run_id)
        labels[scenario] = {"expected": c.get("expected", ""), "source": c.get("source", "")}
        lvl = res.level.value if res.level else "-"
        layers = {l.layer: l.verdict.value for l in (res.validity.layers if res.validity else [])}
        print(f"{cid:20s} {res.state.value:20s} level={lvl:13s} V1={layers.get('V1', '-'):8s} V6={layers.get('V6', '-'):8s} "
              f"risk={res.risk.risk_level.value if res.risk else '-'}")
    (set_dir / "labels.json").write_text(json.dumps(labels, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    rows = [r for r in collect([out_root]) if r["run_id"] in run_ids]
    tools_note = "V1~V4 로컬 도구 실행 (--local-tools)" if local_tools else "검증 결과는 파일로 받은 것만 (도구 미실행)"
    env_line = _env_line(rows, out_root)
    table = render_table(rows, title=f"세트 {m['set_id']} 결과 ({len(rows)}건) — {tools_note}", labels=labels)
    table = table.replace("\n\n", f"\n\n- 실행 환경: {env_line}\n", 1)
    res_dir = Path(args.results_dir) if args.results_dir else set_dir
    res_dir.mkdir(parents=True, exist_ok=True)
    (res_dir / "results.md").write_text(table, encoding="utf-8")
    # 환경별 실행 이력 (샌드박스 실행과 팀 WSL 실행이 서로 덮어쓰지 않게)
    import datetime as _dt, platform
    hist = res_dir / "results-history"
    hist.mkdir(exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    (hist / f"{stamp}-{platform.node() or 'host'}.md").write_text(table, encoding="utf-8")
    print(table)
    print(f"→ {res_dir / 'results.md'}  (이력: {hist})")
    return 0


def _env_line(rows, out_root: Path) -> str:
    """run 폴더의 local_verify/tools.json 에서 도구 버전을 읽어 한 줄로 (없으면 '도구 미실행')."""
    import platform
    tools = {}
    for r in rows:
        tj = out_root / str(r["run_id"]) / "local_verify" / "tools.json"
        if tj.exists():
            try:
                tools = json.loads(tj.read_text(encoding="utf-8"))
                break
            except json.JSONDecodeError:
                pass
    parts = [f"host={platform.node() or '?'}", f"python={platform.python_version()}"]
    for k, v in tools.items():
        parts.append(f"{v.get('kind') or k}={v.get('version') or '없음'}")
    if not tools:
        parts.append("도구 미실행")
    return ", ".join(parts)


if __name__ == "__main__":
    sys.exit(main())
