#!/usr/bin/env python3
"""mock fixture 전부 + rule-based 를 sg-baseline 에 돌려 결과 표를 만든다 (실행 기록 요약본 생성).

    TERRAFORM_BIN=... TRIVY_BIN=... IACPATCH_TF_VAR_FILE=terraform.tfvars.example \
      python3 scripts/run_fixture_matrix.py --out data/runs-sample

각 실행은 실제 Trivy 스캔 + 실제 plan 을 수행한다 (오프라인). 실행마다 30~60초.
출력: <out>/SUMMARY.md, <out>/<fixture>/{run.json, gate.json, verification.json, candidate.diff, pr_body.md}
(원문 Trivy/plan JSON 은 크기 때문에 복사하지 않는다 — data/runs/ 원본 기록에 남는다)
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iacpatch.config import load_settings  # noqa: E402
from iacpatch.pipeline import run_predeploy  # noqa: E402

FIXTURES = [
    ("sg_baseline_ok", "llm", "정상: 승인 출처만 남김"),
    ("sg_baseline_ok_propose_low", "llm", "정상 + LLM 이 LOW 제안 (하향 반영)"),
    ("sg_baseline_cidr_split", "llm", "CIDR 분할 우회 (seeded)"),
    ("sg_baseline_inplan_prefix_list", "llm", "plan 내 prefix list(0.0.0.0/0) 경유 (seeded)"),
    ("sg_baseline_external_prefix_list", "llm", "외부 prefix list ID 참조 → 전개 불가"),
    ("sg_baseline_ipv6_open", "llm", "IPv4 는 고치고 IPv6 ::/0 개방"),
    ("sg_baseline_unapproved_cidr", "llm", "인터넷 전체는 아니지만 승인 밖 출처"),
    ("sg_baseline_breaks_required", "llm", "필요한 접근까지 제거"),
    ("sg_baseline_deletes_sg", "llm", "대상 리소스 삭제"),
    ("sg_baseline_unknown_value", "llm", "plan 시점 미확정 값(EIP)"),
    ("sg_baseline_edits_provider", "llm", "provider.tf 수정 (정책 위반)"),
    ("sg_baseline_truncated", "llm", "잘린 API 응답"),
    ("sg_baseline_garbage", "llm", "JSON 아닌 응답"),
    ("sg_baseline_wrong_schema", "llm", "스키마 위반 응답"),
    ("sg_baseline_insufficient", "llm", "모델이 INSUFFICIENT_INFO"),
    ("rule_based", "rule_based", "Rule-based baseline"),
]
TWO_GROUPS = ("sg_two_groups_fix_app_only", "llm", "같은 인스턴스의 다른 SG 에 허용 규칙 잔존 (scenarios/eval/sg-two-groups)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/runs-sample")
    ap.add_argument("--intent", default="tests/fixtures/intents/sg-baseline.test.json")
    args = ap.parse_args()
    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    jobs = [(f, g, d, "infrastructure/sg-baseline", args.intent, None) for f, g, d in FIXTURES]
    jobs.append((TWO_GROUPS[0], TWO_GROUPS[1], TWO_GROUPS[2], "scenarios/eval/sg-two-groups", "tests/fixtures/intents/sg-two-groups.test.json", "aws_security_group.app"))
    for fixture, gen, desc, target_dir, intent, resource in jobs:
        s = load_settings(str(ROOT), {"llm_provider": "mock", "llm_mock_fixture": fixture, "max_attempts": 1, "offline_plan": True})
        if target_dir != "infrastructure/sg-baseline":
            s.tf_var_file = ""
        res = run_predeploy(s, target_dir, intent, f"matrix-{fixture}", generator_kind=gen, target_resource=resource)
        layers = {l.layer: l.verdict.value for l in res.validity.layers} if res.validity else {}
        gate = res.gate.action.value if res.gate else "-"
        risk = res.gate.risk_level.value if (res.gate and res.gate.risk_level) else "-"
        cand = res.candidate.status if res.candidate else "-"
        rows.append((fixture, desc, cand, layers, gate, risk, res.status, res.run_id))
        dst = out / fixture
        dst.mkdir(exist_ok=True)
        for name in ("run.json", "gate.json", "risk.json", "candidate.diff", "pr_body.md"):
            p = res.run_dir / name
            if p.exists():
                shutil.copy(p, dst / name)
        v = res.run_dir / "candidates" / "01" / "verification.json"
        if v.exists():
            shutil.copy(v, dst / "verification.json")
        print(f"{fixture:36s} {res.status:18s} gate={gate:20s} {layers}")

    def cell(layers, k):
        return layers.get(k, "-")

    lines = ["# 실행 결과 요약 (mock fixture 매트릭스)", "",
             "생성기 응답은 전부 **seeded(손으로 만든) mock** 이다. LLM 이 실제로 생성한 출력이 아니며, 검증 계층의 동작을 보이기 위한 것이다.", "",
             "| fixture | 내용 | 후보 | V1 | V2 | V3 | V4 | V5 | V6 | 위험도 | 게이트 | run |", "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for fixture, desc, cand, layers, gate, risk, status, run_id in rows:
        lines.append(f"| {fixture} | {desc} | {cand} | {cell(layers,'V1')} | {cell(layers,'V2')} | {cell(layers,'V3')} | {cell(layers,'V4')} | {cell(layers,'V5')} | {cell(layers,'V6')} | {risk} | {gate if status=='DONE' else status} | {run_id} |")
    tv = json.loads((ROOT / "data" / "runs" / rows[0][7] / "run.json").read_text(encoding="utf-8")).get("tool_versions", {})
    lines += ["", f"도구: {tv}", "", "게이트 의미: CREATE_PR_AUTO(자율성 HIGH) / CREATE_PR_APPROVAL(MEDIUM) / REPORT_ONLY(LOW 또는 후보 없음) / HOLD_FOR_HUMAN(검증 INCOMPLETE) / BLOCK(검증 FAIL 또는 정책 위반)"]
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"→ {out / 'SUMMARY.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
