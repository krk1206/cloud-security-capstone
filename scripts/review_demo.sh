#!/usr/bin/env bash
# B·C 로컬 검토 흐름 데모 (도구·API·네트워크 불필요). 사용법: scripts/review_demo.sh [manual|mock|split]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"; export PYTHONPATH="$ROOT/src"
case "${1:-manual}" in
  manual) python3 -m iacpatch review --tf-dir infrastructure/sg-baseline --trivy-json infrastructure/sg-baseline/baseline-scan.json \
            --candidate manual:examples/bc/manual_candidate_ok --scenario demo-manual ;;
  mock)   python3 -m iacpatch review --tf-dir infrastructure/sg-baseline --trivy-json infrastructure/sg-baseline/baseline-scan.json \
            --candidate mock:sg_baseline_ok --scenario demo-mock ;;
  split)  python3 -m iacpatch review --tf-dir scenarios/dev/case00-baseline --trivy-json scenarios/dev/case00-baseline/trivy-scan.json \
            --candidate manual:examples/bc/case00/candidate_cidr_split --scenario demo-split --verification examples/bc/verification/example_all_pass.json \
            --baseline-plan tests/fixtures/plans/00-baseline/plan.json --candidate-plan examples/bc/case00/plan_candidate_cidr_split.json --intent examples/bc/case00/intent.json ;;
  *) echo "usage: $0 [manual|mock|split]"; exit 2 ;;
esac
python3 -m iacpatch metrics --title "data/reviews 집계"
