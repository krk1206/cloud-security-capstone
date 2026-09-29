#!/usr/bin/env bash
# 키 없이 mock 으로 sg-baseline 배포 전 파이프라인을 돌린다. (실제 LLM API 호출 없음, AWS 접속 없음, push 없음)
#   scripts/predeploy_demo.sh                  # 정상 패치 fixture
#   scripts/predeploy_demo.sh sg_baseline_cidr_split   # 기만적 패치 fixture → V6 가 차단
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="${1:-sg_baseline_ok}"
export PYTHONPATH="$ROOT/src"
export IACPATCH_TF_VAR_FILE="${IACPATCH_TF_VAR_FILE:-terraform.tfvars.example}"
cd "$ROOT"
python3 -m iacpatch predeploy \
  --target-dir infrastructure/sg-baseline \
  --intent tests/fixtures/intents/sg-baseline.test.json \
  --scenario "demo-$FIXTURE" \
  --generator llm --llm-provider mock --llm-mock-fixture "$FIXTURE" --offline
