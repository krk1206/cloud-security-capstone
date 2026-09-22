#!/usr/bin/env bash
# 혼자 돌리는 실험 한 방 (WSL / Linux / macOS).
#
#   bash scripts/run_experiments.sh            # 전부
#   bash scripts/run_experiments.sh --no-tools # trivy/terraform 없이 (검증 계층은 NOT_RUN 으로 남는다)
#
# 하는 일 (순서대로):
#   0. tools/ 에 받아둔 trivy/terraform 을 잡는다 (없으면 PATH, 그것도 없으면 그 계층은 NOT_RUN)
#   1. A 의 Trivy 우회 실험 9 케이스 결과가 이 컴퓨터에서 재현되는지 (A_RESULTS_CHECK.md)
#   2. eval-a-probe-rule  : A 9 케이스 × 규칙 기반 후보 (E1 기준선, SG)
#   3. eval-seeded-sg     : 00-baseline × seeded 11 후보 (E2, SG)
#   4. eval-iam-rule      : IAM 5 케이스 × 규칙 기반 후보 (E1 기준선, IAM)
#   5. eval-seeded-iam    : iam-report-worker × seeded 13 후보 (E2, IAM)
#   6. eval-claude-code   : Claude Code 후보 (manifest 에 항목이 있을 때만)
#   7. 오라클 실험 (실제 plan) → 8. experiments/RESULTS_SUMMARY.md 로 합산
# 하지 않는 일: LLM API 호출, Claude Code 자동 호출, AWS 접속/생성, git push. terraform 은 오프라인 plan 만.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/src"
PY="${PYTHON:-python3}"
USE_TOOLS=1
[ "${1:-}" = "--no-tools" ] && USE_TOOLS=0

if [ $USE_TOOLS = 1 ]; then
  if [ -x "$ROOT/tools/trivy" ]; then export TRIVY_BIN="$ROOT/tools/trivy"; fi
  if [ -x "$ROOT/tools/terraform" ]; then export TERRAFORM_BIN="$ROOT/tools/terraform"; fi
  export TRIVY_SKIP_CHECK_UPDATE="${TRIVY_SKIP_CHECK_UPDATE:-1}"      # 내장 체크 번들 사용 (네트워크 불필요)
  export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-$ROOT/tools/plugin-cache}"; mkdir -p "$TF_PLUGIN_CACHE_DIR"
  echo "trivy    : $(${TRIVY_BIN:-trivy} --version 2>/dev/null | head -1 || echo '없음 → V1/V2 NOT_RUN')"
  echo "terraform: $(${TERRAFORM_BIN:-terraform} version 2>/dev/null | head -1 || echo '없음 → V3~V6 NOT_RUN')"
else
  export TRIVY_BIN="/nonexistent/trivy" TERRAFORM_BIN="/nonexistent/terraform"
  echo "도구 없이 실행 (검증 계층 NOT_RUN)"
fi
echo

LOG="$ROOT/experiments/run_experiments.log"; echo "run_experiments $(date -Is)" > "$LOG"
run() { "$@" 2>&1 | tee -a "$LOG"; }
step() { echo; echo "================ $1" | tee -a "$LOG"; }

step "1/8 A 의 9 케이스 결과 재현 확인"
run $PY experiments/candidate-sets/a-probe-dev/check_a_results.py

step "2/8 eval-a-probe-rule (규칙 기반 기준선, SG)"
run $PY scripts/run_candidate_set.py experiments/candidate-sets/eval-a-probe-rule/manifest.json

step "3/8 eval-seeded-sg (오라클 유무 재료, SG)"
run $PY scripts/run_candidate_set.py experiments/candidate-sets/eval-seeded-sg/manifest.json

step "4/8 eval-iam-rule (규칙 기반 기준선, IAM)"
run $PY scripts/run_candidate_set.py experiments/candidate-sets/eval-iam-rule/manifest.json

step "5/8 eval-seeded-iam (오라클 유무 재료, IAM)"
run $PY scripts/run_candidate_set.py experiments/candidate-sets/eval-seeded-iam/manifest.json

step "6/8 eval-claude-code (LLM 후보)"
if $PY - <<'EOF'
import json, sys
m = json.load(open("experiments/candidate-sets/eval-claude-code/manifest.json", encoding="utf-8"))
sys.exit(0 if m.get("candidates") else 1)
EOF
then
  run $PY scripts/run_candidate_set.py experiments/candidate-sets/eval-claude-code/manifest.json
else
  echo "후보 0건 — scripts/cc_prompt.py 로 프롬프트 뽑아 Claude Code 에서 받고, scripts/cc_add.py 로 등록하면 여기서 돈다"
fi

step "7/8 오라클 실험 (스캐너 vs V6, 실제 plan — SG + IAM)"
run $PY scripts/oracle_experiment.py

step "8/8 요약"
run $PY scripts/summarize_experiments.py
run $PY scripts/why_this_gate.py
echo
echo "결과 파일:"
echo "  experiments/ORACLE_RESULTS.md                        ← E2 핵심 (스캐너 vs 오라클, 실제 plan)"
echo "  experiments/RESULTS_SUMMARY.md                       ← 한 장 요약"
echo "  experiments/WHY_THIS_GATE.md                         ← 기업용 한 장 (스캐너 vs 게이트, 실측만)"
echo "  experiments/candidate-sets/<세트>/results.md         ← 세트별 표 (+ results-history/ 에 이 실행이 추가됨)"
echo "  data/reviews/<id>/review.md                          ← 후보별 리포트·diff·검증 원문"
echo "  experiments/run_experiments.log                      ← 이 실행의 전체 출력 (문제 생기면 이 파일을 보낼 것)"
