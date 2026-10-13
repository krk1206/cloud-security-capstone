#!/usr/bin/env bash
# WSL(Ubuntu) 환경 점검/설치 도우미. 설치는 확인 후 진행한다 (전부 선택).
set -uo pipefail
echo "== python =="; python3 --version || echo "python3 없음: sudo apt install -y python3"
echo "== terraform =="; terraform version 2>/dev/null | head -1 || echo "terraform 없음: https://developer.hashicorp.com/terraform/install (팀 기준 1.16.1)"
echo "== trivy =="; trivy --version 2>/dev/null | head -1 || echo "trivy 없음: https://trivy.dev/latest/getting-started/installation/ (팀 기준 0.74.0)"
echo "== aws cli =="; aws --version 2>/dev/null || echo "aws cli 없음 (V7/V8/apply 에만 필요)"
echo
echo "== 환경변수 (선택) =="
cat <<'TXT'
  export TERRAFORM_BIN=terraform            # 또는 tofu
  export TRIVY_BIN=trivy
  export AWS_PROFILE=capstone               # V7/V8/online plan 에만 필요
  export LLM_PROVIDER=mock                  # mock | anthropic | openai | openai_compatible
  export LLM_MODEL=...                      # 실제 API 사용 시
  export LLM_API_KEY=...                    # 실제 API 사용 시. 파일에 쓰지 말 것
  export IACPATCH_TF_VAR_FILE=terraform.tfvars.example
TXT
echo
echo "테스트: scripts/run_tests.sh   |   데모: scripts/predeploy_demo.sh"
