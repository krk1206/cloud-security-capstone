#!/usr/bin/env bash
# 단위 테스트(도구 불필요) + 통합 테스트(terraform/trivy 있으면 자동 포함, 없으면 skip)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/tests/unit"
export PYTHONPATH="$ROOT/src"
python3 -m unittest discover -s . -p "test_*.py" -v "$@"
