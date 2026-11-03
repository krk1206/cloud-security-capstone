#!/usr/bin/env bash
# tests/fixtures/src/<case>/ 마다 plan JSON(오프라인 plan) 과 Trivy JSON 을 만들어 tests/fixtures/{plans,trivy}/ 에 저장한다.
#
#   TERRAFORM_BIN=terraform TRIVY_BIN=trivy scripts/generate_fixtures.sh
#
# - 오프라인 plan: AWS 자격증명 없이 provider override(zz_iacpatch_offline_override.tf)를 임시 복사본에만 넣는다.
# - 결과 파일 머리에 도구 버전을 tests/fixtures/plans/GENERATED.md 로 기록한다.
# - 샌드박스에서는 OpenTofu 1.10.6 + AWS provider 5.100.0 으로 생성했다. 팀 환경(Terraform 1.16.1)에서 재생성해 비교할 것.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF="${TERRAFORM_BIN:-terraform}"
TRIVY="${TRIVY_BIN:-trivy}"
SRC="$ROOT/tests/fixtures/src"
PLANS="$ROOT/tests/fixtures/plans"
TRV="$ROOT/tests/fixtures/trivy"
WORK="${IACPATCH_FIXTURE_WORK:-$(mktemp -d)}"
mkdir -p "$PLANS" "$TRV"

echo "terraform: $($TF version | head -1)"
echo "trivy    : $($TRIVY --version | head -1)"

for dir in "$SRC"/*/; do
  name="$(basename "$dir")"
  wd="$WORK/$name"
  rm -rf "$wd"; mkdir -p "$wd"
  cp "$dir"/*.tf "$wd/"
  cat > "$wd/zz_iacpatch_offline_override.tf" <<'EOF'
provider "aws" {
  region                      = "ap-northeast-2"
  profile                     = null
  access_key                  = "offline-plan-fake"
  secret_key                  = "offline-plan-fake"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}
EOF
  ( cd "$wd" \
    && $TF init -backend=false -input=false -no-color >/dev/null \
    && $TF validate -no-color >/dev/null \
    && $TF plan -input=false -no-color -lock=false -out=plan.bin >/dev/null \
    && $TF show -json plan.bin > plan.json ) || { echo "  $name: plan FAILED"; continue; }
  mkdir -p "$PLANS/$name"
  python3 - "$wd/plan.json" "$PLANS/$name/plan.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
# 실행 환경마다 달라지는 값 제거 (timestamp) — 나머지는 그대로 보존
d.pop("timestamp", None)
json.dump(d, open(sys.argv[2], "w"), indent=1, ensure_ascii=False)
PY
  $TRIVY config "$dir" --format json --include-non-failures --quiet --output "$TRV/$name.json" 2>/dev/null || echo "  $name: trivy FAILED"
  echo "  $name: ok"
done

cat > "$PLANS/GENERATED.md" <<EOF
# fixture 생성 기록

- 생성 시각: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- terraform: $($TF version | head -1)
- trivy: $($TRIVY --version | head -1)
- 방식: 오프라인 plan (상태 없음, 전부 create). provider override 는 fixture 에 포함되지 않는다.
- 주의: OpenTofu 로 생성된 plan JSON 은 provider_name 이 registry.opentofu.org/... 로 나온다. 코드는 type/address 만 사용하므로 판정에 영향 없다.
EOF
echo "done → $PLANS, $TRV"
