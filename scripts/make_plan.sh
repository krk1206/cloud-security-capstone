#!/usr/bin/env bash
# 후보(또는 원본) 하나의 **오프라인 plan JSON** 을 만든다 — 실험 재료 3번(plan JSON) 용.
#
#   scripts/make_plan.sh <원본 tf 디렉터리> <출력 plan.json> [후보 .tf 파일 | 후보 디렉터리] [대체할 파일명]
#
#   예) 원본 plan:   scripts/make_plan.sh scenarios/eval/case00 plans/case00-baseline.json
#       후보 plan:   scripts/make_plan.sh scenarios/eval/case00 plans/cc-01.json candidates/cc-01.tf main.tf
#                   (후보 .tf 하나면 원본의 <대체할 파일명>(기본: 후보 파일과 같은 이름, 없으면 main.tf) 을 통째로 바꾼다)
#                   (후보 디렉터리면 안의 *.tf 를 같은 이름의 원본 파일 위에 덮어쓴다)
#
# - AWS 자격증명·요금 없음: provider override(zz_iacpatch_offline_override.tf) 를 임시 복사본에만 넣는다.
#   `terraform init` 이 provider 를 내려받을 때만 네트워크가 필요하다 (한 번 받으면 캐시).
# - 원본 디렉터리는 건드리지 않는다. 결과는 <출력>.meta.txt 에 도구 버전·후보 sha256·시각을 같이 남긴다.
# - 오프라인 plan 은 "상태 없음 → 전부 create" 이다. 배포된 상태 기준 plan 은 RUNBOOK 7절(--online).
# - 이 스크립트는 scripts/generate_fixtures.sh 와 같은 방식이다. 작성 세션(2026-09-15)에는 terraform 이 없어 실행 확인을 못 했다.
set -euo pipefail
if [ $# -lt 2 ]; then
  sed -n '2,12p' "$0"; exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF="${TERRAFORM_BIN:-terraform}"
SRC="$1"; OUT="$2"; CAND="${3:-}"; AS="${4:-}"
[ -d "$SRC" ] || { echo "원본 디렉터리가 없다: $SRC" >&2; exit 2; }
WD="$(mktemp -d)"
trap 'rm -rf "$WD"' EXIT
cp "$SRC"/*.tf "$WD/"
[ -f "$SRC/terraform.tfvars" ] && cp "$SRC/terraform.tfvars" "$WD/" || true

CAND_SHA="-"
if [ -n "$CAND" ]; then
  if [ -d "$CAND" ]; then
    cp "$CAND"/*.tf "$WD/"
    CAND_SHA="$(cat "$CAND"/*.tf | sha256sum | cut -d' ' -f1)"
  else
    [ -f "$CAND" ] || { echo "후보 파일이 없다: $CAND" >&2; exit 2; }
    name="${AS:-$(basename "$CAND")}"
    [ -f "$WD/$name" ] || name="main.tf"
    cp "$CAND" "$WD/$name"
    CAND_SHA="$(sha256sum "$CAND" | cut -d' ' -f1)"
    echo "후보 $CAND → $name 대체" >&2
  fi
fi

cat > "$WD/zz_iacpatch_offline_override.tf" <<'EOF'
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

( cd "$WD" \
  && $TF init -backend=false -input=false -no-color >/dev/null \
  && $TF validate -no-color >/dev/null \
  && $TF plan -input=false -no-color -lock=false -out=plan.bin >/dev/null \
  && $TF show -json plan.bin > plan.json )

mkdir -p "$(dirname "$OUT")"
python3 - "$WD/plan.json" "$OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d.pop("timestamp", None)   # 실행 때마다 달라지는 값만 제거
json.dump(d, open(sys.argv[2], "w"), indent=1, ensure_ascii=False)
PY
{
  echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "terraform: $($TF version | head -1)"
  echo "source_dir: $SRC"
  echo "candidate: ${CAND:-(원본)}"
  echo "candidate_sha256: $CAND_SHA"
  echo "mode: offline (상태 없음, 전부 create; provider override 는 결과에 포함되지 않음)"
} > "$OUT.meta.txt"
echo "→ $OUT (+ .meta.txt)"
