#!/usr/bin/env bash
# 혼자 실험용 도구 설치 (WSL / Linux). trivy 와 terraform 을 저장소 안 tools/ 에만 받는다 (시스템 PATH 안 건드림).
#
#   bash scripts/setup_tools.sh            # 둘 다
#   bash scripts/setup_tools.sh trivy      # 하나만
#
# 버전은 팀 기준(A 의 VERIFY.md): Trivy 0.74.0, Terraform 1.16.1. 바꾸려면 아래 변수만.
# - AWS 계정·자격증명 불필요. 네트워크는 다운로드 때만.
# - terraform 이 막힌 환경이면 OpenTofu 로 대체할 수 있다: TERRAFORM_BIN=tofu (plan JSON 구조 동일, provider_name 만 다름)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/tools"
TRIVY_VER="${TRIVY_VER:-0.74.0}"
TF_VER="${TF_VER:-1.16.1}"
mkdir -p "$TOOLS"
want="${1:-all}"

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) trivy_arch="64bit"; tf_arch="amd64";;
  aarch64|arm64) trivy_arch="ARM64"; tf_arch="arm64";;
  *) echo "지원하지 않는 아키텍처: $arch"; exit 1;;
esac

if [ "$want" = "all" ] || [ "$want" = "trivy" ]; then
  if [ -x "$TOOLS/trivy" ] && "$TOOLS/trivy" --version 2>/dev/null | grep -q "$TRIVY_VER"; then
    echo "trivy $TRIVY_VER 이미 있음: $TOOLS/trivy"
  else
    url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-${trivy_arch}.tar.gz"
    echo "trivy 다운로드: $url"
    tmp="$(mktemp -d)"
    curl -fsSL "$url" -o "$tmp/trivy.tgz"
    tar -xzf "$tmp/trivy.tgz" -C "$tmp" trivy
    mv "$tmp/trivy" "$TOOLS/trivy"; chmod +x "$TOOLS/trivy"; rm -rf "$tmp"
    echo "trivy: $("$TOOLS/trivy" --version | head -1)"
  fi
fi

if [ "$want" = "all" ] || [ "$want" = "terraform" ]; then
  if [ -x "$TOOLS/terraform" ] && "$TOOLS/terraform" version 2>/dev/null | grep -q "v$TF_VER"; then
    echo "terraform $TF_VER 이미 있음: $TOOLS/terraform"
  else
    url="https://releases.hashicorp.com/terraform/${TF_VER}/terraform_${TF_VER}_linux_${tf_arch}.zip"
    echo "terraform 다운로드: $url"
    tmp="$(mktemp -d)"
    if curl -fsSL "$url" -o "$tmp/tf.zip"; then
      (cd "$tmp" && unzip -qo tf.zip terraform)
      mv "$tmp/terraform" "$TOOLS/terraform"; chmod +x "$TOOLS/terraform"; rm -rf "$tmp"
      echo "terraform: $("$TOOLS/terraform" version | head -1)"
    else
      echo "terraform 다운로드 실패 (네트워크/차단). 대안: OpenTofu — https://github.com/opentofu/opentofu/releases (tofu 바이너리를 tools/terraform 이름으로 두거나 TERRAFORM_BIN=tofu)"
      rm -rf "$tmp"
    fi
  fi
fi

mkdir -p "$TOOLS/plugin-cache"
echo
echo "완료. 실험 실행: bash scripts/run_experiments.sh   (tools/ 를 자동으로 잡는다)"
