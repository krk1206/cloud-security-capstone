#!/usr/bin/env bash
# Claude Code 로 후보를 **사람이 시작해서** 일괄로 받는 보조 스크립트 (WSL/Linux). 파이프라인이 자동 호출하지 않는다 (D-5).
#
#   bash scripts/cc_batch.sh [--reps 3] [--cases "00-baseline iam-00-literal-list"] [--dry-run]
#
# 하는 일: experiments/candidate-sets/eval-claude-code/prompts/<case>.md 를 하나씩 `claude -p` (비대화형, 매번 새 세션) 에 넣고
#          응답을 responses/<case>-r<n>.md 로 저장한다. 등록(expected 라벨 부여)은 사람이 scripts/cc_add.py 로 한다.
# 제약 (docs/AI_CONSTRAINTS.md 3절):
#   - 빈 임시 디렉터리에서 실행 → 저장소·자격증명에 접근 불가
#   - 도구 전부 금지(--disallowedTools) + --max-turns 1 → 파일 수정·명령 실행 불가, 텍스트만 돌려받음
#   - 프롬프트는 고정본(prompt.md v1/v1-iam) 그대로. 스크립트가 프롬프트를 바꾸지 않는다
# 확인 필요: 이 스크립트는 작성 세션(샌드박스)에 claude CLI 가 없어 실행 확인을 못 했다. 첫 실행 전에 `claude --help` 로
#            -p / --disallowedTools / --max-turns / --output-format 플래그 이름을 확인하고, --dry-run 으로 명령만 먼저 본다.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SET="$ROOT/experiments/candidate-sets/eval-claude-code"
REPS=3; CASES=""; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --reps) REPS="$2"; shift 2;;
    --cases) CASES="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    *) echo "unknown arg $1"; exit 2;;
  esac
done
command -v claude >/dev/null 2>&1 || { echo "claude CLI 가 PATH 에 없다 (Claude Code 설치 후 다시)"; exit 2; }
[ -n "$CASES" ] || CASES="$(ls "$SET/prompts" | sed 's/\.md$//' | tr '\n' ' ')"
mkdir -p "$SET/responses"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cat > "$WORK/CLAUDE.md" <<'EOM'
You are answering a single Terraform fix request. Output only one ```hcl code block with the full corrected file. Do not run commands, do not read or write files, do not ask questions.
EOM
DISALLOW="Bash,Edit,Write,MultiEdit,NotebookEdit,Read,Glob,Grep,LS,WebFetch,WebSearch,Task,TodoWrite"
for c in $CASES; do
  P="$SET/prompts/$c.md"
  [ -f "$P" ] || { echo "skip $c: 프롬프트 없음"; continue; }
  for r in $(seq 1 "$REPS"); do
    OUT="$SET/responses/$c-r$r.md"
    if [ -f "$OUT" ]; then echo "skip $c r$r: 이미 있음 ($OUT)"; continue; fi
    CMD=(claude -p --output-format text --max-turns 1 --disallowedTools "$DISALLOW")
    echo "== $c r$r  (cwd=$WORK)"
    if [ $DRY = 1 ]; then echo "   ${CMD[*]} < $P > $OUT"; continue; fi
    ( cd "$WORK" && "${CMD[@]}" < "$P" > "$OUT" 2> "$OUT.err" ) || { echo "   실패 (종료코드 $?) — $OUT.err 확인"; continue; }
    { echo; echo "<!-- cc_batch: case=$c rep=$r at=$(date -Is) host=$(hostname) claude=$(claude --version 2>/dev/null | head -1) -->"; } >> "$OUT"
    echo "   → $OUT ($(wc -l < "$OUT") lines)"
  done
done
echo
echo "다음: 응답을 읽고 사람이 라벨을 적어 등록 — python3 scripts/cc_add.py <case> $SET/responses/<case>-r<n>.md --rep <n> --expected <label>"
