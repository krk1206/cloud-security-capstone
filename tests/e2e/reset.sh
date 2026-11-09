#!/bin/bash
cp /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/experiments/candidate-sets/arch-3tier-sg/candidates/correct-design.tf /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/scenarios/arch/webapp-3tier-testbed/security_groups.tf
echo '{"version":4,"serial":173,"lineage":"fake-e2e","resources":[]}' > /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/scenarios/arch/webapp-3tier-testbed/terraform.tfstate
rm -f /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/fakeaws_calls.jsonl /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/faketf_calls.jsonl /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/testbed_ops.jsonl; rm -rf /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/testbed_ops /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/shots /tmp/iacpatch-plans
E=/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e
for r in 20261022-185739-9c9b0f 20261022-185751-05ac43 20261023-124957-af6f0b; do rm -rf $E/cap/data/reviews/$r; cp -a $E/pristine/$r $E/cap/data/reviews/$r; done
find /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/measurements -mindepth 1 -maxdepth 1 -type d ! -name 20261023-125118 -exec rm -rf {} +
cp /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/pristine/testbed_switch.jsonl /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/testbed_switch.jsonl
rm -rf /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/designs /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/llm_runs /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/fakeclaude/calls.jsonl
for d in $(ls /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/reviews); do if [ ! -d /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/pristine/reviews_keep/$d ] && grep -qE '"scenario": "ui/arch-[a-z0-9-]+/ai-2026' /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/reviews/$d/state.json 2>/dev/null; then rm -rf /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/reviews/$d; fi; done
rm -rf /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/projects
for d in $(ls /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/reviews); do if grep -qE '"scenario": "ui/[a-z0-9-]+-[0-9a-f]{6}\.' /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/reviews/$d/state.json 2>/dev/null; then rm -rf /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/reviews/$d; fi; done
rm -rf /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/llm_runs
# 15차 (D-51): 요청 3 (IAM) E2E 는 수정안 2 를 승인한다 — 다음 실행이 '승인됨' 기록을 다시 쓰지 않게 이 세트의 기록을 지운다 (시험 사본에서만). 16차: 요청 4 · 6 도 같게
for d in $(ls /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/reviews); do if grep -qE '"scenario": "ui/three-tier-team-(iam|dbsg|upload)/' /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/reviews/$d/state.json 2>/dev/null; then rm -rf /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/reviews/$d; fi; done
# 16차 (D-52): 고객 요청함 — 시험은 늘 같은 상태에서 시작 (요청 1 ~ 3 도착 · 읽음).
# 17차 (D-53): 타이머를 뺐으므로 날짜 기준만 — 서버의 '지금' 은 start.sh 의 IACPATCH_INBOX_NOW(11-06 21:00)로 고정해 날이 바뀌어도 같은 결과
mkdir -p /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/inbox
cat > /tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/cap/data/inbox/state.json <<'JSON'
{"ver": 2,
 "arrived": {"three-tier-team": {"at": "2026-11-05T09:10:00+09:00", "how": "date"},
             "three-tier-team-s3": {"at": "2026-11-06T10:30:00+09:00", "how": "date"},
             "three-tier-team-iam": {"at": "2026-11-06T15:20:00+09:00", "how": "date"}},
 "read": ["three-tier-team", "three-tier-team-s3", "three-tier-team-iam"]}
JSON
