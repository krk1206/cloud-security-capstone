#!/bin/bash
set -e
E=/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e; SP=/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad; R=/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/work/cap
waitport() { for i in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:8897/api/app && return 0; sleep 0.5; done; echo "server not up"; return 1; }
if [ -f $E/server.pid ]; then kill $(cat $E/server.pid) 2>/dev/null || true; sleep 1; fi
bash $E/reset.sh
rm -rf $E/cap/src && cp -a $R/src $E/cap/src && find $E/cap/src -name __pycache__ -prune -exec rm -rf {} +
# 고객 제안서 예제 (D-46) 도 같이 맞춘다
rm -rf $E/cap/scenarios/arch/board-saas $E/cap/experiments/arch-board-saas $E/cap/experiments/candidate-sets/board-saas-sg
cp -a $R/scenarios/arch/board-saas $E/cap/scenarios/arch/board-saas && cp -a $R/experiments/arch-board-saas $E/cap/experiments/arch-board-saas && cp -a $R/experiments/candidate-sets/board-saas-sg $E/cap/experiments/candidate-sets/board-saas-sg
# 팀 3계층 예제 (D-49)
rm -rf $E/cap/scenarios/arch/three-tier-team $E/cap/experiments/arch-three-tier-team $E/cap/experiments/candidate-sets/three-tier-team-sg
cp -a $R/scenarios/arch/three-tier-team $E/cap/scenarios/arch/three-tier-team && cp -a $R/experiments/arch-three-tier-team $E/cap/experiments/arch-three-tier-team && cp -a $R/experiments/candidate-sets/three-tier-team-sg $E/cap/experiments/candidate-sets/three-tier-team-sg
cp $R/experiments/candidate-sets/arch-3tier-sg/manifest.json $E/cap/experiments/candidate-sets/arch-3tier-sg/manifest.json && cp $R/src/iacpatch/web/static/main.html $E/cap/src/iacpatch/web/static/main.html
# 가상 고객 요청서 (D-50) — Terraform 폴더 밖 scenarios/requests
rm -rf $E/cap/scenarios/requests && cp -a $R/scenarios/requests $E/cap/scenarios/requests
# 팀 3계층 요청 2 (S3, 정책 밖) · 요청 3 (IAM) (D-51) · 요청 4 ~ 11 (D-52, 16차 요청함)
for x in three-tier-team-s3 three-tier-team-iam three-tier-team-dbsg three-tier-team-dbpublic three-tier-team-upload three-tier-team-imds three-tier-team-dbenc three-tier-team-deletion three-tier-team-flowlog three-tier-team-backup; do
  rm -rf "${E:?}/cap/scenarios/arch/${x:?}" "${E:?}/cap/experiments/arch-${x:?}"; cp -a "$R/scenarios/arch/$x" "$E/cap/scenarios/arch/$x"; cp -a "$R/experiments/arch-$x" "$E/cap/experiments/arch-$x"; done
for x in three-tier-team-iam three-tier-team-dbsg three-tier-team-upload; do rm -rf "${E:?}/cap/experiments/candidate-sets/${x:?}"; cp -a "$R/experiments/candidate-sets/$x" "$E/cap/experiments/candidate-sets/$x"; done
bash $E/start.sh; waitport; echo restarted
