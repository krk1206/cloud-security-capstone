#!/bin/bash
set -e
E=/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e; SP=/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad; R=/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/work/cap
waitport() { for i in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:8897/api/app && return 0; sleep 0.5; done; echo "server not up"; return 1; }
if [ -f $E/server.pid ]; then kill $(cat $E/server.pid) 2>/dev/null || true; sleep 1; fi
bash $E/reset.sh
rm -rf $E/cap/src && cp -a $R/src $E/cap/src && find $E/cap/src -name __pycache__ -prune -exec rm -rf {} +
bash $E/start.sh; waitport; echo restarted
