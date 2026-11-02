#!/usr/bin/env python3
"""`python -m iacpatch <명령>` 을 python 없는 팀 PC 에서 exe 로 돌리기 위한 얇은 래퍼.

    IaCPatch-console.exe --exec scripts/iacpatch_cli.py pr --review <기록 id> --base claude/iacpatch-sg-slice
    IaCPatch-console.exe --exec scripts/iacpatch_cli.py postdeploy --review <기록 id> --intent <intent.json> --v8-checks <checks.json> [--execute]
    IaCPatch-console.exe --exec scripts/iacpatch_cli.py findings --trivy-json experiments/arch-webapp-2tier/trivy-scan.json

하는 일: tools\\ 의 trivy·terraform 을 환경변수로 잡고(아키텍처 점검 스크립트와 같은 규칙) iacpatch.cli.main 에 인자를 그대로 넘긴다.
안 하는 일: 인자 해석·판정·AWS 접속. `--execute` 가 없으면 pr/postdeploy 는 명령만 출력한다 (원래 CLI 의 규칙 그대로).
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from iacpatch.archscan import tool_env  # noqa: E402
from iacpatch.cli import main as cli_main  # noqa: E402
from iacpatch.config import package_root  # noqa: E402


def main(argv=None) -> int:
    root = package_root() if (package_root() / "policy" / "patch_policy.json").exists() else ROOT
    env = tool_env(root)
    for k, v in env.items():
        if k.endswith("_BIN") or k not in os.environ:
            os.environ[k] = v
    os.chdir(root)
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(__doc__)
        return 2
    return int(cli_main(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
