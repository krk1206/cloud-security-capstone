"""subprocess 실행 공통 도우미 (도구 존재 확인, 타임아웃, 출력 캡처)."""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional


class ToolNotFound(RuntimeError):
    pass


@dataclass
class CmdResult:
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str
    cwd: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def run(argv: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
        timeout: int = 600, input_text: Optional[str] = None) -> CmdResult:
    if which(argv[0]) is None and not os.path.exists(argv[0]):
        raise ToolNotFound(f"executable not found: {argv[0]}")
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        # encoding 을 명시하지 않으면 윈도우(한국어)에서 cp949 로 읽어 terraform 의 UTF-8 출력(→, ─ 등)에서 죽는다
        p = subprocess.run(argv, cwd=cwd, env=full_env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout, input=input_text)
        return CmdResult(argv, p.returncode, p.stdout, p.stderr, cwd or os.getcwd())
    except subprocess.TimeoutExpired as e:
        def _txt(x):
            return x.decode("utf-8", errors="replace") if isinstance(x, bytes) else (x or "")
        return CmdResult(argv, -1, _txt(e.stdout), _txt(e.stderr), cwd or os.getcwd(), timed_out=True)
