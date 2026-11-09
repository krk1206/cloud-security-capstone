"""subprocess 실행 공통 도우미 (도구 존재 확인, 타임아웃, 출력 캡처)."""
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional


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


def _git_fallbacks() -> List[str]:
    """Windows 에서 PATH 에 git 이 없을 때 찾아볼 자리 — GitHub Desktop 이 같이 설치한 git · Git for Windows 기본 설치 위치.
    (9차, 2026-11-02: 팀 PC 에 GitHub Desktop 만 있어 PR 준비 확인이 'git 없음' 으로 막혔다.)"""
    if os.name != "nt":
        return []
    out: List[str] = []
    la = os.environ.get("LOCALAPPDATA") or ""
    if la:
        gd = os.path.join(la, "GitHubDesktop")
        if os.path.isdir(gd):
            apps = sorted((d for d in os.listdir(gd) if d.startswith("app-")), reverse=True)     # 최신 판부터
            out += [os.path.join(gd, d, "resources", "app", "git", "cmd", "git.exe") for d in apps]
        out.append(os.path.join(la, "Programs", "Git", "cmd", "git.exe"))
    for pf in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramW6432")):
        if pf:
            out.append(os.path.join(pf, "Git", "cmd", "git.exe"))
    return out


def which(binary: str) -> Optional[str]:
    hit = shutil.which(binary)
    if hit is None and binary in ("git", "git.exe"):
        for cand in _git_fallbacks():
            if os.path.isfile(cand):
                return cand
    return hit


def _call_argv(argv: List[str], exe: Optional[str]) -> List[str]:
    """PATH 에 없고 알려진 자리에서 찾은 것(예: GitHub Desktop 의 git)은 그 경로로 실행한다. 기록(CmdResult.argv)에는 부른 이름 그대로 남긴다."""
    if exe and os.path.basename(argv[0]) in ("git", "git.exe") and exe != argv[0]:
        return [exe] + list(argv[1:])
    return list(argv)


def no_console_window() -> Dict[str, int]:
    """Windows: 창 없는 IaCPatch.exe(PyInstaller --windowed)가 trivy·terraform 같은 콘솔 프로그램을 부를 때
    호출마다 검은 터미널 창이 새로 뜨지 않게 하는 subprocess 인자. 다른 OS 에서는 빈 dict.
    (팀 PC 실측 2026-10-19: 후보 하나 검토에 터미널 창이 여러 개 뜨고, 끝나도 '프로세스 종료됨' 으로 남았다.)"""
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)}
    return {}


def run(argv: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
        timeout: int = 600, input_text: Optional[str] = None, unset: Optional[List[str]] = None) -> CmdResult:
    """unset: 자식 프로세스 환경에서 지울 변수 이름 (예: AI 호출에 API 키 · AWS 자격증명이 넘어가지 않게)."""
    exe = which(argv[0])
    if exe is None and not os.path.exists(argv[0]):
        raise ToolNotFound(f"executable not found: {argv[0]}")
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    for k in unset or []:
        full_env.pop(k, None)
    try:
        # encoding 을 명시하지 않으면 윈도우(한국어)에서 cp949 로 읽어 terraform 의 UTF-8 출력(→, ─ 등)에서 죽는다
        p = subprocess.run(_call_argv(argv, exe), cwd=cwd, env=full_env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout, input=input_text,
                           **no_console_window())
        return CmdResult(argv, p.returncode, p.stdout, p.stderr, cwd or os.getcwd())
    except subprocess.TimeoutExpired as e:
        def _txt(x):
            return x.decode("utf-8", errors="replace") if isinstance(x, bytes) else (x or "")
        return CmdResult(argv, -1, _txt(e.stdout), _txt(e.stderr), cwd or os.getcwd(), timed_out=True)


def run_stream(argv: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
               timeout: int = 1800, on_line: Optional[Callable[[str], None]] = None) -> CmdResult:
    """오래 걸리는 명령(terraform apply 등)을 돌리면서 출력 줄을 바로바로 on_line 으로 넘긴다 (화면 실행 로그가 멈춰 보이지 않게).
    stdout·stderr 를 한 줄씩 합쳐서 받는다 (CmdResult.stdout 에 전부, stderr 는 빈 문자열). 시간을 넘기면 프로세스를 끝내고 timed_out."""
    exe = which(argv[0])
    if exe is None and not os.path.exists(argv[0]):
        raise ToolNotFound(f"executable not found: {argv[0]}")
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    p = subprocess.Popen(_call_argv(argv, exe), cwd=cwd, env=full_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         text=True, encoding="utf-8", errors="replace", **no_console_window())
    q: "queue.Queue[Optional[str]]" = queue.Queue()

    def reader() -> None:
        try:
            for line in p.stdout:              # type: ignore[union-attr]
                q.put(line)
        finally:
            q.put(None)
    t = threading.Thread(target=reader, daemon=True)
    t.start()
    lines: List[str] = []
    deadline = time.time() + timeout
    timed_out = False
    while True:
        left = deadline - time.time()
        if left <= 0:                          # 출력이 계속 나와도 시간은 지킨다
            timed_out = True
            p.kill()
            break
        try:
            line = q.get(timeout=min(0.5, left))
        except queue.Empty:
            continue
        if line is None:
            break
        lines.append(line)
        if on_line is not None:
            try:
                on_line(line.rstrip("\r\n"))
            except Exception:                  # 화면 기록 실패가 명령을 멈추지 않게
                pass
    try:
        rc = p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = -1
    t.join(timeout=5)
    while True:                                # 끝낸 뒤 도착한 줄도 기록에 남긴다
        try:
            rest = q.get_nowait()
        except queue.Empty:
            break
        if rest is not None:
            lines.append(rest)
    try:
        if p.stdout is not None:
            p.stdout.close()
    except Exception:
        pass
    return CmdResult(argv, -1 if timed_out else rc, "".join(lines), "", cwd or os.getcwd(), timed_out=timed_out)
