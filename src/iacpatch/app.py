"""IaCPatch 한 번 클릭 실행기 — 도구 확인 → 실험 8단계 → HTML 리포트 → 브라우저.

    python -m iacpatch.app            # 창(tkinter) 이 있으면 창, 없으면 콘솔
    python -m iacpatch.app --console  # 콘솔 강제
    python -m iacpatch.app --report-only   # 실험은 건너뛰고 리포트만 다시 만들어 연다
    python -m iacpatch.app --no-open       # 브라우저를 열지 않는다

exe 로 만들 때(팀 PC, Windows): packaging/build_exe.ps1 → dist/IaCPatch.exe 를 저장소 루트에 두고 더블클릭.
exe 는 실행기일 뿐이고 저장소 폴더(policy/, scenarios/, experiments/, tools/)가 옆에 있어야 한다.
하지 않는 것: LLM API 호출, Claude Code 자동 호출, AWS 접속, git push, terraform apply (D-5, D-11).
"""
from __future__ import annotations

import os
import platform
import queue
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Callable, List, Optional


def find_root() -> Path:
    """저장소 루트: 환경변수 IACPATCH_ROOT > exe/스크립트 위치에서 위로 올라가며 policy/patch_policy.json 찾기."""
    env = os.environ.get("IACPATCH_ROOT")
    if env and (Path(env) / "policy" / "patch_policy.json").exists():
        return Path(env).resolve()
    start = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    for p in [start, *start.parents]:
        if (p / "policy" / "patch_policy.json").exists():
            return p
    return Path.cwd().resolve()


ROOT = find_root()
FROZEN = bool(getattr(sys, "frozen", False))   # PyInstaller exe 로 실행 중이면 True


def _script_cmd(script: str, *args: str) -> List[str]:
    """scripts/x.py 를 돌리는 명령. exe 이면 자기 자신을 `--exec` 로 다시 띄운다 (PC 에 python 이 없어도 됨)."""
    if FROZEN:
        return [sys.executable, "--exec", script, *args]
    return [sys.executable, script, *args]


def _unittest_cmd() -> List[str]:
    if FROZEN:
        return [sys.executable, "--unittest"]
    return [sys.executable, "-m", "unittest", "discover", "-s", "tests/unit", "-p", "test_*.py"]


def _exec_script(script: str, args: List[str]) -> int:
    """`--exec` 처리: 저장소의 스크립트를 이 프로세스 안에서 __main__ 으로 실행한다."""
    import runpy
    path = (ROOT / script) if not Path(script).is_absolute() else Path(script)
    if not path.exists():
        print(f"스크립트가 없다: {path}", file=sys.stderr)
        return 2
    sys.argv = [str(path), *args]
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(path.parent))
    os.chdir(ROOT)
    try:
        runpy.run_path(str(path), run_name="__main__")
    except SystemExit as e:
        return int(e.code or 0) if isinstance(e.code, (int, type(None))) else 1
    return 0


def _exec_unittest() -> int:
    import unittest
    sys.path.insert(0, str(ROOT / "src"))
    os.chdir(ROOT)
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests" / "unit"), pattern="test_*.py")
    res = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if res.wasSuccessful() else 1


def tool_status() -> dict:
    """tools/ 의 trivy·terraform 을 잡고 버전을 읽는다 (없으면 PATH). run_experiments.* 와 같은 규칙."""
    win = platform.system() == "Windows"
    st = {}
    for name, key in (("trivy", "TRIVY_BIN"), ("terraform", "TERRAFORM_BIN")):
        exe = ROOT / "tools" / (name + (".exe" if win else ""))
        binp = str(exe) if exe.exists() else os.environ.get(key, name)
        try:
            args = [binp, "--version"] if name == "trivy" else [binp, "version"]
            out = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
            ver = (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr).strip() else "?"
            st[name] = {"bin": binp, "ok": out.returncode == 0, "version": ver}
        except (OSError, subprocess.TimeoutExpired):
            st[name] = {"bin": binp, "ok": False, "version": "없음"}
    return st


def _env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("TRIVY_SKIP_CHECK_UPDATE", "1")
    win = platform.system() == "Windows"
    for name, key in (("trivy", "TRIVY_BIN"), ("terraform", "TERRAFORM_BIN")):
        exe = ROOT / "tools" / (name + (".exe" if win else ""))
        if exe.exists():
            env[key] = str(exe)
    cache = ROOT / "tools" / "plugin-cache"
    cache.mkdir(parents=True, exist_ok=True)
    env.setdefault("TF_PLUGIN_CACHE_DIR", str(cache))
    return env


def steps(include_cc: bool) -> List[tuple]:
    """scripts/run_experiments.sh 의 8 단계와 같은 순서. (제목, 명령 또는 None=건너뜀)"""
    rcs = "scripts/run_candidate_set.py"
    s = [
        ("0/8 단위 테스트 (tests/unit, 도구 불필요)", _unittest_cmd()),
        ("1/8 A 의 9 케이스 결과 재현 확인", _script_cmd("experiments/candidate-sets/a-probe-dev/check_a_results.py")),
        ("2/8 eval-a-probe-rule (규칙 기반, SG)", _script_cmd(rcs, "experiments/candidate-sets/eval-a-probe-rule/manifest.json")),
        ("3/8 eval-seeded-sg (오라클 유무, SG)", _script_cmd(rcs, "experiments/candidate-sets/eval-seeded-sg/manifest.json")),
        ("4/8 eval-iam-rule (규칙 기반, IAM)", _script_cmd(rcs, "experiments/candidate-sets/eval-iam-rule/manifest.json")),
        ("5/8 eval-seeded-iam (오라클 유무, IAM)", _script_cmd(rcs, "experiments/candidate-sets/eval-seeded-iam/manifest.json")),
    ]
    if include_cc:
        s.append(("6/8 eval-claude-code (LLM 후보)", _script_cmd(rcs, "experiments/candidate-sets/eval-claude-code/manifest.json")))
    else:
        s.append(("6/8 eval-claude-code — 후보 0건, 건너뜀 (scripts/cc_prompt.py → Claude Code → scripts/cc_add.py 로 채운다)", None))
    s += [
        ("7/8 오라클 실험 (스캐너 vs V6, 실제 plan)", _script_cmd("scripts/oracle_experiment.py")),
        ("8/8 요약", _script_cmd("scripts/summarize_experiments.py")),
        ("8/8 기업용 한 장 (실측만)", _script_cmd("scripts/why_this_gate.py")),
    ]
    return s


def has_cc_candidates() -> bool:
    import json
    try:
        m = json.loads((ROOT / "experiments/candidate-sets/eval-claude-code/manifest.json").read_text(encoding="utf-8"))
        return bool(m.get("candidates"))
    except (OSError, ValueError):
        return False


def run_all(log: Callable[[str], None], progress: Callable[[int, int], None], report_only: bool = False, open_browser: bool = True) -> Path:
    """실험 8단계 + 리포트. 각 단계의 출력은 log() 로 흘려보내고 experiments/run_experiments.log 에도 남긴다."""
    env = _env()
    logf = ROOT / "experiments" / "run_experiments.log"
    logf.parent.mkdir(parents=True, exist_ok=True)
    with logf.open("w", encoding="utf-8") as lf:
        lf.write(f"IaCPatch app {time.strftime('%Y-%m-%dT%H:%M:%S')} host={platform.node()} root={ROOT}\n")
        ts = tool_status()
        for k, v in ts.items():
            line = f"{k:9s}: {v['version']}  ({v['bin']})" + ("" if v["ok"] else "  ← 없음: 해당 계층은 NOT_RUN")
            log(line); lf.write(line + "\n")
        if not ts["terraform"]["ok"]:
            log("terraform 이 없으면 V3~V6 이 NOT_RUN 이 된다. scripts/setup_tools.bat 를 먼저 돌려라.")
        todo = [] if report_only else steps(has_cc_candidates())
        total = len(todo) + 1
        for i, (title, argv) in enumerate(todo, 1):
            progress(i - 1, total)
            log(f"\n================ {title}"); lf.write(f"\n================ {title}\n")
            if argv is None:
                continue
            p = subprocess.Popen(argv, cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
            assert p.stdout is not None
            for line in p.stdout:
                line = line.rstrip("\n")
                log(line); lf.write(line + "\n")
            rc = p.wait()
            if rc != 0:
                log(f"  (종료 코드 {rc} — 이 단계는 실패. 로그를 확인)"); lf.write(f"exit={rc}\n")
        progress(total - 1, total)
        log("\n================ 리포트 생성")
        from .report_html import build
        out = build(ROOT / "report" / "index.html")
        log(f"→ {out}"); lf.write(f"report: {out}\n")
        progress(total, total)
    if open_browser:
        try:
            webbrowser.open(out.as_uri())
        except Exception as e:  # pragma: no cover
            log(f"브라우저 열기 실패: {e} — 파일을 직접 열어라: {out}")
    return out


# --------------------------------------------------------------------------- GUI
def gui() -> int:
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title("IaCPatch — AI가 생성한 테라폼 보안패치의 실효성 검증 자동화")
    root.geometry("980x640")
    q: "queue.Queue[tuple]" = queue.Queue()

    top = ttk.Frame(root, padding=10); top.pack(fill="x")
    ttk.Label(top, text="AI가 생성한 테라폼 보안패치의 실효성 검증 자동화 — 한 번 클릭 실행", font=("", 13, "bold")).pack(anchor="w")
    ttk.Label(top, text=f"저장소: {ROOT}", foreground="#52514e").pack(anchor="w")
    ts = tool_status()
    tool_var = tk.StringVar(value="  ·  ".join(f"{k}: {v['version'] if v['ok'] else '없음'}" for k, v in ts.items()))
    ttk.Label(top, textvariable=tool_var, foreground="#52514e").pack(anchor="w", pady=(2, 0))
    ttk.Label(top, text="하는 일: Trivy 스캔 → 후보 → V1~V6 검증 → 위험도/검토 수준 → HTML 리포트.  하지 않는 것: AWS 접속·apply, LLM API, Claude Code 자동 호출, git push.",
              foreground="#52514e", wraplength=940).pack(anchor="w", pady=(2, 6))

    btns = ttk.Frame(root, padding=(10, 0)); btns.pack(fill="x")
    pb = ttk.Progressbar(root, mode="determinate", maximum=10); pb.pack(fill="x", padx=10, pady=6)
    status = tk.StringVar(value="대기")
    ttk.Label(root, textvariable=status).pack(anchor="w", padx=10)
    txt = tk.Text(root, wrap="none", height=24, font=("Consolas", 10))
    txt.pack(fill="both", expand=True, padx=10, pady=(4, 10))
    last_report: List[Optional[Path]] = [ROOT / "report" / "index.html" if (ROOT / "report" / "index.html").exists() else None]

    def worker(report_only: bool):
        try:
            out = run_all(lambda s: q.put(("log", s)), lambda i, n: q.put(("prog", i, n)), report_only=report_only, open_browser=True)
            q.put(("done", out))
        except Exception as e:
            q.put(("log", f"오류: {e}")); q.put(("done", None))

    def start(report_only: bool):
        for b in (b_run, b_rep, b_tools):
            b.state(["disabled"])
        txt.delete("1.0", "end"); status.set("실행 중… (SG+IAM 세트 전체는 PC 에서 1시간 안팎)")
        threading.Thread(target=worker, args=(report_only,), daemon=True).start()

    def setup_tools():
        win = platform.system() == "Windows"
        script = ROOT / "scripts" / ("setup_tools.ps1" if win else "setup_tools.sh")
        argv = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)] if win else ["bash", str(script)]
        def w():
            q.put(("log", f"도구 설치: {' '.join(argv)}"))
            p = subprocess.Popen(argv, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
            for line in p.stdout:  # type: ignore[union-attr]
                q.put(("log", line.rstrip("\n")))
            p.wait(); q.put(("tools", None)); q.put(("done", None))
        for b in (b_run, b_rep, b_tools):
            b.state(["disabled"])
        threading.Thread(target=w, daemon=True).start()

    def open_report():
        if last_report[0] and last_report[0].exists():
            webbrowser.open(last_report[0].as_uri())
        else:
            status.set("리포트가 아직 없다. '전체 실행' 또는 '리포트만' 을 먼저.")

    b_tools = ttk.Button(btns, text="도구 설치/확인 (trivy·terraform → tools\\)", command=setup_tools); b_tools.pack(side="left", padx=(0, 6))
    b_run = ttk.Button(btns, text="▶ 전체 실행 (실험 8단계 + 리포트)", command=lambda: start(False)); b_run.pack(side="left", padx=(0, 6))
    b_rep = ttk.Button(btns, text="리포트만 다시 생성", command=lambda: start(True)); b_rep.pack(side="left", padx=(0, 6))
    ttk.Button(btns, text="리포트 열기", command=open_report).pack(side="left")

    def pump():
        try:
            while True:
                item = q.get_nowait()
                if item[0] == "log":
                    txt.insert("end", item[1] + "\n"); txt.see("end")
                elif item[0] == "prog":
                    pb.configure(maximum=max(item[2], 1), value=item[1])
                elif item[0] == "tools":
                    ts2 = tool_status(); tool_var.set("  ·  ".join(f"{k}: {v['version'] if v['ok'] else '없음'}" for k, v in ts2.items()))
                elif item[0] == "done":
                    if item[1]:
                        last_report[0] = item[1]; status.set(f"완료 — 리포트: {item[1]}")
                    else:
                        status.set("끝 (리포트 없음 또는 오류 — 로그 확인)")
                    for b in (b_run, b_rep, b_tools):
                        b.state(["!disabled"])
        except queue.Empty:
            pass
        root.after(100, pump)

    root.after(100, pump)
    root.mainloop()
    return 0


def console(report_only: bool, open_browser: bool) -> int:
    def log(s: str) -> None:
        print(s, flush=True)
    def prog(i: int, n: int) -> None:
        pass
    out = run_all(log, prog, report_only=report_only, open_browser=open_browser)
    print(f"\n완료. 리포트: {out}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    # 내부용: exe 가 자기 자신을 다시 띄워 스크립트/테스트를 돌릴 때 (PC 에 python 이 없어도 됨)
    if argv[:1] == ["--exec"] and len(argv) >= 2:
        return _exec_script(argv[1], argv[2:])
    if argv[:1] == ["--unittest"]:
        return _exec_unittest()
    ap = argparse.ArgumentParser(description="IaCPatch 한 번 클릭 실행기")
    ap.add_argument("--console", action="store_true", help="창 없이 콘솔로")
    ap.add_argument("--report-only", action="store_true", help="실험은 건너뛰고 리포트만")
    ap.add_argument("--no-open", action="store_true", help="브라우저를 열지 않음")
    a = ap.parse_args(argv)
    if not a.console:
        try:
            import tkinter  # noqa: F401
            return gui()
        except Exception as e:  # tkinter 없음 / 디스플레이 없음
            print(f"(창을 열 수 없어 콘솔로 진행: {e})")
    return console(a.report_only, not a.no_open)


if __name__ == "__main__":
    sys.exit(main())
