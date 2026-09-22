"""IaCPatch 한 번 클릭 실행기 — 도구 확인 → 실험 8단계 → HTML 리포트 → 브라우저.

    python -m iacpatch.app            # 창(tkinter) 이 있으면 창, 없으면 콘솔
    python -m iacpatch.app --console  # 콘솔 강제
    python -m iacpatch.app --report-only   # 실험은 건너뛰고 리포트만 다시 만들어 연다
    python -m iacpatch.app --no-open       # 브라우저를 열지 않는다
    python -m iacpatch.app --fresh         # 이전 기록 재사용 없이 전부 다시 (기본은 바뀐 후보만 다시 돈다)

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
from typing import Any, Callable, Dict, List, Optional


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


def steps(include_cc: bool, fresh: bool = False) -> List[tuple]:
    """scripts/run_experiments.sh 의 8 단계와 같은 순서. (제목, 명령 또는 None=건너뜀). fresh=True 면 이전 기록 재사용 없이 전부 다시 돌린다."""
    rcs = "scripts/run_candidate_set.py"
    extra = ["--fresh"] if fresh else []
    s = [
        ("0/8 단위 테스트 (tests/unit, 도구 불필요)", _unittest_cmd()),
        ("1/8 A 의 9 케이스 결과 재현 확인", _script_cmd("experiments/candidate-sets/a-probe-dev/check_a_results.py")),
        ("2/8 eval-a-probe-rule (규칙 기반, SG)", _script_cmd(rcs, "experiments/candidate-sets/eval-a-probe-rule/manifest.json", *extra)),
        ("3/8 eval-seeded-sg (오라클 유무, SG)", _script_cmd(rcs, "experiments/candidate-sets/eval-seeded-sg/manifest.json", *extra)),
        ("4/8 eval-iam-rule (규칙 기반, IAM)", _script_cmd(rcs, "experiments/candidate-sets/eval-iam-rule/manifest.json", *extra)),
        ("5/8 eval-seeded-iam (오라클 유무, IAM)", _script_cmd(rcs, "experiments/candidate-sets/eval-seeded-iam/manifest.json", *extra)),
    ]
    if include_cc:
        s.append(("6/8 eval-claude-code (LLM 후보)", _script_cmd(rcs, "experiments/candidate-sets/eval-claude-code/manifest.json", *extra)))
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


def run_all(log: Callable[[str], None], progress: Callable[[int, int], None], report_only: bool = False, open_browser: bool = True, fresh: bool = False) -> Path:
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
        todo = [] if report_only else steps(has_cc_candidates(), fresh=fresh)
        if todo:
            log("재사용: " + ("끔 — 전부 다시 돌린다 (--fresh)" if fresh else "켬 — 입력·정책·코드·도구가 같은 후보는 이전 기록을 쓴다 (처음 한 번은 전부 돈다)"))
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
TITLE = "AI가 생성한 테라폼 보안패치의 실효성 검증 자동화"
C = {"bg": "#f6f5f1", "panel": "#ffffff", "line": "#e3e2dc", "hero": "#0f2a4a", "hero_sub": "#b9cbe3", "ink": "#0b0b0b", "ink2": "#52514e",
     "ink3": "#8a8985", "accent": "#2a78d6", "good": "#0ca30c", "crit": "#d03b3b", "warn": "#9a6b00", "muted": "#a9a8a3", "code": "#f1f0ea", "s2": "#eb6834"}


def gui() -> int:
    import tkinter as tk
    from tkinter import ttk

    win = platform.system() == "Windows"
    UI = ("Malgun Gothic", 10) if win else ("TkDefaultFont", 10)
    UI_B = (UI[0], 10, "bold")
    MONO = ("Consolas", 10) if win else ("TkFixedFont", 10)

    root = tk.Tk()
    root.title(f"IaCPatch — {TITLE}")
    root.geometry("1120x760")
    root.minsize(900, 600)
    root.configure(bg=C["bg"])
    st = ttk.Style(root)
    try:
        st.theme_use("clam")
    except tk.TclError:
        pass
    st.configure(".", background=C["bg"], foreground=C["ink"], font=UI)
    st.configure("TFrame", background=C["bg"])
    st.configure("Panel.TFrame", background=C["panel"])
    st.configure("TLabel", background=C["bg"], foreground=C["ink"], font=UI)
    st.configure("Panel.TLabel", background=C["panel"], foreground=C["ink"], font=UI)
    st.configure("PanelSub.TLabel", background=C["panel"], foreground=C["ink2"], font=UI)
    st.configure("PanelH.TLabel", background=C["panel"], foreground=C["ink"], font=(UI[0], 11, "bold"))
    st.configure("Sub.TLabel", background=C["bg"], foreground=C["ink2"], font=UI)
    st.configure("TButton", padding=(12, 6), font=UI, background=C["panel"], foreground=C["ink"], bordercolor=C["line"], relief="flat")
    st.map("TButton", background=[("active", "#eceae4"), ("disabled", C["bg"])], foreground=[("disabled", C["ink3"])])
    st.configure("Accent.TButton", background=C["accent"], foreground="#ffffff", font=UI_B, bordercolor=C["accent"])
    st.map("Accent.TButton", background=[("active", "#1c5cab"), ("disabled", "#9dbde6")], foreground=[("disabled", "#ffffff")])
    st.configure("TCheckbutton", background=C["bg"], foreground=C["ink2"], font=UI)
    st.map("TCheckbutton", background=[("active", C["bg"])])
    st.configure("Blue.Horizontal.TProgressbar", troughcolor=C["line"], background=C["accent"], bordercolor=C["line"], lightcolor=C["accent"], darkcolor=C["accent"])
    q: "queue.Queue[tuple]" = queue.Queue()

    # ---- 머리 (짙은 띠): 제목 + 한 줄 설명 + 도구 상태 칩
    hero = tk.Frame(root, bg=C["hero"], padx=22, pady=16)
    hero.pack(fill="x")
    tk.Label(hero, text="IACPATCH  ·  한 번 클릭 실행기", bg=C["hero"], fg=C["hero_sub"], font=(UI[0], 9)).pack(anchor="w")
    tk.Label(hero, text=TITLE, bg=C["hero"], fg="#ffffff", font=(UI[0], 17, "bold")).pack(anchor="w", pady=(2, 4))
    tk.Label(hero, text="Trivy 가 통과시킨 패치를 그대로 믿지 않는다 — 8계층 검증 + 위험도 기준표가 후보마다 '사람이 어떤 검토를 해야 하나' 를 정한다.",
             bg=C["hero"], fg=C["hero_sub"], font=UI, wraplength=1040, justify="left").pack(anchor="w")
    chips = tk.Frame(hero, bg=C["hero"]); chips.pack(anchor="w", pady=(10, 0))
    chip_widgets: List[tk.Label] = []

    def _chip(text: str, ok: Optional[bool]) -> tk.Label:
        fg = "#ffffff"; border = C["good"] if ok else (C["crit"] if ok is False else C["hero_sub"])
        lb = tk.Label(chips, text=f"  {text}  ", bg=C["hero"], fg=fg, font=(UI[0], 9), highlightthickness=1, highlightbackground=border, highlightcolor=border)
        lb.pack(side="left", padx=(0, 6)); return lb

    def refresh_chips():
        for w in chip_widgets:
            w.destroy()
        chip_widgets.clear()
        ts = tool_status()
        for k, v in ts.items():
            chip_widgets.append(_chip(f"{k} {v['version'].replace('Version: ', '') if v['ok'] else '없음 → 도구 설치 버튼'}", v["ok"]))
        chip_widgets.append(_chip(f"저장소 {ROOT}", None))
        chip_widgets.append(_chip("하지 않는 것: AWS 접속·apply · LLM API · Claude Code 자동 호출 · git push", None))

    refresh_chips()

    # ---- 본문: 왼쪽 단계 목록 + 결과 타일, 오른쪽 로그
    body = tk.Frame(root, bg=C["bg"], padx=16, pady=12); body.pack(fill="both", expand=True)
    body.columnconfigure(1, weight=1); body.rowconfigure(0, weight=1)
    left = tk.Frame(body, bg=C["panel"], highlightthickness=1, highlightbackground=C["line"], padx=14, pady=12, width=330)
    left.grid(row=0, column=0, sticky="nsw", padx=(0, 12)); left.grid_propagate(False)
    ttk.Label(left, text="단계", style="PanelH.TLabel").pack(anchor="w")
    ttk.Label(left, text="처음 한 번은 전부 돈다. 이후엔 바뀐 후보만 다시 돈다.", style="PanelSub.TLabel", wraplength=290).pack(anchor="w", pady=(0, 8))
    step_rows: List[Dict[str, Any]] = []
    steps_box = tk.Frame(left, bg=C["panel"]); steps_box.pack(fill="x")

    def build_steps(fresh: bool):
        for w in steps_box.winfo_children():
            w.destroy()
        step_rows.clear()
        for title, argv in steps(has_cc_candidates(), fresh=fresh) + [("리포트 생성 (report/index.html)", "report")]:
            row = tk.Frame(steps_box, bg=C["panel"]); row.pack(fill="x", pady=1)
            ic = tk.Label(row, text="○", bg=C["panel"], fg=C["muted"], font=(UI[0], 11), width=2, anchor="w"); ic.pack(side="left")
            short = title.split(" (")[0] if len(title) > 40 else title
            tx = tk.Label(row, text=short, bg=C["panel"], fg=C["ink2"] if argv is not None else C["muted"], font=UI, anchor="w", wraplength=230, justify="left"); tx.pack(side="left", fill="x", expand=True)
            el = tk.Label(row, text="", bg=C["panel"], fg=C["ink3"], font=(UI[0], 9), width=6, anchor="e"); el.pack(side="right")
            step_rows.append({"title": title, "ic": ic, "tx": tx, "el": el, "skip": argv is None, "t0": None})

    build_steps(False)

    result_box = tk.Frame(left, bg=C["panel"]); result_box.pack(fill="x", pady=(14, 0))
    ttk.Label(result_box, text="결과 (리포트와 같은 숫자)", style="PanelH.TLabel").pack(anchor="w")
    tiles_box = tk.Frame(result_box, bg=C["panel"]); tiles_box.pack(fill="x", pady=(6, 0))
    tiles_box.columnconfigure(0, weight=1); tiles_box.columnconfigure(1, weight=1)

    def show_tiles(S: Dict[str, Any]):
        for w in tiles_box.winfo_children():
            w.destroy()
        blind = (S["blind_sg"][0] if S.get("blind_sg") else 0) + (S["blind_iam"][0] if S.get("blind_iam") else 0)
        items = [(str(blind), "스캐너 통과 ∧ 오라클 FAIL\n(실제 plan, SG+IAM)", C["crit"]),
                 (f"{S['label_agree']}/{S['label_total']}", "기대 라벨 일치", C["good"]),
                 (str(S["not_run_total"]), "미검증 계층", C["warn"] if S["not_run_total"] else C["good"]),
                 (str(S["n_llm"]), "LLM 후보" + (" (미측정)" if S["n_llm"] == 0 else ""), C["warn"] if S["n_llm"] == 0 else C["good"])]
        for i, (n, l, col) in enumerate(items):
            t = tk.Frame(tiles_box, bg=C["code"], highlightthickness=1, highlightbackground=C["line"], padx=8, pady=6)
            t.grid(row=i // 2, column=i % 2, sticky="nsew", padx=2, pady=2)
            tk.Frame(t, bg=col, width=4).pack(side="left", fill="y", padx=(0, 8))
            tk.Label(t, text=n, bg=C["code"], fg=C["ink"], font=(UI[0], 18, "bold")).pack(anchor="w")
            tk.Label(t, text=l, bg=C["code"], fg=C["ink2"], font=(UI[0], 9), justify="left").pack(anchor="w")

    try:
        from .report_html import summarize
        if (ROOT / "report" / "index.html").exists():
            show_tiles(summarize())
        else:
            tk.Label(tiles_box, text="아직 실행 전", bg=C["panel"], fg=C["ink3"], font=UI).grid(row=0, column=0, sticky="w")
    except Exception:
        tk.Label(tiles_box, text="아직 실행 전", bg=C["panel"], fg=C["ink3"], font=UI).grid(row=0, column=0, sticky="w")

    right = tk.Frame(body, bg=C["panel"], highlightthickness=1, highlightbackground=C["line"])
    right.grid(row=0, column=1, sticky="nsew")
    ttk.Label(right, text="로그", style="PanelH.TLabel").pack(anchor="w", padx=14, pady=(10, 0))
    txt = tk.Text(right, wrap="none", font=MONO, bg=C["panel"], fg=C["ink"], relief="flat", padx=12, pady=8, insertbackground=C["ink"])
    sb = ttk.Scrollbar(right, orient="vertical", command=txt.yview); txt.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y", pady=(4, 8)); txt.pack(fill="both", expand=True, padx=(4, 0), pady=(4, 8))
    txt.tag_configure("hdr", foreground=C["accent"], font=(MONO[0], 10, "bold"))
    txt.tag_configure("pass", foreground=C["good"], font=(MONO[0], 10, "bold"))
    txt.tag_configure("fail", foreground=C["crit"], font=(MONO[0], 10, "bold"))
    txt.tag_configure("unk", foreground=C["warn"])
    txt.tag_configure("reuse", foreground=C["ink3"])
    txt.tag_configure("dim", foreground=C["ink3"])

    def append_log(line: str):
        tag = None
        if line.startswith("================"):
            tag = "hdr"
        elif "FAIL" in line or "종료 코드" in line or "오류" in line or "Traceback" in line:
            tag = "fail"
        elif "재사용" in line:
            tag = "reuse"
        elif "UNKNOWN" in line or "NOT_RUN" in line:
            tag = "unk"
        elif "PASS" in line or " OK" in line or "완료" in line or "일치" in line:
            tag = "pass"
        elif line.startswith(("|", "-", "#")):
            tag = "dim"
        txt.insert("end", line + "\n", tag) if tag else txt.insert("end", line + "\n")
        txt.see("end")

    # ---- 아래: 진행 막대 + 상태 + 버튼
    foot = tk.Frame(root, bg=C["bg"], padx=16, pady=10); foot.pack(fill="x")
    pb = ttk.Progressbar(foot, mode="determinate", maximum=10, style="Blue.Horizontal.TProgressbar"); pb.pack(fill="x")
    status = tk.StringVar(value="대기 — '▶ 전체 실행' 을 누르면 단위 테스트 → 실험 8단계 → 리포트 순서로 돈다.")
    ttk.Label(foot, textvariable=status, style="Sub.TLabel", wraplength=1080).pack(anchor="w", pady=(6, 8))
    btns = tk.Frame(foot, bg=C["bg"]); btns.pack(fill="x")
    fresh_var = tk.BooleanVar(value=False)
    last_report: List[Optional[Path]] = [ROOT / "report" / "index.html" if (ROOT / "report" / "index.html").exists() else None]

    def mark_step(title: str):
        now = time.time()
        for r in step_rows:
            if r["t0"] is not None and r["ic"].cget("text") == "◔":
                r["ic"].configure(text="●", fg=C["good"]); r["el"].configure(text=f"{now - r['t0']:.0f}s")
        for r in step_rows:
            if r["title"] == title or (title.startswith("리포트") and r["title"].startswith("리포트")):
                if r["skip"]:
                    r["ic"].configure(text="–", fg=C["muted"]); r["el"].configure(text="건너뜀")
                else:
                    r["ic"].configure(text="◔", fg=C["accent"]); r["t0"] = now
                break

    def finish_steps(ok: bool):
        now = time.time()
        for r in step_rows:
            if r["ic"].cget("text") == "◔":
                r["ic"].configure(text="●" if ok else "✖", fg=C["good"] if ok else C["crit"]); r["el"].configure(text=f"{now - r['t0']:.0f}s" if r["t0"] else "")

    def worker(report_only: bool):
        try:
            out = run_all(lambda s: q.put(("log", s)), lambda i, n: q.put(("prog", i, n)), report_only=report_only, open_browser=True, fresh=fresh_var.get())
            try:
                from .report_html import summarize
                q.put(("summary", summarize()))
            except Exception as e:  # 집계 실패는 리포트 생성과 별개
                q.put(("log", f"집계 실패: {e}"))
            q.put(("done", out))
        except Exception as e:
            q.put(("log", f"오류: {e}")); q.put(("done", None))

    def start(report_only: bool):
        for b in (b_run, b_rep, b_tools):
            b.state(["disabled"])
        txt.delete("1.0", "end")
        build_steps(fresh_var.get())
        if report_only:
            for r in step_rows[:-1]:
                r["ic"].configure(text="–", fg=C["muted"]); r["el"].configure(text="건너뜀")
        status.set("실행 중… 처음 한 번은 후보 38개를 전부 돈다 (PC 마다 다름). 이후에는 바뀐 후보만 다시 돈다." if not report_only else "리포트만 다시 만드는 중…")
        threading.Thread(target=worker, args=(report_only,), daemon=True).start()

    def setup_tools():
        script = ROOT / "scripts" / ("setup_tools.ps1" if win else "setup_tools.sh")
        argv = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)] if win else ["bash", str(script)]

        def w():
            q.put(("log", f"도구 설치: {' '.join(argv)}"))
            try:
                p = subprocess.Popen(argv, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
                for line in p.stdout:  # type: ignore[union-attr]
                    q.put(("log", line.rstrip("\n")))
                p.wait()
            except OSError as e:
                q.put(("log", f"도구 설치 실패: {e}"))
            q.put(("tools", None)); q.put(("done", None))
        for b in (b_run, b_rep, b_tools):
            b.state(["disabled"])
        txt.delete("1.0", "end")
        status.set("trivy / terraform 을 tools\\ 에 받는 중… (처음 한 번, 수백 MB)")
        threading.Thread(target=w, daemon=True).start()

    def open_report():
        if last_report[0] and last_report[0].exists():
            webbrowser.open(last_report[0].as_uri())
        else:
            status.set("리포트가 아직 없다. '전체 실행' 또는 '리포트만' 을 먼저.")

    b_run = ttk.Button(btns, text="▶  전체 실행", style="Accent.TButton", command=lambda: start(False)); b_run.pack(side="left", padx=(0, 8))
    b_rep = ttk.Button(btns, text="리포트만 다시 생성", command=lambda: start(True)); b_rep.pack(side="left", padx=(0, 8))
    ttk.Button(btns, text="리포트 열기", command=open_report).pack(side="left", padx=(0, 8))
    b_tools = ttk.Button(btns, text="도구 설치/확인", command=setup_tools); b_tools.pack(side="left", padx=(0, 8))
    ttk.Checkbutton(btns, text="전부 다시 돌리기 (이전 기록 재사용 안 함)", variable=fresh_var).pack(side="left", padx=(10, 0))
    ttk.Label(btns, text="로그: experiments\\run_experiments.log", style="Sub.TLabel").pack(side="right")

    def pump():
        try:
            while True:
                item = q.get_nowait()
                if item[0] == "log":
                    line = item[1]
                    append_log(line)
                    if line.startswith("================ "):
                        mark_step(line[len("================ "):].strip())
                elif item[0] == "prog":
                    pb.configure(maximum=max(item[2], 1), value=item[1])
                elif item[0] == "tools":
                    refresh_chips()
                elif item[0] == "summary":
                    show_tiles(item[1])
                elif item[0] == "done":
                    finish_steps(item[1] is not None)
                    if item[1]:
                        last_report[0] = item[1]; status.set(f"완료 — 리포트: {item[1]}  (브라우저로 열었다. 안 열리면 '리포트 열기')")
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


def console(report_only: bool, open_browser: bool, fresh: bool = False) -> int:
    def log(s: str) -> None:
        print(s, flush=True)
    def prog(i: int, n: int) -> None:
        pass
    out = run_all(log, prog, report_only=report_only, open_browser=open_browser, fresh=fresh)
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
    ap.add_argument("--fresh", action="store_true", help="이전 기록 재사용 없이 전부 다시 돌림")
    a = ap.parse_args(argv)
    if not a.console:
        try:
            import tkinter  # noqa: F401
            return gui()
        except Exception as e:  # tkinter 없음 / 디스플레이 없음
            print(f"(창을 열 수 없어 콘솔로 진행: {e})")
    return console(a.report_only, not a.no_open, fresh=a.fresh)


if __name__ == "__main__":
    sys.exit(main())
