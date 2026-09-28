"""IaCPatch 실행기 — 브라우저 화면(로컬 웹 서버) 또는 콘솔.

    python -m iacpatch.app                 # 127.0.0.1 의 빈 포트에 화면을 띄우고 기본 브라우저를 연다 (exe 더블클릭과 같음)
    python -m iacpatch.app --port 8765     # 포트 지정
    python -m iacpatch.app --no-open       # 브라우저를 열지 않는다 (주소만 출력)
    python -m iacpatch.app --console       # 화면 없이 콘솔에서 실험 8단계 + 리포트
    python -m iacpatch.app --console --report-only   # 실험은 건너뛰고 리포트만
    python -m iacpatch.app --console --fresh         # 이전 기록 재사용 없이 전부 다시
    python -m iacpatch.app --selfcheck               # 루트·exe 여부·도구·설치 상태 검사만 찍고 끝 (진단용, 문제 있으면 종료 코드 1)

화면(iacpatch/web): 4주차(위험도 기준표·상한 강제) · 5주차(패치→검증→PR 미리보기) · 실험 8단계 · 리포트 · 도구.

exe: packaging/build_exe.ps1 (팀 PC) 또는 GitHub Actions build-exe 워크플로가 만든 IaCPatch.exe 를 저장소 루트에 두고 더블클릭.
exe 는 실행기일 뿐이고 저장소 폴더(policy/, scenarios/, experiments/, tools/)가 옆에 있어야 한다.
하지 않는 것: LLM API 호출, Claude Code 자동 호출, AWS 접속, git push, terraform apply (D-5, D-11).
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# 이 파일은 세 가지 방식으로 시작된다: `python -m iacpatch.app`(패키지), `python src/iacpatch/app.py`(스크립트), PyInstaller exe(스크립트와 같은 __main__).
# 스크립트/exe 로 시작되면 __package__ 가 비어 있어 `from .x import` 가 "attempted relative import with no known parent package" 로 죽는다
# (build-exe 워크플로 첫 실행의 스모크 실패 원인, 2026-09-28). 그래서 이 파일 안에서는 절대 import(iacpatch.…)만 쓰고, 스크립트로 시작됐으면 src/ 를 경로에 넣는다.
if not __package__ and not getattr(sys, "frozen", False):
    _src = str(Path(__file__).resolve().parents[1])
    if _src not in sys.path:
        sys.path.insert(0, _src)

from iacpatch.config import package_root  # noqa: E402


def find_root() -> Path:
    """저장소 루트: 환경변수 IACPATCH_ROOT > exe 위치(exe 면) / 소스 위치에서 위로 올라가며 policy/patch_policy.json 찾기 (config.package_root)."""
    return package_root()


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
    res = unittest.TextTestRunner(stream=sys.stdout, verbosity=1).run(suite)
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
    env.setdefault("TRIVY_SKIP_VERSION_CHECK", "true")
    win = platform.system() == "Windows"
    for name, key in (("trivy", "TRIVY_BIN"), ("terraform", "TERRAFORM_BIN")):
        exe = ROOT / "tools" / (name + (".exe" if win else ""))
        if exe.exists():
            env[key] = str(exe)
    cache = ROOT / "tools" / "plugin-cache"
    cache.mkdir(parents=True, exist_ok=True)
    env.setdefault("TF_PLUGIN_CACHE_DIR", str(cache))
    return env


def _installed_pythons() -> List[str]:
    """Windows: `py -0p` 로 설치된 파이썬 경로를 높은 버전부터. 그 외: PATH 의 python3.x."""
    found: List[tuple] = []
    if platform.system() == "Windows":
        import shutil as _sh
        # 1) py 런처에 버전을 직접 물어본다 (구 런처·새 Python 설치 관리자 둘 다 동작)
        for mi in (14, 13, 12, 11, 10):
            try:
                r = subprocess.run(["py", f"-3.{mi}", "-c", "import sys;print(sys.executable)"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
                if r.returncode == 0 and r.stdout.strip():
                    found.append(((3, mi), r.stdout.strip()))
            except (OSError, subprocess.TimeoutExpired):
                pass
        # 2) PATH 의 python
        for name in ("python", "python3"):
            pth = _sh.which(name)
            if pth:
                found.append(((1, 0), pth))
        # 3) `py -0p` 목록 (형식이 런처마다 달라 마지막 수단)
        try:
            out = subprocess.run(["py", "-0p"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20).stdout
            import re
            for m in re.finditer(r"-V?:?(\d+)\.(\d+)(?:-\d+)?\s+\*?\s*(\S.*?)\s*$", out, re.M):
                found.append(((int(m.group(1)), int(m.group(2))), m.group(3).strip()))
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        import shutil as _sh
        for name in ("python3.14", "python3.13", "python3.12", "python3.11", "python3.10", "python3"):
            p = _sh.which(name)
            if p:
                found.append(((0, 0), p))
    found.sort(key=lambda t: t[0], reverse=True)
    return [p for _, p in found]


def ensure_python(argv: List[str]) -> None:
    """3.10 미만 파이썬으로 시작됐으면(팀 PC 의 `py -3` 가 3.7 을 가리킨 사례) 설치된 3.10+ 로 자기 자신을 다시 띄운다."""
    if FROZEN or sys.version_info >= (3, 10):
        return
    for cand in _installed_pythons():
        try:
            chk = subprocess.run([cand, str(ROOT / "scripts" / "pyver.py")], capture_output=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if chk.returncode == 0:
            env = dict(os.environ); env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
            print(f"(python {platform.python_version()} 은 너무 낮음 → {cand} 로 다시 시작)")
            rc = subprocess.call([cand, "-X", "utf8", "-m", "iacpatch.app", *argv], cwd=str(ROOT), env=env)
            raise SystemExit(rc)
    raise SystemExit(f"Python 3.10 이상이 필요하다 (지금 {platform.python_version()}). python.org 에서 설치하고 'Add python.exe to PATH' 를 체크.")


def selfcheck() -> List[str]:
    """설치 상태 검사 — 옛 파일과 새 파일이 섞였는지(zip 을 기존 폴더에 풀며 '건너뛰기' 한 사례), 필수 스크립트가 있는지."""
    problems: List[str] = []
    if not (ROOT / "policy" / "patch_policy.json").exists():
        # 팀 PC 실측(09-28): 아티팩트 zip 을 풀면 exe 와 '안쪽 zip' 이 나오는데 exe 만 더블클릭 → 저장소 파일이 옆에 없어 검사 7건이 전부 '없음'
        problems.append(f"저장소 폴더가 아니다: {ROOT} 에 policy\\patch_policy.json 이 없다. " + NOT_REPO_HINT)
        return problems
    if sys.version_info < (3, 10):
        problems.append(f"python {platform.python_version()} — 3.10 이상 필요")
    checks = [("iacpatch.config", "Settings", "tf_template_dir"), ("iacpatch.report_html", "summarize", None), ("iacpatch.fuzz.runner", "run_variants", None),
              ("iacpatch.fingerprint", "code_digest", None), ("iacpatch.tools.terraform", "TerraformAdapter", "restore_provider_template"),
              ("iacpatch.review.local_verify", "run_local_verification", None), ("iacpatch.web.server", "serve", None),
              ("iacpatch.rubric_demo", "labeled_matrix", None)]
    import importlib
    for mod, name, attr in checks:
        try:
            m = importlib.import_module(mod)
            obj = getattr(m, name)
            if attr and not hasattr(obj, attr):
                raise AttributeError(attr)
        except Exception as e:  # ImportError / AttributeError = 옛 파일이 남아 있음 (exe 면 = exe 에 모듈이 안 들어감)
            problems.append(f"{mod}.{name}{'.' + attr if attr else ''} 없음 ({type(e).__name__}: {e}) — "
                            + ("exe 에 이 모듈이 안 들어갔다 (packaging/build_exe.ps1 의 PYTHONPATH·--collect-submodules)" if FROZEN else "옛 파일이 남아 있음"))
    for rel in ("scripts/fuzz_scanner.py", "scripts/oracle_fuzz.py", "scripts/run_candidate_set.py", "tests/unit/test_fuzz.py", "policy/risk_rubric.json",
                "tests/fixtures/plan-pairs/README.md", "src/iacpatch/web/static/index.html"):
        if not (ROOT / rel).exists():
            problems.append(f"{rel} 없음")
    problems += _frozen_bundle_gaps()
    return problems


def _frozen_bundle_gaps() -> List[str]:
    """exe 안에서: 저장소 src/iacpatch 의 모든 모듈이 exe 에 들어갔는지 하나씩 import 해 본다 (스크립트는 --exec 로 exe 안에서 돌기 때문에
    빠진 모듈이 하나라도 있으면 그 단계가 죽는다). build-exe #2·#3 이 여기서 죽었다: --collect-submodules 가 src/ 를 못 봐 iacpatch.fuzz 가 빠짐."""
    if not FROZEN:
        return []
    pkg = ROOT / "src" / "iacpatch"
    if not pkg.is_dir():
        return []
    import importlib
    gaps: List[str] = []
    for py in sorted(pkg.rglob("*.py")):
        rel = py.relative_to(pkg.parent).with_suffix("")
        parts = list(rel.parts)
        if parts[-1] == "__main__":     # iacpatch/__main__.py 는 import 하면 CLI 가 실행된다
            continue
        if parts[-1] == "__init__":
            parts = parts[:-1]
        mod = ".".join(parts)
        try:
            importlib.import_module(mod)
        except Exception as e:
            gaps.append(f"exe 에 {mod} 없음 ({type(e).__name__}: {e})")
    return gaps


def _selfcheck_cli() -> int:
    """`--selfcheck`: 실행 환경(루트·exe 여부·임시 폴더·python)과 설치 상태 검사 결과를 찍는다. 문제 0건이면 0, 아니면 1. CI 스모크와 팀 PC 진단용."""
    print(f"root      : {ROOT}")
    print(f"frozen    : {FROZEN}" + (f"  (_MEIPASS={getattr(sys, '_MEIPASS', '')})" if FROZEN else ""))
    print(f"executable: {sys.executable}")
    print(f"python    : {platform.python_version()} {platform.system()} {platform.release()}")
    print(f"cwd       : {os.getcwd()}")
    for k, v in tool_status().items():
        print(f"{k:9s} : {v['version']}  ({v['bin']})" + ("" if v["ok"] else "  ← 없음"))
    probs = selfcheck()
    for pr in probs:
        print(f"selfcheck : {pr}")
    print("selfcheck : OK" if not probs else f"selfcheck : 문제 {len(probs)}건")
    return 0 if not probs else 1


STALE_HINT = "옛 파일과 새 파일이 섞여 있다. zip 을 기존 폴더에 덮어쓰지 말고 **빈 새 폴더**에 풀어서 거기서 실행할 것 (tools\\ 는 버튼으로 다시 받으면 됨)."
NOT_REPO_HINT = ("exe 는 저장소 파일(policy\\, scripts\\, experiments\\ 폴더)이 옆에 있는 곳에서 실행해야 한다. "
                 "아티팩트 zip 을 빈 새 폴더에 풀고, policy\\ 폴더가 보이는 그 자리의 IaCPatch.exe 를 더블클릭할 것 (exe 만 다른 곳으로 옮기면 안 됨. "
                 "zip 을 풀었는데 또 zip 이 보이면 그것도 풀 것).")


def install_hint() -> str:
    """설치 검사 실패 때 보여 줄 안내: 저장소 폴더 자체가 없으면 NOT_REPO_HINT, 있으면 옛/새 파일 섞임 안내."""
    return NOT_REPO_HINT if not (ROOT / "policy" / "patch_policy.json").exists() else STALE_HINT.replace("**", "")


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
        ("8/8 스캐너 사각 탐색 (변형 자동 생성 → Trivy vs 오라클)", _script_cmd("scripts/fuzz_scanner.py", *extra)),
        ("8/8 오라클 차등 검증 (무작위 20,000건)", _script_cmd("scripts/oracle_fuzz.py")),
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


def run_all(log: Callable[[str], None], progress: Callable[[int, int], None], report_only: bool = False, open_browser: bool = True, fresh: bool = False,
            report_out: Optional[Path] = None) -> Path:
    """실험 8단계 + 리포트. 각 단계의 출력은 log() 로 흘려보내고 experiments/run_experiments.log 에도 남긴다. report_out: 리포트 경로(기본 report/index.html)."""
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
        probs = selfcheck()
        if probs:
            log("설치 상태 검사 실패 — 실험을 돌리지 않는다:")
            for pr in probs:
                log(f"  - {pr}"); lf.write(f"selfcheck: {pr}\n")
            log(install_hint())
            raise RuntimeError("설치 상태 검사 실패 (위 목록). " + install_hint())
        log(f"설치 상태 검사 OK (python {platform.python_version()})")
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
        from iacpatch.report_html import build
        out = build(Path(report_out) if report_out else ROOT / "report" / "index.html")
        log(f"→ {out}"); lf.write(f"report: {out}\n")
        progress(total, total)
    if open_browser:
        try:
            webbrowser.open(out.as_uri())
        except Exception as e:  # pragma: no cover
            log(f"브라우저 열기 실패: {e} — 파일을 직접 열어라: {out}")
    return out


# --------------------------------------------------------------------------- 화면
TITLE = "AI가 생성한 테라폼 보안 패치의 실효성 검증 자동화 구현"


def gui(port: Optional[int] = None, open_browser: bool = True) -> int:
    """브라우저 화면: 로컬 웹 서버를 띄우고 기본 브라우저를 연다. 화면이 닫히면(heartbeat 끊김) 스스로 끝난다."""
    from iacpatch.web.server import serve
    return serve(port=port, open_browser=open_browser)


def console(report_only: bool, open_browser: bool, fresh: bool = False, report_out: Optional[Path] = None) -> int:
    def log(s: str) -> None:
        print(s, flush=True)
    def prog(i: int, n: int) -> None:
        pass
    out = run_all(log, prog, report_only=report_only, open_browser=open_browser, fresh=fresh, report_out=report_out)
    print(f"\n완료. 리포트: {out}")
    return 0


def _ensure_streams() -> None:
    """창 없는(windowed) exe 는 sys.stdout/stderr 가 None 이라 unittest·print 가 죽는다 → experiments/exe-console.log 로 보낸다."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    try:
        logp = ROOT / "experiments" / "exe-console.log"
        logp.parent.mkdir(parents=True, exist_ok=True)
        f = open(logp, "a", encoding="utf-8", buffering=1)
        f.write(f"\n==== {time.strftime('%Y-%m-%dT%H:%M:%S')} argv={sys.argv[1:]}\n")
    except OSError:
        import io
        f = io.StringIO()
    if sys.stdout is None:
        sys.stdout = f  # type: ignore[assignment]
    if sys.stderr is None:
        sys.stderr = f  # type: ignore[assignment]


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    _ensure_streams()
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    ensure_python(argv)     # 3.10 미만이면 설치된 3.10+ 로 다시 시작 (아래는 실행되지 않음)
    # 내부용: exe 가 자기 자신을 다시 띄워 스크립트/테스트를 돌릴 때 (PC 에 python 이 없어도 됨)
    if argv[:1] == ["--exec"] and len(argv) >= 2:
        return _exec_script(argv[1], argv[2:])
    if argv[:1] == ["--unittest"]:
        return _exec_unittest()
    if argv[:1] == ["--selfcheck"]:
        return _selfcheck_cli()
    ap = argparse.ArgumentParser(description="IaCPatch 실행기 (브라우저 화면 / 콘솔)")
    ap.add_argument("--console", action="store_true", help="화면 없이 콘솔로 실험 8단계 + 리포트")
    ap.add_argument("--report-only", action="store_true", help="(콘솔) 실험은 건너뛰고 리포트만")
    ap.add_argument("--no-open", action="store_true", help="브라우저를 열지 않음")
    ap.add_argument("--fresh", action="store_true", help="(콘솔) 이전 기록 재사용 없이 전부 다시 돌림")
    ap.add_argument("--port", type=int, default=None, help="화면 포트 (기본: 8765 부터 빈 포트)")
    ap.add_argument("--report-out", default=None, help="(콘솔) 리포트 파일 경로 (기본 report/index.html)")
    a = ap.parse_args(argv)
    if not a.console:
        return gui(port=a.port, open_browser=not a.no_open)
    return console(a.report_only, not a.no_open, fresh=a.fresh, report_out=Path(a.report_out) if a.report_out else None)


if __name__ == "__main__":
    sys.exit(main())
