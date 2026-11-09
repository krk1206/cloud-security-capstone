"""로컬 웹 서버 — 화면의 뒷단. 표준 라이브러리만 쓴다 (설치 0). 127.0.0.1 에서만 받는다.
Host 가 127.0.0.1·localhost 가 아니거나 POST 의 Origin 이 다른 사이트면 거절한다 (다른 웹 페이지가 버튼 API 를 부르지 못하게).

    python -m iacpatch.app                 # 서버 띄우고 브라우저 열기 (기본)
    python -m iacpatch.app --port 8765 --no-open

화면 API (사용자 작업 순서대로):
    GET  /api/app                         도구 상태(이 PC 에 Trivy·Terraform 이 있나), 제목
    GET  /api/cases                       사례 목록
    GET  /api/case?id=                    1. 요구사항 — 요구사항 문장, Trivy 가 찾은 것의 분류(검토 대상 / 판단 안 함), 아키텍처 요약
    GET  /api/case/current?id=            2. 현재 설정의 문제 — 원본 plan 에 요구사항 대입 (같은 오라클, 지금 계산)
    GET  /api/case/candidates?id=         3. 후보 비교 — 후보 목록 + 후보별 최신 기록 + 분류
    POST /api/review                      {"case_id","set_id","candidate_id" | "paste" | "upload":{"files":[{"path","content"}],"folder"} | "generator":"rule_based"}
    POST /api/review/prefetch             {"case_id","set_id"} — 보이는 수정안(featured) 미리 분석 (D-47)
                                          한 후보 검토 (작업). 제출 파일은 data/cache/submissions/ 에 따로 두고 그 사본으로 검사 (web/submission.py)
    POST /api/submission/check            {"set_id","files":[{"path","content"}],"folder"}  제출 파일 사전 확인 — 파일별 상태 · 이유 (실행 없음)
    POST /api/case/scan                   {"case_id"}  원본 점검 (Trivy · 오프라인 plan) → 사례의 점검 결과·원본 plan 저장 (작업)
    POST /api/review_all                  {"case_id","set_id"}                                                       세트의 후보 전부 차례로 (작업)
    GET  /api/record?id=                  4~6. 기록 하나의 화면용 묶음 (결론·요구사항 전/후·검증 표·위험도·정책·확인 목록·결정·배포 후)
    POST /api/decision                    {"record_id","decision","reason","by","base_branch"}  사람의 결정 기록 (승인은 통과한 후보만)
    GET  /api/records                     기록 전체 목록 (설정 화면)
    GET  /api/log?since=N  POST /api/heartbeat  POST /api/quit
    POST /api/job/setup_tools  POST /api/job/run_all  GET /report/      (설정 화면: 도구 설치, 실험 재현, 리포트)
    GET  /api/candidate/source?set_id=&id=  3단계 미리보기 — 대상 파일의 원본과 후보 파일 내용 (읽기만, id 없으면 원본만)
    GET  /api/job/progress                 검토 작업의 실제 진행 — 기록 폴더에 생긴 파일(Trivy 결과·plan)로 단계 완료를 판단
    GET  /static/<파일>                     화면 파일 (js·css·이미지). 이 폴더 밖은 읽지 않는다
    GET  /classic                          이전 화면 (보존)
  실제 AWS 검사 (실제 AWS 시험 환경 — 배포·삭제는 사람이 한다):
    GET  /api/measure/setup?id=            시험 환경 상태 (배포 여부·파일 지문·plan 확인 결과·버튼을 켤 수 있나)
    POST /api/testbed/use                  {"which":"original"|"candidate","record_id"}  시험 환경 파일 바꾸기 (파일 복사만)
    POST /api/plan_check                   {"record_id","profile"}  plan 확인 — 실제 상태 기준 terraform plan (읽기 전용, 작업)
    POST /api/measure                      {"record_id"?,"profile","region"}  V7·V8 측정 (AWS 읽기·접속 시험만, 작업)
    POST /api/testbed/prepare              {"kind":"apply_original"|"destroy","profile"}  반영 1단계 — plan 만 만들어 보관 (작업)
    POST /api/testbed/execute              {"plan_id","confirm":"apply"|"destroy","profile"}  반영 2단계 — 사람이 확인 창에서 누른 요청만,
                                           보관한 plan 파일 그대로 terraform apply (시험 환경 폴더만, 작업). testbed_ops.py · DECISIONS D-19

이전 API(/api/state, /api/week4/*, /api/week5/*)는 호환을 위해 남겨 둔다 — 새 화면은 쓰지 않는다.
하지 않는 것: LLM API 호출, git push, PR 생성, 사람 확인 없는 terraform apply / destroy, 시험 환경 밖 AWS 변경.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import platform
import re
import socket
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .. import app as _app
from . import explain

def _static_dir() -> Path:
    """index.html 위치. 보통 이 파일 옆의 static/. PyInstaller onefile 이면 _MEIPASS 아래(--add-data), 그것도 없으면 저장소 소스."""
    cands = [Path(__file__).resolve().parent / "static"]
    mp = getattr(sys, "_MEIPASS", "")
    if mp:
        cands.append(Path(mp) / "iacpatch" / "web" / "static")
    cands.append(_app.ROOT / "src" / "iacpatch" / "web" / "static")
    for c in cands:
        if (c / "index.html").exists():
            return c
    return cands[0]


STATIC = _static_dir()
IDLE_EXIT_SECONDS = 180          # 화면(heartbeat)이 이만큼 조용하면 서버 종료 (브라우저를 닫은 뒤 프로세스가 남지 않게). 작업 중엔 안 끔


class _ProcLock:
    """다른 IaCPatch 창(다른 프로세스)과 검사·측정이 겹치지 않게 하는 파일 잠금.
    같은 도구(terraform·trivy)와 provider 캐시를 두 창이 동시에 쓰면 provider 실행 파일이 깨져 검사가 잘못 실패한다 (2026-10-23 실측)."""

    def __init__(self, path_fn: Callable[[], Path]) -> None:
        self.path_fn = path_fn
        self.fh: Any = None

    def acquire(self) -> bool:
        try:
            p = self.path_fn()
            p.parent.mkdir(parents=True, exist_ok=True)
            fh = open(p, "a+")
        except OSError:
            return True                     # 잠금 파일을 못 만들면 예전처럼 막지 않는다
        try:
            if os.name == "nt":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            return False
        self.fh = fh
        return True

    def release(self) -> None:
        fh, self.fh = self.fh, None
        if fh is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        fh.close()


def _job_lock_path() -> Path:
    return _root() / "data" / ".job.lock"


class Job:
    """한 번에 하나만 도는 작업 + 로그 버퍼. 다른 IaCPatch 창과도 겹치지 않는다 (_ProcLock)."""

    def __init__(self) -> None:
        self.plock = _ProcLock(_job_lock_path)
        self.busy_other = False             # 마지막 start 가 다른 창 때문에 거절됐는지
        self.lock = threading.Lock()
        self.name = ""
        self.running = False
        self.log: List[str] = []
        self.progress = (0, 0)
        self.started = 0.0
        self.finished = 0.0
        self.error = ""
        self.result: Any = None
        self.thread: Optional[threading.Thread] = None

    def start(self, name: str, fn: Callable[[Callable[[str], None], Callable[[int, int], None]], Any]) -> bool:
        with self.lock:
            if self.running:
                return False
            if not self.plock.acquire():
                self.busy_other = True
                return False
            self.busy_other = False
            self.name, self.running, self.log, self.progress = name, True, [], (0, 0)
            self.started, self.finished, self.error, self.result = time.time(), 0.0, "", None

        def logf(line: str) -> None:
            with self.lock:
                self.log.append(line)

        def prog(i: int, n: int) -> None:
            with self.lock:
                self.progress = (i, n)

        def run() -> None:
            try:
                res = fn(logf, prog)
                with self.lock:
                    self.result = res
            except Exception as e:  # 작업 실패는 로그와 error 에 남기고 서버는 계속
                with self.lock:
                    self.error = f"{type(e).__name__}: {e}"
                    self.log.append(f"오류: {type(e).__name__}: {e}")
                    self.log.extend(traceback.format_exc().splitlines()[-6:])
            finally:
                with self.lock:
                    self.running, self.finished = False, time.time()
                    self.plock.release()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        return True

    def snapshot(self, since: int = 0) -> Dict[str, Any]:
        with self.lock:
            return {"name": self.name, "running": self.running, "progress": list(self.progress), "started": self.started,
                    "finished": self.finished, "error": self.error, "result": self.result if isinstance(self.result, (str, int, float, dict, list, type(None))) else str(self.result),
                    "log_total": len(self.log), "log": self.log[since:]}


JOB = Job()
_STATE: Dict[str, Any] = {"last_heartbeat": 0.0, "quit": False, "cache": {}}


# ----------------------------------------------------------------------------- 자료 조회
def _root() -> Path:
    return _app.ROOT


def reviews_root() -> Path:
    """화면에서 돌린 기록의 위치. 기본 data/reviews (실험 기록과 같은 곳, 시나리오 이름에 ui/ 접두어). 테스트는 IACPATCH_REVIEWS_DIR 로 임시 폴더를 준다."""
    env = os.environ.get("IACPATCH_REVIEWS_DIR")
    return Path(env) if env else _root() / "data" / "reviews"


def _build_info() -> Dict[str, Any]:
    try:
        from .. import update as up
        return up.build_info()
    except Exception as e:  # 화면이 죽지 않게
        return {"sha": None, "error": str(e)}


def state_payload() -> Dict[str, Any]:
    root = _root()
    report = root / "report" / "index.html"
    summary = None
    if report.exists():
        try:
            from ..report_html import summarize
            s = summarize()
            summary = {k: v for k, v in s.items() if k in ("funnel", "levels", "spof_total", "label_agree", "label_total", "not_run_total", "n_llm",
                                                                "aws_runs", "blind_sg", "blind_iam", "fuzz", "oracle_fuzz", "rows_total", "latest_total")}
            summary["stops"] = dict(s.get("stops") or {})
        except Exception as e:  # 집계 실패는 화면에 그대로
            summary = {"error": str(e)}
    return {
        "root": str(root), "python": platform.python_version(), "host": platform.node(), "os": platform.system(), "frozen": _app.FROZEN, "build": _build_info(),
        "title": _app.TITLE, "tools": _app.tool_status(), "selfcheck": _app.selfcheck(), "stale_hint": _app.install_hint(),
        "report_exists": report.exists(), "report_mtime": report.stat().st_mtime if report.exists() else None,
        "cc_candidates": _app.has_cc_candidates(), "steps": [t for t, _ in _app.steps(_app.has_cc_candidates())],
        "summary": summary, "job": JOB.snapshot(10**9),
    }


def _manifests() -> List[Dict[str, Any]]:
    root = _root()
    out = []
    for m in sorted((root / "experiments" / "candidate-sets").glob("*/manifest.json")):
        try:
            man = json.loads(m.read_text(encoding="utf-8"))
        except ValueError:
            continue
        cands = []
        for c in man.get("candidates") or []:
            cands.append({"id": c.get("id"), "candidate": c.get("candidate"), "expected": c.get("expected"), "expected_risk": c.get("expected_risk"),
                          "source": c.get("source"), "note": c.get("note", ""), "tf_dir": c.get("tf_dir") or man.get("tf_dir"),
                          "intent": c.get("intent") or man.get("intent"), "rule": c.get("rule") or man.get("rule")})
        out.append({"set_id": man.get("set_id") or m.parent.name, "note": man.get("_note", ""), "tf_dir": man.get("tf_dir"), "intent": man.get("intent"),
                    "rule": man.get("rule"), "resource": man.get("resource"), "local_tools": man.get("local_tools", False), "candidates": cands, "path": str(m.relative_to(root))})
    return out


def _latest_records(limit: int = 80) -> List[Dict[str, Any]]:
    reviews = reviews_root()
    rows = []
    if not reviews.is_dir():
        return rows
    for d in sorted(reviews.iterdir(), reverse=True):
        st = d / "state.json"
        if not st.exists():
            continue
        try:
            s = json.loads(st.read_text(encoding="utf-8"))
        except ValueError:
            continue
        rows.append({"id": d.name, "scenario": s.get("scenario"), "state": s.get("state"), "level": s.get("review_level"),
                     "verification": s.get("verification_status"), "started": s.get("started_at"), "origin": s.get("candidate_origin"),
                     "generator": s.get("candidate_generator")})
        if len(rows) >= limit:
            break
    return rows


def _read(p: Path, limit: int = 200_000) -> str:
    try:
        return p.read_text(encoding="utf-8")[:limit]
    except OSError:
        return ""


def record_detail(rid: str) -> Dict[str, Any]:
    d = reviews_root() / rid
    if ".." in rid or "/" in rid or "\\" in rid or not d.is_dir():
        return {"error": f"기록 없음: {rid}"}
    out: Dict[str, Any] = {"id": rid}
    for name in ("state.json", "policy.json", "risk.json", "candidate.json"):
        if (d / name).exists():
            try:
                out[name.split(".")[0]] = json.loads(_read(d / name))
            except ValueError:
                out[name.split(".")[0]] = {"error": "json 파싱 실패"}
    if (d / "verification.json").exists():
        try:
            v = json.loads(_read(d / "verification.json"))
            rep = v.get("report") or {}
            out["verification"] = {"validity": rep.get("validity"), "summary": rep.get("summary"), "layers": rep.get("layers") or [],
                                   "notes": v.get("notes") or [], "source": v.get("source")}
        except ValueError:
            out["verification"] = {"error": "json 파싱 실패"}
    for name in ("candidate.diff", "review.md", "pr_body.md", "pr_commands.sh"):
        if (d / name).exists():
            out[name.replace(".", "_")] = _read(d / name, 60_000)
    if "candidate" in out and isinstance(out["candidate"], dict):
        out["candidate"].pop("files", None)     # 파일 본문은 diff 로 충분
    lv = d / "local_verify"
    if (lv / "tools.json").exists():
        try:
            out["tools"] = json.loads(_read(lv / "tools.json"))
        except ValueError:
            pass
    return out


# ----------------------------------------------------------------------------- 작업
def job_run_all(fresh: bool, report_only: bool) -> Callable:
    def fn(log, prog):
        out = _app.run_all(log, prog, report_only=report_only, open_browser=False, fresh=fresh)
        return str(out)
    return fn


def job_setup_tools() -> Callable:
    import subprocess
    from ..tools.runner import no_console_window
    win = platform.system() == "Windows"
    root = _root()
    script = root / "scripts" / ("setup_tools.ps1" if win else "setup_tools.sh")
    argv = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)] if win else ["bash", str(script)]

    def fn(log, prog):
        if not script.exists():
            log(f"설치 스크립트 없음: {script}")
            log(_app.install_hint())
            return {"rc": 2, "tools": _app.tool_status()}
        log(f"도구 설치: {' '.join(argv)}")
        # 출력은 바이트로 받아 UTF-8 → (Windows) 콘솔 코드페이지 순으로 푼다. PowerShell 의 한글 오류가 cp949 라 utf-8 로만 읽으면 깨진다 (팀 PC 실측 09-28)
        p = subprocess.Popen(argv, cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **no_console_window())
        assert p.stdout is not None
        for raw in p.stdout:
            log(decode_console(raw).rstrip("\r\n"))
        rc = p.wait()
        log(f"종료 코드 {rc}" + ("" if rc == 0 else " — 실패. 위 메시지 확인 필요 (인터넷 연결, 압축 해제 권한, 폴더 위치)"))
        return {"rc": rc, "tools": _app.tool_status()}
    return fn


def decode_console(raw: bytes) -> str:
    """자식 프로세스 출력 한 줄을 문자열로. UTF-8 이 아니면 Windows 의 ANSI 코드페이지(cp949 등, 'mbcs'), 그것도 아니면 대체 문자."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if platform.system() == "Windows":
        try:
            return raw.decode("mbcs")
        except (UnicodeDecodeError, LookupError):
            pass
    return raw.decode("utf-8", errors="replace")


def job_update() -> Callable:
    """새 빌드 받기 (GitHub Release dev-latest → 옆 폴더 → tools/data 복사 → 새 exe 실행). 네트워크는 github.com 만."""
    from .. import update as up
    from ..config import load_settings
    root = _root()
    url = os.environ.get("IACPATCH_UPDATE_URL") or load_settings(str(root)).extra.get("update_url") or up.DEFAULT_UPDATE_URL

    def fn(log, prog):
        res = up.install(root, url, log=log)
        if res.get("launched"):
            _STATE["quit_after"] = time.time() + 20   # 새 exe 가 떴으니 이 서버는 잠시 뒤 스스로 끝난다
        return res
    return fn


def job_case_scan(case_id: str) -> Callable:
    """원본 점검: 사례의 Terraform 폴더를 이 PC 의 Terraform(오프라인 plan)·Trivy 로 점검하고, 화면이 쓰는 두 파일을 저장한다.
    - Trivy 결과 → 사례의 trivy_json (1단계 '점검 도구가 찾은 것', 검토 흐름의 대상 지적)
    - 원본 plan  → data/cache/baseline/scan-<사례>/plan_baseline.json (2단계 '현재 구조 검사')
    AWS 접속·apply 없음 (archscan.run_scan 과 같은 동작)."""
    from . import cases as cs
    from ..archscan import run_scan
    case = cs.get_case(case_id)
    if case is None:
        raise ValueError(f"사례 없음: {case_id}")

    def run(log: Callable[[str], None], prog: Callable[[int, int], None]) -> Dict[str, Any]:
        import shutil
        root = _root()
        out = root / "data" / "arch" / time.strftime("%Y%m%d-%H%M%S-scan")
        res = run_scan(root / case["tf_dir"], out, root, do_plan=True, log=log)
        saved: Dict[str, str] = {}
        if (out / "trivy.json").exists() and (res.get("scan") or {}).get("status") == "PASS":
            dst = root / case["trivy_json"]
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(out / "trivy.json", dst)
            saved["trivy"] = str(dst.relative_to(root))
            log(f"원본 점검 결과 저장: {saved['trivy']}")
        if (out / "plan.json").exists():
            cdir = root / "data" / "cache" / "baseline" / f"scan-{case_id}"
            cdir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(out / "plan.json", cdir / "plan_baseline.json")
            (cdir / "meta.json").write_text(json.dumps({"tf_dir": case["tf_dir"], "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                                        "source": f"원본 점검 {out.name}"}, ensure_ascii=False, indent=2), encoding="utf-8")
            saved["plan"] = str((cdir / "plan_baseline.json").relative_to(root))
            log(f"원본 plan 저장: {saved['plan']}")
        return {"scan_dir": str(out.relative_to(root)), "saved": saved, "plan": (res.get("plan") or {}).get("status"),
                "scan": (res.get("scan") or {}).get("status")}
    return run


def job_candidate(req: Dict[str, Any]) -> Callable:
    """한 후보 검토 흐름 (5주차): 세트의 후보 / 붙여넣은 후보 / 규칙 기반 생성. 도구가 있으면 V1~V4 도 실행. AWS·LLM 호출 없음."""
    from ..config import load_settings
    from ..review.flow import ReviewOptions, run_review
    from ..rubric_demo import _resolve
    root = _root()
    set_id = str(req.get("set_id") or "")
    cid = str(req.get("candidate_id") or "")
    paste = req.get("paste")
    upload = req.get("upload")
    generator = req.get("generator")
    submission = None
    from .cases import _manifest_path
    mpath = _manifest_path(set_id)
    if not mpath.exists():
        raise ValueError(f"세트 없음: {set_id}")
    man = json.loads(mpath.read_text(encoding="utf-8"))
    from .projects import set_problem
    why = set_problem(man)
    if why:
        raise ValueError(why)
    set_dir = mpath.parent
    cands = {c["id"]: c for c in man.get("candidates") or []}
    c = cands.get(cid, {}) if cid else {}

    def pick(key, default=None):
        return c[key] if key in c else man.get(key, default)

    tf_dir = pick("tf_dir")
    from .cases import display_labels, label_for
    labels = display_labels(set_id, man)
    if upload:
        # 제출한 파일 여러 개 · 폴더 (web/submission.py). 저장소 원본 폴더가 아니라 data/cache/submissions/ 에 따로 두고 그 사본으로 검사
        from .submission import analyze, store
        res = analyze(root / str(tf_dir), (upload or {}).get("files") if isinstance(upload, dict) else None,
                      bool((upload or {}).get("folder")) if isinstance(upload, dict) else False)
        if not res.get("ok"):
            raise ValueError(res.get("error") or "제출 파일 확인 실패")
        d = store(root, res, set_id)
        cand = f"manual:{d / 'files'}"
        scenario = f"ui/{set_id}/upload-{d.name}"
        note = f"화면에서 제출한 파일 {len(res['candidate_files'])}개 (직접 제출 — 사람 작성 · AI 출력 모두 가능, 프로그램 자동 생성 아님)"
        label = label_for(set_id, "upload", time.strftime("%Y-%m-%dT%H:%M"))
        submission = {"kind": "upload", "files": res["files"], "summary": res.get("summary", ""), "stored": d.relative_to(root).as_posix()}
    elif paste:
        # 붙여넣은 내용 = 대상 finding 이 가리키는 파일의 전체 내용 (manual:<file.tf>)
        tmpd = root / "data" / "cache" / "paste"
        tmpd.mkdir(parents=True, exist_ok=True)
        pth = tmpd / f"paste-{int(time.time())}.tf"
        pth.write_text(str(paste), encoding="utf-8")
        cand = f"manual:{pth}"
        scenario = f"ui/{set_id}/paste-{pth.stem.split('-')[-1]}"
        note = "화면에서 직접 붙여넣은 후보 (직접 제출 — 사람 또는 Claude Code 세션 출력, 프로그램 자동 생성 아님)"
        label = label_for(set_id, "paste", time.strftime("%Y-%m-%dT%H:%M"))
    elif generator == "rule_based":
        cand = "rule_based"
        scenario = f"ui/{set_id}/{cid or 'rule-based'}-rb"
        # 후보 id 없이 부르면 ⑤ '설계도대로 자동 수정' (D-45): 승인 출처 = 지금 기준 설계도(③)의 외부 출발 화살표. LLM 아님
        note = "규칙 기반 생성기 (LLM 아님)" if cid else "규칙 기반 생성기 (LLM 아님) — 설계도(③)에서 외부 → 이 계층으로 그린 통신의 IP 대역을 허용 목록으로 씀"
        label = label_for(set_id, f"{cid or 'rule-based'}-rb", labels=labels)
    else:
        if not c:
            raise ValueError(f"후보 없음: {set_id}/{cid}")
        cand = c["candidate"]
        if cand.startswith("manual:"):
            cand = "manual:" + str(_resolve(cand[7:], set_dir))
        scenario = f"ui/{set_id}/{cid}"          # ui/ 접두어: 실험 세트의 최신 기록(리포트 집계)을 덮지 않는다
        note = c.get("note", "")
        label = labels.get(cid, cid)
    # 설계 기준 (D-30): 후보에 따로 정한 것이 없으면 '지금 기준' 설계도 (화면에서 고친 버전 포함). design_version 을 주면 그 버전으로
    from . import designs
    if c.get("intent"):
        intent_p = _resolve(c.get("intent"), set_dir)
    else:
        dv = req.get("design_version")
        intent_p = designs.path_for(set_id, int(dv)) if dv not in (None, "") else designs.active_path(set_id)
        if intent_p is None:
            if dv not in (None, ""):
                raise ValueError(f"설계도 버전 없음: v{dv}")
            intent_p = _resolve(man.get("intent"), set_dir)
    opt = ReviewOptions(tf_dir=tf_dir, trivy_json=_resolve(pick("trivy_json"), set_dir), candidate=cand, scenario=scenario,
                        rule=pick("rule", "AVD-AWS-0107"), filename=pick("file"), resource=pick("resource"), line=pick("line"),
                        candidate_note=note, verification=None, baseline_plan=_resolve(pick("baseline_plan"), set_dir),
                        candidate_plan=_resolve(c.get("candidate_plan"), set_dir), intent=intent_p,
                        out_dir=str(reviews_root()), local_tools=True, fresh_baseline=bool(req.get("fresh_baseline")),
                        display_name=label, submission=submission,
                        design_meta=(designs.confirmation(set_id, int(dv)) if dv not in (None, "") else designs.confirmation(set_id)) if not c.get("intent") else None)

    def fn(log, prog):
        env = _app._env()
        os.environ.update({k: env[k] for k in ("TRIVY_BIN", "TERRAFORM_BIN", "TRIVY_SKIP_CHECK_UPDATE", "TRIVY_SKIP_VERSION_CHECK", "TF_PLUGIN_CACHE_DIR") if k in env})
        s = load_settings(str(root))
        ts = _app.tool_status()
        for k, v in ts.items():
            log(f"{k}: {v['version'] if v['ok'] else '없음 → 해당 단계 미실행 (NOT_RUN)'}")
        log(f"후보 {label} · 원본 {tf_dir}")      # 후보 id·파일 이름은 기대 결과를 드러낼 수 있어 로그에 쓰지 않는다 (피드백 7)
        from .proof_api import attach_calibration, ensure_calibration
        cal = None
        try:
            cal = ensure_calibration(s, root / str(tf_dir), log)
        except Exception as e:  # 점검 실패는 검사를 막지 않되 기록에 남긴다
            log(f"검증 도구 사전 점검 실패: {type(e).__name__}: {e}")
        prog(1, 3)
        res = run_review(s, opt)
        if cal is not None and (reviews_root() / res.run_id).is_dir():
            try:
                attach_calibration(reviews_root() / res.run_id, cal)
            except OSError as e:
                log(f"사전 점검 결과 기록 첨부 실패: {e}")
        prog(2, 3)
        for line in res.console().splitlines():
            log(line)
        prog(3, 3)
        return {"record_id": res.run_id, "label": label, "state": res.state.value, "level": res.level.value if res.level else None,
                "risk": res.risk.risk_level.value if res.risk else None, "message": res.message}
    return fn


def needs_analysis(c: Dict[str, Any], st: Dict[str, Any]) -> bool:
    """이 수정안을 지금 기준으로 (다시) 검사해야 하나 — 기록 없음 · 설계도 파일이 바뀜 · 초안 기준 기록인데 지금은 확정됨."""
    l = c.get("latest") or {}
    if not l:
        return True
    cur = st.get("design_sha256")
    rec = l.get("design") or {}
    if cur and rec.get("sha256") and rec["sha256"] != cur:
        return True
    conf = st.get("design_confirmation") or {}
    if conf.get("confirmed") and rec and rec.get("confirmed") is False:
        return True
    return False


def job_prefetch(req: Dict[str, Any]) -> Callable:
    """⑤ 미리 분석 (D-47, B 2026-11-03 "누르면 설계도가 바뀌게"): 화면에 보이는 수정안(featured) 가운데 지금 기준으로 검사한 기록이 없는 것을
    차례로 검사해 둔다 — 그래야 수정안을 누르는 즉시 '적용 후' 그림이 바뀐다. 검사 내용 · 판정 · 승인 규칙은 사람이 하나씩 눌렀을 때와 같다
    (같은 job_candidate). 설계도가 초안이면 돌리지 않는다 (확정 전 기준 기록만 쌓이므로)."""
    from . import cases as cs
    case_id = str(req.get("case_id") or "")
    set_id = str(req.get("set_id") or "")
    data = cs.candidates(case_id)
    if data.get("error"):
        raise ValueError(data["error"])
    st = next((x for x in data.get("sets") or [] if x.get("set_id") == set_id), None)
    if st is None:
        raise ValueError(f"세트 없음: {set_id}")
    conf = st.get("design_confirmation") or {}
    if conf and not conf.get("confirmed"):
        raise ValueError("설계도가 아직 초안 — ③ 에서 확정한 뒤에 미리 분석")
    order = {cid: i for i, cid in enumerate(st.get("featured") or [])}
    todo = sorted([c for c in st.get("candidates") or [] if c.get("featured") and needs_analysis(c, st)], key=lambda c: order.get(c["id"], 99))   # 화면 번호 순서 (1번부터)
    jobs = [(c["id"], c["label"], job_candidate({"case_id": case_id, "set_id": set_id, "candidate_id": c["id"]})) for c in todo]

    def fn(log: Callable[[str], None], prog: Callable[[int, int], None]) -> Dict[str, Any]:
        n = len(jobs)
        results = []
        if not n:
            log("미리 분석할 수정안 없음 — 모두 지금 기준 기록이 있음")
        for i, (cid, label, f) in enumerate(jobs, 1):
            prog(i - 1, n)
            log(f"미리 분석 {i}/{n}: {label}")
            try:
                r = f(lambda line: log(f"  {line}"), lambda _a, _b: None)
                results.append({"id": cid, "label": label, "record_id": r.get("record_id"), "state": r.get("state")})
            except Exception as e:  # noqa: BLE001 — 하나가 실패해도 나머지는 돈다, 실패는 기록
                log(f"  실패: {type(e).__name__}: {e}")
                results.append({"id": cid, "label": label, "error": f"{type(e).__name__}: {e}"})
        prog(n, n)
        return {"n": n, "results": results}
    return fn


def job_llm_fix(req: Dict[str, Any]) -> Callable:
    """AI 수정 (D-27): Claude Code(구독)에게 수정안을 받아 8개 관문에 통과시키고, 막히면 이유를 붙여 다시 요청 (최대 3번).
    AI 는 도구 없이 글만 만든다 (llmfix.NO_TOOLS) · 빈 폴더에서 실행 · API 키 · AWS 자격증명 제거. apply · 승인은 하지 않는다."""
    from .. import llmfix
    from . import designs
    set_id = str(req.get("set_id") or "")
    from .cases import _manifest_path
    if not designs.SET_RE.match(set_id) or not _manifest_path(set_id).exists():
        raise ValueError(f"세트 없음: {set_id}")
    from .projects import set_problem
    why = set_problem(json.loads(_manifest_path(set_id).read_text(encoding="utf-8")))
    if why:
        raise ValueError(why)
    context = "design" if str(req.get("context") or "") == "design" else "trivy"
    n = max(1, min(int(req.get("max_attempts") or llmfix.MAX_ATTEMPTS), llmfix.MAX_ATTEMPTS))

    def fn(log, prog):
        env = _app._env()
        os.environ.update({k: env[k] for k in ("TRIVY_BIN", "TERRAFORM_BIN", "TRIVY_SKIP_CHECK_UPDATE", "TRIVY_SKIP_VERSION_CHECK", "TF_PLUGIN_CACHE_DIR") if k in env})
        st = llmfix.claude_status(refresh=True)
        log(f"Claude Code: {st.get('version') or '없음'} · 로그인: {'됨' if st.get('logged_in') else '안 됨' if st.get('logged_in') is False else '확인 불가'}"
            + (f" ({st.get('auth_method')})" if st.get("auth_method") else ""))
        if not st.get("found"):
            raise RuntimeError(st.get("note") or "Claude Code 없음")
        has_design = designs.active_path(set_id) is not None
        log(f"AI 에게 주는 정보: {'Trivy 결과 + 고객 설계도' if context == 'design' and has_design else 'Trivy 결과'} · 최대 {n}번 · "
            + (f"설계도 v{designs.active_version(set_id)}" if has_design else "고객 설계도 없음 (고객 구조 검사 V6 는 판정 불가)"))
        rec = llmfix.run_fix(_root(), set_id, context, n, log, reviews_dir=reviews_root(), prog=prog)
        return {"run_id": rec["run_id"], "status": rec["status"], "record_id": rec.get("final_record_id"), "attempts": len(rec.get("attempts") or []),
                "error": rec.get("error")}
    return fn


def job_pr_create(record_id: str, base_branch: str = "main") -> Callable:
    """승인된 기록 → 이 PC 의 git · GitHub 로그인으로 브랜치 · 커밋 · push · PR 생성 (tools/github.prepare_pr execute=True).
    사람이 화면에서 확인 문구를 넣고 누른 요청으로만 시작한다. 사람의 결정이 승인(APPROVED)이고 승인 조건이 지금도 맞는 기록만 (여기서 거른다).
    병합은 하지 않는다."""
    from ..config import load_settings
    from ..tools.github import prepare_pr
    from .decision import can_approve, load_decision
    d0 = reviews_root() / record_id
    dec = load_decision(d0) or {}
    if dec.get("decision") != "APPROVED":
        raise ValueError("승인(APPROVED) 결정이 기록된 후보만 PR 을 만들 수 있음")
    ok, why = can_approve(_read_json_file(d0 / "state.json"), bool(dec.get("aws_unverified_ack")))
    if not ok:
        raise ValueError(f"승인 조건이 맞지 않음: {why}")
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", base_branch or "") or ".." in base_branch:
        raise ValueError("기준 브랜치 이름 형식이 아님")

    def fn(log, prog):
        s = load_settings(str(_root()))
        d = reviews_root() / record_id
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = prepare_pr(s, None, execute=True, base_branch=base_branch, review_id=str(d), header=closing_markdown(record_id))
        for line in buf.getvalue().splitlines():
            log(line)
        if rc != 0:
            raise RuntimeError(f"PR 만들기 실패 (rc={rc}) — 위 기록 확인")
        return {"rc": rc, "record_id": record_id, "output": buf.getvalue()[-4000:]}
    return fn


def _read_json_file(p: Path) -> Dict[str, Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def pr_check(record_id: str, base_branch: str = "main") -> Dict[str, Any]:
    """PR 만들기 전 확인 (읽기만 — fetch · commit · push 없음): 승인 기록인가 + 이 PC 의 git 상태 (tools/github.pr_readiness)."""
    from ..config import load_settings
    from ..tools.github import pr_readiness
    from .decision import load_decision
    if not record_id or ".." in record_id or "/" in record_id or "\\" in record_id or not (reviews_root() / record_id).is_dir():
        return {"ok": False, "error": "기록 없음"}
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", base_branch or "") or ".." in base_branch:
        return {"ok": False, "error": "기준 브랜치 이름 형식이 아님"}
    d = reviews_root() / record_id
    approved = (load_decision(d) or {}).get("decision") == "APPROVED"
    r = pr_readiness(load_settings(str(_root())), str(d), base_branch=base_branch)
    r["checks"] = [{"name": "사람의 승인", "ok": approved, "detail": "승인(APPROVED) 기록됨" if approved else "승인 기록 없음", "todo": "" if approved else "⑧ 에서 승인 기록"}] + list(r.get("checks") or [])
    r["ok"] = bool(r.get("ok")) and approved
    return r


def pr_preview(record_id: str, base_branch: str = "main") -> Dict[str, Any]:
    """`iacpatch pr --review <id>` 미리보기와 같음. push·PR 생성은 하지 않는다 (execute=False 고정)."""
    from ..config import load_settings
    from ..tools.github import prepare_pr
    root = _root()
    if not record_id or ".." in record_id or "/" in record_id:
        return {"error": "record_id"}
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", base_branch or "") or ".." in base_branch:
        return {"error": "기준 브랜치 이름 형식이 아님"}
    s = load_settings(str(root))
    d = reviews_root() / record_id
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = prepare_pr(s, None, execute=False, base_branch=base_branch, review_id=str(d) if d.is_dir() else record_id, header=closing_markdown(record_id))
    body = d / ("pr_body_final.md" if (d / "pr_body_final.md").exists() else "pr_body.md")   # 실제 AWS 미검증 문구 · 끝맺음 세 줄이 붙은 본문
    return {"rc": rc, "output": buf.getvalue(), "pr_body": _read(body, 60_000), "commands": _read(d / "pr_commands.sh", 20_000),
            "note": "미리보기 전용 (아무것도 실행 안 함). 실행은 화면의 'PR 만들기'(사람이 확인 문구 입력) 또는 사람이 pr_commands.sh 를 검토 후 직접 (D-5 · D-31)."}



def closing_markdown(record_id: str) -> str:
    """PR 본문 맨 위에 붙는 '끝맺음 세 줄' (product._closing — 확인한 것 · 결정 · 남은 것, D-42). 못 만들면 빈 글 (PR 은 그대로)."""
    try:
        from .product import final_view
        f = final_view(record_id)
        c = f.get("closing") if f.get("ok") else None
        if not c:
            return ""
        left = "".join(f"\n  - {x}" for x in (c.get("left") or [])) or " 없음"
        from .request import markdown as request_md            # 가상 고객 요청서의 조건마다 결과 (D-50) — 없으면 빈 글
        req = request_md(f.get("request"))
        return (f"## IaCPatch 기록 {record_id} — 끝맺음\n- 확인한 것: {c.get('checked')}\n- 결정: {c.get('decided')}\n- 남은 것:{left}\n"
                f"- 이 PR 은 사람이 승인 조건을 확인하고 만든 것이며, 병합 · apply 는 하지 않았습니다." + (f"\n\n{req}" if req else ""))
    except Exception:
        return ""


# ----------------------------------------------------------------------------- 새 화면용 묶음
def app_payload() -> Dict[str, Any]:
    tools = _app.tool_status()
    probs = _app.selfcheck()
    from ..version import provenance, short
    prov = provenance(_root(), tools)          # 프로그램 판 · 커밋 · 소스 지문 · 정책 판 (D-37) — ① 준비 상태 · ⑧ 에 표시
    return {"title": _app.TITLE, "product": "IaCPatch", "tools": tools, "tools_ok": all(v.get("ok") for v in tools.values()),
            "selfcheck_ok": not probs, "selfcheck": probs, "hint": _app.install_hint() if probs else "",
            "python": platform.python_version(), "frozen": _app.FROZEN, "job": JOB.snapshot(10**9),
            "provenance": prov, "version_line": short(prov),
            "does_not": ["유료 LLM API 호출 (AI 수정은 이 PC 의 Claude Code 구독으로, 사람이 누를 때만)", "시험 환경 밖 AWS 리소스 생성·변경·삭제",
                         "병합(merge) · 사람 확인 없는 git push · PR 생성 (PR 은 승인 뒤 사람이 확인 문구를 넣을 때만)",
                         "사람 확인 없는 terraform apply · destroy (시험 환경 반영은 확인 창에서 사람이 실행할 때만)"]}


def _record_files(d: Path) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name in ("state.json", "policy.json", "risk.json", "candidate.json", "verification.json", "decision.json"):
        p = d / name
        if p.exists():
            try:
                out[name.split(".")[0]] = json.loads(_read(p))
            except ValueError:
                out[name.split(".")[0]] = None
    for name in ("candidate.diff", "pr_body.md", "pr_commands.sh", "commit_message.txt", "review.md"):
        if (d / name).exists():
            out[name.replace(".", "_")] = _read(d / name, 60_000)
    sel = d / "input" / "selected_finding.json"
    if sel.exists():
        try:
            out["finding"] = json.loads(_read(sel))
        except ValueError:
            pass
    return out


def _set_for_scenario(scenario: str) -> tuple:
    """scenario 'ui/<set>/<cand>' 또는 '<set>/<cand>' → (case, set_info, candidate_id)."""
    from . import cases as cs
    parts = str(scenario or "").split("/")
    if parts and parts[0] == "ui":
        parts = parts[1:]
    set_id = parts[0] if parts else ""
    cid = "/".join(parts[1:]) if len(parts) > 1 else ""
    for case in cs.all_cases():
        for sref in case.get("sets", []):
            if sref["set_id"] == set_id:
                return case, cs.load_set(case, sref), cid
    return None, None, cid


def record_view(rid: str) -> Dict[str, Any]:
    """기록 하나를 4~6단계 화면이 쓰는 형태로. 판정 값은 기록에서 그대로 가져오고 문장만 만든다."""
    from . import cases as cs
    from .decision import can_approve
    d = reviews_root() / rid
    if ".." in rid or "/" in rid or "\\" in rid or not d.is_dir():
        return {"error": f"기록 없음: {rid}"}
    f = _record_files(d)
    st = f.get("state") or {}
    ver, risk, pol, cand = f.get("verification"), f.get("risk"), f.get("policy"), f.get("candidate")
    case, sinfo, cid = _set_for_scenario(st.get("scenario", ""))
    req_rows_after: List[Dict[str, Any]] = []
    req_rows_before: List[Dict[str, Any]] = []
    layers = ((ver or {}).get("report") or {}).get("layers") or []
    v6 = next((l for l in layers if l.get("layer") == "V6"), None)
    # 이 기록을 해석할 설계도 = 기록에 저장한 사본 (2026-10-31~). 사본이 없는 예전 기록만 지금 설계도로 해석한다.
    # 설계도가 바뀌어도 과거 결과를 새 설계도로 다시 판정하지 않는다 — 새 기준 결과가 필요하면 새로 검사한다.
    dview = design_view(st, sinfo)
    design_raw: Optional[Dict[str, Any]] = None
    rec_reqs = (sinfo or {}).get("requirements") or []
    rec_kind = (sinfo or {}).get("intent_kind")
    copy = d / "input" / "design.json"
    if copy.exists():
        from ..iam_intent import try_load_any_intent
        try:
            design_raw = json.loads(_read(copy))
        except ValueError:
            design_raw = None
        spec_rec, kind_rec, _err = try_load_any_intent(copy)
        if spec_rec is not None:
            rec_reqs, rec_kind = explain.requirements_for(kind_rec, spec_rec), kind_rec
    elif sinfo and sinfo.get("intent_path") and (_root() / sinfo["intent_path"]).exists():
        try:
            design_raw = json.loads(_read(_root() / sinfo["intent_path"]))
        except ValueError:
            design_raw = None
    if sinfo and (sinfo.get("intent") is not None or rec_reqs):
        if v6 and isinstance(v6.get("details"), dict) and v6.get("verdict") not in ("NOT_RUN", "SKIPPED") and v6["details"]:
            req_rows_after = explain.oracle_rows(rec_kind, v6["details"], rec_reqs)
        else:
            for r in rec_reqs:
                req_rows_after.append({**r, "verdict": "UNKNOWN", "status_ko": "판정 불가", "where": [], "effective": [], "excess": [], "evidence": [],
                                       "reasons": [(v6 or {}).get("summary") or "요구사항 검증(V6) 미실행"]})
        if case and dview.get("same_as_current") is not False:     # 다른 설계도로 계산한 '수정 전' 과 섞지 않는다
            cur = cs.current_state(case["id"])
            for s in cur.get("sets", []):
                if s.get("set_id") == sinfo["set_id"]:
                    req_rows_before = s.get("rows", [])
    before_by = {r["id"]: r for r in req_rows_before}
    requirements = []
    for r in req_rows_after:
        b = before_by.get(r["id"])
        requirements.append({"id": r["id"], "kind": r["kind"], "text": r["text"], "label": r.get("label"),
                             "before": {"verdict": b["verdict"], "status_ko": b["status_ko"], "effective": b.get("effective", []), "reasons": b.get("reasons", [])} if b else None,
                             "after": {"verdict": r["verdict"], "status_ko": r["status_ko"], "effective": r.get("effective", []), "excess": r.get("excess", []),
                                       "reasons": r.get("reasons", []), "where": r.get("where", []), "evidence": r.get("evidence", [])}})
    from .product import has_testbed
    concl = explain.conclusion(st, ver, risk, pol, req_rows_after, testbed=has_testbed(sinfo["set_id"]) if sinfo else None)
    ok_appr, why_appr = can_approve(st)
    concl["can_approve"] = bool(concl.get("can_approve")) and ok_appr
    if not ok_appr and why_appr:
        concl["approve_blocked_reason"] = why_appr
    dec = f.get("decision")
    post = st.get("post_deploy") or {}
    return {
        "id": rid, "case": {"id": case["id"], "name": case["name"]} if case else None,
        "candidate_label": cs.record_label(st), "design": dview,
        "problems": problems_for(st, ver, pol, design_raw, st.get("design") if isinstance(st.get("design"), dict) else None),
        "unchecked": unchecked_for(rec_kind, (post or {}).get("status"), has_testbed(sinfo["set_id"]) if sinfo else None,
                                   auto_design=bool((design_raw or {}).get("auto"))),
        # 그림 모델: 이 기록의 설계도 사본 + 이 후보 코드에서 계산한 V6 결과(붙은 리소스) — 고정 그림 없음 (2026-10-31)
        "topology_model": _topology_model(design_raw, (v6 or {}).get("details") if isinstance((v6 or {}).get("details"), dict) else None, "record", d),
        "candidate_sha256": st.get("candidate_sha256"),
        "set": {"set_id": sinfo["set_id"], "label": sinfo["label"], "intent_kind": sinfo.get("intent_kind")} if sinfo else None,
        "topology": ({k: (v6.get("details") or {}).get(k) for k in ("flows", "excess", "tiers", "notes")}
                     if sinfo and sinfo.get("intent_kind") == "topology" and v6 and isinstance(v6.get("details"), dict) and v6["details"] else None),
        "candidate_id": cid,
        "state": {"code": st.get("state"), "ko": explain.STATE_KO.get(str(st.get("state")), st.get("state")), "level": st.get("review_level"),
                  "level_ko": explain.LEVEL_KO.get(str(st.get("review_level")), st.get("review_level")), "verification_status": st.get("verification_status"),
                  "started_at": st.get("started_at"), "finished_at": st.get("finished_at"), "history": st.get("history") or [], "errors": st.get("errors") or []},
        "classification": explain.classify_candidate(st, ver, pol),
        "conclusion": concl,
        "requirements": requirements,
        "layers": explain.layers_table(ver, post),
        "validity": ((ver or {}).get("report") or {}).get("validity"),
        "validity_summary": ((ver or {}).get("report") or {}).get("summary"),
        "verification_notes": (ver or {}).get("notes") or [],
        "risk": explain.risk_summary(risk),
        "policy": {"ok": (pol or {}).get("ok"), "violations": (pol or {}).get("violations") or [], "checks": (pol or {}).get("checks") or [], "version": (pol or {}).get("policy_version")},
        # 후보 파일 이름(generator) · 작성 메모(provenance)는 기대 결과를 드러낼 수 있어 화면으로 보내지 않는다 (기록 파일에는 그대로 있음)
        "candidate": {"origin": explain.origin_label((cand or {}).get("origin"), (cand or {}).get("generator"), (cand or {}).get("provenance", "")),
                      "rationale": (cand or {}).get("rationale"),
                      "assumptions": (cand or {}).get("assumptions") or [], "needs_info": (cand or {}).get("needs_info") or [], "status": (cand or {}).get("status")},
        "finding": f.get("finding"),
        "diff": f.get("candidate_diff", ""), "diff_summary": explain.diff_summary(f.get("candidate_diff", "")),
        "human_checks": explain.human_checks(req_rows_after, st, risk, cand),
        "tools": st.get("local_tools") or {}, "verification_source": st.get("verification_source"),
        "decision": dec, "decision_ko": explain.DECISION_KO.get(str((dec or {}).get("decision")), None),
        "pr_draft": _pr_draft(f) if (dec or {}).get("decision") == "APPROVED" else None,
        "post_deploy": post, "post_deploy_ko": explain.POST_KO.get(str(post.get("status")), None) if post else None,
        "recovery": st.get("recovery") or None,
        "postdeploy_howto": _postdeploy_howto(rid, sinfo),
        "submission": _submission_view(d),
    }


def _topology_model(design_raw: Optional[Dict[str, Any]], details: Optional[Dict[str, Any]], source: str,
                    record_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    from .topomodel import model, unmapped_resources
    if not design_raw or design_raw.get("kind") != "topology":
        return None
    tiers = (details or {}).get("tiers") if (details or {}).get("kind") == "topology" else None
    if tiers is not None and "undesigned" in (details or {}):     # D-30 이후 기록: V6 가 계산한 '설계도에 없는 리소스' 를 그대로
        return model(design_raw, tiers, source, undesigned=(details or {}).get("undesigned") or [])
    unmapped: List[Dict[str, Any]] = []
    if record_dir is not None and tiers:
        # 후보 코드에만 있는 리소스: 이 기록의 후보 plan 을 V6 와 같은 방법으로 읽는다 (원본 + 후보 파일을 소스로)
        plan_p = record_dir / "local_verify" / "plan_candidate.json"
        if plan_p.exists():
            try:
                plan = json.loads(_read(plan_p, 20_000_000))
                srcs = {p.name: _read(p) for p in sorted((record_dir / "original").glob("*.tf"))}
                srcs.update({p.name: _read(p) for p in sorted((record_dir / "candidate").glob("*.tf"))})
                unmapped = unmapped_resources(plan, tiers, srcs)
            except (OSError, ValueError):
                unmapped = []
    return model(design_raw, tiers, source, unmapped)


def topology_view(case_id: str, set_id: str) -> Dict[str, Any]:
    """지금 설계도로 만든 그림 모델 (1~3단계). 원본 코드 검사 결과가 있으면 실제 붙은 리소스로 아이콘을 정한다."""
    from . import cases as cs
    case = cs.get_case(case_id)
    if case is None:
        return {"ok": False, "reason": f"사례 없음: {case_id}", "nodes": [], "flows": []}
    sinfo = next((s for s in cs._sets(case) if s["set_id"] == set_id), None) or next(iter(cs._sets(case)), None)
    if not sinfo or not sinfo.get("intent_path") or not (_root() / sinfo["intent_path"]).exists():
        return {"ok": False, "reason": "설계도 파일 없음", "nodes": [], "flows": []}
    try:
        design = json.loads(_read(_root() / sinfo["intent_path"]))
    except ValueError as e:
        return {"ok": False, "reason": f"설계도 읽기 실패: {e}", "nodes": [], "flows": []}
    tiers, und = None, None
    try:
        cur = cs.current_state(case["id"])
        s = next((x for x in cur.get("sets", []) if x.get("set_id") == sinfo["set_id"]), None)
        tiers = ((s or {}).get("topology") or {}).get("tiers")
        und = ((s or {}).get("topology") or {}).get("undesigned")
    except Exception:  # 원본 plan 이 없으면 설계도만으로
        tiers = None
    det = {"kind": "topology", "tiers": tiers} if tiers else None
    if det is not None and und is not None:
        det["undesigned"] = und
    m = _topology_model(design, det, "current" if tiers else "design")
    if m is not None:
        m["design"]["version"] = sinfo.get("design_version", 1)
    return m or {"ok": False, "reason": "토폴로지 형식 설계도가 아님 — 그림 없음", "nodes": [], "flows": []}


def problems_for(st, ver, pol, design_raw, design_rec) -> List[Dict[str, Any]]:
    from .problems import problems
    return problems(st, ver, pol, design_raw, design_rec)


def unchecked_for(intent_kind, post_status, testbed=None, auto_design=False) -> List[str]:
    from .problems import unchecked
    return unchecked(intent_kind, post_status, testbed, auto_design)


def design_view(st: Dict[str, Any], sinfo: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """이 기록이 쓴 설계 기준과, 지금 같은 묶음의 설계 기준 파일이 같은가. 다르면 화면이 '이전 설계도 기준 결과' 로 표시한다."""
    from ..evidence_log import sha256_file
    rec = st.get("design") if isinstance(st.get("design"), dict) else None
    cur_path = (sinfo or {}).get("intent_path")
    cur = _root() / cur_path if cur_path else None
    cur_sha = sha256_file(cur) if cur is not None and cur.is_file() else None
    return {"recorded": rec, "current_path": cur_path, "current_sha256": cur_sha,
            "same_as_current": bool(rec and cur_sha and rec.get("sha256") == cur_sha) if rec else None}


def _submission_view(d: Path) -> Optional[Dict[str, Any]]:
    p = d / "input" / "submission.json"
    if not p.exists():
        return None
    try:
        sub = json.loads(_read(p))
    except ValueError:
        return None
    return {"files": [{k: x.get(k) for k in ("path", "status", "reason", "bytes", "sha256", "used_as")} for x in sub.get("files") or []],
            "kind": sub.get("kind"), "summary": sub.get("summary")}


def _pr_draft(f: Dict[str, Any]) -> Dict[str, Any]:
    cmds = f.get("pr_commands_sh") or ""
    branch = base = title = ""
    for line in cmds.splitlines():
        if line.startswith("git checkout -b "):
            parts = line.split()
            branch = parts[3] if len(parts) > 3 else ""
            base = parts[4].split("/", 1)[-1] if len(parts) > 4 else ""
        if line.startswith("gh pr create") and "--title" in line:
            title = line.split("--title", 1)[1].strip().split('"')[1] if '"' in line.split("--title", 1)[1] else ""
    files = [l.split()[-1] for l in cmds.splitlines() if l.startswith("cp ")]
    return {"branch": branch, "base": base, "title": title, "files": [str(x).replace("\\", "/").split("/")[-1] for x in files],
            "commands": cmds, "body": f.get("pr_body_md"), "commit_message": f.get("commit_message_txt")}


def _postdeploy_howto(rid: str, sinfo: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    intent = (sinfo or {}).get("intent_path") or "<요구사항 파일>"
    return {"note": "실제 AWS 검사(V7 AWS 적용 규칙 조회, V8 통신 시험)는 5단계에서 실행 (조회·통신 시험만). 아래는 터미널에서 직접 실행할 때의 명령.",
            "commands": [f"python scripts/iacpatch_cli.py postdeploy --review {rid} --intent {intent} --v8-checks <checks.json>            # 미리보기 (AWS 접속 없음)",
                         f"python scripts/iacpatch_cli.py postdeploy --review {rid} --intent {intent} --v8-checks <checks.json> --execute  # 실제 측정 (사람 승인 뒤)"]}


def all_records_brief(limit: int = 200) -> List[Dict[str, Any]]:
    from .cases import _record_brief
    rr = reviews_root()
    rows = []
    if not rr.is_dir():
        return rows
    for d in sorted(rr.iterdir(), reverse=True):
        st_p = d / "state.json"
        if not st_p.exists():
            continue
        try:
            st = json.loads(st_p.read_text(encoding="utf-8"))
        except ValueError:
            continue
        from .cases import record_label, scenario_parts
        b = _record_brief(d.name, st, d)
        sc = str(st.get("scenario") or "")
        b["ui"] = sc.startswith("ui/")                       # 화면에서 만든 기록 (실험 일괄 실행 기록과 구분)
        b["set_id"] = scenario_parts(sc)[0]
        b["label"] = record_label(st)
        rows.append(b)
        if len(rows) >= limit:
            break
    return rows


def job_review_all(case_id: str, set_id: str) -> Callable:
    """세트의 후보 전부를 차례로 검토한다 (후보마다 job_candidate 와 같은 코드)."""
    from .cases import get_case
    case = get_case(case_id)
    from .cases import _manifest_path
    mpath = _manifest_path(set_id)
    if case is None or not mpath.exists():
        raise ValueError("사례 또는 후보 세트 없음")
    man = json.loads(mpath.read_text(encoding="utf-8"))
    ids = [c["id"] for c in man.get("candidates") or []]
    from .cases import display_labels
    labels = display_labels(set_id, man)
    ids.sort(key=lambda i: labels.get(i, i))                  # 화면 번호 순서대로 (작성 순서 아님)

    def fn(log, prog):
        results = []
        n = len(ids)
        for i, cid in enumerate(ids):
            prog(i, n)
            log(f"\n================ {i + 1}/{n}: {labels.get(cid, cid)}")
            body = {"set_id": set_id, "candidate_id": cid}
            if next((c for c in man["candidates"] if c["id"] == cid), {}).get("candidate") == "rule_based":
                body["generator"] = "rule_based"
            try:
                res = job_candidate(body)(log, lambda a, b: None)
                results.append({"candidate_id": cid, "label": labels.get(cid, cid), **res})
            except Exception as e:  # 한 후보가 죽어도 나머지는 계속
                log(f"오류: {type(e).__name__}: {e}")
                results.append({"candidate_id": cid, "label": labels.get(cid, cid), "error": f"{type(e).__name__}: {e}"})
        prog(n, n)
        return {"results": results}
    return fn


# ----------------------------------------------------------------------------- 새 화면(3D) 지원
_MIME = {".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".html": "text/html; charset=utf-8", ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml",
         ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".ico": "image/x-icon",
         ".woff2": "font/woff2", ".woff": "font/woff", ".ttf": "font/ttf", ".txt": "text/plain; charset=utf-8"}


def static_file(rel: str) -> Optional[tuple]:
    """화면 파일 하나 (bytes, content-type). static 폴더 밖·모르는 확장자·숨김 경로는 None."""
    from urllib.parse import unquote
    rel = unquote(str(rel or "")).replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p]
    if not parts or any(p in ("..", ".") or p.startswith(".") or ":" in p for p in parts):
        return None
    base = STATIC.resolve()
    p = (base / Path(*parts)).resolve()
    try:
        p.relative_to(base)
    except ValueError:
        return None
    ctype = _MIME.get(p.suffix.lower())
    if ctype is None or not p.is_file():
        return None
    return p.read_bytes(), ctype


def _find_set(set_id: str) -> tuple:
    """set_id → (case, set_ref, manifest, set_dir). 화면의 사례에 등록된 세트만 받는다."""
    from . import cases as cs
    for case in cs.all_cases():
        for sref in case.get("sets", []):
            if sref["set_id"] == set_id:
                man, set_dir = cs._manifest(set_id)
                return case, sref, man, set_dir
    return None, None, None, None


def candidate_source(set_id: str, cid: str = "") -> Dict[str, Any]:
    """3단계 미리보기: 대상 finding 이 가리키는 파일의 원본 내용과 후보 파일 내용. 읽기만 한다.
    규칙 기반 후보는 검토를 실행할 때 만들어지므로 내용이 없다 (candidate=None, generated_at_run=True)."""
    from . import cases as cs
    from ..rubric_demo import _resolve
    case, sref, man, set_dir = _find_set(str(set_id or ""))
    if case is None or not man:
        return {"error": f"세트 없음: {set_id}"}
    fc = cs.findings_classified(case, [cs.load_set(case, sref)])
    target = next((f for f in fc.get("in_scope", []) if f.get("set_id") == set_id), None)
    if target is None or not target.get("file"):
        return {"error": "이 세트의 대상 탐지 항목(Trivy finding) 없음", "set_id": set_id}
    fname = Path(str(target["file"])).name
    tf_dir = _root() / str(man.get("tf_dir") or case["tf_dir"])
    original = _read(tf_dir / fname)
    out: Dict[str, Any] = {"set_id": set_id, "candidate_id": cid or None, "file": fname, "rule_id": target.get("rule_id"),
                           "resource": target.get("resource"), "line": target.get("line"), "original": original,
                           "candidate": None, "generated_at_run": False}
    if cid:
        c = next((x for x in man.get("candidates") or [] if x.get("id") == cid), None)
        if c is None:
            return {"error": f"후보 없음: {set_id}/{cid}"}
        ref = str(c.get("candidate") or "")
        if ref == "rule_based":
            out["generated_at_run"] = True
            out["note"] = "규칙 기반 후보는 배포 전 검사 시작 시 규칙으로 생성"
        elif ref.startswith("manual:"):
            p = Path(str(_resolve(ref[7:], set_dir)))
            try:
                p.resolve().relative_to(set_dir.resolve())
            except ValueError:
                return {"error": "후보 파일 위치가 세트 폴더 밖"}
            out["candidate"] = _read(p)
    return out


_PROGRESS_STAGES = [
    ("prepare", "후보 준비 · 기록 폴더", None),
    ("trivy_before", "Trivy · 원본 점검 결과", "local_verify/trivy_before.json"),
    ("trivy_after", "Trivy · 후보 재검사 (V1·V2)", "local_verify/trivy_after.json"),
    ("plan_baseline", "Terraform · 원본 실행 계획", "local_verify/plan_baseline.json"),
    ("plan_candidate", "Terraform · 후보 validate·plan (V3·V4)", "local_verify/plan_candidate.json"),
    ("verify", "변경 허용 범위·설계 기준 계산 (V5·V6)", "verification.json"),
]


def job_progress() -> Dict[str, Any]:
    """검토 작업이 지금 어디까지 왔는지. 추측하지 않고 기록 폴더에 실제로 생긴 파일만 본다 (파일이 생긴 시각 = 그 단계가 끝난 시각)."""
    with JOB.lock:
        running, name, started, finished = JOB.running, JOB.name, JOB.started, JOB.finished
        result = JOB.result if isinstance(JOB.result, dict) else None
    out: Dict[str, Any] = {"running": running, "name": name, "elapsed": round((time.time() if running else (finished or time.time())) - started, 1) if started else 0,
                           "record_id": None, "stages": [{"key": k, "label": lab, "done": False, "at": None} for k, lab, _ in _PROGRESS_STAGES]}
    if name not in ("review", "candidate", "review_all", "llm_fix") or not started:
        return out
    rr = reviews_root()
    d: Optional[Path] = None
    if name not in ("review_all", "llm_fix") and result and result.get("record_id") and (rr / str(result["record_id"])).is_dir():
        d = rr / str(result["record_id"])
    elif rr.is_dir():
        fresh = [x for x in rr.iterdir() if x.is_dir() and x.stat().st_mtime >= started - 1]
        if fresh:
            d = sorted(fresh, key=lambda x: x.name)[-1]
    if d is None:
        return out
    out["record_id"] = d.name
    # 기준 시각 = 이 기록 폴더가 만들어진 시각 (폴더 이름 YYYYmmdd-HHMMSS, 이 PC 의 현지 시각). 후보 전부 검사에서도 후보마다 맞게 잰다
    ref = started
    try:
        ref = max(started, time.mktime(time.strptime(d.name[:15], "%Y%m%d-%H%M%S")))
    except (ValueError, OverflowError):
        pass
    for st in out["stages"]:
        rel = next(r for k, _, r in _PROGRESS_STAGES if k == st["key"])
        p = d if rel is None else d / rel
        if p.exists():
            mt = p.stat().st_mtime
            st["done"] = True
            st["cached"] = rel is not None and mt < ref - 1      # 캐시에서 복사한 파일(copy2 는 원래 시각 유지) = 이전 결과 재사용
            st["at"] = None if st["cached"] else round(max(0.0, mt - ref), 1)
    return out


# ----------------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "IaCPatch/0.4"

    def log_message(self, fmt: str, *args: Any) -> None:  # 콘솔 소음 제거
        if os.environ.get("IACPATCH_HTTP_LOG"):
            super().log_message(fmt, *args)

    # -- helpers
    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"))

    def _body(self) -> Dict[str, Any]:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8"))
            return obj if isinstance(obj, dict) else {}
        except ValueError:
            return {}

    def _local(self) -> bool:
        return self.client_address[0] in ("127.0.0.1", "::1")

    def _same_site(self, post: bool) -> bool:
        """다른 웹 페이지가 이 PC 의 서버를 부르지 못하게 (시험 환경 apply·destroy 버튼이 생겨서, D-19).
        Host 가 이 서버 주소가 아니면 거절 (DNS rebinding — 다른 도메인 이름을 127.0.0.1 로 돌려 화면 API 를 읽는 공격).
        POST 에 Origin 이 붙어 오면 이 서버 화면이어야 한다 (다른 사이트에서 보낸 요청 거절). Origin 이 없으면 브라우저가 아닌
        이 PC 의 프로그램(curl·테스트)이다 — 127.0.0.1 에서만 받으므로 허용."""
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        if (self.headers.get("Host") or "").strip().lower() not in hosts:
            return False
        if post:
            origin = (self.headers.get("Origin") or "").strip().lower()
            if origin and origin not in {"http://" + h for h in hosts}:
                return False
        return True

    # -- routes
    def do_GET(self) -> None:  # noqa: N802
        if not self._local():
            self._json({"error": "local only"}, 403); return
        if not self._same_site(post=False):
            self._json({"error": "이 서버 주소(127.0.0.1 · localhost)로 연 화면의 요청만 허용"}, 403); return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        qid = q.get("id", [""])[0]
        try:
            if u.path in ("/", "/demo", "/demo.html"):
                # 첫 화면 = 시연 화면 (2026-11-10: 4단계 — 문제 · 수정안 · 검사 결과 · 결정). 8단계 전체 화면은 /main, 전문가 화면은 /work
                self._send(200, (STATIC / "demo.html").read_bytes(), "text/html; charset=utf-8")
            elif u.path in ("/main", "/main.html"):
                # 8단계 사용자 질문 흐름 (2026-11-01 갈아엎기 3차). 시연 화면의 '자세히 보기'
                self._send(200, (STATIC / "main.html").read_bytes(), "text/html; charset=utf-8")
            elif u.path in ("/story", "/story.html"):
                self._send(200, (STATIC / "story.html").read_bytes(), "text/html; charset=utf-8")
            elif u.path in ("/work", "/index.html"):
                self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif u.path.startswith("/static/"):
                hit = static_file(u.path[len("/static/"):])
                if hit is None:
                    self._json({"error": "not found"}, 404)
                else:
                    self._send(200, hit[0], hit[1])
            elif u.path in ("/classic", "/classic.html"):
                p = STATIC / "classic.html"
                if p.exists():
                    self._send(200, p.read_bytes(), "text/html; charset=utf-8")
                else:
                    self._json({"error": "이전 화면 파일 없음"}, 404)
            elif u.path == "/api/candidate/source":
                self._json(candidate_source(q.get("set_id", [""])[0], qid))
            elif u.path == "/api/job/progress":
                self._json(job_progress())
            # ---- 새 화면
            elif u.path == "/api/app":
                self._json(app_payload())
            elif u.path == "/api/cases":
                from .cases import list_cases
                self._json({"cases": list_cases()})
            elif u.path == "/api/case":
                from .cases import case_summary
                self._json(case_summary(qid))
            elif u.path == "/api/case/current":
                from .cases import current_state
                self._json(current_state(qid))
            elif u.path == "/api/case/candidates":
                from .cases import candidates
                self._json(candidates(qid))
            elif u.path == "/api/record":
                self._json(record_view(qid))
            elif u.path == "/api/records":
                self._json({"records": all_records_brief()})
            elif u.path == "/api/log":
                self._json(JOB.snapshot(int(q.get("since", ["0"])[0])))
            # ---- 탐지 방식 · 증거
            elif u.path == "/api/proof":
                from .proof_api import proof_view
                self._json(proof_view(qid))
            elif u.path == "/api/proof/calibration":
                from .proof_api import calibration_view
                self._json(calibration_view())
            elif u.path == "/api/proof/report":
                from .proof_api import report_html
                h = report_html(qid)
                if h is None:
                    self._json({"error": "기록 없음"}, 404)
                else:
                    self._send(200, h.encode("utf-8"), "text/html; charset=utf-8")
            elif u.path == "/api/proof/file":
                from .proof_api import evidence_file
                self._json(evidence_file(qid, q.get("path", [""])[0]))
            elif u.path == "/api/topomap":
                from .proof_api import topomap_view
                self._json(topomap_view(q.get("case", [""])[0], q.get("set", [""])[0]))
            elif u.path == "/api/topology":
                self._json(topology_view(q.get("case", [""])[0], q.get("set", [""])[0]))
            # ---- 새 프로그램 (2026-11-01 갈아엎기 3차, web/product.py)
            elif u.path == "/api/p/projects":
                from .product import projects
                self._json(projects(include_hidden=q.get("all", ["0"])[0] == "1"))     # all=1: 숨긴 예제(실험용)도 — 주소로 열 때만
            elif u.path in ("/api/p/infra", "/api/p/design", "/api/p/issues"):
                from . import product
                self._json({"/api/p/infra": product.infra, "/api/p/design": product.design, "/api/p/issues": product.issues}[u.path](qid))
            elif u.path == "/api/inbox":
                # 고객 요청함 (16차, D-52): 부를 때마다 시간이 된 요청을 도착시킨다 (화면은 10초마다 부른다)
                from . import inbox
                self._json(inbox.view())
            elif u.path == "/api/p/coverage":
                from .product import coverage
                self._json(coverage())
            elif u.path == "/api/p/testbed":
                # ⑦ AWS 시험 환경 — 지금 상태 + 다음 작업 재료 (measure_setup + 측정 요약). 반영·측정은 POST 쪽 (사람 확인 창)
                from .product import testbed_view
                self._json(testbed_view(qid))
            elif u.path in ("/api/p/impact", "/api/p/verdict", "/api/p/final"):
                from . import product
                self._json({"/api/p/impact": product.impact, "/api/p/verdict": product.verdict_view, "/api/p/final": product.final_view}[u.path](qid))
            elif u.path == "/api/p/pr_check":
                self._json(pr_check(qid, q.get("base", ["main"])[0] or "main"))
            # ---- 고객 설계도 버전 (D-30)
            elif u.path == "/api/design":
                from .designs import payload
                v = q.get("version", [""])[0]
                self._json(payload(q.get("set", [""])[0], int(v) if v.isdigit() else None))
            # ---- AI 수정 (D-27)
            elif u.path == "/api/llm/status":
                from ..llmfix import claude_status
                self._json(claude_status(refresh=bool(q.get("refresh"))))
            elif u.path == "/api/llm/runs":
                from .llm_api import runs
                self._json(runs(q.get("set", [""])[0]))
            elif u.path == "/api/llm/run":
                from .llm_api import run_view
                self._json(run_view(qid))
            elif u.path == "/api/llm/text":
                from .llm_api import attempt_text
                n = q.get("n", ["1"])[0]
                self._json(attempt_text(qid, int(n) if n.isdigit() else 0, q.get("what", ["prompt"])[0]))
            elif u.path == "/api/proof/baseline":
                from .proof_api import baseline_view
                self._json(baseline_view())
            elif u.path == "/api/measure/setup":
                from .proof_api import measure_setup
                self._json(measure_setup(qid))
            # ---- 이전 API (호환)
            elif u.path == "/api/state":
                self._json(state_payload())
            elif u.path == "/api/week4/rubric":
                from ..rubric_demo import rubric_view
                self._json(rubric_view())
            elif u.path == "/api/week4/labels":
                from ..rubric_demo import label_agreement, labeled_matrix
                key = "labels"
                if key not in _STATE["cache"] or q.get("refresh"):
                    _STATE["cache"][key] = {"replay": labeled_matrix(), "records": label_agreement()}
                self._json(_STATE["cache"][key])
            elif u.path == "/api/week4/capcheck":
                from ..rubric_demo import cap_enforcement_check
                self._json(cap_enforcement_check())
            elif u.path == "/api/week5/sets":
                self._json({"sets": _manifests()})
            elif u.path == "/api/week5/records":
                self._json({"records": _latest_records()})
            elif u.path == "/api/week5/record":
                self._json(record_detail(qid))
            elif u.path == "/api/update/check":
                from .. import update as up
                from ..config import load_settings
                url = os.environ.get("IACPATCH_UPDATE_URL") or load_settings(str(_root())).extra.get("update_url") or up.DEFAULT_UPDATE_URL
                self._json(up.check(url))
            elif u.path in ("/report", "/report/", "/report/index.html"):
                p = _root() / "report" / "index.html"
                if p.exists():
                    self._send(200, p.read_bytes(), "text/html; charset=utf-8")
                else:
                    self._send(404, "<p>리포트 없음. 이전 화면(/classic) 설정의 '개발용: 실험 재현 · 리포트' 먼저 실행.</p>".encode("utf-8"), "text/html; charset=utf-8")
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:  # 화면이 죽지 않게 오류를 JSON 으로
            self._json({"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc().splitlines()[-5:]}, 500)

    def do_POST(self) -> None:  # noqa: N802
        if not self._local():
            self._json({"error": "local only"}, 403); return
        if not self._same_site(post=True):
            self._json({"error": "다른 사이트에서 보낸 요청 거부 (이 PC 의 IaCPatch 화면 요청만 허용)"}, 403); return
        u = urlparse(self.path)
        if int(self.headers.get("Content-Length") or 0) > MAX_BODY_BYTES:
            self._json({"error": f"요청이 너무 큼 — {MAX_BODY_BYTES // 1_000_000}MB 까지"}, 413); return
        body = self._body()
        try:
            if u.path == "/api/heartbeat":
                _STATE["last_heartbeat"] = time.time()
                self._json({"ok": True})
            elif u.path == "/api/quit":
                _STATE["quit"] = True
                self._json({"ok": True, "bye": "서버 종료. 이 탭은 닫아도 됨."})
            # ---- 새 화면
            elif u.path == "/api/review":
                try:
                    fn = job_candidate(body)
                except ValueError as e:
                    self._json({"started": False, "error": str(e)}, 400); return
                ok = JOB.start("review", fn)
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path == "/api/review/prefetch":
                # ⑤ 미리 분석 (D-47): 보이는 수정안 중 지금 기준 기록이 없는 것을 차례로. 작업 이름 'prefetch' — 화면은 /api/job/progress 로 진행을 본다
                try:
                    fn = job_prefetch(body)
                except ValueError as e:
                    self._json({"started": False, "error": str(e)}, 400); return
                ok = JOB.start("prefetch", fn)
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path in ("/api/inbox/insert", "/api/inbox/read"):
                # 고객 요청함 (16차 D-52 · 17차 D-53): 고객 역할로 넣기 / 읽음. 요청 내용 · 판정은 바꾸지 않는다 (17차: 타이머 · 지금 받기 · 처음부터 뺌)
                from . import inbox
                try:
                    if u.path == "/api/inbox/insert":
                        self._json({"ok": True, **inbox.insert(body)})
                    else:
                        self._json(inbox.mark_read(str(body.get("id") or "")))
                except inbox.InboxError as e:
                    self._json({"ok": False, "errors": [str(e)]}, 400)
            elif u.path == "/api/design/confirm":
                # 설계도 확정 (D-38): 담당자 이름 · 메모 → data/designs/<키>/confirmed.json. 판정 · 승인은 확정된 버전 기준 검사만
                from . import designs
                sid = str(body.get("set_id") or "")
                if not designs.SET_RE.match(sid):
                    self._json({"ok": False, "errors": [f"세트 · 프로젝트 없음: {sid}"]}, 404); return
                if JOB.running:
                    self._json({"ok": False, "errors": ["검사 · AI 수정이 진행 중 — 끝난 뒤 확정"]}, 409); return
                vv = body.get("version")
                res = designs.confirm(sid, int(vv) if str(vv or "").isdigit() else None, str(body.get("by") or ""), str(body.get("note") or ""))
                self._json(res, 200 if res.get("ok") else 400)
            elif u.path == "/api/design/req/import":
                # 요구사항 파일(IAM · 보안 그룹 형식) 새 버전 올리기 (D-40): JSON 본문 그대로 → 형식 · 대상 검사 → v<N> 저장 · 지금 기준. 올린 판은 초안
                from . import designs
                sid = str(body.get("set_id") or "")
                if not designs.SET_RE.match(sid):
                    self._json({"ok": False, "errors": [f"세트 없음: {sid}"]}, 404); return
                if JOB.running:
                    self._json({"ok": False, "errors": ["검사 · AI 수정이 진행 중 — 끝난 뒤 올리기"]}, 409); return
                raw = body.get("json")
                if isinstance(raw, str) and len(raw) > 200000:
                    self._json({"ok": False, "errors": ["파일이 너무 큼 (200KB 넘음)"]}, 400); return
                res = designs.import_version(sid, raw, str(body.get("note") or ""), str(body.get("by") or ""))
                self._json(res, 200 if res.get("ok") else 400)
            elif u.path in ("/api/design/preview", "/api/design/save", "/api/design/activate"):
                from . import designs
                from .cases import get_case
                sid = str(body.get("set_id") or "")
                if not designs.SET_RE.match(sid) or (designs.base_path(sid) is None and get_case(sid) is None):
                    self._json({"ok": False, "errors": [f"세트 · 프로젝트 없음: {sid}"]}, 404); return
                if u.path.endswith("preview"):
                    self._json(designs.preview(sid, body.get("design") or {}))
                elif u.path.endswith("save"):
                    if JOB.running:
                        self._json({"ok": False, "errors": ["검사 · AI 수정이 진행 중 — 끝난 뒤 저장"]}, 409); return
                    bv = body.get("base_version")
                    res = designs.save(sid, body.get("design") or {}, str(body.get("note") or ""), int(bv) if str(bv or "").isdigit() else None)
                    self._json(res, 200 if res.get("ok") else 400)
                else:
                    if JOB.running:
                        self._json({"ok": False, "errors": ["검사 · AI 수정이 진행 중 — 끝난 뒤 바꾸기"]}, 409); return
                    res = designs.activate(sid, int(body.get("version") or 0))
                    self._json(res, 200 if res.get("ok") else 400)
            elif u.path == "/api/p/design/create":
                # 설계도가 없는 프로젝트: 지금 코드로 만든 초안을 사람이 고쳐 처음 확정 (v1)
                from . import designs
                from .cases import get_case
                pid = str(body.get("project") or "")
                c = get_case(pid)
                if c is None:
                    self._json({"ok": False, "errors": [f"프로젝트 없음: {pid}"]}, 404); return
                if JOB.running:
                    self._json({"ok": False, "errors": ["검사 · AI 수정이 진행 중 — 끝난 뒤 저장"]}, 409); return
                res = designs.create_first(pid, body.get("design") or {}, str(body.get("note") or ""), c["tf_dir"])
                self._json(res, 200 if res.get("ok") else 400)
            elif u.path in ("/api/p/structure/auto", "/api/p/structure/preview", "/api/p/structure/save"):
                # 원하는 구조 = 자동 기준 + 그림에서 바꾼 것 (D-33, web/structure.py). 저장은 사람이 누른 요청만
                from . import structure
                from .cases import get_case
                pid = str(body.get("project") or "")
                if get_case(pid) is None:
                    self._json({"ok": False, "errors": [f"프로젝트 없음: {pid}"]}, 404); return
                bv = body.get("base_version")
                bv = int(bv) if str(bv or "").isdigit() else None
                if u.path.endswith("preview"):
                    self._json(structure.preview(pid, body.get("edits") or [], bv))
                    return
                if JOB.running:
                    self._json({"ok": False, "errors": ["검사 · AI 수정이 진행 중 — 끝난 뒤 저장"]}, 409); return
                res = structure.ensure_auto(pid) if u.path.endswith("auto") else structure.save(pid, body.get("edits") or [], str(body.get("note") or ""), bv)
                self._json(res, 200 if res.get("ok") else 400)
            elif u.path == "/api/p/pr":
                # PR 만들기 — 사람이 화면에서 누른 요청만 (확인 문구 필수). 승인(APPROVED) 기록만. 병합은 하지 않는다
                rid = str(body.get("record_id") or "")
                if str(body.get("confirm") or "") != "PR 만들기":
                    self._json({"started": False, "error": "확인 문구가 필요함"}, 400); return
                if not rid or ".." in rid or "/" in rid or "\\" in rid or not (reviews_root() / rid).is_dir():
                    self._json({"started": False, "error": "기록 없음"}, 404); return
                try:
                    fn = job_pr_create(rid, str(body.get("base_branch") or "main"))
                except ValueError as e:
                    self._json({"started": False, "error": str(e)}, 400); return
                ok = JOB.start("pr_create", fn)
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path == "/api/llm/fix":
                try:
                    fn = job_llm_fix(body)
                except ValueError as e:
                    self._json({"started": False, "error": str(e)}, 400); return
                ok = JOB.start("llm_fix", fn)
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path == "/api/submission/check":
                # 제출 파일 사전 확인 — 파일별 상태(변경 · 원본과 같음 · 원본에 없음 · 검사에 안 씀 + 이유). 아무것도 실행하지 않는다
                from ..config import load_json, load_settings
                from .submission import analyze, public_view
                case, sref, man, _sd = _find_set(str(body.get("set_id") or ""))
                if case is None or not man:
                    self._json({"error": "세트 없음"}, 404); return
                res = public_view(analyze(_root() / str(man.get("tf_dir") or case["tf_dir"]), body.get("files"), bool(body.get("folder"))))
                st_ = load_settings(str(_root()))
                res["max_patch_files"] = int((load_json(st_.path(st_.policy_file)) or {}).get("max_patch_files", 2))
                self._json(res)
            elif u.path == "/api/case/scan":
                from .cases import get_case
                cid = str(body.get("case_id") or "")
                c = get_case(cid)
                if c is not None and c.get("kind") == "user":
                    from .projects import job_scan
                    ok = JOB.start("project_scan", job_scan(cid))
                else:
                    ok = JOB.start("case_scan", job_case_scan(cid))
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            # ---- 내 Terraform 폴더 연결 (D-32): 경로로 연결 · 읽기만, 점검은 작업 폴더 사본에서
            elif u.path == "/api/p/project/inspect":
                from .projects import inspect_folder
                self._json(inspect_folder(str(body.get("path") or "")))
            elif u.path == "/api/p/project/create":
                from .projects import create, job_scan
                if JOB.running:
                    self._json({"ok": False, "errors": ["다른 작업(검사 · AI 수정)이 진행 중 — 끝난 뒤 연결"]}, 409); return
                res = create(str(body.get("name") or ""), str(body.get("path") or ""))
                if res.get("ok"):
                    res["started"] = JOB.start("project_scan", job_scan(res["project"]))
                self._json(res, 200 if res.get("ok") else 400)
            elif u.path == "/api/p/project/remove":
                from .projects import remove
                if str(body.get("confirm") or "") != "연결 끊기":
                    self._json({"ok": False, "error": "확인 문구가 필요함"}, 400); return
                try:
                    self._json(remove(str(body.get("id") or "")))
                except ValueError as e:
                    self._json({"ok": False, "error": str(e)}, 400)
            elif u.path == "/api/p/target":
                # ④ 에서 고른 문제 → ⑤ 의 고칠 대상 (연결한 프로젝트). 예제는 이미 있는 세트를 쓴다
                from .projects import ensure_target
                try:
                    self._json(ensure_target(str(body.get("project") or ""), str(body.get("rule") or ""), str(body.get("resource") or "")))
                except ValueError as e:
                    self._json({"ok": False, "error": str(e)}, 400)
            elif u.path == "/api/proof/calibrate":
                from .proof_api import job_calibrate
                ok = JOB.start("calibrate", job_calibrate(str(body.get("case_id") or "")))
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path == "/api/measure":
                from .proof_api import job_measure
                try:
                    fn = job_measure(body)
                except ValueError as e:
                    self._json({"started": False, "error": str(e)}, 400); return
                ok = JOB.start("measure", fn)
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path == "/api/plan_check":
                from .proof_api import job_plan_check
                try:
                    fn = job_plan_check(body)
                except ValueError as e:
                    self._json({"started": False, "error": str(e)}, 400); return
                ok = JOB.start("plan_check", fn)
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path in ("/api/testbed/prepare", "/api/testbed/execute"):
                # 시험 환경 apply · destroy — prepare 는 plan 만, execute 는 사람이 확인 창에서 누른 요청만 (confirm 값 필수)
                from .proof_api import job_testbed_execute, job_testbed_prepare
                try:
                    fn = job_testbed_prepare(body) if u.path.endswith("prepare") else job_testbed_execute(body)
                except ValueError as e:
                    self._json({"started": False, "error": str(e)}, 400); return
                ok = JOB.start("testbed_prepare" if u.path.endswith("prepare") else "testbed_apply", fn)
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path == "/api/testbed/use":
                from .proof_api import testbed_use
                try:
                    self._json(testbed_use(body))
                except ValueError as e:
                    self._json({"ok": False, "error": str(e)}, 400)
            elif u.path == "/api/review_all":
                ok = JOB.start("review_all", job_review_all(str(body.get("case_id") or ""), str(body.get("set_id") or "")))
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path == "/api/decision":
                from ..config import load_settings
                from .decision import record_decision
                rid = str(body.get("record_id") or "")
                if not rid or ".." in rid or "/" in rid or "\\" in rid or not (reviews_root() / rid).is_dir():
                    self._json({"error": "기록 없음"}, 404); return
                res = record_decision(load_settings(str(_root())), reviews_root() / rid, str(body.get("decision") or ""), str(body.get("reason") or ""),
                                      str(body.get("by") or ""), str(body.get("base_branch") or "main"), ack_unverified=bool(body.get("ack_unverified")))
                self._json(res, 200 if res.get("ok") else (403 if res.get("refused") else 400))
            # ---- 작업
            elif u.path == "/api/job/run_all":
                ok = JOB.start("run_all" if not body.get("report_only") else "report_only", job_run_all(bool(body.get("fresh")), bool(body.get("report_only"))))
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path == "/api/job/setup_tools":
                ok = JOB.start("setup_tools", job_setup_tools())
                self._json({"started": ok}, 200 if ok else 409)
            elif u.path == "/api/job/candidate":       # 이전 이름 (호환)
                ok = JOB.start("candidate", job_candidate(body))
                self._json({"started": ok}, 200 if ok else 409)
            elif u.path == "/api/job/update":
                ok = JOB.start("update", job_update())
                self._json({"started": ok}, 200 if ok else 409)
            # ---- 이전 API (호환)
            elif u.path == "/api/week4/calc":
                from ..rubric_demo import calc_risk
                self._json(calc_risk(body))
            elif u.path == "/api/week4/gate":
                from ..rubric_demo import gate_demo
                self._json(gate_demo(str(body.get("risk_level", "LOW")), body.get("proposal") or None, str(body.get("validity", "PASS")),
                                     bool(body.get("policy_ok", True)), int(body.get("score", 0) or 0)))
            elif u.path == "/api/week5/pr_preview":
                self._json(pr_preview(str(body.get("record_id") or ""), str(body.get("base_branch") or "main")))
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc().splitlines()[-5:]}, 500)


MAX_BODY_BYTES = 8_000_000      # 화면 요청 한도 (파일 제출 포함). web/submission.py 의 전체 한도(6MB) + JSON 여유


def pick_port(preferred: int = 8765) -> int:
    for port in [preferred, *range(preferred + 1, preferred + 20)]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def request_quit() -> None:
    """자체 창(데스크톱 창)이 닫히면 서버도 끝낸다."""
    _STATE["quit"] = True


def wait_ready(port: int, timeout: float = 15.0) -> bool:
    import socket as _so
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with _so.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def serve(port: Optional[int] = None, open_browser: bool = True, idle_exit: bool = True, ready: Optional[Callable[[str], None]] = None) -> int:
    port = port or pick_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{port}/"
    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True)
    t.start()
    print(f"IaCPatch 화면: {url}   (브라우저 탭을 닫으면 잠시 후 자동 종료. 즉시 종료: Ctrl+C)", flush=True)
    if ready:
        ready(url)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception as e:  # pragma: no cover
            print(f"브라우저 열기 실패: {e} — 주소 직접 열기: {url}")
    t_start = time.time()
    try:
        while not _STATE["quit"]:
            time.sleep(0.5)
            qa = _STATE.get("quit_after")
            if qa and time.time() > qa:                                        # 업데이트로 새 exe 를 띄운 뒤
                print("새 빌드 실행 — 이 서버 종료.", flush=True)
                break
            if not idle_exit or JOB.running:
                continue
            hb = _STATE["last_heartbeat"]
            if hb and time.time() - hb > IDLE_EXIT_SECONDS:
                print("화면 종료 감지 — 서버 종료.", flush=True)
                break
            if not hb and time.time() - t_start > 5 * IDLE_EXIT_SECONDS:     # 브라우저가 한 번도 안 열렸으면 15분 뒤 종료 (창 없는 exe 가 남지 않게)
                print("화면이 열리지 않음 — 서버 종료.", flush=True)
                break
    except KeyboardInterrupt:
        pass
    httpd.shutdown()
    return 0
