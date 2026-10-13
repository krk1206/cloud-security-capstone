"""로컬 웹 서버 — 브라우저 화면의 뒷단. 표준 라이브러리만 쓴다 (설치 0).

    python -m iacpatch.app                 # 서버 띄우고 브라우저 열기 (기본)
    python -m iacpatch.app --port 8765 --no-open

API (전부 127.0.0.1 에서만):
    GET  /                       화면 (static/index.html, 인라인 CSS/JS)
    GET  /api/state              도구·설치 검사·작업 상태·리포트 유무·요약 숫자
    GET  /api/log?since=N        작업 로그 (N 번째 줄 이후)
    POST /api/job/run_all        {"fresh": bool, "report_only": bool}   실험 8단계 + 리포트 (app.run_all)
    POST /api/job/setup_tools    trivy/terraform 을 tools/ 에 받기 (scripts/setup_tools.*)
    POST /api/job/candidate      {"set_id","candidate_id"} | {"set_id","paste": "<main.tf 전체>"} | {"set_id","generator":"rule_based"}  한 후보 검토 흐름
    GET  /api/week4/rubric       기준표
    GET  /api/week4/labels       라벨 25건을 도구 없이 실제 흐름으로 (plan 쌍 fixture) — 기대 등급 vs 코드 등급
    GET  /api/week4/capcheck     상한 강제 전수 검사 (72 조합)
    POST /api/week4/calc         목업 입력 → 점수·등급
    POST /api/week4/gate         {"risk_level","proposal","validity","policy_ok"} → 게이트 결정
    GET  /api/week5/sets         후보 세트·후보 목록
    GET  /api/week5/records      data/reviews 최신 기록 목록
    GET  /api/week5/record?id=   기록 상세 (검증 표·위험도·diff·PR 본문)
    POST /api/week5/pr_preview   {"record_id"} → PR 미리보기 (브랜치·제목·명령; push/PR 생성은 하지 않음)
    GET  /report/                report/index.html
    POST /api/heartbeat, POST /api/quit
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import platform
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


class Job:
    """한 번에 하나만 도는 작업 + 로그 버퍼."""

    def __init__(self) -> None:
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
        return {"error": f"기록이 없다: {rid}"}
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
    win = platform.system() == "Windows"
    root = _root()
    script = root / "scripts" / ("setup_tools.ps1" if win else "setup_tools.sh")
    argv = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)] if win else ["bash", str(script)]

    def fn(log, prog):
        if not script.exists():
            log(f"설치 스크립트가 없다: {script}")
            log(_app.install_hint())
            return {"rc": 2, "tools": _app.tool_status()}
        log(f"도구 설치: {' '.join(argv)}")
        # 출력은 바이트로 받아 UTF-8 → (Windows) 콘솔 코드페이지 순으로 푼다. PowerShell 의 한글 오류가 cp949 라 utf-8 로만 읽으면 깨진다 (팀 PC 실측 09-28)
        p = subprocess.Popen(argv, cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert p.stdout is not None
        for raw in p.stdout:
            log(decode_console(raw).rstrip("\r\n"))
        rc = p.wait()
        log(f"종료 코드 {rc}" + ("" if rc == 0 else " — 실패. 위 메시지를 확인 (인터넷 연결, 압축 해제 권한, 폴더 위치)"))
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


def job_candidate(req: Dict[str, Any]) -> Callable:
    """한 후보 검토 흐름 (5주차): 세트의 후보 / 붙여넣은 후보 / 규칙 기반 생성. 도구가 있으면 V1~V4 도 실행. AWS·LLM 호출 없음."""
    from ..config import load_settings
    from ..review.flow import ReviewOptions, run_review
    from ..rubric_demo import _resolve
    root = _root()
    set_id = str(req.get("set_id") or "")
    cid = str(req.get("candidate_id") or "")
    paste = req.get("paste")
    generator = req.get("generator")
    mpath = root / "experiments" / "candidate-sets" / set_id / "manifest.json"
    if not mpath.exists():
        raise ValueError(f"세트가 없다: {set_id}")
    man = json.loads(mpath.read_text(encoding="utf-8"))
    set_dir = mpath.parent
    cands = {c["id"]: c for c in man.get("candidates") or []}
    c = cands.get(cid, {}) if cid else {}

    def pick(key, default=None):
        return c[key] if key in c else man.get(key, default)

    tf_dir = pick("tf_dir")
    if paste:
        # 붙여넣은 내용 = 대상 finding 이 가리키는 파일의 전체 내용 (manual:<file.tf>)
        tmpd = root / "data" / "cache" / "paste"
        tmpd.mkdir(parents=True, exist_ok=True)
        pth = tmpd / f"paste-{int(time.time())}.tf"
        pth.write_text(str(paste), encoding="utf-8")
        cand = f"manual:{pth}"
        scenario = f"ui/{set_id}/paste-{pth.stem.split('-')[-1]}"
        note = "브라우저 화면에서 붙여넣은 후보 (사람 또는 Claude Code 세션의 출력 — 프로그램이 자동 생성한 것이 아님)"
    elif generator == "rule_based":
        cand = "rule_based"
        scenario = f"ui/{set_id}/{cid or 'rule-based'}-rb"
        note = "규칙 기반 생성기 (LLM 아님)"
    else:
        if not c:
            raise ValueError(f"후보가 없다: {set_id}/{cid}")
        cand = c["candidate"]
        if cand.startswith("manual:"):
            cand = "manual:" + str(_resolve(cand[7:], set_dir))
        scenario = f"ui/{set_id}/{cid}"          # ui/ 접두어: 실험 세트의 최신 기록(리포트 집계)을 덮지 않는다
        note = c.get("note", "")
    opt = ReviewOptions(tf_dir=tf_dir, trivy_json=_resolve(pick("trivy_json"), set_dir), candidate=cand, scenario=scenario,
                        rule=pick("rule", "AVD-AWS-0107"), filename=pick("file"), resource=pick("resource"), line=pick("line"),
                        candidate_note=note, verification=None, baseline_plan=_resolve(pick("baseline_plan"), set_dir),
                        candidate_plan=_resolve(c.get("candidate_plan"), set_dir), intent=_resolve(pick("intent"), set_dir),
                        out_dir=str(reviews_root()), local_tools=True)

    def fn(log, prog):
        env = _app._env()
        os.environ.update({k: env[k] for k in ("TRIVY_BIN", "TERRAFORM_BIN", "TRIVY_SKIP_CHECK_UPDATE", "TRIVY_SKIP_VERSION_CHECK", "TF_PLUGIN_CACHE_DIR") if k in env})
        s = load_settings(str(root))
        ts = _app.tool_status()
        for k, v in ts.items():
            log(f"{k}: {v['version'] if v['ok'] else '없음 → 해당 계층 NOT_RUN'}")
        log(f"시나리오 {scenario} · 원본 {tf_dir} · 후보 {cand if not paste else '(붙여넣기)'}")
        prog(1, 3)
        res = run_review(s, opt)
        prog(2, 3)
        for line in res.console().splitlines():
            log(line)
        prog(3, 3)
        return {"record_id": res.run_id, "state": res.state.value, "level": res.level.value if res.level else None,
                "risk": res.risk.risk_level.value if res.risk else None, "message": res.message}
    return fn


def pr_preview(record_id: str) -> Dict[str, Any]:
    """`iacpatch pr --review <id>` 미리보기와 같음. push·PR 생성은 하지 않는다 (execute=False 고정)."""
    from ..config import load_settings
    from ..tools.github import prepare_pr
    root = _root()
    if not record_id or ".." in record_id or "/" in record_id:
        return {"error": "record_id"}
    s = load_settings(str(root))
    d = reviews_root() / record_id
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = prepare_pr(s, None, execute=False, review_id=str(d) if d.is_dir() else record_id)
    return {"rc": rc, "output": buf.getvalue(), "pr_body": _read(d / "pr_body.md", 60_000), "commands": _read(d / "pr_commands.sh", 20_000),
            "note": "미리보기만. 실제 브랜치 push 와 PR 생성은 사람이 pr_commands.sh 를 검토한 뒤 GitHub 권한이 있는 PC 에서 실행한다 (D-5)."}


# ----------------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "IaCPatch/0.3"

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

    # -- routes
    def do_GET(self) -> None:  # noqa: N802
        if not self._local():
            self._json({"error": "local only"}, 403); return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path in ("/", "/index.html"):
                self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif u.path == "/api/state":
                self._json(state_payload())
            elif u.path == "/api/log":
                self._json(JOB.snapshot(int(q.get("since", ["0"])[0])))
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
                self._json(record_detail(q.get("id", [""])[0]))
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
                    self._send(404, "<p>리포트가 아직 없다. '전체 실행' 또는 '리포트만 다시 생성' 을 먼저.</p>".encode("utf-8"), "text/html; charset=utf-8")
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:  # 화면이 죽지 않게 오류를 JSON 으로
            self._json({"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc().splitlines()[-5:]}, 500)

    def do_POST(self) -> None:  # noqa: N802
        if not self._local():
            self._json({"error": "local only"}, 403); return
        u = urlparse(self.path)
        body = self._body()
        try:
            if u.path == "/api/heartbeat":
                _STATE["last_heartbeat"] = time.time()
                self._json({"ok": True})
            elif u.path == "/api/quit":
                _STATE["quit"] = True
                self._json({"ok": True, "bye": "서버를 끈다. 이 탭은 닫아도 된다."})
            elif u.path == "/api/job/run_all":
                ok = JOB.start("run_all" if not body.get("report_only") else "report_only", job_run_all(bool(body.get("fresh")), bool(body.get("report_only"))))
                self._json({"started": ok, "job": JOB.snapshot(10**9)}, 200 if ok else 409)
            elif u.path == "/api/job/setup_tools":
                ok = JOB.start("setup_tools", job_setup_tools())
                self._json({"started": ok}, 200 if ok else 409)
            elif u.path == "/api/job/candidate":
                ok = JOB.start("candidate", job_candidate(body))
                self._json({"started": ok}, 200 if ok else 409)
            elif u.path == "/api/job/update":
                ok = JOB.start("update", job_update())
                self._json({"started": ok}, 200 if ok else 409)
            elif u.path == "/api/week4/calc":
                from ..rubric_demo import calc_risk
                self._json(calc_risk(body))
            elif u.path == "/api/week4/gate":
                from ..rubric_demo import gate_demo
                self._json(gate_demo(str(body.get("risk_level", "LOW")), body.get("proposal") or None, str(body.get("validity", "PASS")),
                                     bool(body.get("policy_ok", True)), int(body.get("score", 0) or 0)))
            elif u.path == "/api/week5/pr_preview":
                self._json(pr_preview(str(body.get("record_id") or "")))
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc().splitlines()[-5:]}, 500)


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


def serve(port: Optional[int] = None, open_browser: bool = True, idle_exit: bool = True, ready: Optional[Callable[[str], None]] = None) -> int:
    port = port or pick_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{port}/"
    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True)
    t.start()
    print(f"IaCPatch 화면: {url}   (끝내려면 화면의 '종료' 또는 Ctrl+C)", flush=True)
    if ready:
        ready(url)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception as e:  # pragma: no cover
            print(f"브라우저 열기 실패: {e} — 주소를 직접 열어라: {url}")
    t_start = time.time()
    try:
        while not _STATE["quit"]:
            time.sleep(0.5)
            qa = _STATE.get("quit_after")
            if qa and time.time() > qa:                                        # 업데이트로 새 exe 를 띄운 뒤
                print("새 빌드가 실행돼 이 서버를 끝낸다.", flush=True)
                break
            if not idle_exit or JOB.running:
                continue
            hb = _STATE["last_heartbeat"]
            if hb and time.time() - hb > IDLE_EXIT_SECONDS:
                print("화면이 닫힌 것 같아 서버를 끝낸다.", flush=True)
                break
            if not hb and time.time() - t_start > 5 * IDLE_EXIT_SECONDS:     # 브라우저가 한 번도 안 열렸으면 15분 뒤 종료 (창 없는 exe 가 남지 않게)
                print("화면이 열리지 않아 서버를 끝낸다.", flush=True)
                break
    except KeyboardInterrupt:
        pass
    httpd.shutdown()
    return 0
