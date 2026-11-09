"""AI 수정(llmfix, D-27) 화면 API — 실행 목록 · 실행 하나 · AI 에게 보낸 요청문. 판정을 만들지 않는다: run.json 을 그대로 보여 준다.

AI 에게 보낸 요청문(prompt.txt)을 화면에서 그대로 볼 수 있게 한다 — '정답(기대 결과)을 AI 에게 흘렸나' 를 사람이 직접 확인하게
(교수 피드백 10-31 '짜고 치기' 대응). 응답 원문(response.json)도 같은 이유로 연다.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

RUN_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")


def _root() -> Path:
    from .. import app as _app
    return _app.ROOT


def runs_dir() -> Path:
    from ..llmfix import runs_root
    return runs_root(_root())


def _read(p: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def runs(set_id: str = "", limit: int = 30) -> Dict[str, Any]:
    d = runs_dir()
    out: List[Dict[str, Any]] = []
    if d.is_dir():
        for x in sorted(d.iterdir(), reverse=True):
            if not RUN_RE.match(x.name):
                continue
            r = _read(x / "run.json")
            if not r or (set_id and r.get("set_id") != set_id):
                continue
            # 시도마다 따로 (⑤ 후보 버튼 — 6차 · D-34: AI 시도 하나 = 후보 하나, 누르면 그 시도의 적용 후 그림)
            atts = [{k: a.get(k) for k in ("n", "status", "record_id", "title", "error")} for a in r.get("attempts") or [] if isinstance(a, dict)]
            out.append({k: r.get(k) for k in ("run_id", "set_id", "context", "status", "status_ko", "next", "exit_code", "started_at", "finished_at", "max_attempts", "final_record_id", "design", "error")}
                       | {"n_attempts": len(atts), "attempts": atts})
            if len(out) >= limit:
                break
    return {"runs": out}


def run_view(run_id: str) -> Dict[str, Any]:
    if not RUN_RE.match(str(run_id or "")):
        return {"error": "실행 id 형식이 아님"}
    r = _read(runs_dir() / run_id / "run.json")
    if r is None:
        return {"error": f"AI 수정 실행 없음: {run_id}"}
    # 실행 자체의 오류 글(AI 오류 · 같은 수정안 반복 · 실행 오류 · 검증 불가 이유)은 run_error 로 — API 오류(error)와 섞이면 화면이 기록을 못 연다 (D-36)
    out = dict(r)
    out["run_error"] = out.pop("error", None)
    out["ok"] = True
    return out


def attempt_text(run_id: str, n: int, what: str) -> Dict[str, Any]:
    """what: prompt(요청문) · response(응답 원문). 지문(sha256)도 같이 — 기록의 prompt_sha256 과 같은지 화면에서 비교할 수 있게."""
    import hashlib
    if not RUN_RE.match(str(run_id or "")) or what not in ("prompt", "response"):
        return {"error": "요청 형식이 아님"}
    p = runs_dir() / run_id / f"attempt-{int(n)}" / ("prompt.txt" if what == "prompt" else "response.json")
    try:
        raw = p.read_bytes()
    except OSError:
        return {"error": "파일 없음"}
    text = raw.decode("utf-8", "replace")
    if what == "response":
        try:
            j = json.loads(text)
            if isinstance(j, list):
                j = next((x for x in reversed(j) if isinstance(x, dict) and x.get("type") == "result"), {})
            text = str(j.get("result") or text)
        except ValueError:
            pass
    return {"run_id": run_id, "n": int(n), "what": what, "text": text[:200_000], "sha256": hashlib.sha256(raw).hexdigest()}
