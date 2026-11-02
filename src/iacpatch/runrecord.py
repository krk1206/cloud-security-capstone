"""실행 기록 (Run Record).

실행마다 data/runs/<timestamp>-<id>/ 아래에 입력·출력·사용 모델·프롬프트 버전·검증 결과를 남긴다.
원본 코드와 패치 후보는 분리 저장한다 (baseline_files.json vs candidates/<n>/files/).
API 키 등 비밀값은 어떤 파일에도 쓰지 않는다 (redact 로 환경변수 이름만 기록).

레이아웃
  run.json                     요약 (상태, 단계별 결과, 결정, 시간)
  settings.json                사용 설정 (비밀값 없음)
  bundle.json                  Evidence Bundle
  baseline_files.json          원본 파일 스냅샷 (복구용)
  trivy_before.json            원본 스캔 원문
  plan_baseline.json           원본 plan JSON
  candidates/<n>/candidate.json, files/<name>, llm_raw_response.txt, trivy_after.json, plan_candidate.json,
                  verification.json, policy.json
  risk.json / gate.json / pr_body.md / timings.json
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from .config import SECRET_ENV_NAMES
from .textio import write_text_lf


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def redact(obj: Any) -> Any:
    """dict/list 안에서 비밀값처럼 보이는 키를 지운다."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if any(s in lk for s in ("api_key", "apikey", "secret", "token", "password", "authorization")):
                out[k] = "<redacted>"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


class RunRecord:
    def __init__(self, data_dir: str | Path, run_id: Optional[str] = None, label: str = "predeploy"):
        self.data_dir = Path(data_dir)
        self.run_id = run_id or f"{_dt.datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        self.dir = self.data_dir / self.run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.started = time.time()
        self.timings: Dict[str, float] = {}
        self._t0: Dict[str, float] = {}
        self.summary: Dict[str, Any] = {
            "run_id": self.run_id, "label": label, "started_at": _now_iso(), "status": "RUNNING",
            "steps": [], "secrets_policy": "API keys are read from environment variables only; never written to this record",
            "env_keys_present": {k: bool(os.environ.get(k)) for k in SECRET_ENV_NAMES},  # 값이 아니라 존재 여부만
        }

    # -- 파일 --------------------------------------------------------------
    def write_json(self, rel: str, obj: Any) -> Path:
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(redact(obj), ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return p

    def write_text(self, rel: str, text: str) -> Path:
        return write_text_lf(self.dir / rel, text)   # LF 고정 (textio.py)

    def candidate_dir(self, attempt: int) -> Path:
        d = self.dir / "candidates" / f"{attempt:02d}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    # -- 단계/시간 ----------------------------------------------------------
    def step(self, name: str, status: str, note: str = "", **extra: Any) -> None:
        self.summary["steps"].append({"step": name, "status": status, "note": note, "at": _now_iso(), **extra})

    def start_timer(self, key: str) -> None:
        self._t0[key] = time.time()

    def stop_timer(self, key: str) -> float:
        t = time.time() - self._t0.pop(key, time.time())
        self.timings[key] = self.timings.get(key, 0.0) + t
        return t

    def finish(self, status: str, **fields: Any) -> Path:
        self.summary.update(fields)
        self.summary["status"] = status
        self.summary["finished_at"] = _now_iso()
        self.summary["automated_seconds_total"] = round(time.time() - self.started, 3)
        self.summary["timings_seconds"] = {k: round(v, 3) for k, v in self.timings.items()}
        self.write_json("timings.json", self.summary["timings_seconds"])
        return self.write_json("run.json", self.summary)
