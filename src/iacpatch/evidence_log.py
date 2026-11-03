"""실행 기록 — 검사 단계마다 '실제로 무엇을 실행했는가' 를 남긴다 (commands.json).

화면의 '탐지 방식' 카드는 이 기록을 그대로 보여 준다. 사람이 쓴 설명이 아니라 실행한 명령(argv)·시작 시각·걸린 시간·
종료 코드·출력 끝부분·결과 파일이다. 캐시를 재사용한 단계는 cached=True 와 캐시가 처음 만들어진 시각을 남긴다
(재사용을 새 실행처럼 보이게 하지 않는다).

파일에 쓰는 시점: 항목을 추가할 때마다 (검사가 도는 중에도 화면이 지금까지 실행된 명령을 읽을 수 있게).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


def now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(p: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _tail(text: Optional[str], n: int) -> str:
    t = text or ""
    return t if len(t) <= n else "…" + t[-n:]


class CommandLog:
    """한 검사 묶음(local_verify, 배포 후 측정, 탐지기 점검)의 실행 기록."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.items: List[Dict[str, Any]] = []
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, step: str, layer: str, argv: Optional[List[str]], *, cwd: Optional[str] = None,
            returncode: Optional[int] = None, started_at: str = "", elapsed: Optional[float] = None,
            stdout: str = "", stderr: str = "", output: Optional[Path] = None, cached: bool = False,
            cache_created_at: Optional[str] = None, ok: Optional[bool] = None, note: str = "") -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "step": step, "layer": layer, "argv": list(argv) if argv else None, "cwd": cwd,
            "started_at": started_at or now_iso(), "elapsed_s": elapsed, "returncode": returncode, "ok": ok,
            "stdout_tail": _tail(stdout, 1500), "stderr_tail": _tail(stderr, 1500),
            "cached": cached, "cache_created_at": cache_created_at, "note": note,
        }
        if output is not None:
            op = Path(output)
            entry["output"] = op.name
            entry["output_sha256"] = sha256_file(op) if op.exists() else None
            entry["output_bytes"] = op.stat().st_size if op.exists() else None
        self.items.append(entry)
        self.flush()
        return entry

    def flush(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"schema": "iacpatch-commands-v1", "commands": self.items}, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)


def load_commands(path: Path) -> List[Dict[str, Any]]:
    try:
        return list((json.loads(Path(path).read_text(encoding="utf-8")) or {}).get("commands") or [])
    except (OSError, ValueError):
        return []


def write_manifest(record_dir: Path, extra: Optional[Dict[str, Any]] = None) -> Path:
    """기록 폴더의 모든 파일 해시 목록 (evidence/manifest.json). '남는 것' 의 목록이자, 나중에 파일이 바뀌었는지 확인하는 기준.
    작업 복사본(local_verify/work/)은 크고 다시 만들 수 있어 제외한다."""
    record_dir = Path(record_dir)
    files: List[Dict[str, Any]] = []
    for p in sorted(record_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(record_dir).as_posix()
        if rel.startswith("local_verify/work/") or rel.startswith("evidence/manifest"):
            continue
        files.append({"path": rel, "bytes": p.stat().st_size, "sha256": sha256_file(p)})
    doc = {"schema": "iacpatch-evidence-manifest-v1", "record": record_dir.name, "created_at": now_iso(), "files": files}
    if extra:
        doc.update(extra)
    out = record_dir / "evidence" / "manifest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
