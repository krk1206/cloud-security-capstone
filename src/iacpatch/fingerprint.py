"""재실행 회피용 지문(fingerprint) — "같은 입력·같은 정책·같은 코드·같은 도구" 를 sha256 하나로.

후보 세트를 다시 돌릴 때, 지문이 같은 이전 기록이 있으면 그 기록을 재사용한다 (scripts/run_candidate_set.py).
지문에 들어가는 것: 세트/후보 식별자, 원본 tf_dir 내용, 후보 파일 내용, Trivy 입력 스캔, intent, 정책 3파일, iacpatch 코드 전체,
도구 버전(로컬 도구 실행 시). 이 중 하나라도 바뀌면 지문이 달라져 다시 돌린다. 판정 결과는 지문에 넣지 않는다.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

_SKIP_DIRS = {".terraform", ".git", "__pycache__"}
_SKIP_SUFFIX = (".tfstate", ".tfstate.backup", ".tfplan", "plan.bin", "plan.json")


def tree_digest(root: Path, suffixes: Optional[tuple] = None) -> str:
    """디렉터리 내용의 sha256 (상대 경로 + 바이트). .terraform/, 상태·plan 파일 제외. suffixes 를 주면 그 확장자만."""
    h = hashlib.sha256()
    if not root.is_dir():
        return "missing:" + str(root)
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if not p.is_file() or any(part in _SKIP_DIRS for part in rel.parts) or p.name.endswith(_SKIP_SUFFIX):
            continue
        if suffixes and not p.name.endswith(suffixes):
            continue
        h.update(rel.as_posix().encode("utf-8") + b"\0")
        h.update(p.read_bytes() + b"\0")
    return h.hexdigest()


def file_digest(path: Optional[str | Path]) -> str:
    if not path:
        return "none"
    p = Path(path)
    if not p.is_file():
        return "missing:" + str(path)
    return hashlib.sha256(p.read_bytes()).hexdigest()


# 판정에 영향이 없는 모듈(실행기·리포트·집계·CLI·배포 후)은 지문에서 뺀다 — 화면만 고쳤는데 실험 전체가 다시 도는 일을 막기 위해.
_NON_JUDGING = {"app.py", "report_html.py", "metrics.py", "cli.py", "postdeploy.py", "__main__.py"}


def code_digest(repo_root: Path) -> str:
    """src/iacpatch 의 판정 관련 .py + 프롬프트 파일. 코드가 바뀌면 이전 판정을 재사용하지 않기 위해."""
    root = repo_root / "src" / "iacpatch"
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if not p.is_file() or "__pycache__" in rel.parts or not p.name.endswith((".py", ".md", ".json")):
            continue
        if len(rel.parts) == 1 and p.name in _NON_JUDGING:
            continue
        h.update(rel.as_posix().encode("utf-8") + b"\0")
        h.update(p.read_bytes() + b"\0")
    return h.hexdigest()


def combine(parts: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()
