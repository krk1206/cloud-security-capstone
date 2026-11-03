"""화면에서 제출한 Terraform 파일 처리 — .tf 여러 개 · 폴더 (교수 피드백 7, 2026-10-31).

제출 코드는 검사 대상이지 신뢰된 프로그램이 아니다. 그래서
- 저장소의 원본 폴더에 쓰지 않는다. data/cache/submissions/<id>/ 에 따로 두고, 검사는 그 사본으로만 한다
  (검사 중 Terraform 은 기록 폴더의 작업 복사본에서 돈다 — review/local_verify.py).
- 경로는 상대 경로 그대로 보존한다 (평평하게 합치지 않는다). 절대 경로 · '..' · 숨김 폴더(.terraform 등)는 받지 않는다.
- .tf 만 검사에 쓴다. 다른 파일은 '검사에 안 씀 + 이유' 로 목록에 남긴다 — 조용히 빼지 않는다.
- 지금 사례들은 하위 폴더가 없는 단일 폴더(루트 모듈) 구조라, 하위 폴더 파일은 검사에 쓰지 않고 이유를 적는다.
- 원본에 없는 파일 이름도 후보에 넣는다 — 후보 검사(새 파일 금지)가 기록과 함께 막는다.
- 원본과 내용이 같은 파일은 '변경 없음' 으로 표시하고 후보에서 뺀다.
- 실행 전 안전 점검(policy/validator.exec_guard)은 검사 시작 뒤, Trivy·Terraform 실행 전에 돈다.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

MAX_FILES = 300            # 폴더째 올렸을 때 .tf 아닌 파일까지 센 수
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 6_000_000


def _norm_text(t: str) -> str:
    return t.replace("\r\n", "\n").replace("\r", "\n")


def _rel(raw: str, folder: bool) -> Optional[PurePosixPath]:
    """브라우저가 준 경로 → 사례 폴더 기준 상대 경로. 폴더째 올리면 맨 앞(고른 폴더 이름)을 뗀다. 쓸 수 없으면 None."""
    p = str(raw or "").replace("\\", "/").strip()
    if not p or p.startswith("/") or (len(p) > 1 and p[1] == ":"):
        return None
    parts = [x for x in p.split("/") if x not in ("", ".")]
    if any(x == ".." for x in parts):
        return None
    if folder and len(parts) > 1:
        parts = parts[1:]
    return PurePosixPath(*parts) if parts else None


def analyze(tf_dir: Path, files: Any, folder: bool) -> Dict[str, Any]:
    """제출 파일 목록 → 파일별 상태와, 후보로 쓸 파일(이름 → 내용). 내용은 바꾸지 않는다 (줄바꿈 비교만 정규화)."""
    if not isinstance(files, list) or not files:
        return {"ok": False, "error": "제출한 파일 없음", "files": [], "candidate_files": {}}
    if len(files) > MAX_FILES:
        return {"ok": False, "error": f"파일 {len(files)}개 — 한 번에 {MAX_FILES}개까지", "files": [], "candidate_files": {}}
    original = {p.name: p.read_text(encoding="utf-8") for p in sorted(tf_dir.glob("*.tf")) if p.is_file() and not p.name.startswith("zz_iacpatch_")}
    out: List[Dict[str, Any]] = []
    cand: Dict[str, str] = {}
    seen = set()
    total = 0
    for f in files:
        f = f if isinstance(f, dict) else {}
        raw_path = str(f.get("path") or "")
        content = f.get("content")
        row: Dict[str, Any] = {"path": raw_path, "status": "excluded", "reason": "", "bytes": None, "sha256": None, "used_as": None}
        out.append(row)
        if f.get("aggregated"):
            # 화면이 숨김 폴더(.terraform · .git 등)를 폴더 하나로 묶어 보낸 줄 — 내용 없이 목록에만 남긴다
            row["reason"] = f"숨김 폴더 — 검사에 안 씀 (파일 {int(f.get('count') or 0)}개)"
            continue
        # 1) 경로부터 본다 (검사에 안 쓰는 파일은 내용을 받지 않아도 이유를 적을 수 있게)
        rel = _rel(raw_path, folder)
        if rel is None:
            row["status"], row["reason"] = "rejected", "허용되지 않는 경로 (절대 경로 · '..' 포함)"
            continue
        row["path"] = rel.as_posix()
        if rel.as_posix() in seen:
            row["reason"] = "같은 경로가 두 번 제출됨 — 첫 번째만 사용"
            continue
        seen.add(rel.as_posix())
        if any(part.startswith(".") for part in rel.parts):
            row["reason"] = "숨김 폴더·파일 (.terraform · .git · 잠금 파일 등) — 검사에 안 씀"
            continue
        if not rel.name.lower().endswith(".tf"):
            row["reason"] = ("변수 값 파일(.tfvars)은 지원 안 함 — 원본 변수 기본값으로 검사" if rel.name.lower().endswith(".tfvars")
                             else ".tf 파일 아님 — 검사에 안 씀")
            continue
        if len(rel.parts) > 1:
            row["reason"] = "하위 폴더 파일 — 이 사례는 단일 폴더(루트 모듈) 구조라 검사에 안 씀"
            continue
        # 2) 내용
        if not isinstance(content, str):
            size = f.get("size")
            row["status"] = "rejected"
            row["reason"] = (f"파일 크기 {int(size):,} bytes — 한도 {MAX_FILE_BYTES:,} bytes" if isinstance(size, (int, float)) and size > MAX_FILE_BYTES
                             else "내용을 읽지 못함 (텍스트 파일 아님)")
            continue
        data = content.encode("utf-8")
        row["bytes"], row["sha256"] = len(data), hashlib.sha256(data).hexdigest()
        total += len(data)
        if "\x00" in content:
            row["status"], row["reason"] = "rejected", "텍스트(UTF-8) 파일 아님"
            continue
        if len(data) > MAX_FILE_BYTES:
            row["status"], row["reason"] = "rejected", f"파일 크기 {len(data):,} bytes — 한도 {MAX_FILE_BYTES:,} bytes"
            continue
        name = rel.name
        if name in original and _norm_text(original[name]) == _norm_text(content):
            row["status"], row["reason"] = "same", "원본과 같음 — 바뀐 내용 없음"
            continue
        if name in original:
            row["status"], row["used_as"] = "changed", name
        else:
            row["status"], row["used_as"] = "new", name
            row["reason"] = "원본에 없는 파일 — 정책상 새 파일은 허용 안 됨 (검사에서 차단되고 기록됨)"
        cand[name] = content
    if total > MAX_TOTAL_BYTES:
        return {"ok": False, "error": f"전체 {total:,} bytes — 한 번에 {MAX_TOTAL_BYTES:,} bytes 까지", "files": out, "candidate_files": {}}
    from ..review.change_summary import summarize
    summary = summarize(original, cand)["text"] if cand else ""
    return {"ok": bool(cand), "error": "" if cand else "검사할 변경 파일 없음 (모두 원본과 같거나 검사에 안 쓰는 파일)",
            "files": out, "candidate_files": cand, "summary": summary,
            "originals": {n: original[n] for n in cand if n in original}}


def public_view(res: Dict[str, Any]) -> Dict[str, Any]:
    """화면에 돌려줄 것: 파일별 상태 + 바뀐 파일의 원본 내용(화면이 차이를 그리게). 제출 내용은 다시 보내지 않는다."""
    return {"ok": res.get("ok"), "error": res.get("error"), "files": res.get("files") or [], "summary": res.get("summary", ""),
            "originals": res.get("originals") or {}}


def store(root: Path, res: Dict[str, Any], set_id: str) -> Path:
    """검사에 쓸 파일만 따로 저장 (저장소 원본 폴더 밖). 돌려주는 폴더를 manual:<폴더> 후보로 쓴다."""
    sid = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    d = root / "data" / "cache" / "submissions" / sid
    (d / "files").mkdir(parents=True, exist_ok=False)
    for name, content in (res.get("candidate_files") or {}).items():
        if "/" in name or "\\" in name or name.startswith("."):
            continue                                   # analyze 가 이미 막는다 — 여기서도 한 번 더
        (d / "files" / name).write_bytes(content.encode("utf-8"))
    meta = {"id": sid, "set_id": set_id, "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": "upload",
            "files": res.get("files") or [], "summary": res.get("summary", "")}
    (d / "submission.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return d
