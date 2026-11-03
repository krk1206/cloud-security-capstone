"""프로그램 · 소스 · 정책 버전 한 묶음 (D-37, 2026-11-02 — 검토 문서 1번 "소스 · 실행 파일 · CI 결과가 같은 버전인지 확인할 수 있어야").

무엇을 식별하나
  - program_version : 사람이 읽는 판 번호 (PROGRAM_VERSION). 화면 개편 차수와 맞춘다.
  - build           : exe 를 만들 때 넣은 build_info.json — 커밋(sha) · 빌드 시각 · 그때의 소스 지문(src_fingerprint).
  - src_fingerprint : src/iacpatch 의 코드 · 화면 파일 · policy/ 의 내용을 전부 합친 sha256 앞 12자리. git 이 없어도 계산되고,
                      커밋하지 않은 수정도 반영된다 (커밋 번호만으로는 '커밋 안 한 6주치 수정' 을 구분하지 못했다 — 2026-11-02 실측).
  - git_head        : 지금 폴더의 .git/HEAD 가 가리키는 커밋 (git 실행 파일 없이 파일만 읽음) — PC 에 git 이 PATH 에 없어도 보인다.
  - policy_version · rubric_version · prompt_version : 판정 규칙의 판.
  - stale_exe       : exe 안의 소스 지문 ≠ 옆 폴더 src 의 지문 → exe 를 다시 빌드하지 않은 상태 (화면에 경고).

쓰는 곳: /api/app(① 준비 상태 · ⑧) · 검사 기록 state.json["provenance"] · AI 실행 run.json["provenance"] · PR 요약.
여기서 판정은 하지 않는다. 값을 모으기만 한다.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

PROGRAM_VERSION = "0.7.0"          # 7차 화면(2026-11-02). 바꾸면 src/iacpatch/__init__.py 의 __version__ 도 같이

# 지문에 넣는 파일: 프로그램 동작을 정하는 것만. 기록(data/) · 실험 입력(experiments/) · 문서는 넣지 않는다
FINGERPRINT_PARTS: Dict[str, Iterable[str]] = {
    "src/iacpatch": ("*.py", "*.md", "*.html", "*.js", "*.css", "*.svg", "*.json"),
    "policy": ("*.json", "*.md"),
}
EXCLUDE_NAMES = {"build_info.json", "__pycache__"}


def _files(root: Path) -> list:
    out = []
    for rel, pats in FINGERPRINT_PARTS.items():
        base = root / rel
        if not base.is_dir():
            continue
        for pat in pats:
            for p in base.rglob(pat):
                if any(part in EXCLUDE_NAMES for part in p.relative_to(root).parts) or not p.is_file():
                    continue
                out.append(p)
    return sorted(set(out), key=lambda p: p.relative_to(root).as_posix())


def source_fingerprint(root: Path) -> Optional[str]:
    """src/iacpatch + policy 의 내용 지문 (sha256 앞 12자리). 줄바꿈(CRLF/LF) 차이는 같은 것으로 본다 — Windows 체크아웃과 같은 값이 나오게."""
    files = _files(root)
    if not files:
        return None
    h = hashlib.sha256()
    for p in files:
        try:
            data = p.read_bytes().replace(b"\r\n", b"\n")
        except OSError:
            continue
        h.update(p.relative_to(root).as_posix().encode("utf-8") + b"\0" + data + b"\0")
    return h.hexdigest()[:12]


def git_head(root: Path) -> Dict[str, Any]:
    """git 실행 파일 없이 .git 파일만 읽는다: HEAD → ref → refs/heads/<branch> 또는 packed-refs. 못 읽으면 sha None."""
    g = root / ".git"
    out: Dict[str, Any] = {"sha": None, "branch": None}
    try:
        if g.is_file():                                   # worktree: 'gitdir: <path>'
            txt = g.read_text(encoding="utf-8", errors="replace").strip()
            if txt.startswith("gitdir:"):
                g = (root / txt.split(":", 1)[1].strip()).resolve()
        head = (g / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return out
    common = g
    try:                                                  # worktree 의 .git/worktrees/<이름>/commondir → refs 는 본 저장소에 있다
        if (g / "commondir").is_file():
            common = (g / (g / "commondir").read_text(encoding="utf-8", errors="replace").strip()).resolve()
    except OSError:
        pass
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        out["branch"] = ref.split("/", 2)[-1] if ref.startswith("refs/heads/") else ref
        try:
            out["sha"] = (common / ref).read_text(encoding="utf-8", errors="replace").strip() or None
        except OSError:
            try:
                for line in (common / "packed-refs").read_text(encoding="utf-8", errors="replace").splitlines():
                    parts = line.strip().split()
                    if len(parts) == 2 and parts[1] == ref:
                        out["sha"] = parts[0]
                        break
            except OSError:
                pass
    else:
        out["sha"] = head or None                          # detached HEAD
    return out


def _policy_versions(root: Path) -> Dict[str, Any]:
    out: Dict[str, Any] = {"policy_version": None, "rubric_version": None}
    for key, rel, field in (("policy_version", "policy/patch_policy.json", "policy_version"), ("rubric_version", "policy/risk_rubric.json", "rubric_version")):
        try:
            out[key] = json.loads((root / rel).read_text(encoding="utf-8")).get(field)
        except (OSError, ValueError):
            pass
    return out


def provenance(root: Path, tools: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """한 묶음. root = 저장소(프로그램) 폴더. tools = app.tool_status() 결과(있으면 버전만 옮긴다)."""
    try:
        from .update import build_info
        build = build_info()
    except Exception as e:  # 화면 · 기록이 이 때문에 죽지 않게
        build = {"sha": None, "error": str(e)}
    frozen = bool(getattr(sys, "frozen", False))
    now_fp = source_fingerprint(root)
    build_fp = build.get("src_fingerprint")
    out: Dict[str, Any] = {
        "program_version": PROGRAM_VERSION,
        "frozen": frozen,
        "build": {k: build.get(k) for k in ("sha", "built_at", "src_fingerprint", "version", "ref", "source")},
        "git_head": git_head(root),
        "src_fingerprint": now_fp,
        # exe 로 돌 때: exe 안 코드의 지문(build) 과 옆 폴더 src 의 지문(now)이 다르면 exe 가 옛 코드다 (다시 빌드 필요)
        "stale_exe": bool(frozen and build_fp and now_fp and build_fp != now_fp),
        "prompt_version": None,
    }
    try:
        from .llmfix import PROMPT_VERSION
        out["prompt_version"] = PROMPT_VERSION
    except Exception:
        pass
    out.update(_policy_versions(root))
    if tools:
        out["tools"] = {k: (v or {}).get("version") for k, v in tools.items()}
    return out


def short(p: Dict[str, Any]) -> str:
    """한 줄 표시: 'v0.7.0 · 커밋 9e95775 · 소스 지문 a1b2c3d4e5f6 · 빌드 2026-11-02 15:06Z'."""
    b = p.get("build") or {}
    sha = b.get("sha") or (p.get("git_head") or {}).get("sha") or ""
    parts = [f"v{p.get('program_version', '?')}"]
    parts.append(f"커밋 {sha[:7]}" if sha else "커밋 없음")
    fp = b.get("src_fingerprint") or p.get("src_fingerprint")
    if fp:
        parts.append(f"소스 지문 {fp}")
    if b.get("built_at"):
        parts.append(f"빌드 {str(b['built_at']).replace('T', ' ')[:16]}")
    return " · ".join(parts)


def main(argv: Optional[list] = None) -> int:
    """`python -m iacpatch.version [--root R] [--fingerprint | --json]` — 빌드 스크립트(packaging/build_exe.ps1)가 지문을 받아 build_info.json 에 넣는다."""
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--fingerprint", action="store_true", help="소스 지문만 출력")
    ap.add_argument("--json", action="store_true", help="묶음 전체를 JSON 으로")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve() if a.root else Path(__file__).resolve().parents[2]
    if a.fingerprint:
        print(source_fingerprint(root) or "")
        return 0
    p = provenance(root)
    print(json.dumps(p, ensure_ascii=False, indent=1) if a.json else short(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
