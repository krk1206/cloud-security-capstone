"""새 빌드 받기 — GitHub Release `dev-latest` (build-exe 워크플로가 브랜치 빌드마다 갱신) 에서 IaCPatch-portable.zip 을 받아
옆 폴더(IaCPatch-<sha7>)에 풀고, 지금 폴더의 tools\\ 와 data\\(기록·원본 캐시)를 복사한 뒤 새 exe 를 띄운다.

왜: 팀원 PC 에서 "Actions 로그인 → 아티팩트 받기 → 풀기 → tools 복사 → 다시 실행" 을 버튼 하나로 (B, 2026-09-29: "수정하고 또 붙여놓고 하기 귀찮다").
Release 자산은 로그인 없이 받아진다. 받은 zip 은 latest.json 의 sha256 과 대조한 뒤에만 푼다 (다른 파일이면 중단).

하지 않는 것: 지금 폴더를 덮어쓰기(실행 중인 exe 는 못 바꾸고, 옛 파일과 섞이면 설치 검사가 막는다), git push, 자동 실행 예약.
소스로 돌 때(python -m iacpatch.app)는 새 폴더에 받기만 하고 실행은 하지 않는다.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, Optional

DEFAULT_UPDATE_URL = "https://github.com/krk1206/cloud-security-capstone/releases/download/dev-latest"
ZIP_NAME = "IaCPatch-portable.zip"
INFO_NAME = "latest.json"
COPY_DIRS = ("tools", "data")            # 새 폴더로 가져갈 것: 도구 바이너리, 실험 기록, 원본(baseline) 캐시 (provider 템플릿은 크므로 제외)
SKIP_UNDER_DATA = ("cache/tf-template", "cache/tf-template.tmp")


def build_info() -> Dict[str, Any]:
    """이 실행 파일이 어느 커밋으로 만들어졌나. exe 면 PyInstaller 에 넣은 build_info.json, 소스면 src/iacpatch/build_info.json(빌드 때 생성) 또는 git."""
    cands = []
    mp = getattr(sys, "_MEIPASS", "")
    if mp:
        cands.append(Path(mp) / "iacpatch" / "build_info.json")
    cands.append(Path(__file__).resolve().parent / "build_info.json")
    for p in cands:
        try:
            if p.exists():
                d = json.loads(p.read_text(encoding="utf-8"))
                d.setdefault("source", "build_info.json")
                return d
        except (OSError, ValueError):
            pass
    root = Path(__file__).resolve().parents[2]
    if (root / ".git").exists():
        try:
            sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root), capture_output=True, text=True, timeout=10).stdout.strip()
            if sha:
                return {"sha": sha, "built_at": None, "source": "git"}
        except (OSError, subprocess.TimeoutExpired):
            pass
    return {"sha": None, "built_at": None, "source": "unknown"}


def _fetch(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "IaCPatch-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec - 팀 저장소의 Release 자산
        return r.read()


def check(update_url: str = DEFAULT_UPDATE_URL, fetch: Callable[[str], bytes] = _fetch) -> Dict[str, Any]:
    """latest.json 을 읽어 지금 빌드와 비교한다. 네트워크 실패는 error 로 돌려준다 (예외 없음)."""
    cur = build_info()
    out: Dict[str, Any] = {"current": cur, "update_url": update_url, "latest": None, "newer": False, "error": None}
    try:
        latest = json.loads(fetch(update_url.rstrip("/") + "/" + INFO_NAME).decode("utf-8"))
    except urllib.error.HTTPError as e:
        out["error"] = f"HTTP {e.code} — Release 'dev-latest' 가 아직 없거나 주소가 다르다 ({update_url})"
        return out
    except (urllib.error.URLError, OSError, ValueError) as e:
        out["error"] = f"접속 실패: {e}"
        return out
    out["latest"] = latest
    out["newer"] = bool(latest.get("sha")) and latest.get("sha") != cur.get("sha")
    return out


def _sha7(sha: Optional[str]) -> str:
    return (sha or "unknown")[:7]


def install(root: Path, update_url: str = DEFAULT_UPDATE_URL, log: Callable[[str], None] = print, fetch: Callable[[str], bytes] = _fetch,
            launch: bool = True, dest_parent: Optional[Path] = None) -> Dict[str, Any]:
    """새 빌드를 옆 폴더에 받아 풀고 tools/data 를 복사한 뒤 (exe 면) 새 exe 를 띄운다. 결과 dict: dest, sha, launched."""
    info = check(update_url, fetch)
    if info["error"]:
        raise RuntimeError(info["error"])
    latest = info["latest"] or {}
    sha = latest.get("sha")
    if not info["newer"]:
        log(f"이미 최신 빌드다: {_sha7(build_info().get('sha'))}")
        return {"dest": None, "sha": sha, "launched": False, "up_to_date": True}
    log(f"최신 빌드 {_sha7(sha)} ({latest.get('built_at', '?')}) ← 지금 {_sha7(build_info().get('sha'))}")
    zip_url = update_url.rstrip("/") + "/" + (latest.get("zip") or ZIP_NAME)
    log(f"받는 중: {zip_url}")
    data = fetch(zip_url)
    digest = hashlib.sha256(data).hexdigest()
    want = latest.get("sha256")
    if want and digest != want:
        raise RuntimeError(f"받은 zip 의 sha256 이 latest.json 과 다르다 — 풀지 않는다. ({digest[:12]}… ≠ {want[:12]}…)")
    log(f"받음 {len(data) / 1e6:.1f} MB, sha256 {'확인' if want else '(latest.json 에 없음 — 대조 생략)'}")
    parent = dest_parent or root.parent
    dest = parent / f"IaCPatch-{_sha7(sha)}"
    n = 1
    while dest.exists():
        n += 1
        dest = parent / f"IaCPatch-{_sha7(sha)}-{n}"
    dest.mkdir(parents=True)
    tmp_zip = dest / "_portable.zip"
    tmp_zip.write_bytes(data)
    with zipfile.ZipFile(tmp_zip) as z:
        raw_names = z.namelist()
        names = [n.replace("\\", "/") for n in raw_names]        # Windows 도구가 만든 zip 은 '\' 구분자일 수 있다
        by_norm = dict(zip(names, raw_names))
        # zip 루트에 policy/ 가 바로 있어야 한다 (아티팩트 포장 방식). 한 겹 폴더 안에 있으면 그 안을 루트로
        prefix = ""
        if not any(nm.startswith("policy/") for nm in names):
            tops = {nm.split("/")[0] for nm in names if "/" in nm}
            if len(tops) == 1:
                prefix = tops.pop() + "/"
        for nm in names:
            if not nm.startswith(prefix) or nm.endswith("/"):
                continue
            rel = nm[len(prefix):]
            if not rel:
                continue
            if ".." in rel.split("/") or rel.startswith("/"):
                continue                                          # zip 안의 이상한 경로는 무시
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(by_norm[nm]) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
    tmp_zip.unlink()
    if not (dest / "policy" / "patch_policy.json").exists():
        raise RuntimeError(f"푼 폴더에 policy/patch_policy.json 이 없다 — zip 구조가 다르다: {dest}")
    log(f"풀었음: {dest}")
    for d in COPY_DIRS:
        src = root / d
        if not src.is_dir():
            continue
        copied = _copy_tree(src, dest / d)
        log(f"복사: {d}\\ ({copied}개 파일)")
    exe_name = "IaCPatch.exe" if platform.system() == "Windows" else None
    launched = False
    if launch and getattr(sys, "frozen", False) and exe_name and (dest / exe_name).exists():
        try:
            subprocess.Popen([str(dest / exe_name)], cwd=str(dest), close_fds=True,
                             creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
            launched = True
            log(f"새 exe 실행: {dest / exe_name} — 새 탭이 열리면 이 창은 닫아도 된다. 앞으로는 새 폴더를 쓴다.")
        except OSError as e:
            log(f"새 exe 실행 실패: {e} — 직접 더블클릭: {dest / exe_name}")
    elif launch:
        log(f"소스로 돌고 있어 실행은 하지 않는다. 새 폴더: {dest}")
    return {"dest": str(dest), "sha": sha, "launched": launched, "up_to_date": False}


def _copy_tree(src: Path, dst: Path) -> int:
    n = 0
    for p in src.rglob("*"):
        rel = p.relative_to(src)
        rel_s = str(rel).replace("\\", "/")
        if src.name == "data" and any(rel_s == s or rel_s.startswith(s + "/") for s in SKIP_UNDER_DATA):
            continue
        t = dst / rel
        if p.is_dir():
            t.mkdir(parents=True, exist_ok=True)
        elif p.is_file():
            t.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(p, t)
                n += 1
            except OSError:
                pass
    return n


def main(argv: Optional[list] = None) -> int:
    """`IaCPatch-console.exe --update` / `python -m iacpatch.update`: 확인만 하려면 --check."""
    import argparse
    from .app import ROOT
    ap = argparse.ArgumentParser(description="IaCPatch 새 빌드 받기 (GitHub Release dev-latest)")
    ap.add_argument("--check", action="store_true", help="확인만")
    ap.add_argument("--url", default=os.environ.get("IACPATCH_UPDATE_URL", DEFAULT_UPDATE_URL))
    ap.add_argument("--no-launch", action="store_true")
    a = ap.parse_args(argv)
    info = check(a.url)
    print(f"지금 빌드: {_sha7(info['current'].get('sha'))} ({info['current'].get('source')})")
    if info["error"]:
        print(info["error"]); return 2
    print(f"최신 빌드: {_sha7(info['latest'].get('sha'))} ({info['latest'].get('built_at', '?')}) → {'새 빌드 있음' if info['newer'] else '같음'}")
    if a.check or not info["newer"]:
        return 0
    install(ROOT, a.url, launch=not a.no_launch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
