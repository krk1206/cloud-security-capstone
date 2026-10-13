"""Policy Validator — 패치 후보가 허용된 변경 범위 안인지 (등급과 무관하게) 검사한다.

검사 항목 (patch_policy.json):
  1. 파일 경로: 상대 경로, 상위 이동(..) 금지, 편집 가능 glob(*.tf)만, 보호 파일/경로 금지
  2. 파일 수·크기 제한, 새 파일 생성 금지(allow_new_files=false)
  3. 금지 토큰이 **새로 도입**됐는지 (provisioner, local-exec, backend, null_resource ...)
  4. terraform / provider 최상위 블록이 변경됐는지 (블록 단위 텍스트 비교)
  5. diff 통계 (Risk Rubric 입력)

이 검사는 구문 수준 가드다. Terraform 의미 수준 검사는 V5(plan diff) 가 맡는다.
"""
from __future__ import annotations

import difflib
import fnmatch
import re
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

from ..models import PatchCandidate, PolicyResult

_BLOCK_HEADER_RE = re.compile(r'^\s*(terraform|provider|resource|data|variable|output|locals|module)\b([^{]*)\{', re.M)


def extract_top_level_blocks(text: str) -> List[Tuple[str, str]]:
    """최상위 블록을 (헤더, 본문) 으로. 중괄호 매칭은 문자열/주석을 건너뛴다 (휴리스틱)."""
    blocks: List[Tuple[str, str]] = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _BLOCK_HEADER_RE.search(text, pos)
        if not m:
            break
        i = m.end()
        depth = 1
        in_str = False
        esc = False
        while i < n and depth > 0:
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "#" or text[i:i + 2] == "//":
                    j = text.find("\n", i)
                    i = n if j < 0 else j
                    continue
                elif text[i:i + 2] == "/*":
                    j = text.find("*/", i + 2)
                    i = n if j < 0 else j + 2
                    continue
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
            i += 1
        header = " ".join((m.group(1) + " " + m.group(2)).split())
        blocks.append((header, text[m.end():i - 1]))
        pos = i
    return blocks


def _norm(s: str) -> str:
    return "\n".join(line.strip() for line in s.strip().splitlines() if line.strip())


def validate_candidate(candidate: PatchCandidate, baseline_files: Dict[str, str], policy: Dict[str, Any],
                       target_dir: str = "") -> PolicyResult:
    version = str(policy.get("policy_version", ""))
    checks: List[Dict[str, Any]] = []
    violations: List[str] = []

    def check(name: str, ok: bool, note: str = "") -> None:
        checks.append({"check": name, "ok": ok, "note": note})
        if not ok:
            violations.append(f"{name}: {note}" if note else name)

    if candidate.status != "PATCH":
        check("candidate_status", True, f"status={candidate.status}; nothing to validate")
        return PolicyResult(True, [], checks, version)

    globs = policy.get("editable_file_globs") or ["*.tf"]
    protected_paths = [p.rstrip("/") + "/" for p in (policy.get("protected_paths") or [])]
    protected_names = set(policy.get("protected_file_names") or [])
    max_files = int(policy.get("max_patch_files", 2))
    max_bytes = int(policy.get("max_file_bytes", 65536))
    allow_new = bool(policy.get("allow_new_files", False))
    forbidden = policy.get("forbidden_tokens") or []
    forbidden_blocks = set(policy.get("forbidden_block_changes") or ["terraform", "provider"])

    check("file_count", len(candidate.files) <= max_files, f"{len(candidate.files)} files (max {max_files})")
    check("has_files", len(candidate.files) > 0, "" if candidate.files else "candidate declares no files")

    total_added = total_removed = 0
    for rel, content in candidate.files.items():
        p = PurePosixPath(rel.replace("\\", "/"))
        if p.is_absolute() or ".." in p.parts or str(p).startswith("/"):
            check(f"path_safe:{rel}", False, "absolute path or parent traversal")
            continue
        joined = f"{target_dir.rstrip('/')}/{p}" if target_dir else str(p)
        if any(joined.startswith(pp) or str(p).startswith(pp) for pp in protected_paths):
            check(f"path_protected:{rel}", False, "path is under a protected directory (policy/tests/src/.github/...)")
            continue
        if p.name in protected_names:
            check(f"file_protected:{rel}", False, "provider/backend/versions files may not be modified by a patch")
            continue
        if not any(fnmatch.fnmatch(p.name, g) for g in globs):
            check(f"path_editable:{rel}", False, f"not matching editable globs {globs}")
            continue
        if rel not in baseline_files and not allow_new:
            check(f"file_exists:{rel}", False, "new file creation not allowed (allow_new_files=false)")
            continue
        if not isinstance(content, str):
            check(f"content_type:{rel}", False, "content is not a string")
            continue
        if len(content.encode("utf-8")) > max_bytes:
            check(f"file_size:{rel}", False, f"{len(content.encode('utf-8'))} bytes > {max_bytes}")
            continue
        base = baseline_files.get(rel, "")
        # 금지 토큰: 새로 도입된 것만
        introduced = [t for t in forbidden if t in content and t not in base]
        check(f"forbidden_tokens:{rel}", not introduced, f"introduced {introduced}" if introduced else "")
        # terraform/provider 블록 불변
        bblocks = {h: _norm(b) for h, b in extract_top_level_blocks(base) if h.split()[0] in forbidden_blocks}
        cblocks = {h: _norm(b) for h, b in extract_top_level_blocks(content) if h.split()[0] in forbidden_blocks}
        check(f"protected_blocks:{rel}", bblocks == cblocks,
              "" if bblocks == cblocks else f"terraform/provider blocks changed: {sorted(set(bblocks) ^ set(cblocks)) or 'body changed'}")
        diff = list(difflib.unified_diff(base.splitlines(), content.splitlines(), lineterm="", n=0))
        added = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))
        total_added += added
        total_removed += removed
        check(f"diff_nonempty:{rel}", (added + removed) > 0, "file content identical to baseline")

    checks.append({"check": "diff_stats", "ok": True, "note": f"+{total_added} -{total_removed}",
                   "added_lines": total_added, "removed_lines": total_removed, "files": len(candidate.files)})

    # 리소스 블록 단위 (텍스트 근거). plan 이 없어도 "허용 밖 타입 생성 / 삭제 / 허용 밖 타입 변경" 은 여기서 막는다. V5 가 plan 으로 다시 확인한다
    for name, ok, note in _resource_block_checks(candidate, baseline_files, policy):
        check(name, ok, note)
    return PolicyResult(not violations, violations, checks, version)


_RES_HEADER_RE = re.compile(r'^resource\s+"([^"]+)"\s+"([^"]+)"')


def _resource_blocks(text: str) -> Dict[str, Tuple[str, str]]:
    """{address: (type, normalized body)} — 최상위 resource 블록만."""
    out: Dict[str, Tuple[str, str]] = {}
    for header, body in extract_top_level_blocks(text):
        m = _RES_HEADER_RE.match(header.strip())
        if m:
            out[f"{m.group(1)}.{m.group(2)}"] = (m.group(1), _norm(body))
    return out


def _resource_block_checks(candidate: PatchCandidate, baseline_files: Dict[str, str], policy: Dict[str, Any]) -> List[Tuple[str, bool, str]]:
    """패치에 포함된 파일들의 합집합에서 resource 블록을 비교한다 (패치 밖 파일은 그대로이므로 제외).
    - 생성: allowed_create_resource_types 밖이면 위반
    - 삭제: allow_delete=false 면 위반 (같은 패치 안 다른 파일로 옮긴 것은 삭제가 아님)
    - 변경: allowed_change_resource_types 밖이면 위반
    """
    allowed_create = set(policy.get("allowed_create_resource_types") or [])
    allowed_change = set(policy.get("allowed_change_resource_types") or [])
    allow_delete = bool(policy.get("allow_delete", False))
    before: Dict[str, Tuple[str, str]] = {}
    after: Dict[str, Tuple[str, str]] = {}
    for rel, content in candidate.files.items():
        if not isinstance(content, str):
            continue
        before.update(_resource_blocks(baseline_files.get(rel, "")))
        after.update(_resource_blocks(content))
    results: List[Tuple[str, bool, str]] = []
    for addr in sorted(set(after) - set(before)):
        rtype = after[addr][0]
        ok = rtype in allowed_create
        results.append((f"resource_create:{addr}", ok, "" if ok else f"new resource type {rtype!r} not in allowed_create_resource_types (text-level; V5 re-checks with plan)"))
    for addr in sorted(set(before) - set(after)):
        results.append((f"resource_delete:{addr}", allow_delete, "" if allow_delete else "resource block removed from the patch (allow_delete=false; text-level, V5 re-checks with plan)"))
    for addr in sorted(set(before) & set(after)):
        if before[addr][1] != after[addr][1]:
            rtype = after[addr][0]
            ok = rtype in allowed_change
            results.append((f"resource_change:{addr}", ok, "" if ok else f"changed resource type {rtype!r} not in allowed_change_resource_types"))
    return results
