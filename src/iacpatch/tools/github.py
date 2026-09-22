"""PR 준비/생성. 기본은 **미리보기**(명령만 출력). --execute 일 때만 브랜치 push + PR 생성.

입력은 두 종류의 기록 중 하나다.
- `--run <id>`    : `iacpatch predeploy` 기록(data/runs). 게이트 결정이 CREATE_PR_AUTO / CREATE_PR_APPROVAL 일 때만 PR.
- `--review <id>` : `iacpatch review` 기록(data/reviews, 실험에 쓰는 흐름). 검토 수준이 LIGHT_REVIEW / FULL_REVIEW 일 때만 PR.
                    BLOCKED / REPORT_ONLY / PENDING(검증 미완) 은 거부한다. FULL_REVIEW 는 제목에 [approval required] 를 붙인다.

- 병합(merge)과 apply 는 어떤 경우에도 자동으로 하지 않는다.
- GitHub API 는 urllib 로 호출하며 토큰은 환경변수 GITHUB_TOKEN 에서만 읽는다.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..config import Settings
from .runner import run, which

REVIEW_LEVELS_FOR_PR = ("LIGHT_REVIEW", "FULL_REVIEW")
GATE_ACTIONS_FOR_PR = ("CREATE_PR_AUTO", "CREATE_PR_APPROVAL")


def _repo_slug(remote_url: str) -> Optional[str]:
    m = re.search(r"github\.com[:/]([^/]+)/([^/.]+)(\.git)?/?$", remote_url.strip())
    return f"{m.group(1)}/{m.group(2)}" if m else None


@dataclass
class PrSource:
    """PR 로 만들 재료. run 기록이든 review 기록이든 여기로 정규화한다."""
    kind: str                     # "run" | "review"
    record_id: str
    record_dir: Path
    decision: str                 # gate action 또는 review level
    approval_required: bool
    files: List[Path]             # 후보 파일 (record_dir 아래)
    files_root: Path              # files 의 기준 디렉터리 (상대 경로 계산용)
    target_dir: str               # 저장소 안에서 파일을 놓을 위치 (상대 경로)
    scenario: str
    rule_id: str = ""
    resource: str = ""
    body_path: Optional[Path] = None
    verification_summary: str = ""
    generator: str = ""
    refusal: str = ""             # 비어 있지 않으면 PR 을 만들지 않는 이유
    notes: List[str] = field(default_factory=list)


def _load_run_source(run_dir: Path, run_id: str) -> PrSource:
    run_json = run_dir / "run.json"
    if not run_json.exists():
        return PrSource("run", run_id, run_dir, "", False, [], run_dir, "", "", refusal=f"run record not found: {run_dir}")
    info = json.loads(run_json.read_text(encoding="utf-8"))
    action = (info.get("gate") or {}).get("action")
    attempt = int(info.get("final_attempt") or 1)
    files_dir = run_dir / "candidates" / f"{attempt:02d}" / "files"
    files = sorted(p for p in files_dir.rglob("*") if p.is_file()) if files_dir.is_dir() else []
    tf = info.get("target_finding") or {}
    src = PrSource("run", run_id, run_dir, str(action), action == "CREATE_PR_APPROVAL", files, files_dir,
                   str(info.get("target_dir") or ""), str(info.get("scenario_id") or "scenario"),
                   rule_id=str(tf.get("rule_id") or ""), resource=str(tf.get("resource") or ""),
                   body_path=run_dir / "pr_body.md", verification_summary=str((info.get("validity") or {}).get("summary") or ""),
                   generator=str(info.get("generator") or ""))
    if action not in GATE_ACTIONS_FOR_PR:
        src.refusal = f"gate action is {action!r} (only {' / '.join(GATE_ACTIONS_FOR_PR)} may become PRs)"
    return src


def _load_review_source(review_dir: Path, review_id: str, tf_dir_override: Optional[str]) -> PrSource:
    state_json = review_dir / "state.json"
    if not state_json.exists():
        return PrSource("review", review_id, review_dir, "", False, [], review_dir, "", "", refusal=f"review record not found: {review_dir}")
    st = json.loads(state_json.read_text(encoding="utf-8"))
    level = st.get("review_level")
    cand_dir = review_dir / "candidate"
    files = sorted(p for p in cand_dir.rglob("*") if p.is_file()) if cand_dir.is_dir() else []
    finding: Dict = {}
    sel = review_dir / "input" / "selected_finding.json"
    if sel.exists():
        try:
            finding = json.loads(sel.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            finding = {}
    target_dir = tf_dir_override or str(st.get("tf_dir") or "")
    vsum = f"state={st.get('state')} verification={st.get('verification_status')} review_level={level}"
    src = PrSource("review", review_id, review_dir, str(level), level == "FULL_REVIEW", files, cand_dir, target_dir,
                   str(st.get("scenario") or "scenario"), rule_id=str(finding.get("rule_id") or ""),
                   resource=str(finding.get("resource") or ""), body_path=review_dir / "pr_body.md",
                   verification_summary=vsum, generator=str(st.get("candidate_generator") or st.get("candidate_origin") or ""))
    if level not in REVIEW_LEVELS_FOR_PR:
        why = {"BLOCKED": "정책 위반 또는 검증 FAIL", "REPORT_ONLY": "위험도 근거 부족 — 리포트만",
               "PENDING": "검증 미완(NOT_RUN/UNKNOWN 남음)", "None": "검토 수준 없음(후보 없음/탐지 없음/입력 오류)"}.get(str(level), "")
        src.refusal = f"review level is {level!r} ({why}); only {' / '.join(REVIEW_LEVELS_FOR_PR)} may become PRs. {vsum}"
    elif not target_dir:
        src.refusal = "review record has no tf_dir (older record) — pass --tf-dir <repo-relative Terraform dir>"
    return src


def load_pr_source(settings: Settings, run_id: Optional[str] = None, review_id: Optional[str] = None,
                   tf_dir: Optional[str] = None) -> PrSource:
    if bool(run_id) == bool(review_id):
        raise ValueError("exactly one of run_id / review_id is required")
    if run_id:
        return _load_run_source(settings.path(settings.data_dir) / run_id, run_id)
    # review 기록: id(기본 data/reviews/<id>) 또는 기록 폴더 경로(review --out 으로 다른 곳에 쓴 경우) 둘 다 받는다
    as_path = Path(review_id)
    if (as_path / "state.json").exists():
        return _load_review_source(as_path.resolve(), as_path.name, tf_dir)
    return _load_review_source(settings.path("data/reviews") / review_id, review_id, tf_dir)


def prepare_pr(settings: Settings, run_id: Optional[str] = None, execute: bool = False, base_branch: str = "main",
               remote: str = "origin", draft: bool = False, review_id: Optional[str] = None,
               tf_dir: Optional[str] = None) -> int:
    src = load_pr_source(settings, run_id, review_id, tf_dir)
    if src.refusal:
        print(f"refusing to create a PR: {src.refusal}")
        return 3 if (src.record_dir / ("state.json" if src.kind == "review" else "run.json")).exists() else 2
    if not src.files:
        print("no candidate files in the record")
        return 2
    record_dir, target_dir, scenario = src.record_dir, src.target_dir, src.scenario
    branch = f"iacpatch/{scenario.replace('/', '-').replace(' ', '-')}-{src.record_id}"   # 세트/케이스 이름의 '/' 는 브랜치 구분자와 충돌
    title = f"[iacpatch] {scenario}: {src.rule_id} on {src.resource}"
    if src.approval_required:
        title = "[approval required] " + title
    repo_root = Path(settings.repo_root)
    commands: List[str] = [
        f"cd {repo_root}",
        f"git fetch {remote} {base_branch}",
        f"git checkout -b {branch} {remote}/{base_branch}",
    ]
    for p in src.files:
        rel = p.relative_to(src.files_root)
        commands.append(f"cp {p} {repo_root / target_dir / rel}")
    body_path = src.body_path if (src.body_path and src.body_path.exists()) else None
    commands += [
        f"git add {target_dir}",
        f"git commit -F {record_dir / 'commit_message.txt'}",
        f"git push -u {remote} {branch}",
        f"gh pr create --base {base_branch} --head {branch} --title \"{title}\"" + (f" --body-file {body_path}" if body_path else " --body \"(pr_body.md 없음)\"")
        + (" --draft" if draft else ""),
    ]
    commit_msg = (f"{title}\n\nGenerated by iacpatch {src.kind} {src.record_id} (generator={src.generator}, decision={src.decision}).\n"
                  f"Verification: {src.verification_summary}\n"
                  "This commit was produced by an automated pipeline; a human must review and approve before merge and before terraform apply.\n")
    (record_dir / "commit_message.txt").write_text(commit_msg, encoding="utf-8")
    (record_dir / "pr_commands.sh").write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + "\n".join(commands) + "\n", encoding="utf-8")
    print(f"PR preparation for {src.kind} {src.record_id} (decision={src.decision})")
    print(f"  branch : {branch}")
    print(f"  title  : {title}")
    print(f"  files  : {', '.join(str(p.relative_to(src.files_root)) for p in src.files)} -> {target_dir}/")
    print(f"  body   : {body_path or '(없음)'}")
    print(f"  script : {record_dir / 'pr_commands.sh'}")
    if not execute:
        print("preview only. Review pr_body.md, then either run the script above yourself or re-run with --execute.")
        return 0

    # --- execute -------------------------------------------------------------
    if which("git") is None:
        print("git not found")
        return 2
    st = run(["git", "status", "--porcelain", "--", target_dir], cwd=str(repo_root))
    if st.stdout.strip():
        print(f"working tree has uncommitted changes under {target_dir}; refusing to continue")
        return 4
    cur = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=str(repo_root)).stdout.strip()
    steps = [["git", "fetch", remote, base_branch], ["git", "checkout", "-b", branch, f"{remote}/{base_branch}"]]
    for argv in steps:
        r = run(argv, cwd=str(repo_root))
        if not r.ok:
            print(f"{' '.join(argv)} failed: {r.stderr.strip()}")
            return 5
    for p in src.files:
        rel = p.relative_to(src.files_root)
        dst = repo_root / target_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    for argv in (["git", "add", target_dir], ["git", "commit", "-F", str(record_dir / "commit_message.txt")], ["git", "push", "-u", remote, branch]):
        r = run(argv, cwd=str(repo_root))
        if not r.ok:
            print(f"{' '.join(argv)} failed: {r.stderr.strip()}")
            run(["git", "checkout", cur], cwd=str(repo_root))
            return 5
    remote_url = run(["git", "remote", "get-url", remote], cwd=str(repo_root)).stdout.strip()
    slug = _repo_slug(remote_url)
    token = os.environ.get("GITHUB_TOKEN")
    if not slug or not token:
        print(f"branch pushed. PR not created automatically ({'no GITHUB_TOKEN' if not token else 'remote is not github.com'}). Run: {commands[-1]}")
        return 0
    body_text = body_path.read_text(encoding="utf-8") if body_path else "(pr_body.md 없음)"
    body = {"title": title, "head": branch, "base": base_branch, "body": body_text, "draft": draft}
    req = urllib.request.Request(f"https://api.github.com/repos/{slug}/pulls", data=json.dumps(body).encode("utf-8"), method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"PR creation failed: HTTP {e.code} {e.read().decode('utf-8', 'replace')[:300]}")
        return 6
    (record_dir / "pr.json").write_text(json.dumps({"number": d.get("number"), "url": d.get("html_url"), "branch": branch}, indent=2), encoding="utf-8")
    print(f"PR created: {d.get('html_url')}  (merge and apply remain manual)")
    return 0
