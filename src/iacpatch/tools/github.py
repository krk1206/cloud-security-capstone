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
from typing import Dict, List, Optional, Tuple

from ..config import Settings
from ..textio import write_text_lf
from shutil import which as shutil_which

from .runner import run, which

REVIEW_LEVELS_FOR_PR = ("LIGHT_REVIEW", "FULL_REVIEW")
# 예제(이 프로그램 저장소 안의 scenarios/…)를 고치는 PR 은 흐름 시연용 — 예제는 의도적으로 설정 오류를 넣어 둔 실험 재료라 병합하지 않는다 (2026-11-03).
# 병합하면 예제가 '고쳐져' 시연 · 단위 시험(원본을 기준으로 읽음)이 깨진다. 실제로 PR 의 pull_request 검사에서 단위 시험 6건이 그 이유로 빨간 X 로 나왔다.
DEMO_NOTE = ("> **시연용 PR (예제 폴더) — 병합하지 않습니다.** 이 저장소의 예제(scenarios/…)는 의도적으로 설정 오류를 넣어 둔 실험 재료입니다. "
             "이 PR 은 '승인 → PR' 흐름을 보여 주는 것이고, 병합하면 예제와 단위 시험(원본 기준)이 깨집니다. "
             "GitHub 의 단위 시험 검사가 실패로 나오는 것은 그 때문입니다. 실제 고객 프로젝트의 PR 은 그 프로젝트의 저장소에 만들어집니다.\n\n")


def is_example_target(target_dir: str) -> bool:
    """상대 경로 = 이 프로그램 저장소 안의 예제 폴더 (연결한 프로젝트는 절대 경로, D-32)."""
    return not Path(str(target_dir or "")).is_absolute()
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


def public_name(scenario: str) -> str:
    """화면 검토 기록의 scenario 'ui/<세트>/<후보 id>' → '<세트>'. 후보 id(correct-design 같은 이름)는 기대 결과를 드러내므로
    (교수 피드백 2026-10-31) PR 제목 · 브랜치 · 커밋 메시지에 쓰지 않는다. 그 밖의 scenario 는 그대로.
    연결한 프로젝트의 세트 '<프로젝트 id>.<이름>' (D-32) → '<프로젝트 id>' (고칠 대상은 제목의 룰 · 리소스로 보인다)."""
    parts = str(scenario or "").split("/")
    if len(parts) == 3 and parts[0] == "ui" and parts[1]:
        return parts[1].split(".", 1)[0]
    return str(scenario or "scenario")


def _jp(a: str, b: str) -> str:
    return f"{a.rstrip('/')}/{b}" if a else b


def repo_target(settings: Settings, target_dir: str) -> Tuple[Optional[Path], str, str]:
    """PR 을 만들 git 저장소와 그 안의 대상 폴더 (저장소 기준 상대 경로, 저장소 맨 위면 '').
    예제(저장소 상대 경로) = 이 프로그램의 저장소. 연결한 프로젝트(절대 경로, D-32) = 그 폴더가 들어 있는 git 저장소."""
    t = Path(target_dir)
    if not t.is_absolute():
        return Path(settings.repo_root), target_dir.replace("\\", "/").strip("/"), ""
    if which("git") is None:
        return None, target_dir, "이 PC 에 git 이 없음"
    r = run(["git", "-C", str(t), "rev-parse", "--show-toplevel"])
    if not r.ok or not r.stdout.strip():
        return None, target_dir, "이 폴더는 git 저장소가 아님 — 검사 · AI 수정은 되지만 PR 은 못 만듦"
    top = Path(r.stdout.strip())
    try:
        rel = t.resolve().relative_to(top.resolve()).as_posix()
    except ValueError:
        return None, target_dir, "저장소 안의 위치를 계산하지 못함"
    return top, ("" if rel == "." else rel), ""


def _unverified(record_dir: Path) -> bool:
    try:
        return bool(json.loads((record_dir / "decision.json").read_text(encoding="utf-8")).get("aws_unverified_ack"))
    except (OSError, ValueError):
        return False


def _base_problems(repo_root: Path, src: PrSource, remote: str, base_branch: str, target: Optional[str] = None) -> List[str]:
    """기준 브랜치(<remote>/<base>)에 대상 폴더 · 원본 파일이 검사 때와 같게 있는가. 다르면 PR 의 diff 가 검사한 diff 와 달라진다.
    로컬 원격 참조만 읽는다 (fetch 하지 않음 — execute 경로는 fetch 뒤에 부른다)."""
    out: List[str] = []
    tgt = src.target_dir if target is None else target
    ref = f"{remote}/{base_branch}"
    if not run(["git", "rev-parse", "--verify", "--quiet", ref], cwd=str(repo_root)).ok:
        return [f"기준 브랜치 {ref} 를 이 PC 의 git 이 모름 (브랜치 이름 확인 · fetch 필요)"]
    if tgt and not run(["git", "cat-file", "-e", f"{ref}:{tgt}"], cwd=str(repo_root)).ok:
        return [f"{ref} 에 프로젝트 폴더 {tgt} 가 없음 — PR 이 폴더 전체를 새로 만드는 것으로 보임"]
    orig_root = src.record_dir / "original"
    # predeploy(run) 기록은 original/ 폴더 대신 baseline_files.json 에 원본을 둔다 (CI 경로). 둘 중 있는 쪽을 쓴다.
    baseline: Dict[str, str] = {}
    bf = src.record_dir / "baseline_files.json"
    if bf.exists():
        try:
            baseline = {str(k): str(v) for k, v in json.loads(bf.read_text(encoding="utf-8")).items()}
        except Exception:
            baseline = {}
    for p in src.files:
        rel = p.relative_to(src.files_root).as_posix()
        o = orig_root / rel
        b = run(["git", "show", f"{ref}:{_jp(tgt, rel)}"], cwd=str(repo_root))
        if o.exists():
            orig_text: Optional[str] = o.read_text(encoding="utf-8")
        elif rel in baseline:
            orig_text = baseline[rel]
        else:
            orig_text = None
        if orig_text is None:
            out.append(f"{rel}: 이 기록에 원본 사본이 없음 — 기준 브랜치와 같은지 확인 못 함")
        elif not b.ok:
            out.append(f"{rel}: {ref} 에 없는 파일 — PR 이 새 파일로 만듦")
        elif b.stdout.replace("\r\n", "\n") != orig_text.replace("\r\n", "\n"):
            out.append(f"{rel}: {ref} 의 파일이 검사한 원본과 다름 — PR 의 변경이 검사한 변경과 달라짐")
    return out


def pr_readiness(settings: Settings, review_id: str, base_branch: str = "main", remote: str = "origin") -> Dict[str, object]:
    """PR 만들기 전에 이 PC 의 git 상태를 읽기만 해서 확인한다 (fetch · commit · push 없음). 막히는 것마다 사람이 할 일을 같이 준다."""
    checks: List[Dict[str, object]] = []

    def add(name: str, ok: bool, detail: str, todo: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail, "todo": todo})
    src = load_pr_source(settings, review_id=review_id)
    out: Dict[str, object] = {"base": base_branch, "remote": remote, "checks": checks}
    if src.refusal:
        add("검사 결과", False, src.refusal)
        return {**out, "ok": False}
    git = which("git")
    if git is None:
        add("git", False, "이 PC 에 git 이 없음 (PATH · GitHub Desktop 내장 git · Git for Windows 기본 위치를 찾아봄)", "Git for Windows 설치(설치 중 'PATH 에 추가' 기본값) 후 프로그램을 다시 열고 확인")
        return {**out, "ok": False}
    if os.path.sep in git and shutil_which("git") is None:
        add("git", True, f"PATH 에는 없지만 {git} 을 씀 (GitHub Desktop 내장 또는 기본 설치 위치)")
    repo_root, tgt, why = repo_target(settings, src.target_dir)
    if repo_root is not None:
        top = run(["git", "rev-parse", "--show-toplevel"], cwd=str(repo_root))
        if not top.ok:
            repo_root, why = None, "프로그램 폴더가 git 저장소가 아님"
    add("git 저장소", repo_root is not None, repo_root.as_posix() if repo_root is not None else why,
        "" if repo_root is not None else "Terraform 폴더를 git 저장소(clone 한 폴더) 안에 두고 다시 연결")
    if repo_root is None:
        return {**out, "ok": False}
    cur = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=str(repo_root)).stdout.strip()
    url = run(["git", "remote", "get-url", remote], cwd=str(repo_root)).stdout.strip()
    slug = _repo_slug(url)
    add("GitHub 원격 저장소", bool(slug), slug or (url or f"원격 '{remote}' 없음"), "" if slug else "GitHub 저장소를 원격(origin)으로 연결")
    if is_example_target(src.target_dir):
        add("예제 프로젝트 — 시연용 PR", True, "대상이 이 프로그램 저장소의 예제 폴더라 PR 은 '승인 → PR' 흐름 시연용. 예제는 의도적으로 취약한 실험 재료라 "
            "병합하지 않는다 (병합하면 예제 · 단위 시험이 깨짐 — GitHub 의 단위 시험 검사가 실패로 나오는 것이 정상). 실제 프로젝트의 PR 은 그 프로젝트 저장소에 생긴다")
    st = run(["git", "status", "--porcelain", "--", tgt or "."], cwd=str(repo_root))
    dirty = [x for x in st.stdout.splitlines() if x.strip()]
    add("프로젝트 폴더가 커밋된 상태", not dirty, "커밋된 그대로" if not dirty else f"추적 안 됨 · 고친 채로 남음 {len(dirty)}개: " + ", ".join(x[3:] for x in dirty[:3]),
        "" if not dirty else "원본 코드를 먼저 커밋해서 GitHub 에 올리기 (사람) — PR 은 원본에서 바뀐 부분만 올린다")
    probs = _base_problems(repo_root, src, remote, base_branch, tgt)
    add(f"기준 브랜치 {remote}/{base_branch} 의 원본 = 검사한 원본", not probs, "같음" if not probs else " · ".join(probs[:3]),
        "" if not probs else "원본 코드가 올라간 브랜치를 기준으로 고르기 (또는 원본을 그 브랜치에 올리기)")
    token = bool(os.environ.get("GITHUB_TOKEN"))
    add("PR 만드는 방법", True, "GITHUB_TOKEN 있음 — push 뒤 PR 까지 만듦" if token else "GITHUB_TOKEN 없음 — push 뒤 화면에 나오는 GitHub 주소에서 사람이 'Create pull request'")
    if _unverified(src.record_dir):
        add("AWS 시험 환경", True, "미검증 — 사람이 확인하고 승인함. PR 제목 · 본문에 '실제 AWS 미검증' 이 붙음")
    branch = f"iacpatch/{public_name(src.scenario).replace('/', '-').replace(' ', '-')}-{src.record_id}"
    return {**out, "ok": all(c["ok"] for c in checks), "current_branch": cur, "slug": slug, "branch": branch, "repo": repo_root.as_posix(), "target": tgt,
            "note": f"{remote}/{base_branch} 는 이 PC 가 마지막으로 받아 온(fetch) 상태 기준 — 실제 실행 때 다시 받아 와서 한 번 더 확인함"}


def prepare_pr(settings: Settings, run_id: Optional[str] = None, execute: bool = False, base_branch: str = "main",
               remote: str = "origin", draft: bool = False, review_id: Optional[str] = None,
               tf_dir: Optional[str] = None, header: str = "") -> int:
    """header: PR 본문 맨 위에 붙일 글 (화면이 주는 '끝맺음 세 줄' — 확인한 것 · 결정 · 남은 것, D-42). 원본 pr_body.md 는 바꾸지 않고
    pr_body_final.md 사본에만 붙는다."""
    src = load_pr_source(settings, run_id, review_id, tf_dir)
    if src.refusal:
        print(f"refusing to create a PR: {src.refusal}")
        return 3 if (src.record_dir / ("state.json" if src.kind == "review" else "run.json")).exists() else 2
    if not src.files:
        print("no candidate files in the record")
        return 2
    record_dir, target_dir, scenario = src.record_dir, src.target_dir, public_name(src.scenario)
    branch = f"iacpatch/{scenario.replace('/', '-').replace(' ', '-')}-{src.record_id}"   # 세트/케이스 이름의 '/' 는 브랜치 구분자와 충돌
    title = f"[iacpatch] {scenario}: {src.rule_id} on {src.resource}"
    if src.approval_required:
        title = "[approval required] " + title
    unverified = _unverified(record_dir)
    if unverified:
        title = "[실제 AWS 미검증] " + title
    repo_root, target_dir, repo_why = repo_target(settings, src.target_dir)
    if repo_root is None:
        print(f"refusing to create a PR: {repo_why}")
        return 8
    commands: List[str] = [
        f"cd {repo_root}",
        f"git fetch {remote} {base_branch}",
        f"git checkout -b {branch} {remote}/{base_branch}",
    ]
    for p in src.files:
        rel = p.relative_to(src.files_root)
        commands.append(f"cp {p} {repo_root / target_dir / rel}")
    body_path = src.body_path if (src.body_path and src.body_path.exists()) else None
    demo = is_example_target(src.target_dir)
    if unverified or header or demo:
        # PR 본문 맨 위에 '시연용(예제)' · '실제 AWS 미검증' · 끝맺음 세 줄을 적은 사본 (원본 pr_body.md 는 그대로)
        final = record_dir / "pr_body_final.md"
        top = (DEMO_NOTE if demo else "") + (("> **실제 AWS 미검증** — 이 수정은 AWS 시험 환경에 반영해 적용 · 연결을 확인하지 않았습니다. 승인한 사람이 그 사실을 확인하고 승인했습니다 "
               "(IaCPatch D-32). 병합 · apply 전에 스테이징에서 확인하세요.\n\n") if unverified else "")
        final.write_text(top + (header.rstrip() + "\n\n" if header else "") + (body_path.read_text(encoding="utf-8") if body_path else ""), encoding="utf-8")
        body_path = final
    commands += [
        f"git add {target_dir or '.'}",
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
    print(f"  files  : {', '.join(str(p.relative_to(src.files_root)) for p in src.files)} -> {target_dir + '/' if target_dir else '(저장소 맨 위)'}")
    print(f"  body   : {body_path or '(없음)'}")
    if demo:
        print("  note   : 예제 폴더(실험 재료)를 고치는 시연용 PR — 병합하지 않는다 (본문 맨 위에 적음)")
    print(f"  script : {record_dir / 'pr_commands.sh'}")
    if not execute:
        print("preview only. Review pr_body.md, then either run the script above yourself or re-run with --execute.")
        return 0

    # --- execute -------------------------------------------------------------
    if which("git") is None:
        print("git not found")
        return 2
    st = run(["git", "status", "--porcelain", "--", target_dir or "."], cwd=str(repo_root))
    if st.stdout.strip():
        print(f"working tree has uncommitted changes under {target_dir}; refusing to continue")
        return 4
    cur = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=str(repo_root)).stdout.strip()
    r = run(["git", "fetch", remote, base_branch], cwd=str(repo_root))
    if not r.ok:
        print(f"git fetch {remote} {base_branch} failed: {r.stderr.strip()}")
        return 5
    # 기준 브랜치의 원본이 검사한 원본과 같아야 PR 의 변경 = 검사한 변경 (다르면 멈춘다 — 2026-11-01)
    probs = _base_problems(repo_root, src, remote, base_branch, target_dir)
    if probs:
        print("refusing to continue: " + " / ".join(probs))
        return 7
    r = run(["git", "checkout", "-b", branch, f"{remote}/{base_branch}"], cwd=str(repo_root))
    if not r.ok:
        print(f"git checkout -b {branch} {remote}/{base_branch} failed: {r.stderr.strip()}")
        return 5
    for p in src.files:
        rel = p.relative_to(src.files_root)
        dst = repo_root / target_dir / rel
        write_text_lf(dst, p.read_text(encoding="utf-8"))   # 저장소 파일은 LF 로 (textio.py)
    for argv in (["git", "add", target_dir or "."], ["git", "commit", "-F", str(record_dir / "commit_message.txt")], ["git", "push", "-u", remote, branch]):
        r = run(argv, cwd=str(repo_root))
        if not r.ok:
            print(f"{' '.join(argv)} failed: {r.stderr.strip()}")
            run(["git", "checkout", cur], cwd=str(repo_root))
            return 5
    # push 가 끝나면 원래 브랜치로 돌아간다 (프로그램이 도는 작업 폴더를 새 브랜치에 남겨 두지 않는다, 2026-11-01)
    run(["git", "checkout", cur], cwd=str(repo_root))
    remote_url = run(["git", "remote", "get-url", remote], cwd=str(repo_root)).stdout.strip()
    slug = _repo_slug(remote_url)
    token = os.environ.get("GITHUB_TOKEN")
    if slug:
        (record_dir / "pr.json").write_text(json.dumps({"branch": branch, "base": base_branch, "compare_url": f"https://github.com/{slug}/compare/{base_branch}...{branch}?expand=1",
                                                        "number": None, "url": None}, indent=2), encoding="utf-8")
    if not slug or not token:
        print(f"branch pushed: {branch}. PR not created automatically ({'no GITHUB_TOKEN' if not token else 'remote is not github.com'}).")
        if slug:
            print(f"open in browser to create the PR: https://github.com/{slug}/compare/{base_branch}...{branch}?expand=1")
        print(f"or run: {commands[-1]}")
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
