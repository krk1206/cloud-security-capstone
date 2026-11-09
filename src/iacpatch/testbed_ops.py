"""시험 환경 apply · destroy (화면 버튼) — 사람이 plan 결과를 보고 [실행] 을 눌렀을 때만, 그 plan 파일 그대로 반영한다.

왜 있나: 교수님 시연 때 PowerShell 로 apply·destroy 를 오가는 수고를 줄이려고 (B 요청, 2026-10-25, docs/DECISIONS.md D-19).

지키는 것
  - 시험 환경 폴더(scenarios/arch/webapp-3tier-testbed)만 바꾼다. 다른 폴더·운영 환경은 이 코드로 바꿀 수 없다.
  - 자동 실행 없음. 화면의 확인 창에서 사람이 체크하고 [실행] 을 눌러 confirm 값(apply / destroy)을 보낸 요청만 받는다.
    후보를 만드는 쪽(AI·규칙)이나 검사 코드는 이 함수를 부르지 않는다. AI(Claude Code)는 버튼도 누르지 않는다 (CLAUDE.md).
  - 계획한 그대로만 반영한다. 먼저 plan 파일을 만들어 사람에게 보이고(새로 만듦·수정·교체·삭제 수), 실행은
    `terraform apply <그 plan 파일>` 로만 한다. plan 뒤에 상태가 바뀌면 terraform 이 'Saved plan is stale' 로 거절하고,
    여기서도 상태 파일 번호(serial)·시험 환경 파일 지문(sha256)이 plan 때와 같은지 먼저 본다.
  - apply 는 교체·삭제가 없는 plan 만. 후보 apply 는 plan 확인이 '보안 그룹만 제자리 수정'(CLEAN)일 때만. destroy 는 삭제만 있는 plan 만.
  - plan 파일은 저장소 밖 임시 폴더(%TEMP%/iacpatch-plans/<id>)에 두고, 1시간이 지나거나 실행하면 지운다.
  - 모든 plan·실행은 data/testbed_ops.jsonl 한 줄 + data/testbed_ops/<시각>-<종류>/ 폴더에 남는다
    (plan 요약·plan 출력·apply 출력·실행 명령 — 계정 번호·공인 IP 는 가림).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .evidence_log import CommandLog, now_iso, sha256_file
from .tools.runner import ToolNotFound, run, run_stream

TESTBED_REL = "scenarios/arch/webapp-3tier-testbed"
ORIGINAL_REL = "scenarios/arch/webapp-3tier/security_groups.tf"
PLAN_TTL_S = 3600
KIND_KO = {"apply_original": "원본 반영 (apply)", "apply_candidate": "후보 반영 (apply)", "destroy": "시험 환경 삭제 (destroy)"}
CONFIRM = {"apply_original": "apply", "apply_candidate": "apply", "destroy": "destroy"}
_PID = re.compile(r"^[0-9a-f]{16}$")


# ----------------------------------------------------------------------------- plan 파일 보관 (저장소 밖)
def store_root() -> Path:
    """%TEMP%/iacpatch-plans (IACPATCH_PLAN_STORE 로 바꿀 수 있다 — 테스트가 사용자 임시 폴더를 건드리지 않게)."""
    return Path(os.environ.get("IACPATCH_PLAN_STORE") or (Path(tempfile.gettempdir()) / "iacpatch-plans"))


def new_slot() -> Tuple[str, Path]:
    pid = secrets.token_hex(8)
    d = store_root() / pid
    d.mkdir(parents=True, exist_ok=False)
    return pid, d


def slot_dir(pid: str) -> Optional[Path]:
    return store_root() / pid if _PID.match(str(pid or "")) else None


def save_meta(d: Path, meta: Dict[str, Any]) -> None:
    (d / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")


def load_meta(pid: str) -> Optional[Dict[str, Any]]:
    d = slot_dir(pid)
    if d is None:
        return None
    try:
        return json.loads((d / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def drop(pid: str) -> None:
    d = slot_dir(pid)
    if d is not None:
        shutil.rmtree(d, ignore_errors=True)


def sweep(now: Optional[float] = None, supersede: Optional[str] = None) -> int:
    """1시간 넘은 plan 파일을 지운다 (임시 폴더 안 iacpatch-plans 만).
    supersede: 이 종류(kind)의 실행 안 된 plan 도 지운다 — 새 plan 을 만들기 직전에 (확인 창을 취소한 plan 이 남지 않게)."""
    now = time.time() if now is None else now
    n = 0
    root = store_root()
    if not root.is_dir():
        return 0
    for d in root.iterdir():
        if not d.is_dir() or not _PID.match(d.name):
            continue
        meta = load_meta(d.name) or {}
        if now - float(meta.get("created") or 0) > PLAN_TTL_S or (supersede and meta.get("kind") == supersede):
            shutil.rmtree(d, ignore_errors=True)
            n += 1
    return n


# ----------------------------------------------------------------------------- 상태
def state_info(testbed: Path) -> Dict[str, Any]:
    """상태 파일의 번호(serial)·리소스 수. 파일이 없으면 exists=False."""
    p = testbed / "terraform.tfstate"
    if not p.exists():
        return {"exists": False, "serial": None, "resources": 0}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"exists": True, "serial": None, "resources": None}
    res = doc.get("resources") if isinstance(doc, dict) else None
    return {"exists": True, "serial": doc.get("serial") if isinstance(doc, dict) else None, "resources": len(res) if isinstance(res, list) else None}


def fresh(meta: Dict[str, Any], testbed: Path, now: Optional[float] = None) -> Tuple[bool, str]:
    """plan 을 만든 뒤 아무것도 바뀌지 않았나 — 시간(1시간), 시험 환경 파일 지문, 상태 파일 번호."""
    now = time.time() if now is None else now
    if now - float(meta.get("created") or 0) > PLAN_TTL_S:
        return False, "plan 생성 후 1시간 경과 — plan 재생성 필요"
    if sha256_file(testbed / "security_groups.tf") != meta.get("testbed_sha256"):
        return False, "plan 생성 후 시험 환경 security_groups.tf 변경됨 — plan 재생성 필요"
    st = state_info(testbed)
    if (st["exists"], st["serial"]) != (bool(meta.get("state_exists")), meta.get("state_serial")):
        return False, "plan 생성 후 상태 파일 변경됨 (다른 apply·destroy 발생) — plan 재생성 필요"
    return True, ""


def eligible(kind: str, summary: Dict[str, Any]) -> Tuple[bool, str]:
    cnt = summary.get("counts") or {}
    n = sum(int(cnt.get(k) or 0) for k in ("replace", "delete", "update", "create", "other"))
    if n == 0:
        return False, "변경 없음 — 반영할 내용 없음"
    if kind == "destroy":
        if int(cnt.get("delete") or 0) != n:
            return False, "destroy plan 에 삭제 외 동작 포함 — 사람이 PowerShell 에서 plan 검토 후 판단"
        return True, ""
    if int(cnt.get("replace") or 0) or int(cnt.get("delete") or 0) or int(cnt.get("other") or 0):
        return False, "plan 에 교체·삭제 포함 — apply 하지 않음"
    if kind == "apply_candidate" and summary.get("verdict") != "CLEAN":
        return False, "후보 반영은 '보안 그룹 제자리 수정만'(CLEAN)일 때만 가능 — 사람이 PowerShell 에서 plan 검토 후 판단"
    return True, ""


def destroy_summary(cnt: Dict[str, Any]) -> str:
    n = int(cnt.get("delete") or 0)
    return f"시험 환경 삭제 (destroy) — 리소스 {n}개 삭제 예정 (비용 발생 방지)"


def apply_summary(kind: str, cnt: Dict[str, Any]) -> str:
    parts = [f"{ko} {int(cnt.get(k) or 0)}개" for k, ko in (("create", "생성"), ("update", "제자리 수정"), ("replace", "교체"), ("delete", "삭제"))
             if int(cnt.get(k) or 0)]
    return f"{KIND_KO.get(kind, kind)} — " + ((" · ".join(parts) + " 예정") if parts else "변경 없음")


# ----------------------------------------------------------------------------- 기록
def ops_log(root: Path, entry: Dict[str, Any]) -> None:
    p = root / "data" / "testbed_ops.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")


def last_ops(root: Path, n: int = 1, ops: Tuple[str, ...] = ("apply", "destroy")) -> List[Dict[str, Any]]:
    try:
        lines = (root / "data" / "testbed_ops.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("op") in ops:
            out.append(e)
            if len(out) >= n:
                break
    return out


def _tf(settings: Any) -> str:
    return getattr(settings, "terraform_bin", None) or os.environ.get("TERRAFORM_BIN") or "terraform"


def _env(profile: str) -> Dict[str, str]:
    env = {"TF_IN_AUTOMATION": "1"}
    if profile:
        env["AWS_PROFILE"] = profile
    return env


def short_changes(summary: Dict[str, Any], limit: int = 30) -> List[Dict[str, Any]]:
    return [{k: e.get(k) for k in ("address", "type", "kind", "replace_paths")} for e in (summary.get("changes") or [])[:limit]]


# ----------------------------------------------------------------------------- 1. plan (원본 apply · destroy)
def prepare(settings: Any, *, root: Path, kind: str, profile: str, log: Callable[[str], None] = print,
            runner: Optional[Callable[..., Any]] = None) -> Dict[str, Any]:
    """plan 을 만들어 보관하고 요약을 돌려준다. 반영은 하지 않는다 (execute 가 한다).
    kind: apply_original (시험 환경 파일 = 원본일 때 배포 또는 되돌리기) | destroy (배포가 있을 때)."""
    from .plancheck import mask, plan_error_ko, summarize_plan
    runner = runner or run
    if kind not in ("apply_original", "destroy"):
        raise ValueError(f"알 수 없는 kind 값: {kind}")
    sweep(supersede=kind)
    testbed = root / TESTBED_REL
    sha = sha256_file(testbed / "security_groups.tf")
    st = state_info(testbed)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    ops_dir = root / "data" / "testbed_ops" / f"{stamp}-plan-{kind}"
    ops_dir.mkdir(parents=True, exist_ok=True)
    clog = CommandLog(ops_dir / "commands.json")
    pid, slot = new_slot()
    plan_file = slot / "plan.bin"
    tf = _tf(settings)
    argv = [tf, "plan", "-input=false", "-no-color", "-lock=false", "-refresh=true"] + (["-destroy"] if kind == "destroy" else []) + [f"-out={plan_file}"]
    log(f"{KIND_KO[kind]} 준비 · terraform plan{' -destroy' if kind == 'destroy' else ''} (계산만, 반영 없음)")
    started = now_iso()
    t0 = time.time()
    error, plan_txt, summary = "", "", {}
    try:
        r = runner(argv, cwd=str(testbed), env=_env(profile), timeout=900)
    except ToolNotFound as e:
        r, error = None, f"terraform 실행 파일 없음: {e}"
    if r is not None:
        plan_txt = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
        clog.add(f"terraform:plan ({kind})", "testbed", [str(x) for x in argv], cwd=str(testbed), returncode=r.returncode, started_at=started,
                 elapsed=round(time.time() - t0, 2), stdout=mask(r.stdout), stderr=mask(r.stderr), ok=r.ok, note="계산만 · 상태 파일 잠금·쓰기 없음")
        if r.timed_out:
            error = "plan 이 15분 내 미완료"
        elif not r.ok:
            error = plan_error_ko(r.stderr or r.stdout)
    if not error:
        argv2 = [tf, "show", "-json", str(plan_file)]
        r2 = runner(argv2, cwd=str(testbed), env=_env(profile), timeout=300)
        clog.add("terraform:show -json", "testbed", [str(x) for x in argv2], cwd=str(testbed), returncode=r2.returncode, started_at=now_iso(),
                 stderr=mask(r2.stderr), ok=r2.ok, note="plan 파일을 JSON 으로")
        if not r2.ok:
            error = plan_error_ko(r2.stderr or r2.stdout)
        else:
            try:
                summary = summarize_plan(json.loads(r2.stdout or "{}"))
            except ValueError as e:
                error = f"plan JSON 조회 실패: {e}"
    if plan_txt:
        (ops_dir / "plan.txt").write_text(mask(plan_txt), encoding="utf-8")
    ok, why = (False, error) if error else eligible(kind, summary)
    cnt = summary.get("counts") or {}
    text = (f"plan 생성 실패 — {error}" if error else destroy_summary(cnt) if kind == "destroy" else apply_summary(kind, cnt))
    meta = {"plan_id": pid if ok else None, "kind": kind, "kind_ko": KIND_KO[kind], "created": time.time(), "created_at": now_iso(),
            "testbed_sha256": sha, "state_exists": st["exists"], "state_serial": st["serial"], "state_resources": st["resources"],
            "eligible": ok, "why": why, "counts": cnt, "summary": text, "verdict": summary.get("verdict"), "record": None,
            "ops_dir": ops_dir.relative_to(root).as_posix(), "changes": short_changes(summary), "n_changes": len(summary.get("changes") or [])}
    (ops_dir / "plan_summary.json").write_text(json.dumps({**meta, "changes": summary.get("changes"), "error": error or None}, ensure_ascii=False, indent=1, default=str),
                                              encoding="utf-8")
    if ok:
        save_meta(slot, meta)
    else:
        drop(pid)
    ops_log(root, {"at": now_iso(), "op": "plan", "kind": kind, "plan_id": meta["plan_id"], "eligible": ok, "why": why or None,
                   "counts": cnt, "testbed_sha256": sha, "state_serial": st["serial"], "dir": meta["ops_dir"]})
    log(f"{KIND_KO[kind]} plan 생성 완료 — 아직 반영 안 함 (확인 창에서 [실행] 필요) · {text}" if ok
        else f"{KIND_KO[kind]} plan 생성 완료 · {text} · 실행 불가: {why}")
    return meta


def register_candidate_plan(*, plan_file: Path, record: str, summary: Dict[str, Any], state: Dict[str, Any],
                            sha: Optional[str], plancheck_dir: str) -> Optional[str]:
    """plan 확인(plancheck.py)이 만든 plan 이 '보안 그룹만 제자리 수정' 이면 실행용으로 보관하고 id 를 돌려준다."""
    ok, why = eligible("apply_candidate", summary)
    if not ok or not plan_file.exists():
        return None
    sweep(supersede="apply_candidate")
    pid, slot = new_slot()
    shutil.move(str(plan_file), str(slot / "plan.bin"))
    cnt = summary.get("counts") or {}
    save_meta(slot, {"plan_id": pid, "kind": "apply_candidate", "kind_ko": KIND_KO["apply_candidate"], "created": time.time(), "created_at": now_iso(),
                     "testbed_sha256": sha, "state_exists": state["exists"], "state_serial": state["serial"], "state_resources": state["resources"],
                     "eligible": True, "why": "", "counts": cnt, "summary": apply_summary("apply_candidate", cnt), "verdict": summary.get("verdict"),
                     "record": record, "ops_dir": plancheck_dir, "changes": short_changes(summary), "n_changes": len(summary.get("changes") or [])})
    return pid


# ----------------------------------------------------------------------------- 2. 실행 (사람 확인 뒤)
def execute(settings: Any, *, root: Path, plan_id: str, confirm: str, profile: str, log: Callable[[str], None] = print,
            runner_stream: Optional[Callable[..., Any]] = None) -> Dict[str, Any]:
    """보관한 plan 파일 그대로 terraform apply. 확인 값·만료·파일 지문·상태 번호가 맞아야 한다."""
    from .plancheck import mask
    runner_stream = runner_stream or run_stream
    meta = load_meta(plan_id)
    if not meta:
        raise ValueError("plan 없음 또는 사용 완료 (1시간 경과 또는 실행 완료) — plan 재생성 필요")
    kind = str(meta.get("kind"))
    if confirm != CONFIRM.get(kind):
        raise ValueError(f"확인 값 불일치 — 확인 창에서 '{CONFIRM.get(kind)} 실행' 필요")
    if not meta.get("eligible"):
        raise ValueError(f"실행 불가 plan — {meta.get('why')}")
    testbed = root / TESTBED_REL
    ok, why = fresh(meta, testbed)
    if not ok:
        drop(plan_id)
        raise ValueError(why)
    plan_file = (slot_dir(plan_id) or Path("/nonexistent")) / "plan.bin"
    if not plan_file.exists():
        raise ValueError("plan 파일 없음 — plan 재생성 필요")
    op = "destroy" if kind == "destroy" else "apply"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    ops_dir = root / "data" / "testbed_ops" / f"{stamp}-{op}"
    ops_dir.mkdir(parents=True, exist_ok=True)
    clog = CommandLog(ops_dir / "commands.json")
    argv = [_tf(settings), "apply", "-input=false", "-no-color", str(plan_file)]
    log(f"{KIND_KO[kind]} 시작 — 사람이 확인한 plan 그대로 ({meta.get('summary')}) · 시험 환경 폴더만")
    started = now_iso()
    t0 = time.time()
    r = runner_stream(argv, cwd=str(testbed), env=_env(profile), timeout=2400, on_line=lambda s: log("  " + mask(s)))
    out = mask(r.stdout or "")
    (ops_dir / f"{op}.txt").write_text(out, encoding="utf-8")
    clog.add(f"terraform:apply ({kind})", "testbed", [str(x) for x in argv], cwd=str(testbed), returncode=r.returncode, started_at=started,
             elapsed=round(time.time() - t0, 2), stdout=out, ok=r.ok, note="사람이 화면에서 확인한 plan 파일 그대로")
    st = state_info(testbed)
    err = None
    if not r.ok:
        from .plancheck import plan_error_ko
        err = "시간 초과 (40분)" if r.timed_out else plan_error_ko(r.stdout)
    entry = {"at": now_iso(), "op": op, "kind": kind, "plan_id": plan_id, "record": meta.get("record"), "ok": r.ok, "error": err,
             "elapsed_s": round(time.time() - t0, 1), "counts": meta.get("counts"), "testbed_sha256": meta.get("testbed_sha256"),
             "state_resources_after": st["resources"], "state_serial_after": st["serial"], "plan_dir": meta.get("ops_dir"),
             "dir": ops_dir.relative_to(root).as_posix()}
    (ops_dir / "result.json").write_text(json.dumps(entry, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    ops_log(root, entry)
    drop(plan_id)                      # 한 번 쓴 plan 은 다시 못 쓴다 (실패해도 상태가 바뀌었을 수 있다)
    log(f"{KIND_KO[kind]} {'완료' if r.ok else '실패'} · {round(time.time() - t0)}초 · 상태 파일 리소스 {st['resources']}개" + (f" · {err}" if err else ""))
    return entry
