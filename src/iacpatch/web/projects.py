"""내 Terraform 폴더 연결 (2026-11-01 갈아엎기 4차, D-32) — 예제(3계층 · 2계층)가 아니라 아무 Terraform 폴더로 ②~⑧ 을 돈다.

- 폴더는 '경로' 로 연결한다: 복사하지 않고, 폴더에 쓰지 않는다 (읽기만). 이 PC 에서 도는 프로그램이라 경로를 바로 읽을 수 있다.
  예외는 사람이 ⑧ 에서 확인 문구를 넣고 누르는 'PR 만들기' 하나 — 그 폴더의 git 저장소에 새 브랜치를 만든다 (tools/github.py).
- 점검 = archscan.run_scan 과 같다: 실행 전 안전 점검(허용 목록) → Terraform 은 작업 폴더 사본에서 오프라인 plan → Trivy 는 읽기만.
- 기록은 data/projects/<id>/ : project.json · scan/(trivy.json · plan_baseline.json · last.json) · sets/<id>.<이름>/manifest.json
  세트 = 고칠 대상(Trivy 지적 하나). '<id>.main' 은 설계도를 붙이는 기본 세트 (고칠 대상 없음).
지원 범위(예제와 같음): Terraform 폴더 하나 · AWS provider · 원격 모듈 없음 · AWS 를 조회하는 data 소스 없이 plan 이 되는 코드.
범위 밖이면 점검 결과에 이유를 남기고, 화면은 '분석 못 함 · 판정 불가' 로 보여 준다.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import cases as cs

MAX_FILES = 3000           # 폴더 안 파일 수 (작업 폴더로 복사하기 때문에 너무 큰 폴더는 받지 않는다)
# AWS 에 묻지 않고 계산만 하는 data 소스 — 자격증명 없는 plan 에서도 된다. 그 밖의 data 소스(aws_vpc · aws_ami · aws_caller_identity 등)는
# plan 중에 AWS 를 조회한다: 가짜 자격증명으로는 실패하거나 재시도로 오래 멈춘다 (샌드박스 실측 2026-11-01: 5분 넘게 응답 없음) → plan 전에 건너뛴다
OFFLINE_DATA_OK = frozenset({"aws_iam_policy_document", "aws_partition", "aws_region"})
MAX_BYTES = 60_000_000
MAX_TF = 300
SKIP_DIRS = {".git", ".terraform", "node_modules", ".venv", "__pycache__"}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _clean_path(raw: str) -> Path:
    s = str(raw or "").strip().strip('"').strip("'").strip()
    return Path(s).expanduser()


def inspect_folder(raw: str) -> Dict[str, Any]:
    """연결 전에 폴더를 읽기만 해서 확인 — .tf 파일 · 크기 · 하위 폴더 · tfstate 유무(내용은 읽지 않음) · git 저장소 여부."""
    p = _clean_path(raw)
    out: Dict[str, Any] = {"ok": False, "input": str(raw or ""), "errors": [], "notes": []}
    if not str(raw or "").strip():
        out["errors"].append("폴더 경로를 넣어 주세요 (예: C:\\Users\\me\\infra)")
        return out
    if not p.is_absolute():
        out["errors"].append("전체 경로로 넣어 주세요 (드라이브 · 맨 앞 / 부터)")
        return out
    if not p.exists() or not p.is_dir():
        out["errors"].append(f"폴더가 없음: {p}")
        return out
    p = p.resolve()
    root = cs._root().resolve()
    if p == root or root in p.parents and (p == root / "data" or root / "data" in p.parents):
        out["errors"].append("프로그램 폴더 자체 · 기록 폴더(data)는 연결할 수 없음")
        return out
    n_files, n_bytes, sub_tf = 0, 0, []
    for q in p.rglob("*"):
        if any(part in SKIP_DIRS for part in q.relative_to(p).parts):
            continue
        if q.is_file():
            n_files += 1
            try:
                n_bytes += q.stat().st_size
            except OSError:
                pass
            if q.suffix == ".tf" and q.parent != p:
                sub_tf.append(q.relative_to(p).as_posix())
        if n_files > MAX_FILES or n_bytes > MAX_BYTES:
            out["errors"].append(f"폴더가 너무 큼 (파일 {MAX_FILES}개 · {MAX_BYTES // 1_000_000}MB 까지) — Terraform 파일이 있는 폴더만 연결하세요")
            return out
    tf = sorted(x.name for x in p.glob("*.tf"))
    out.update({"path": p.as_posix(), "folder": p.name, "tf_files": tf, "n_files": n_files, "bytes": n_bytes})
    if not tf:
        out["errors"].append("이 폴더 바로 아래에 .tf 파일이 없음 — Terraform 코드가 있는 폴더를 고르세요")
    if len(tf) > MAX_TF:
        out["errors"].append(f".tf 파일이 너무 많음 ({len(tf)}개, {MAX_TF}개까지)")
    if sub_tf:
        out["notes"].append(f"하위 폴더의 .tf {len(sub_tf)}개 (예: {', '.join(sub_tf[:3])}) — 모듈은 지원 범위 밖이라 이 폴더의 .tf 만 봅니다")
    if any(p.glob("*.tfstate")):
        out["notes"].append("tfstate 파일이 있음 — 프로그램은 읽지 않습니다 (자격증명 · 실제 값이 들어 있을 수 있음)")
    git = _git_top(p)
    out["git"] = {"repo": git.as_posix() if git else None}
    if not git:
        out["notes"].append("git 저장소가 아님 — 검사 · AI 수정은 되지만 PR 은 못 만듭니다")
    out["ok"] = not out["errors"]
    return out


def offline_blockers(folder: Path) -> List[str]:
    """자격증명 없는 plan 에서 실행할 수 없는 것 = AWS 를 조회하는 data 소스. 주석 · 문자열 안은 보지 않는다 (exec_guard 의 스캐너)."""
    from ..policy.exec_guard import scan
    out: List[str] = []
    for f in sorted(Path(folder).glob("*.tf")):
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for kind, labels, _body, _pos in scan(text)["blocks"]:
            if kind == "data" and len(labels) >= 2 and labels[0] not in OFFLINE_DATA_OK:
                out.append(f"data.{labels[0]}.{labels[1]} ({f.name})")
    return out


def set_problem(man: Dict[str, Any]) -> Optional[str]:
    """연결한 프로젝트의 고칠 대상(세트)으로 검사 · AI 수정을 시작할 수 없는 이유 (없으면 None). 예제 세트는 None."""
    if not man.get("project"):
        return None
    if not Path(str(man.get("trivy_json") or "")).exists():
        return "프로젝트 점검 결과(Trivy)가 없음 — ② 에서 점검을 먼저"
    if not Path(str(man.get("baseline_plan") or "")).exists():
        return "원본 plan 이 없어 수정 검사(V3~V6)를 할 수 없음 — ② 현재 인프라의 이유 참고 (지원 범위 밖이면 탐지만)"
    return None


def _git_top(p: Path) -> Optional[Path]:
    from ..tools.runner import run, which
    if which("git") is None:
        return None
    try:
        r = run(["git", "-C", str(p), "rev-parse", "--show-toplevel"], timeout=20)
    except Exception:  # noqa: BLE001
        return None
    return Path(r.stdout.strip()) if r.ok and r.stdout.strip() else None


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(name or "").lower()).strip("-")[:24]
    return s if len(s) >= 2 else "proj"


def project_dir(pid: str) -> Path:
    if not cs.PROJECT_ID_RE.match(str(pid or "")):
        raise ValueError(f"프로젝트 id 형식이 아님: {pid!r}")
    return cs.projects_root() / pid


def create(name: str, raw_path: str) -> Dict[str, Any]:
    """폴더를 연결해 프로젝트를 만든다. 같은 폴더를 이미 연결했으면 그 프로젝트를 돌려준다 (중복 없음)."""
    info = inspect_folder(raw_path)
    if not info["ok"]:
        return {"ok": False, "errors": info["errors"], "inspect": info}
    for c in cs.user_projects():
        if str(c.get("path")).lower() == info["path"].lower():
            return {"ok": True, "project": c["id"], "existing": True, "inspect": info}
    label = str(name or "").strip()[:40] or info["folder"]
    # id = 폴더 이름 + 경로 지문 — 이름을 바꿔 다시 연결해도 같은 폴더면 같은 id (설계도 · 기록이 다시 붙는다)
    pid = f"{_slug(info['folder'])}-{hashlib.sha256(info['path'].encode('utf-8')).hexdigest()[:6]}"
    d = project_dir(pid)
    (d / "scan").mkdir(parents=True, exist_ok=True)
    meta = {"id": pid, "name": label, "path": info["path"], "folder": info["folder"], "created_at": _now(), "kind": "user",
            "tf_files": info["tf_files"], "git_repo": info["git"]["repo"], "notes": info["notes"]}
    (d / "project.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    _write_set(pid, f"{pid}.main", {"label": "고객 설계 기준"})
    return {"ok": True, "project": pid, "existing": False, "inspect": info}


def remove(pid: str) -> Dict[str, Any]:
    """프로젝트 연결만 끊는다 (data/projects/<id> = 점검 결과 · 고칠 대상 목록 삭제). 연결했던 폴더는 건드리지 않는다.
    고객 설계도(data/designs/<id>) · 검토 기록(data/reviews) · AI 수정 기록은 증거라서 지우지 않는다 — 같은 폴더를 다시 연결하면
    같은 id(이름 + 경로 지문)라서 설계도가 다시 붙는다."""
    d = project_dir(pid)
    if not (d / "project.json").exists():
        return {"ok": False, "error": "프로젝트 없음"}
    shutil.rmtree(d)
    return {"ok": True}


def _write_set(pid: str, set_id: str, extra: Dict[str, Any]) -> Path:
    meta = json.loads((project_dir(pid) / "project.json").read_text(encoding="utf-8"))
    sd = project_dir(pid) / "sets" / set_id
    sd.mkdir(parents=True, exist_ok=True)
    scan = project_dir(pid) / "scan"
    man = {"set_id": set_id, "project": pid, "tf_dir": meta["path"], "trivy_json": (scan / "trivy.json").as_posix(),
           "baseline_plan": (scan / "plan_baseline.json").as_posix(), "candidates": [], "created_at": _now(), **extra}
    (sd / "manifest.json").write_text(json.dumps(man, ensure_ascii=False, indent=2), encoding="utf-8")
    return sd


def ensure_target(pid: str, rule: str, resource: str) -> Dict[str, Any]:
    """④ 에서 고른 문제(Trivy 지적 하나) → 고칠 대상 세트. 같은 (룰, 리소스)는 같은 세트 (다시 만들지 않는다)."""
    from ..review.inputs import list_findings, load_trivy_report
    d = project_dir(pid)
    tj = d / "scan" / "trivy.json"
    if not tj.exists():
        return {"ok": False, "error": "점검 결과 없음 — 프로젝트 점검을 먼저"}
    if not (d / "scan" / "plan_baseline.json").exists():
        return {"ok": False, "error": "원본 plan 이 없어 수정 검사를 할 수 없음 — ② 현재 인프라의 이유 참고 (지원 범위 밖이면 탐지만)"}
    hits = [f for f in list_findings(load_trivy_report(tj)) if f.status == "FAIL" and f.rule_id == rule and f.resource == resource]
    if not hits:
        return {"ok": False, "error": f"점검 결과에 그 문제가 없음: {rule} · {resource}"}
    f = hits[0]
    from .product import projects_sg_target
    if not projects_sg_target(resource):
        return {"ok": False, "error": "연결한 프로젝트는 보안 그룹 문제만 고칠 대상으로 받음 — IAM 은 필요한 권한(요구사항)을 정하는 기능이 없어 고친 뒤 판정할 수 없음 (탐지만)"}
    if "/" in f.filename.replace("\\", "/").strip("/"):
        return {"ok": False, "error": f"하위 폴더(모듈) 파일의 문제는 지원 범위 밖: {f.filename}"}
    set_id = f"{pid}.t{hashlib.sha256(f'{rule}|{resource}'.encode('utf-8')).hexdigest()[:8]}"
    if not (d / "sets" / set_id / "manifest.json").exists():
        from .product import title_ko
        _write_set(pid, set_id, {"rule": rule, "resource": resource, "file": Path(f.filename).name, "line": int(f.start_line),
                                 "label": f"{title_ko(rule, f.title)} — {resource}"})
    return {"ok": True, "set_id": set_id}


def job_scan(pid: str) -> Callable:
    """프로젝트 점검: 실행 전 안전 점검 → (작업 폴더 사본에서) Terraform 오프라인 plan → Trivy. AWS 접속 · apply 없음.
    결과는 data/projects/<id>/scan/ 에: trivy.json (④ 문제 목록) · plan_baseline.json (② 그림 · 설계 비교) · last.json (상태 · 이유)."""
    from ..archscan import run_scan
    d = project_dir(pid)
    meta = json.loads((d / "project.json").read_text(encoding="utf-8"))

    def fn(log: Callable[[str], None], prog: Callable[[int, int], None]) -> Dict[str, Any]:
        root = cs._root()
        src = Path(meta["path"])
        if not src.is_dir():
            raise RuntimeError(f"연결한 폴더가 없음: {src} (옮겼거나 지웠으면 프로젝트를 다시 연결)")
        out = d / "scan" / time.strftime("run-%Y%m%d-%H%M%S")
        log(f"프로젝트 점검: {meta['name']} — {src}")
        prog(1, 3)
        blockers = offline_blockers(src)
        if blockers:
            log("AWS 를 조회하는 data 소스가 있어 Terraform plan 은 건너뜀 (자격증명 없이 실행할 수 없음): " + ", ".join(blockers[:5]))
        res = run_scan(src, out, root, do_plan=not blockers, log=log)
        prog(2, 3)
        last: Dict[str, Any] = {"at": _now(), "run": out.name, "guard": res.get("guard"), "unsupported": blockers,
                                "plan": {k: v for k, v in (res.get("plan") or {}).items() if k in ("status", "error", "steps", "resource_count")},
                                "scan": {k: v for k, v in (res.get("scan") or {}).items() if k in ("status", "error")}, "tools": res.get("tools")}
        for name, dst in (("trivy.json", "trivy.json"), ("plan.json", "plan_baseline.json")):
            if (out / name).exists():
                shutil.copy2(out / name, d / "scan" / dst)
            elif (d / "scan" / dst).exists():
                (d / "scan" / dst).unlink()       # 이번 점검에서 못 만들었으면 예전 결과를 남기지 않는다 (섞이지 않게)
        work = out / "work"
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)   # 작업 폴더 사본은 지운다 (원본 사본 · provider 파일)
        last["why"] = _why(last)
        (d / "scan" / "last.json").write_text(json.dumps(last, ensure_ascii=False, indent=2), encoding="utf-8")
        log("점검 끝: " + (" · ".join(last["why"]) if last["why"] else "Trivy · plan 모두 됨"))
        auto: Dict[str, Any] = {}
        if (d / "scan" / "plan_baseline.json").exists():
            # 원하는 구조가 아직 없으면 자동 기준(지금 코드 − 위험한 통신)을 v1 로 (D-33). 이미 있으면 그대로 — 코드가 바뀌어도 원하는 구조는 사람이 바꾼다
            from . import structure
            try:
                auto = structure.ensure_auto(pid)
            except Exception as e:  # noqa: BLE001 — 자동 기준 실패는 점검 실패가 아님 (③ 에서 다시)
                auto = {"ok": False, "reason": f"{type(e).__name__}: {e}"}
            if auto.get("created"):
                log(f"원하는 구조: 자동 기준 v1 저장 (위험해서 뺀 통신 {len(auto.get('excluded') or [])}개 — ③ 에서 그림으로 바꿀 수 있음)")
            elif not auto.get("ok"):
                log(f"원하는 구조: 자동 기준을 만들지 못함 — {auto.get('reason')}")
        prog(3, 3)
        return {"project": pid, "plan": last["plan"].get("status"), "scan": last["scan"].get("status"), "why": last["why"],
                "auto_design": bool(auto.get("created"))}
    return fn


def _why(last: Dict[str, Any]) -> List[str]:
    """점검이 막힌 이유를 사람 말로 (화면 ② · ④ 의 '분석 못 함' 설명)."""
    out: List[str] = []
    g = last.get("guard") or {}
    if g and not g.get("ok", True):
        vs = g.get("violations") or []
        out.append("실행 전 안전 점검에서 멈춤 — 지원 범위 밖 구문: " + "; ".join(vs[:3]) + (" 외" if len(vs) > 3 else ""))
        return out
    pl = last.get("plan") or {}
    ub = last.get("unsupported") or []
    if ub:
        out.append("AWS 를 조회하는 data 소스가 있어 Terraform plan 을 만들지 않음 (자격증명 없이 실행할 수 없음 — 지원 범위 밖): "
                   + ", ".join(ub[:4]) + (" 외" if len(ub) > 4 else "") + " · Trivy 탐지만 함")
    elif pl.get("status") not in ("PASS", None):
        steps = pl.get("steps") or {}
        bad = [k for k, v in steps.items() if not (v or {}).get("ok", True)]
        err = (steps.get(bad[0]) or {}).get("error", "") if bad else str(pl.get("error") or "")
        hint = ""
        if re.search(r"data\.|data source|No valid credential|InvalidClientTokenId|AuthFailure|STS", err):
            hint = " (AWS 를 조회하는 data 소스는 오프라인 plan 이 안 됨 — 지원 범위 밖)"
        elif "Module not installed" in err or "module" in err.lower():
            hint = " (모듈은 지원 범위 밖)"
        out.append(f"Terraform plan 실패 ({', '.join(bad) or pl.get('status')}){hint}: {err.strip()[:240]}")
    sc = last.get("scan") or {}
    if sc.get("status") not in ("PASS", None):
        out.append(f"Trivy 점검 실패: {str(sc.get('error') or sc.get('status'))[:200]}")
    return out
