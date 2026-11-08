"""화면의 '탐지 방식' 보기에 쓰는 자료.

  /api/proof?id=<기록>          단계별 증거 카드 (V1~V6, 실제 AWS 검사의 시험 환경 반영·V7·V8) + 검증 도구 사전 점검 + 근거 파일 해시 목록
  /api/proof/calibration        가장 최근 검증 도구 사전 점검 결과
  POST /api/proof/calibrate     검증 도구 사전 점검 실행 (작업)
  /api/proof/report?id=<기록>   증거 보고서 HTML (기록 폴더 evidence/report.html 로도 저장)
  /api/proof/file?id=&path=     기록 폴더의 원본 파일 (manifest 에 있는 것만)
  /api/topomap?case=&set=       설계도 ↔ Terraform 코드 대응표

판정은 기록 값만 쓴다. 이 모듈은 판정을 만들지 않는다.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

CALIBRATION_MAX_AGE_S = 12 * 3600


def _root() -> Path:
    from .. import app as _app
    return _app.ROOT


def _reviews() -> Path:
    from .server import reviews_root
    return reviews_root()


def _record_dir(rid: str) -> Optional[Path]:
    if not rid or ".." in rid or "/" in rid or "\\" in rid:
        return None
    d = _reviews() / rid
    return d if d.is_dir() else None


def _j(p: Path) -> Optional[Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ----------------------------------------------------------------------------- 검증 도구 사전 점검
def _tool_versions(settings) -> Dict[str, Optional[str]]:
    from ..tools.terraform import TerraformAdapter
    from ..tools.trivy import TrivyAdapter
    tv = TrivyAdapter(settings.trivy_bin)
    info = TerraformAdapter(settings.terraform_bin, settings.aws_region).info()
    return {"trivy": tv.version() if tv.available() else None,
            "terraform": f"{info.kind or 'terraform'} {info.version}" if info.available else None}


def calibration_brief(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """화면용으로 줄인 점검 결과 (시료 코드 원문 포함, 큰 값 제외)."""
    if not doc:
        return None
    out = {k: doc.get(k) for k in ("id", "started_at", "elapsed_s", "summary", "tools", "probe", "validate")}
    rule = dict(doc.get("rule") or {})
    out["rule"] = {k: rule.get(k) for k in ("version", "bytes", "elapsed_s", "cached", "rule", "reference", "ran", "reason")}
    out["trivy"] = [{k: r.get(k) for k in ("id", "label", "cidrs", "risky", "meaning", "code", "expect", "result", "verdict", "rule_records",
                                             "checks_executed", "elapsed_s", "output", "output_sha256")} for r in doc.get("trivy") or []]
    cidr = doc.get("cidr") or {}
    out["cidr"] = {"split": cidr.get("split"), "differential": {k: (cidr.get("differential") or {}).get(k)
                                                                 for k in ("cases", "seed", "mismatches", "examples", "cases_covering_internet", "elapsed_s")}}
    out["dir"] = Path(str(doc.get("_dir") or "")).name if doc.get("_dir") else doc.get("id")
    return out


def ensure_calibration(settings, tf_dir: Optional[Path], log: Callable[[str], None]) -> Dict[str, Any]:
    """최근 점검이 있고(12시간 안) 도구 버전이 같으면 재사용, 아니면 지금 실행. 재사용 여부를 결과에 적는다."""
    from ..proof import calibrate
    vers = _tool_versions(settings)
    doc = calibrate.latest(settings, CALIBRATION_MAX_AGE_S)
    if doc is not None:
        same = (doc.get("tools") or {}).get("trivy") == vers.get("trivy") and (doc.get("tools_terraform") in (None, vers.get("terraform")))
        ref_ok = ((doc.get("rule") or {}).get("reference") or {}).get("same", True)
        if same and ref_ok:
            age = time.time() - Path(str(doc.get("_dir"))).joinpath("calibration.json").stat().st_mtime
            log(f"검증 도구 사전 점검: {doc.get('id')} 결과 재사용 ({int(age // 60)}분 전, 같은 도구 버전)")
            doc["_reused"] = True
            doc["_age_s"] = round(age)
            return doc
    log("검증 도구 사전 점검 실행 (기대 결과가 고정된 점검 시료로 도구 동작 확인)")
    doc = calibrate.run_calibration(settings, tf_dir, log=log)
    doc["tools_terraform"] = vers.get("terraform")
    try:
        p = settings.path("data/calibration") / str(doc["id"]) / "calibration.json"
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        doc["_dir"] = str(p.parent)
    except OSError:
        pass
    doc["_reused"] = False
    return doc


def attach_calibration(record_dir: Path, doc: Dict[str, Any]) -> None:
    """기록 폴더에 이번 검사 때 쓴 점검 결과를 복사하고 파일 해시 목록을 다시 쓴다."""
    from ..evidence_log import write_manifest
    ev = record_dir / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    keep = {k: v for k, v in doc.items() if not k.startswith("_")}
    keep["reused"] = bool(doc.get("_reused"))
    keep["age_s_at_use"] = doc.get("_age_s", 0)
    (ev / "calibration.json").write_text(json.dumps(keep, ensure_ascii=False, indent=2), encoding="utf-8")
    src = Path(str(doc.get("_dir") or ""))
    if src.is_dir():
        dst = ev / "calibration_files"
        dst.mkdir(exist_ok=True)
        for f in src.iterdir():
            if f.is_file() and f.suffix in (".json", ".tf") and f.name != "calibration.json":
                shutil.copy2(f, dst / f.name)
    write_manifest(record_dir)


def job_calibrate(case_id: str) -> Callable:
    from ..config import load_settings
    from . import cases as cs

    def fn(log, prog):
        from ..proof import calibrate
        from .. import app as _app
        import os
        env = _app._env()
        os.environ.update({k: env[k] for k in ("TRIVY_BIN", "TERRAFORM_BIN", "TRIVY_SKIP_CHECK_UPDATE", "TRIVY_SKIP_VERSION_CHECK", "TF_PLUGIN_CACHE_DIR") if k in env})
        s = load_settings(str(_root()))
        case = cs.get_case(case_id) or cs.CASES[0]
        doc = calibrate.run_calibration(s, _root() / case["tf_dir"], log=log)
        doc["tools_terraform"] = _tool_versions(s).get("terraform")
        p = s.path("data/calibration") / str(doc["id"]) / "calibration.json"
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"calibration": doc["id"], "summary": doc.get("summary")}
    return fn


def calibration_view() -> Dict[str, Any]:
    from ..config import load_settings
    from ..proof import calibrate
    doc = calibrate.latest(load_settings(str(_root())))
    if not doc:
        return {"ok": False, "reason": "사전 점검 기록 없음"}
    age = time.time() - Path(str(doc["_dir"])).joinpath("calibration.json").stat().st_mtime
    b = calibration_brief(doc) or {}
    b["age_s"] = round(age)
    b["ok"] = True
    return b


# ----------------------------------------------------------------------------- 카드
def proof_view(rid: str) -> Dict[str, Any]:
    from ..proof.cards import build_cards
    from ..proof import postcards
    d = _record_dir(rid)
    if d is None:
        return {"error": f"기록 없음: {rid}"}
    out = build_cards(d, _root())
    cal = _j(d / "evidence" / "calibration.json")
    out["calibration"] = calibration_brief(cal) if cal else None
    if cal:
        out["calibration"]["reused"] = cal.get("reused")
        out["calibration"]["age_s_at_use"] = cal.get("age_s_at_use")
    man = _j(d / "evidence" / "manifest.json") or {}
    out["manifest_files"] = man.get("files") or []
    out["manifest_created_at"] = man.get("created_at")
    out["post"] = postcards.build_post_cards(d, _root())
    out["record_dir"] = f"data/reviews/{d.name}"
    return out


def evidence_file(rid: str, rel: str) -> Dict[str, Any]:
    d = _record_dir(rid)
    if d is None or not rel or ".." in rel or rel.startswith(("/", "\\")):
        return {"error": "파일 없음"}
    man = _j(d / "evidence" / "manifest.json") or {}
    allowed = {f["path"] for f in man.get("files") or []} | {"evidence/manifest.json"}
    p = d / rel
    if rel not in allowed and not rel.startswith("postdeploy/"):
        return {"error": "기록 목록(manifest)에 없는 파일"}
    if not p.is_file():
        return {"error": "파일 없음"}
    raw = p.read_bytes()
    from ..evidence_log import sha256_file
    text = raw[:400_000].decode("utf-8", "replace")
    from ..proof.postcards import mask_account
    return {"path": rel, "bytes": len(raw), "sha256": sha256_file(p), "truncated": len(raw) > 400_000, "text": mask_account(text)}


def report_html(rid: str) -> Optional[str]:
    from ..proof.report import render_report
    d = _record_dir(rid)
    if d is None:
        return None
    view = proof_view(rid)
    html = render_report(view)
    try:
        (d / "evidence").mkdir(exist_ok=True)
        (d / "evidence" / "report.html").write_text(html, encoding="utf-8")
    except OSError:
        pass
    return html


# ----------------------------------------------------------------------------- 설계도 ↔ 코드
def topomap_view(case_id: str, set_id: str = "") -> Dict[str, Any]:
    from . import cases as cs
    from ..proof.topomap import build_map
    case = cs.get_case(case_id)
    if case is None:
        return {"error": f"사례 없음: {case_id}"}
    sref = next((s for s in case.get("sets", []) if not set_id or s["set_id"] == set_id), None)
    if sref is None:
        return {"error": f"영역 없음: {set_id}"}
    man, set_dir = cs._manifest(sref["set_id"])
    ipath = cs._resolve((man or {}).get("intent"), set_dir)
    intent = _j(ipath) if ipath else None
    if not intent or intent.get("kind") != "topology":
        return {"ok": False, "reason": "이 영역은 설계도(통신 경로) 형식의 요구사항이 아님"}
    tf_dir = _root() / case["tf_dir"]
    sources = {p.name: p.read_text(encoding="utf-8") for p in sorted(tf_dir.glob("*.tf"))}
    out = build_map(sources, intent, case["tf_dir"])
    from ..evidence_log import sha256_file
    out["ok"] = True
    out["intent_file"] = str(ipath.relative_to(_root())) if ipath and str(ipath).startswith(str(_root())) else str(ipath)
    out["intent_sha256"] = sha256_file(ipath) if ipath else None
    return out


# ----------------------------------------------------------------------------- 실제 AWS 검사 (시험 환경 측정)
TESTBED = "scenarios/arch/webapp-3tier-testbed"
TESTBED_SET = "arch-3tier-sg"        # 시험 환경은 3계층 웹 서비스 하나뿐 — 이 후보 묶음의 기록만 시험 환경에 넣고 잰다


def record_set(rd: Optional[Path]) -> str:
    """기록의 후보 묶음 이름 (state.json scenario 'ui/<묶음>/<후보>' 의 가운데). 모르면 ''."""
    if rd is None:
        return ""
    parts = str((_j(rd / "state.json") or {}).get("scenario") or "").split("/")
    return parts[1] if len(parts) >= 3 and parts[0] == "ui" else ""


def testbed_case_ok(rd: Optional[Path]) -> bool:
    """이 기록의 후보를 3계층 시험 환경에 넣어도 되는가 — 다른 사례(예: 2계층)의 파일을 넣으면 시험 환경 보안 그룹이 통째로 바뀐다."""
    return rd is not None and record_set(rd) == TESTBED_SET
TOPO_INTENT = "experiments/candidate-sets/arch-3tier-sg/intents/arch-3tier-flows.json"


def _compare_files(record_dir: Optional[Path]) -> Dict[str, Path]:
    root = _root()
    files: Dict[str, Path] = {"원본 (scenarios/arch/webapp-3tier)": root / "scenarios" / "arch" / "webapp-3tier" / "security_groups.tf"}
    from .cases import _manifest, display_labels
    man, set_dir = _manifest(TESTBED_SET)
    labels = display_labels(TESTBED_SET, man)
    for c in sorted((man or {}).get("candidates") or [], key=lambda c: labels.get(str(c.get("id")), "")):
        ref = str(c.get("candidate") or "")
        p = set_dir / ref[7:] if ref.startswith("manual:") and ref.endswith(".tf") else None
        if p is not None and p.exists():
            files[labels.get(str(c.get("id")), "후보")] = p           # 화면 이름 '후보 NN' (파일 이름은 기대 결과를 드러낼 수 있음, 피드백 7)
    if record_dir is not None and (record_dir / "candidate" / "security_groups.tf").exists():
        files[f"이 기록의 후보 ({record_dir.name})"] = record_dir / "candidate" / "security_groups.tf"
    return files


SETTLE_AFTER_APPLY_S = 120   # apply 가 끝나고 이만큼 지나야 측정 — 측정기 결과(콘솔 출력이 20~40초 늦게 보임)가 바뀐 설정을 반영하도록
DEFAULT_PROFILE = "capstone-tf"      # 팀 노트북의 Terraform 용 프로필 (aws login 세션을 빌려 씀). 화면에서 바꿀 수 있다.
ORIGINAL_SG = "scenarios/arch/webapp-3tier/security_groups.tf"


def _state_resources(stp: Path) -> Optional[int]:
    """상태 파일의 리소스 수. destroy 뒤에는 0 (파일은 남는다). 읽을 수 없거나 resources 칸이 없으면 None."""
    try:
        doc = json.loads(stp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    res = doc.get("resources") if isinstance(doc, dict) else None
    return len(res) if isinstance(res, list) else None


def _sync_basis(tb: Path, sha: Optional[str], record_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """보안 그룹 파일의 수정 시각이 상태 파일보다 나중이어도, 파일 '내용' 이 지금 배포 상태와 같다는 기록이 있으면 그 근거.
    원본 → 후보 → 원본처럼 같은 내용으로 다시 쓰면 수정 시각만 바뀐다 (2026-10-27 실제 발생 — 원본 재배포 plan 이 '변경 없음' 이라 진행 불가).
    근거 1 apply: 앱의 마지막 apply 가 이 내용(sha256)이었고, 그 뒤 상태 파일 번호(serial)가 그대로
    근거 2 plan: 그 뒤 이 내용으로 한 원본 반영 plan 이 '변경 없음' 이었고, 그때와 상태 파일 번호가 그대로
    근거 3 plan_check: 이 기록의 plan 확인(이 내용)이 '변경 없음' 이었고, 그때와 상태 파일 번호가 그대로
    앱 밖(PowerShell)에서 apply · destroy 하면 상태 파일 번호가 바뀌어 근거가 사라진다 (그때는 수정 시각으로만 판단)."""
    from ..testbed_ops import state_info
    if not sha:
        return None
    cur = state_info(tb).get("serial")
    if cur is None:
        return None
    try:
        lines = (_root() / "data" / "testbed_ops.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in reversed(lines):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        op = e.get("op")
        if op == "destroy":
            break
        if op == "apply":
            if e.get("ok") and e.get("testbed_sha256") == sha and e.get("state_serial_after") == cur:
                return {"basis": "apply", "at": e.get("at")}
            break                                          # 마지막 apply 가 다른 내용 — 배포 상태 ≠ 이 파일
        cnt = e.get("counts") or {}
        if (op == "plan" and e.get("kind") == "apply_original" and e.get("testbed_sha256") == sha and e.get("state_serial") == cur
                and cnt and not any(cnt.values()) and not e.get("eligible")):
            doc = _j(_root() / str(e.get("dir") or "") / "plan_summary.json") or {}
            if doc.get("verdict") == "NO_CHANGES" and not doc.get("error"):
                return {"basis": "plan", "at": e.get("at")}
    if record_dir is not None:
        from ..plancheck import latest_for
        pc = latest_for(_j(record_dir / "state.json") or {}, sha, decisive=True)
        if pc and pc.get("verdict") == "NO_CHANGES":
            doc = _j(record_dir / str(pc.get("path") or "") / "plan_summary.json") or {}
            if doc.get("state_serial") is not None and doc.get("state_serial") == cur:
                return {"basis": "plan_check", "at": pc.get("at")}
    return None


def _testbed_files(record_dir: Optional[Path] = None) -> Dict[str, Any]:
    """시험 환경 폴더의 보안 그룹 파일과 상태 파일의 시각 + 상태 파일의 리소스 수 (destroy 뒤면 0).
    applied_after_change: 지금 파일 내용이 배포(apply)된 상태인가 — 상태 파일이 파일보다 나중이거나, 내용이 같다는 기록(_sync_basis)이 있을 때."""
    from ..measure import _sha
    tb = _root() / TESTBED
    sgp, stp = tb / "security_groups.tf", tb / "terraform.tfstate"
    sg_m = sgp.stat().st_mtime if sgp.exists() else None
    st_m = stp.stat().st_mtime if stp.exists() else None
    since = (time.time() - st_m) if st_m else None
    sha = _sha(sgp)
    by_time = bool(sg_m and st_m and st_m >= sg_m)
    sync = _sync_basis(tb, sha, record_dir) if (not by_time and sg_m and st_m) else None
    return {"tb": tb, "sha": sha, "sg_mtime": sg_m, "state_mtime": st_m, "state": stp.exists(),
            "state_resources": _state_resources(stp) if stp.exists() else None,
            "applied_after_change": by_time or bool(sync),
            "sync_basis": (sync or {}).get("basis"), "sync_at": (sync or {}).get("at"),
            "since_apply_s": round(since) if since is not None else None,
            "settled": since is not None and since >= SETTLE_AFTER_APPLY_S}


def _tf_cmd(sub: str) -> str:
    from .. import app as _app
    tf = _app._env().get("TERRAFORM_BIN") or "terraform"
    return f'& "{tf}" {sub}' if Path(tf).is_absolute() else f"{tf} {sub}"


def measure_setup(rid: str = "") -> Dict[str, Any]:
    from ..config import load_settings
    from ..tools.awscli import AwsCli
    from ..measure import _sha
    s = load_settings(str(_root()))
    rd = _record_dir(rid) if rid else None
    f = _testbed_files(rd)
    tb, sha = f["tb"], f["sha"]
    matches = [k for k, p in _compare_files(rd).items() if sha and _sha(p) == sha]
    cand = (rd / "candidate" / "security_groups.tf") if rd is not None else None
    orig = _root() / ORIGINAL_SG
    profile = s.aws_profile or DEFAULT_PROFILE
    cli = AwsCli(s.aws_bin, profile, s.aws_region)
    rec_state = (_j(rd / "state.json") or {}) if rd is not None else {}
    from ..plancheck import blocked_for, latest_for
    pc_last = rec_state.get("plan_check") if isinstance(rec_state.get("plan_check"), dict) else None
    pc = None
    if pc_last:
        pc = {k: pc_last.get(k) for k in ("run_id", "at", "verdict", "summary", "counts", "replaced", "deleted", "path")}
        pc["current"] = bool(sha) and pc_last.get("candidate_sha256") == sha   # 지금 시험 환경 파일로 한 확인인가
        from ..proof.plain import legacy
        pc["summary"] = legacy(pc.get("summary"))                                 # 예전 기록의 문구는 지금 용어로 (기록 파일은 그대로)
    # [이 후보 apply] 에 쓸 수 있는 plan — plan 확인이 CLEAN 이고, 그 뒤로 파일·상태가 그대로이며 1시간이 안 지났을 때만
    from ..testbed_ops import fresh, last_ops, load_meta, state_info
    plan_ready = None
    pid = (pc_last or {}).get("plan_id")
    pmeta = load_meta(pid) if pid else None
    if pmeta and rd is not None and pmeta.get("kind") == "apply_candidate" and pmeta.get("record") == rd.name and fresh(pmeta, tb)[0]:
        plan_ready = {k: pmeta.get(k) for k in ("plan_id", "kind", "kind_ko", "summary", "counts", "created_at", "changes", "n_changes", "ops_dir")}
        from ..proof.plain import legacy
        plan_ready["summary"], plan_ready["kind_ko"] = legacy(plan_ready.get("summary")), legacy(plan_ready.get("kind_ko"))
    # 앱의 [이 후보 apply] 로 이미 반영했나 (지금 시험 환경 파일이 그 후보이고, 그 뒤로 다른 apply·destroy 가 없을 때)
    ta = rec_state.get("testbed_apply") if isinstance(rec_state.get("testbed_apply"), dict) else None
    ops = last_ops(_root(), 1)
    cand_applied = None
    if (ta and ta.get("ok") and sha and ta.get("candidate_sha256") == sha and ops and ops[0].get("dir") == ta.get("ops_dir")
            and state_info(tb).get("serial") == ops[0].get("state_serial_after")):
        cand_applied = {"at": ta.get("at"), "ops_dir": ta.get("ops_dir")}
    return {"testbed": TESTBED, "testbed_abs": str(tb), "exists": tb.is_dir(), "deployed_state_file": f["state"] and f["state_resources"] != 0,
            "tf_inited": (tb / ".terraform").is_dir(),
            "plan_check": pc, "plan_blocked": bool(blocked_for(rec_state, sha)) if rd is not None else False,
            "plan_ready": plan_ready, "ops_last": ops[0] if ops else None, "cand_applied": cand_applied,
            "plan_clean": bool((latest_for(rec_state, sha, decisive=True) or {}).get("verdict") in ("CLEAN", "NO_CHANGES")) if rd is not None else False,
            "state_resources": f["state_resources"], "destroyed": f["state"] and f["state_resources"] == 0,
            "applied_after_change": f["applied_after_change"], "sync_basis": f["sync_basis"], "sync_at": f["sync_at"],
            "since_apply_s": f["since_apply_s"], "settled": f["settled"],
            "settle_s": SETTLE_AFTER_APPLY_S,
            "security_groups_sha256": sha, "matches": matches, "aws_cli": cli.available(), "aws_bin": s.aws_bin,
            "is_original": bool(sha) and _sha(orig) == sha, "is_record_candidate": bool(sha) and cand is not None and cand.exists() and _sha(cand) == sha,
            "record_passed": rec_state.get("review_level") in ("LIGHT_REVIEW", "FULL_REVIEW"),
            "record_case_ok": testbed_case_ok(rd) if rd is not None else None,
            "profile": profile, "region": s.aws_region,
            "commands": {"cd": f'cd "{tb}"', "profile": f'$env:AWS_PROFILE = "{profile}"', "login": "aws login --profile capstone",
                         "check": "aws sts get-caller-identity", "apply": _tf_cmd("apply"), "plan": _tf_cmd("plan"), "destroy": _tf_cmd("destroy")},
            "does": ["terraform show -json (이 PC 의 상태 파일 조회)",
                     "terraform plan — plan 확인 (실제 상태 기준 계산만, 상태 파일 잠금·쓰기 없음)",
                     "aws ec2 describe-security-groups / describe-network-interfaces (조회)",
                     "aws ec2 get-console-output --latest (조회) — 시험 환경 내부 측정 지점 5곳의 결과",
                     "HTTP GET ALB:443/probe.json · TCP 연결 ALB 443 (이 PC — 참고용)",
                     "terraform apply <plan 파일> — 사람이 확인 창에서 plan 을 검토하고 [실행] 을 누른 경우만 (원본 반영 · 후보 반영 · 시험 환경 삭제, 시험 환경 폴더만)"],
            "does_not": ["사람 확인 없는 apply · destroy (자동 실행 없음)", "검토하지 않은 plan 반영 (plan 생성 후 파일·상태가 바뀌면 거부)",
                         "시험 환경 폴더 밖 변경 (운영 환경 apply 기능 없음)", "보안 그룹 개방·서버 접속(SSH)"]}


def testbed_use(body: Dict[str, Any]) -> Dict[str, Any]:
    """시험 환경 폴더의 security_groups.tf 를 원본 또는 이 기록의 후보로 바꾼다 (이 PC 파일 복사만 — 배포는 사람이 apply)."""
    import os
    from ..evidence_log import now_iso
    from ..measure import _sha
    which = str(body.get("which") or "")
    rid = str(body.get("record_id") or "")
    root = _root()
    tb = root / TESTBED
    if not tb.is_dir():
        raise ValueError("시험 환경 폴더 없음")
    if which == "original":
        src, label = root / ORIGINAL_SG, "원본 (scenarios/arch/webapp-3tier)"
    elif which == "candidate":
        rd = _record_dir(rid) if rid else None
        if rd is None:
            raise ValueError(f"기록 없음: {rid}")
        if not testbed_case_ok(rd):
            raise ValueError("시험 환경은 3계층 웹 서비스 전용 — 다른 사례의 후보 파일은 적용 불가")
        if (_j(rd / "state.json") or {}).get("review_level") not in ("LIGHT_REVIEW", "FULL_REVIEW"):
            raise ValueError("배포 전 검사 통과 후보만 시험 환경에 적용 가능 (차단 후보는 배포하지 않음)")
        src, label = rd / "candidate" / "security_groups.tf", f"후보 · {rd.name}"
    else:
        raise ValueError("which 값은 original 또는 candidate")
    if not src.exists():
        raise ValueError(f"파일 없음: {src.name}")
    dst = tb / "security_groups.tf"
    prev = _sha(dst)
    if prev and prev == _sha(src):
        # 이미 같은 내용 — 파일을 다시 쓰지 않는다 (다시 쓰면 수정 시각이 바뀌어 'apply 후 파일 변경' 으로 보이고 측정이 막힌다). 교체 기록도 남기지 않는다.
        return {"ok": True, "label": label, "sha256": prev, "previous_sha256": prev, "changed": False,
                "next": "변경 없음 — 시험 환경 파일이 이미 같은 내용"}
    tmp = tb / "~security_groups.swap"
    tmp.write_bytes(src.read_bytes())
    os.replace(tmp, dst)
    new = _sha(dst)
    logp = root / "data" / "testbed_switch.jsonl"
    logp.parent.mkdir(parents=True, exist_ok=True)
    entry = {"at": now_iso(), "which": which, "record": rid or None, "source": str(src.relative_to(root)).replace("\\", "/"),
             "from_sha256": prev, "to_sha256": new}
    if body.get("by"):
        entry["by"] = str(body.get("by"))[:80]
    with logp.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return {"ok": True, "label": label, "sha256": new, "previous_sha256": prev, "changed": prev != new,
            "next": "다음: plan 확인으로 보안 그룹 제자리 수정만 있는지 확인 → 확인 창에서 사람이 apply"}


def job_measure(body: Dict[str, Any]) -> Callable:
    from ..config import load_settings
    rid = str(body.get("record_id") or "")
    profile = str(body.get("profile") or "").strip() or DEFAULT_PROFILE
    region = str(body.get("region") or "").strip()
    if profile and not all(ch.isalnum() or ch in "-_." for ch in profile):
        raise ValueError("프로필 이름에 허용되지 않는 문자 포함")
    if region and not all(ch.isalnum() or ch == "-" for ch in region):
        raise ValueError("리전 이름 형식 오류")
    record_dir = _record_dir(rid) if rid else None
    if rid and record_dir is None:
        raise ValueError(f"기록 없음: {rid}")
    from ..measure import _sha
    tf_files = _testbed_files(record_dir)
    tb_sha = tf_files["sha"]
    if not tf_files["state"]:
        raise ValueError("시험 환경 상태 파일 없음 — apply 전")
    if tf_files.get("state_resources") == 0:
        raise ValueError("시험 환경 상태 파일의 리소스 0개 — destroy 완료 또는 apply 전")
    if not tf_files["applied_after_change"]:
        raise ValueError("보안 그룹 파일 변경 후 apply 미실행 (상태 파일이 더 오래됨) — apply 후 측정")
    if not tf_files["settled"]:
        left = SETTLE_AFTER_APPLY_S - int(tf_files["since_apply_s"] or 0)
        raise ValueError(f"apply 완료 후 {tf_files['since_apply_s']}초 경과 — 변경 설정이 측정 결과에 반영되도록 {left}초 후 측정 가능")
    if record_dir is not None:
        st = _j(record_dir / "state.json") or {}
        if not testbed_case_ok(record_dir):
            raise ValueError("시험 환경은 3계층 웹 서비스 전용 — 다른 사례의 기록은 수정 후 측정 대상 아님")
        if st.get("review_level") not in ("LIGHT_REVIEW", "FULL_REVIEW"):
            raise ValueError("배포 전 검사 통과 기록만 수정 후 측정 가능 (차단 후보는 배포 대상 아님)")
        cand = record_dir / "candidate" / "security_groups.tf"
        if not cand.exists() or _sha(cand) != tb_sha:
            raise ValueError("시험 환경 security_groups.tf 가 이 기록의 후보와 다름 — 후보 반영(apply) 후 측정")
        from ..plancheck import blocked_for
        if blocked_for(st, tb_sha):
            raise ValueError("plan 확인에서 교체·삭제가 발생한 후보 — apply 하지 않고 실제 AWS 검사 '차단'으로 기록됨. 측정 대상 아님")
    else:
        orig = _root() / "scenarios" / "arch" / "webapp-3tier" / "security_groups.tf"
        if _sha(orig) != tb_sha:
            raise ValueError("시험 환경 security_groups.tf 가 원본과 다름 — 수정 전 측정은 원본 반영 상태에서만 가능")

    def fn(log, prog):
        from .. import app as _app
        from ..measure import run_measure
        import os
        env = _app._env()
        os.environ.update({k: env[k] for k in ("TERRAFORM_BIN", "TF_PLUGIN_CACHE_DIR") if k in env})
        s = load_settings(str(_root()))
        stamp = time.strftime("%Y%m%d-%H%M%S")
        out = (record_dir / "postdeploy" / stamp) if record_dir is not None else (_root() / "data" / "measurements" / stamp)
        label = f"수정 후 · {record_dir.name}" if record_dir is not None else "수정 전 (원본 배포 상태)"
        log(f"실제 AWS 검사 측정 시작 · {label}")
        doc = run_measure(s, testbed=_root() / TESTBED, intent_path=_root() / TOPO_INTENT, out_dir=out, label=label, record_dir=record_dir,
                          profile=profile, region=region, log=log, compare_files=_compare_files(record_dir),
                          tempenv={k: tf_files.get(k) for k in ("sg_mtime", "state_mtime", "since_apply_s", "applied_after_change", "sync_basis", "settled")})
        return {"measure_dir": str(out.relative_to(_root())).replace("\\", "/"), "status": doc.get("status"), "record_id": rid or None,
                "matches": (doc.get("identity") or {}).get("matches")}
    return fn


def job_plan_check(body: Dict[str, Any]) -> Callable:
    """plan 확인 (읽기 전용): 시험 환경 폴더에 넣은 이 기록의 후보로, 실제 배포 상태 기준 terraform plan 을 만든다.
    교체·삭제가 나오면 apply 하지 않고 실제 AWS 검사 '차단'(PLAN_BLOCKED)으로 기록한다. apply·destroy 는 하지 않는다."""
    from ..config import load_settings
    from ..measure import _sha
    from ..plancheck import OFFLINE_OVERRIDE
    rid = str(body.get("record_id") or "")
    profile = str(body.get("profile") or "").strip() or DEFAULT_PROFILE
    if not all(ch.isalnum() or ch in "-_." for ch in profile):
        raise ValueError("프로필 이름에 허용되지 않는 문자 포함")
    record_dir = _record_dir(rid) if rid else None
    if record_dir is None:
        raise ValueError(f"기록 없음: {rid}" if rid else "기록 선택 필요 (plan 확인은 기록의 후보 기준)")
    if not testbed_case_ok(record_dir):
        raise ValueError("시험 환경은 3계층 웹 서비스 전용 — 다른 사례의 기록은 plan 확인 대상 아님")
    st = _j(record_dir / "state.json") or {}
    if st.get("review_level") not in ("LIGHT_REVIEW", "FULL_REVIEW"):
        raise ValueError("배포 전 검사 통과 기록만 plan 확인 가능 (차단 후보는 배포 대상 아님)")
    f = _testbed_files()
    tb = f["tb"]
    if not tb.is_dir():
        raise ValueError("시험 환경 폴더 없음")
    cand = record_dir / "candidate" / "security_groups.tf"
    if not cand.exists() or _sha(cand) != f["sha"]:
        raise ValueError("시험 환경 security_groups.tf 가 이 기록의 후보와 다름 — 먼저 후보 파일 적용")
    if not f["state"] or not f.get("state_resources"):
        raise ValueError("시험 환경 미배포 — 원본 반영(apply) 먼저 (배포가 없으면 plan 이 전부 '생성'이라 교체 여부 확인 불가)")
    if not (tb / ".terraform").is_dir():
        raise ValueError("시험 환경 폴더에서 terraform init 필요 (사람, 최초 1회)")
    if (tb / OFFLINE_OVERRIDE).exists():
        raise ValueError(f"시험 환경 폴더에 {OFFLINE_OVERRIDE} (가짜 자격 증명 파일) 존재 — 실제 상태 기준 plan 불가")

    def fn(log, prog):
        from .. import app as _app
        from ..plancheck import run_plan_check
        import os
        env = _app._env()
        os.environ.update({k: env[k] for k in ("TERRAFORM_BIN", "TF_PLUGIN_CACHE_DIR") if k in env})
        s = load_settings(str(_root()))
        stamp = time.strftime("%Y%m%d-%H%M%S")
        doc = run_plan_check(s, testbed=tb, record_dir=record_dir, profile=profile, out_dir=record_dir / "plancheck" / stamp, log=log,
                             compare_files=_compare_files(record_dir))
        return {"verdict": doc.get("verdict"), "summary": doc.get("summary"), "record_id": rid,
                "plancheck_dir": f"plancheck/{stamp}"}
    return fn


def _profile_of(body: Dict[str, Any]) -> str:
    profile = str(body.get("profile") or "").strip() or DEFAULT_PROFILE
    if not all(ch.isalnum() or ch in "-_." for ch in profile):
        raise ValueError("프로필 이름에 허용되지 않는 문자 포함")
    return profile


def _testbed_gates(tb: Path) -> None:
    from ..plancheck import OFFLINE_OVERRIDE
    if not tb.is_dir():
        raise ValueError("시험 환경 폴더 없음")
    if not (tb / ".terraform").is_dir():
        raise ValueError("시험 환경 폴더에서 terraform init 필요 (사람, 최초 1회)")
    if (tb / OFFLINE_OVERRIDE).exists():
        raise ValueError(f"시험 환경 폴더에 {OFFLINE_OVERRIDE} (가짜 자격 증명 파일) 존재 — 실제 상태 기준 plan 불가")


def _job_env() -> None:
    from .. import app as _app
    import os
    env = _app._env()
    os.environ.update({k: env[k] for k in ("TERRAFORM_BIN", "TF_PLUGIN_CACHE_DIR") if k in env})


def job_testbed_prepare(body: Dict[str, Any]) -> Callable:
    """[원본 apply] · [destroy] 의 1단계 — plan 만 만들어 보관하고 요약을 돌려준다 (반영 안 함). 화면은 이 요약을 확인 창에 띄운다."""
    from ..config import load_settings
    from ..measure import _sha
    kind = str(body.get("kind") or "")
    if kind not in ("apply_original", "destroy"):
        raise ValueError("kind 값은 apply_original 또는 destroy")
    profile = _profile_of(body)
    f = _testbed_files()
    tb = f["tb"]
    _testbed_gates(tb)
    if kind == "apply_original" and not (f["sha"] and _sha(_root() / ORIGINAL_SG) == f["sha"]):
        raise ValueError("시험 환경 파일이 원본과 다름 — 먼저 원본 파일로 복원 (원본 반영은 원본 파일일 때만)")
    if kind == "destroy" and (not f["state"] or not f.get("state_resources")):
        raise ValueError("삭제 대상 없음 — 상태 파일 리소스 0개 (destroy 완료 또는 apply 전)")

    def fn(log, prog):
        from ..testbed_ops import prepare
        _job_env()
        meta = prepare(load_settings(str(_root())), root=_root(), kind=kind, profile=profile, log=log)
        return {"plan": meta}
    return fn


def job_testbed_execute(body: Dict[str, Any]) -> Callable:
    """[실행] — 사람이 확인 창에서 누른 요청만. 보관한 plan 파일 그대로 apply 한다 (testbed_ops.execute).
    destroy 가 끝나면 시험 환경 파일을 원본으로 복원하고, 후보 반영이면 그 기록에 반영 방법을 남긴다."""
    from ..config import load_settings
    from ..measure import _sha
    from ..plancheck import blocked_for
    from ..testbed_ops import CONFIRM, drop, fresh, load_meta
    pid = str(body.get("plan_id") or "")
    confirm = str(body.get("confirm") or "")
    profile = _profile_of(body)
    meta = load_meta(pid)
    if not meta:
        raise ValueError("plan 없음 또는 사용 완료 (1시간 경과 또는 실행 완료) — plan 재생성 필요")
    kind = str(meta.get("kind"))
    if confirm != CONFIRM.get(kind):
        raise ValueError(f"확인 값 불일치 — 확인 창에서 '{CONFIRM.get(kind)} 실행' 필요")
    if not meta.get("eligible"):
        raise ValueError(f"실행 불가 plan — {meta.get('why')}")
    f = _testbed_files()
    tb = f["tb"]
    _testbed_gates(tb)
    ok, why = fresh(meta, tb)
    if not ok:
        drop(pid)                      # 낡은 plan 은 다시 쓸 수 없다 — 지우고 다시 plan 하게
        raise ValueError(why)
    rd = None
    if kind == "apply_candidate":
        rd = _record_dir(str(meta.get("record") or ""))
        if rd is None or not testbed_case_ok(rd):
            raise ValueError("plan 의 기록이 없거나 3계층 사례가 아님")
        st = _j(rd / "state.json") or {}
        if st.get("review_level") not in ("LIGHT_REVIEW", "FULL_REVIEW"):
            raise ValueError("배포 전 검사 통과 기록만 시험 환경 반영 가능")
        cand = rd / "candidate" / "security_groups.tf"
        if not cand.exists() or _sha(cand) != meta.get("testbed_sha256"):
            raise ValueError("시험 환경 파일이 이 기록의 후보와 다름 — 후보 파일 적용 → plan 확인 재실행")
        if blocked_for(st, meta.get("testbed_sha256")):
            raise ValueError("plan 확인에서 교체·삭제가 발생한 후보 — 반영 대상 아님")

    def fn(log, prog):
        from ..evidence_log import now_iso, write_manifest
        from ..testbed_ops import execute
        _job_env()
        entry = execute(load_settings(str(_root())), root=_root(), plan_id=pid, confirm=confirm, profile=profile, log=log)
        reverted = None
        if entry.get("ok") and kind == "destroy":
            reverted = testbed_use({"which": "original", "by": "destroy 뒤 자동 (앱)"})
            log("destroy 후 시험 환경 파일을 원본으로 복원 (다음 시험을 원본 상태에서 시작)")
        if rd is not None:
            stp = rd / "state.json"
            try:
                s = json.loads(stp.read_text(encoding="utf-8"))
                e = {"at": now_iso(), "how": "앱 [후보 반영] — 확인 창에서 사람이 plan 검토 후 실행", "plan_id": pid, "plan_dir": meta.get("ops_dir"),
                     "ok": bool(entry.get("ok")), "ops_dir": entry.get("dir"), "candidate_sha256": meta.get("testbed_sha256")}
                s["testbed_apply"] = e
                s["testbed_apply_history"] = list(s.get("testbed_apply_history") or []) + [e]
                stp.write_text(json.dumps(s, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
                write_manifest(rd)
            except (OSError, ValueError):
                pass
        return {"ok": bool(entry.get("ok")), "kind": kind, "kind_ko": meta.get("kind_ko"), "error": entry.get("error"),
                "elapsed_s": entry.get("elapsed_s"), "state_resources_after": entry.get("state_resources_after"),
                "reverted": bool(reverted and reverted.get("ok")), "record_id": rd.name if rd is not None else None}
    return fn


def baseline_view() -> Dict[str, Any]:
    """기록과 무관한 '수정 전' 측정만 볼 때 (실제 AWS 검사 화면을 기록 없이 열었을 때)."""
    from ..proof.postcards import build_post_cards
    return build_post_cards(_root() / "data" / "reviews" / "__none__", _root())
