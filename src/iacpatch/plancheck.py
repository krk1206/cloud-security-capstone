"""실제 AWS 검사 전 'plan 확인' — 실제 시험 환경의 상태를 기준으로 terraform plan 을 만들어, 이 후보를 apply 하면
보안 그룹이 교체(-/+)되거나 삭제(-)되는지 본다.

읽기 전용
  - terraform plan 은 AWS 에서 지금 값을 읽어(refresh) 비교만 한다. AWS 의 아무것도 바꾸지 않는다.
  - 이 PC 의 상태 파일(terraform.tfstate)도 바꾸지 않는다: -lock=false (잠금 파일을 남기지 않음), plan 파일은
    시험 환경 폴더 밖 임시 폴더에 쓰고 끝나면 지운다. Terraform 0.15.4 부터 plan 은 상태 파일에 쓰지 않는다.
    결과가 CLEAN 이면 그 plan 파일만 1시간 보관한다 — 사람이 확인 창에서 [apply 실행] 을 누르면 이 plan 그대로 반영한다 (testbed_ops.py).
  - apply / destroy 는 여기서 하지 않는다 (사람이 버튼 확인 뒤 testbed_ops.execute, 또는 PowerShell).

왜 필요한가
  배포 전 검사 V4 의 plan 은 AWS 상태 없이 만든다 → 모든 리소스가 '새로 만듦(+)' 이라 교체·삭제를 볼 수 없다.
  예: 보안 그룹 자체의 description·name 은 바꾸면 교체된다 (AWS provider 문서 aws_security_group: 'Forces new resource').
  교체는 기본이 '먼저 지우고 새로 만들기' 인데, AWS 는 다른 리소스(서버 등)에 붙은 보안 그룹을 지우지 못하게 한다
  (같은 문서의 'Security Group Deletion Problem'). 그런 후보는 배포 전 검사를 통과해도 apply 하면 안 된다.

판정 (verdict)
  BLOCKED     교체 또는 삭제가 하나라도 있다 → apply 하지 않는다. 기록의 실제 AWS 검사 결과를 PLAN_BLOCKED(차단)로 남긴다
  CLEAN       바뀌는 것이 보안 그룹(규칙 리소스 포함)의 제자리 수정뿐이다 → apply 해도 된다 (apply 는 사람)
  CHECK       교체·삭제는 없지만 새로 만들기나 보안 그룹이 아닌 리소스의 수정이 있다 → 사람이 plan 을 읽고 판단
  NO_CHANGES  바뀌는 것이 없다 (이미 apply 했거나 배포된 것과 같은 파일)
  ERROR       plan 을 만들지 못했다 (로그인 만료·init 안 됨 등) — 판정 없음
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .evidence_log import CommandLog, now_iso, sha256_file, write_manifest
from .tools.runner import ToolNotFound, run

NETWORK_TYPES = frozenset({"aws_security_group", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
                           "aws_security_group_rule"})
KIND_KO = {"replace": "교체 (-/+ 삭제 후 재생성)", "delete": "삭제 (-)", "update": "제자리 수정 (~)", "create": "생성 (+)"}
VERDICT_KO = {"BLOCKED": "차단 — 교체·삭제 포함", "CLEAN": "반영 가능 — 보안 그룹 제자리 수정만 포함",
              "CHECK": "사람의 plan 검토 필요", "NO_CHANGES": "변경 없음", "ERROR": "plan 생성 실패"}
IGNORE_ATTRS = frozenset({"tags_all"})          # provider default_tags 가 채우는 값 — 비교에서 뺀다
OFFLINE_OVERRIDE = "zz_iacpatch_offline_override.tf"   # 배포 전 검사 V4 의 가짜 자격증명 파일 — 시험 환경 폴더에 있으면 실제 상태로 plan 할 수 없다
ACCOUNT_RE = re.compile(r"\b\d{12}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_KEEP_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                                                 "0.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/10")]

# plan 실패 원인 요약 (원문은 commands.json · plan.txt 에 그대로 남는다)
_PLAN_ERRORS = [
    (("token has expired", "ExpiredToken", "expired token", "failed to refresh cached credentials", "no valid credential sources",
      "NoCredentialProviders", "InvalidClientTokenId", "SSO session", "sso session", "the security token included in the request is expired",
      "failed to get shared config profile", "unable to load credentials"),
     "AWS 로그인 세션 없음 또는 만료 — PowerShell 에서 aws login --profile capstone 실행 후 재시도"),
    (("Inconsistent dependency lock file", "Required plugins are not installed", "please run \"terraform init\"", "Could not load plugin",
      "Backend initialization required", "Module not installed", "run \"terraform init\""),
     "terraform init 필요 — 시험 환경 폴더에서 terraform init (사람, 최초 1회)"),
    (("Error acquiring the state lock",), "다른 terraform 작업이 상태 파일 사용 중 — apply·destroy 완료 후 재시도"),
    (("UnauthorizedOperation", "AccessDenied", "is not authorized to perform"),
     "이 프로필에 AWS 조회 권한 없음 (예: ec2:Describe*) — 프로필 이름 확인 필요"),
    (("dial tcp", "no such host", "send request failed", "connection refused", "i/o timeout"),
     "AWS 연결 실패 — 인터넷 연결 확인 필요"),
]


def mask(text: str) -> str:
    """계정 번호(12자리)와 공인 IPv4 를 가린다 (사설·문서용 대역은 그대로 — 판정 근거라서)."""
    t = ACCOUNT_RE.sub("############", text or "")

    def ip(m: "re.Match[str]") -> str:
        s = m.group(0)
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            return s
        if any(a in n for n in _KEEP_NETS) or s.endswith(".0"):
            return s
        p = s.split(".")
        return f"{p[0]}.x.x.{p[3]}"
    return IPV4_RE.sub(ip, t)


def plan_error_ko(text: str) -> str:
    raw = text or ""
    low = raw.lower()
    for keys, ko in _PLAN_ERRORS:
        if any(k.lower() in low for k in keys):
            return ko
    from .proof.plain import tf_error_ko
    return tf_error_ko(raw) or "plan 오류"


def _kind(actions: List[str]) -> str:
    a = list(actions or [])
    if "delete" in a and "create" in a:
        return "replace"
    if a == ["delete"]:
        return "delete"
    if a == ["create"]:
        return "create"
    if a == ["update"]:
        return "update"
    return "+".join(a) or "?"


def _short(v: Any) -> Any:
    if isinstance(v, str):
        return mask(v if len(v) <= 200 else v[:200] + "…")
    return v


def summarize_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """terraform show -json 의 plan → 바뀌는 리소스 목록 + 판정. 값은 바꾸지 않고 고르기만 한다."""
    changes: List[Dict[str, Any]] = []
    for rc in plan.get("resource_changes") or []:
        if rc.get("mode") == "data":
            continue
        ch = rc.get("change") or {}
        acts = [str(x) for x in ch.get("actions") or []]
        if not acts or acts in (["no-op"], ["read"]):
            continue
        kind = _kind(acts)
        b = ch.get("before") if isinstance(ch.get("before"), dict) else {}
        a = ch.get("after") if isinstance(ch.get("after"), dict) else {}
        unk = ch.get("after_unknown") if isinstance(ch.get("after_unknown"), dict) else {}
        # 바뀌는 속성: 전후 값이 다 보이고 다른 것 + (제자리 수정이면) 지금은 값이 있는데 apply 뒤에 정해지는 것.
        # 교체면 id·arn 같은 값은 새로 만들면서 당연히 바뀌므로 빼고, 교체를 일으킨 값(replace_paths)이 앞에 오게 한다.
        known = [k for k in set(b) | set(a) if k not in IGNORE_ATTRS and unk.get(k) is not True and b.get(k) != a.get(k)]
        later = [k for k, v in unk.items() if v is True and k not in IGNORE_ATTRS and b.get(k) is not None] if kind == "update" else []
        keys = sorted(known) + sorted(later)
        e: Dict[str, Any] = {"address": rc.get("address"), "type": rc.get("type"), "actions": acts, "kind": kind,
                             "changed": keys[:12] if kind in ("update", "replace") else []}
        if rc.get("action_reason"):
            e["reason"] = rc.get("action_reason")
        rp = ch.get("replace_paths")
        if isinstance(rp, list) and rp:
            e["replace_paths"] = [".".join(str(x) for x in p) if isinstance(p, list) else str(p) for p in rp]
        if kind in ("update", "replace"):
            vals = {}
            for k in keys:
                bv, av = b.get(k), a.get(k)
                if isinstance(bv, (str, int, float, bool, type(None))) and isinstance(av, (str, int, float, bool, type(None))):
                    vals[k] = [_short(bv), "(apply 후 확정)" if unk.get(k) is True else _short(av)]
            if vals:
                e["values"] = vals
            for blk in ("ingress", "egress"):
                if isinstance(b.get(blk), list) and isinstance(a.get(blk), list) and b.get(blk) != a.get(blk):
                    e[f"{blk}_rules"] = [len(b[blk]), len(a[blk])]
        changes.append(e)
    counts = {k: sum(1 for e in changes if e["kind"] == k) for k in ("replace", "delete", "update", "create")}
    counts["other"] = len(changes) - sum(counts.values())
    stop = [e for e in changes if e["kind"] in ("replace", "delete")]
    if not changes:
        verdict = "NO_CHANGES"
    elif stop or counts["other"]:
        verdict = "BLOCKED" if stop else "CHECK"
    elif all(e["kind"] == "update" and e["type"] in NETWORK_TYPES for e in changes):
        verdict = "CLEAN"
    else:
        verdict = "CHECK"
    drift = [d.get("address") for d in plan.get("resource_drift") or [] if isinstance(d, dict)]
    return {"verdict": verdict, "counts": counts, "changes": changes, "drift": drift,
            "replaced": [e["address"] for e in changes if e["kind"] == "replace"],
            "deleted": [e["address"] for e in changes if e["kind"] == "delete"],
            "summary": summary_text(verdict, counts, changes),
            "format_version": plan.get("format_version"), "terraform_version": plan.get("terraform_version")}


ATTR_KO = {"description": "설명(description)", "name": "이름(name)", "name_prefix": "이름 접두사(name_prefix)", "vpc_id": "VPC(vpc_id)"}


def _label(addr: Any) -> str:
    """aws_security_group.bastion → 'Bastion 보안 그룹' (설계도의 계층 이름). 보안 그룹이 아니면 주소 그대로."""
    a = str(addr or "")
    if a.startswith("aws_security_group."):
        try:
            from .proof.plain import sg
            return sg(a, None)
        except Exception:
            return a
    return a


def _why(e: Dict[str, Any]) -> str:
    rp = e.get("replace_paths") or []
    return f" ({', '.join(ATTR_KO.get(k, k) for k in rp)} 변경)" if rp else ""


def summary_text(verdict: str, counts: Dict[str, int], changes: List[Dict[str, Any]]) -> str:
    if verdict == "NO_CHANGES":
        return "변경 없음 — 이미 반영됨 또는 배포 파일과 동일"
    if verdict == "BLOCKED":
        bad = [e for e in changes if e["kind"] in ("replace", "delete")]
        what = ", ".join(f"{_label(e['address'])} {'교체' if e['kind'] == 'replace' else '삭제'}{_why(e)}" for e in bad[:3])
        return f"차단 (apply 미실행) — 교체 {counts['replace']}개 · 삭제 {counts['delete']}개: {what}"
    if verdict == "CLEAN":
        return f"반영 가능 — 보안 그룹 제자리 수정 {counts['update']}개, 교체·삭제 없음"
    outside = [_label(e["address"]) for e in changes if e["kind"] == "update" and e["type"] not in NETWORK_TYPES]
    parts = []
    if counts["create"]:
        parts.append(f"생성 {counts['create']}개")
    if outside:
        parts.append(f"보안 그룹 외 수정 {len(outside)}개 ({', '.join(outside[:3])})")
    if counts["other"]:
        parts.append(f"기타 동작 {counts['other']}개")
    return "교체·삭제 없음 — 사람의 plan 검토 필요: " + " · ".join(parts)


def latest_for(state: Dict[str, Any], sha: Optional[str], decisive: bool = False) -> Optional[Dict[str, Any]]:
    """이 파일(sha256)로 한 plan 확인 중 가장 최근 것. decisive=True 면 ERROR(판정 없음)는 건너뛴다 —
    교체가 나온 뒤 로그인 만료로 한 번 실패했다고 '막힘' 이 풀리지 않게."""
    if not sha:
        return None
    hist = [e for e in state.get("plan_check_history") or [] if isinstance(e, dict) and e.get("candidate_sha256") == sha]
    if decisive:
        hist = [e for e in hist if e.get("verdict") != "ERROR"]
    return hist[-1] if hist else None


def blocked_for(state: Dict[str, Any], sha: Optional[str]) -> Optional[Dict[str, Any]]:
    """이 파일의 마지막 판정(ERROR 제외)이 BLOCKED 면 그 기록. 아니면 None."""
    e = latest_for(state, sha, decisive=True)
    return e if e and e.get("verdict") == "BLOCKED" else None


def _tf_binary(settings: Any) -> str:
    import os
    return getattr(settings, "terraform_bin", None) or os.environ.get("TERRAFORM_BIN") or "terraform"


def run_plan_check(settings: Any, *, testbed: Path, record_dir: Path, profile: str, out_dir: Path,
                   log: Callable[[str], None] = print, compare_files: Optional[Dict[str, Path]] = None,
                   runner: Optional[Callable[..., Any]] = None, keep_plan: bool = True) -> Dict[str, Any]:
    """시험 환경 폴더에서 plan(-lock=false, plan 파일은 임시 폴더) → show -json → 요약. 기록 폴더에 결과를 남기고
    state.json 을 고친다 (BLOCKED 면 실제 AWS 검사 결과 = PLAN_BLOCKED). AWS·상태 파일은 바꾸지 않는다.
    keep_plan: 결과가 '보안 그룹만 제자리 수정'(CLEAN)이면 plan 파일을 지우지 않고 실행용으로 보관한다 —
    화면의 확인 창에서 사람이 [apply 실행] 을 누르면 이 plan 을 그대로 반영한다 (testbed_ops.py, 1시간 뒤 만료)."""
    from .testbed_ops import register_candidate_plan, state_info
    runner = runner or run
    out_dir.mkdir(parents=True, exist_ok=True)
    clog = CommandLog(out_dir / "commands.json")
    sg_file = testbed / "security_groups.tf"
    sha0 = sha256_file(sg_file)
    st0 = state_info(testbed)
    plan_id: Optional[str] = None
    started = now_iso()
    t0 = time.time()
    tf = _tf_binary(settings)
    env = {"AWS_PROFILE": profile, "TF_IN_AUTOMATION": "1"} if profile else {"TF_IN_AUTOMATION": "1"}
    tmp = Path(tempfile.mkdtemp(prefix="iacpatch-plan-"))
    plan_file = tmp / "plan.bin"
    summary: Dict[str, Any] = {}
    error = ""
    plan_txt = ""
    try:
        log(f"plan 확인 · terraform plan (실제 시험 환경 상태 기준 · 읽기 전용 · 프로필 {profile or '(기본)'})")
        argv = [tf, "plan", "-input=false", "-no-color", "-lock=false", "-refresh=true", f"-out={plan_file}"]
        t1 = time.time()
        try:
            r = runner(argv, cwd=str(testbed), env=env, timeout=900)
        except ToolNotFound as e:
            r = None
            error = f"terraform 실행 파일 없음: {e}"
        if r is not None:
            plan_txt = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
            clog.add("terraform:plan (실제 상태)", "plan", [str(x) for x in argv], cwd=str(testbed), returncode=r.returncode,
                     started_at=started, elapsed=round(time.time() - t1, 2), stdout=mask(r.stdout), stderr=mask(r.stderr), ok=r.ok,
                     note="AWS 현재 값 조회·비교만 · 상태 파일 잠금·쓰기 없음 (-lock=false) · plan 파일은 임시 폴더")
            if r.timed_out:
                error = "plan 이 15분 내 미완료"
            elif not r.ok:
                error = plan_error_ko(r.stderr or r.stdout)
        if not error:
            log("plan 확인 · terraform show -json (생성한 plan 파일 조회)")
            argv2 = [tf, "show", "-json", str(plan_file)]
            t2 = time.time()
            r2 = runner(argv2, cwd=str(testbed), env=env, timeout=300)
            clog.add("terraform:show -json", "plan", [str(x) for x in argv2], cwd=str(testbed), returncode=r2.returncode,
                     started_at=now_iso(), elapsed=round(time.time() - t2, 2), stderr=mask(r2.stderr), ok=r2.ok, note="plan 파일을 JSON 으로")
            if not r2.ok:
                error = plan_error_ko(r2.stderr or r2.stdout)
            else:
                try:
                    pj = json.loads(r2.stdout or "{}")
                except ValueError as e:
                    error = f"plan JSON 조회 실패: {e}"
                else:
                    summary = summarize_plan(pj)
                    rcs = [rc for rc in pj.get("resource_changes") or []
                           if rc.get("mode") != "data" and (rc.get("change") or {}).get("actions") not in (["no-op"], ["read"])]
                    (out_dir / "plan_changes.json").write_text(mask(json.dumps({"format_version": pj.get("format_version"),
                                                                                "terraform_version": pj.get("terraform_version"),
                                                                                "resource_changes": rcs}, ensure_ascii=False, indent=1)),
                                                               encoding="utf-8")
        if not error and sha256_file(sg_file) != sha0:
            error = "plan 도중 시험 환경 security_groups.tf 변경됨 — 재시도 필요"
            summary = {}
        if keep_plan and not error and summary.get("verdict") == "CLEAN":
            plan_id = register_candidate_plan(plan_file=plan_file, record=record_dir.name, summary=summary, state=st0, sha=sha0,
                                              plancheck_dir=str(out_dir.relative_to(record_dir)).replace("\\", "/"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if plan_txt:
        (out_dir / "plan.txt").write_text(mask(plan_txt), encoding="utf-8")
    matches = [name for name, p in (compare_files or {}).items() if sha0 and sha256_file(p) == sha0]
    verdict = summary.get("verdict") if summary and not error else "ERROR"
    doc = {"schema": "iacpatch-plancheck-v1", "record": record_dir.name, "started_at": started, "elapsed_s": round(time.time() - t0, 1),
           "testbed": str(testbed), "profile": profile, "testbed_security_groups_sha256": sha0, "matches": matches,
           "verdict": verdict, "verdict_ko": VERDICT_KO.get(verdict, verdict),
           "summary": summary.get("summary") if verdict != "ERROR" else f"plan 생성 실패 — {error}",
           "error": error or None, "plan_id": plan_id, "state_serial": st0.get("serial"),
           **{k: summary.get(k) for k in ("counts", "changes", "drift", "replaced", "deleted", "format_version", "terraform_version")}}
    (out_dir / "plan_summary.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    entry = {"run_id": out_dir.name, "at": now_iso(), "kind": "plan-check", "verdict": verdict, "summary": doc["summary"][:500],
             "counts": doc.get("counts"), "replaced": doc.get("replaced") or [], "deleted": doc.get("deleted") or [],
             "path": str(out_dir.relative_to(record_dir)).replace("\\", "/"), "candidate_sha256": sha0, "profile": profile,
             "plan_id": plan_id}
    stp = record_dir / "state.json"
    try:
        s = json.loads(stp.read_text(encoding="utf-8"))
        s["plan_check"] = entry
        s["plan_check_history"] = list(s.get("plan_check_history") or []) + [entry]
        if verdict == "BLOCKED":
            post = {"run_id": out_dir.name, "at": entry["at"], "executed": True, "status": "PLAN_BLOCKED", "validity": "FAIL",
                    "layers": {"V7": "NOT_RUN", "V8": "NOT_RUN"}, "summary": doc["summary"][:500], "path": entry["path"], "kind": "plan-check",
                    "deployed_file_matches": matches}
            s["post_deploy"] = post
            s["post_deploy_history"] = list(s.get("post_deploy_history") or []) + [post]
        stp.write_text(json.dumps(s, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    except (OSError, ValueError):
        pass
    write_manifest(record_dir)
    log(f"plan 확인 완료 · {verdict} · {doc['summary']}")
    return doc
