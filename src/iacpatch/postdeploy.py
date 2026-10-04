"""배포 후 검증 (V7, V8) 과 복구 절차.

V7  실제 AWS 상태 실측: describe-security-groups + describe-network-interfaces(같은 ENI 의 SG 합산)
    + get-managed-prefix-list-entries(전개) → V6 와 **같은 오라클**로 판정. plan 주소 ↔ GroupId 매핑은
    terraform show -json(state) 또는 GroupName 으로 잡는다.
V8  통신 확인: 허용돼야 할 통신(승인 출처에서)이 성공하고, 금지된 통신(승인 밖 출처에서)이 실패하는지.
    금지 통신 확인은 승인 밖 **vantage(관측 지점)** 가 있어야 의미가 있다. 없으면 PASS 가 아니라 UNKNOWN.
복구  git 되돌리기만으로 "복구됨"이라고 하지 않는다. 원본 파일 복원 → plan → apply(사람 승인) → plan 재실행으로
    변경 없음(drift 없음) 확인 + describe 로 실측 기록 → 그때 RECOVERED.

--execute 없이 호출하면 실제 AWS 조회/통신/apply 를 하지 않고, 실행할 명령만 출력한다.

review 기록(data/reviews, 실험 흐름) 과의 연결: `--review <id>` 를 주면 tf_dir 을 기록에서 읽고, 결과를 기록 안
`postdeploy/<시각>/` 에 남기며 state.json 의 `post_deploy` 에 V7/V8 판정과 배포 상태(VERIFIED / DEPLOY_FAILED /
UNVERIFIED) 를 적는다. 배포 전 검토 수준(review_level) 은 바꾸지 않는다 — 배포 후 결과는 별도 축이다.
"""
from __future__ import annotations

import datetime as _dt
import json
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import Settings, load_json
from .intent import try_load_intent
from .models import LayerResult, Verdict
from .runrecord import RunRecord
from .textio import write_text_lf
from .tools.awscli import AwsCli, AwsError, build_world_from_aws
from .tools.terraform import TerraformAdapter
from .verify.combine import combine
from .verify.sg_oracle import evaluate


# ---------------------------------------------------------------------------
# 주소 ↔ ID 매핑
# ---------------------------------------------------------------------------
def sg_ids_from_state(tf: TerraformAdapter, tf_dir: Path) -> Dict[str, str]:
    """terraform show -json (state) 에서 aws_security_group 주소 → GroupId."""
    out = tf.state_show_json(tf_dir)
    if not out.ok:
        raise RuntimeError(f"terraform show -json failed in {tf_dir}: {out.error}")
    mapping: Dict[str, str] = {}
    root = ((out.data.get("values") or {}).get("root_module") or {})

    def walk(mod: Dict[str, Any]):
        for r in mod.get("resources") or []:
            if r.get("type") == "aws_security_group" and (r.get("values") or {}).get("id"):
                mapping[r["address"]] = r["values"]["id"]
        for c in mod.get("child_modules") or []:
            walk(c)

    walk(root)
    return mapping


# ---------------------------------------------------------------------------
# V7
# ---------------------------------------------------------------------------
def v7_aws_state(cli: AwsCli, intent, aliases: Dict[str, str], execute: bool) -> "tuple[LayerResult, Dict[str, Any]]":
    targets = [aliases.get(t, t) for t in intent.target_security_groups]
    unresolved = [t for t in targets if not t.startswith("sg-")]
    if unresolved:
        return LayerResult("V7", "actual AWS state", Verdict.UNKNOWN, f"cannot map target addresses to GroupIds: {unresolved}", {}, False, "aws cli"), {}
    if not execute:
        preview = [cli.command_preview("ec2", "describe-security-groups", "--group-ids", *targets),
                   cli.command_preview("ec2", "describe-network-interfaces", "--filters", f"Name=group-id,Values=<id>"),
                   cli.command_preview("ec2", "get-managed-prefix-list-entries", "--prefix-list-id", "<pl-id>")]
        return LayerResult("V7", "actual AWS state", Verdict.SKIPPED, "not executed (--execute not given). commands: " + " | ".join(preview),
                           {"commands": preview}, False, "aws cli"), {}
    if not cli.available():
        return LayerResult("V7", "actual AWS state", Verdict.SKIPPED, "aws cli not found", {}, False, "aws cli"), {}
    try:
        world, raw = build_world_from_aws(cli, targets)
    except AwsError as e:
        return LayerResult("V7", "actual AWS state", Verdict.ERROR, str(e), {}, True, "aws cli"), {}
    report = evaluate(world, intent, aliases)
    details = report.to_dict()
    details["disclaimer"] = "Actual SG rules as returned by AWS (post-apply). Still SG-level allow sets, not proof of reachability."
    return LayerResult("V7", "actual AWS state", report.verdict, report.summary[:1500], details, True, "aws cli"), raw


# ---------------------------------------------------------------------------
# V8
# ---------------------------------------------------------------------------
def _tcp_probe(host: str, port: int, timeout: float) -> Dict[str, Any]:
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            try:
                s.settimeout(2.0)
                banner = s.recv(64).decode("utf-8", "replace").strip()
            except (socket.timeout, OSError):
                pass
            return {"result": "open", "elapsed": round(time.time() - t0, 3), "banner": banner}
    except socket.timeout:
        return {"result": "timeout", "elapsed": round(time.time() - t0, 3)}
    except ConnectionRefusedError:
        return {"result": "refused", "elapsed": round(time.time() - t0, 3)}
    except OSError as e:
        return {"result": f"error:{e.__class__.__name__}", "elapsed": round(time.time() - t0, 3), "error": str(e)}


def v8_connectivity(checks_spec: Optional[Dict[str, Any]], intent, execute: bool) -> LayerResult:
    """checks_spec:
        {"checks": [{"label": "...", "host": "...", "port": 22, "expect": "open"|"closed",
                     "vantage": "local"|"<name>", "source_class": "approved"|"unapproved", "timeout_s": 5,
                     "service_label": "ssh"}]}
    판정:
      - expect=open 인 검사가 하나라도 실패 → FAIL (필요한 통신이 막힘)
      - expect=closed 이고 source_class=unapproved 인 검사가 성공(open) → FAIL (금지 통신이 뚫림)
      - 보호 서비스마다 unapproved vantage 의 closed 검사가 없으면 → UNKNOWN (금지 통신 실패를 확인하지 못함)
      - vantage != local 인 검사는 이 러너가 실행하지 않는다 (NOT_RUN) → 그 서비스는 UNKNOWN
    """
    if not checks_spec:
        return LayerResult("V8", "connectivity (allowed succeeds / forbidden fails)", Verdict.UNKNOWN,
                           "no V8 check spec provided (needs a deployed instance/endpoint + vantage points)", {}, False, "socket")
    checks = checks_spec.get("checks") or []
    if not execute:
        return LayerResult("V8", "connectivity (allowed succeeds / forbidden fails)", Verdict.SKIPPED,
                           f"not executed (--execute not given); {len(checks)} checks defined", {"checks": checks}, False, "socket")
    results: List[Dict[str, Any]] = []
    fails: List[str] = []
    covered_unapproved: Dict[str, bool] = {}
    for c in checks:
        label = c.get("label", "?")
        svc = str(c.get("service_label", ""))
        vantage = str(c.get("vantage", "local"))
        expect = str(c.get("expect", "open"))
        sclass = str(c.get("source_class", "approved"))
        entry = dict(c)
        if vantage != "local":
            entry["outcome"] = "NOT_RUN"
            entry["note"] = "non-local vantage must be executed from that vantage (e.g. temporary EC2 in a non-approved SG) and its result pasted into the spec as 'observed'"
            observed = c.get("observed")
            if observed in ("open", "closed", "timeout", "refused"):
                entry["outcome"] = f"OBSERVED:{observed}"
                probe = {"result": observed}
            else:
                results.append(entry)
                continue
        else:
            probe = _tcp_probe(str(c.get("host")), int(c.get("port")), float(c.get("timeout_s", 5)))
            entry["probe"] = probe
        is_open = probe["result"] == "open"
        if expect == "open":
            entry["outcome"] = "PASS" if is_open else "FAIL"
            if not is_open:
                fails.append(f"{label}: expected open, got {probe['result']} (required access broken?)")
        else:
            if sclass != "unapproved":
                entry["outcome"] = "INCONCLUSIVE"
                entry["note"] = "closed-check from an approved source does not prove that unapproved sources are blocked"
            else:
                entry["outcome"] = "FAIL" if is_open else "PASS"
                if is_open:
                    fails.append(f"{label}: expected closed from unapproved source, but connection succeeded")
                else:
                    covered_unapproved[svc] = True
        results.append(entry)
    missing = [g.service.label or g.service.id for g in intent.guarded_services if not covered_unapproved.get(g.service.label or g.service.id)]
    details = {"results": results, "unapproved_closed_coverage": covered_unapproved, "services_without_unapproved_check": missing}
    if fails:
        return LayerResult("V8", "connectivity (allowed succeeds / forbidden fails)", Verdict.FAIL, "; ".join(fails), details, True, "socket")
    if missing:
        return LayerResult("V8", "connectivity (allowed succeeds / forbidden fails)", Verdict.UNKNOWN,
                           f"allowed checks passed, but no 'closed' check from an unapproved vantage for: {missing}", details, True, "socket")
    return LayerResult("V8", "connectivity (allowed succeeds / forbidden fails)", Verdict.PASS, "allowed connections succeed; forbidden connections fail (from the given vantages)", details, True, "socket")


# ---------------------------------------------------------------------------
# review 기록(data/reviews) 연결
# ---------------------------------------------------------------------------
def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def load_review_record(settings: Settings, review_id: str) -> Tuple[Optional[Path], Dict[str, Any], str]:
    """review id(data/reviews/<id>) 또는 기록 폴더 경로 → (폴더, state.json, 오류메시지)."""
    cand = Path(review_id)
    d = cand.resolve() if (cand / "state.json").exists() else settings.path("data/reviews") / review_id
    if not (d / "state.json").exists():
        return None, {}, f"review record not found: {d}"
    try:
        st = json.loads((d / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return None, {}, f"review record unreadable: {e}"
    return d, st, ""


def _update_review_state(review_dir: Path, **kw: Any) -> None:
    p = review_dir / "state.json"
    st = json.loads(p.read_text(encoding="utf-8"))
    st.update(kw)
    p.write_text(json.dumps(st, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def post_deploy_status(report, execute: bool) -> str:
    """배포 후 축의 상태. 배포 전 review_level 과는 별개다.
    VERIFIED      : 실행됐고 V7·V8 모두 PASS
    DEPLOY_FAILED : 실행됐고 FAIL 이 하나라도 있음 → 복구 절차(iacpatch recover) 대상
    UNVERIFIED    : 실행 안 됨 / UNKNOWN·SKIPPED·ERROR 가 남음 (통과가 아니다)
    """
    verdicts = [l.verdict for l in report.layers]
    if any(v == Verdict.FAIL for v in verdicts):
        return "DEPLOY_FAILED"
    if execute and verdicts and all(v == Verdict.PASS for v in verdicts):
        return "VERIFIED"
    return "UNVERIFIED"


# ---------------------------------------------------------------------------
def run_postdeploy(settings: Settings, intent_path: str, sg_ids: List[str], v8_checks_path: Optional[str], execute: bool,
                   run_id: Optional[str] = None, tf_dir: Optional[str] = None, review_id: Optional[str] = None,
                   cli: Optional[AwsCli] = None) -> str:
    intent, err = try_load_intent(settings.path(intent_path))
    if intent is None:
        return f"intent unusable: {err}"
    review_dir: Optional[Path] = None
    if review_id:
        review_dir, st, rerr = load_review_record(settings, review_id)
        if review_dir is None:
            return rerr
        if not tf_dir:
            tf_dir = st.get("tf_dir") or None
        if st.get("review_level") not in ("LIGHT_REVIEW", "FULL_REVIEW"):
            # 배포됐을 리 없는 기록에 배포 후 결과를 붙이지 않는다 (사람이 우회 apply 했더라도 기록상으로는 거부)
            return (f"refusing: review {review_dir.name} has review_level={st.get('review_level')!r} "
                    "(only LIGHT_REVIEW / FULL_REVIEW records can be deployed and post-verified)")
    rec = RunRecord(settings.path(settings.data_dir), label=f"postdeploy:{intent.intent_id}")
    rec.summary["linked_run"] = run_id
    rec.summary["linked_review"] = review_dir.name if review_dir else None
    cli = cli or AwsCli(settings.aws_bin, settings.aws_profile or None, settings.aws_region)
    aliases: Dict[str, str] = {}
    if tf_dir:
        try:
            aliases = sg_ids_from_state(TerraformAdapter(settings.terraform_bin, settings.aws_region), settings.path(tf_dir))
            rec.step("state_mapping", "OK", json.dumps(aliases))
        except RuntimeError as e:
            rec.step("state_mapping", "ERROR", str(e))
    if sg_ids:
        # 대상이 하나면 첫 ID 를 첫 대상에 매핑
        for t, sid in zip(intent.target_security_groups, sg_ids):
            aliases[t] = sid
    v7, raw = v7_aws_state(cli, intent, aliases, execute)
    if raw:
        rec.write_json("aws_raw.json", raw)
    checks = load_json(settings.path(v8_checks_path)) if v8_checks_path else None
    v8 = v8_connectivity(checks, intent, execute)
    report = combine("post_deploy", [v7, v8])
    rec.write_json("verification_post.json", report.to_dict())
    rec.finish("DONE" if execute else "PREVIEW", validity=report.to_dict())
    status = post_deploy_status(report, execute)
    lines = [f"post-deploy run {rec.run_id}: {report.validity.value} — {report.summary}"]
    for l in report.layers:
        lines.append(f"  {l.layer} {l.verdict.value:8s} {l.summary[:300]}")
    if not execute:
        lines.append("  (preview only; re-run with --execute after a human approves AWS read access)")
    lines.append(f"  record: {rec.dir}")
    if review_dir is not None:
        sub = review_dir / "postdeploy" / rec.run_id
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "verification_post.json").write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        if raw:
            (sub / "aws_raw.json").write_text(json.dumps(raw, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        entry = {"run_id": rec.run_id, "at": _now(), "executed": execute, "intent": intent.intent_id, "status": status,
                 "validity": report.validity.value, "layers": {l.layer: l.verdict.value for l in report.layers},
                 "summary": report.summary[:500], "path": str(sub.relative_to(review_dir))}
        st = json.loads((review_dir / "state.json").read_text(encoding="utf-8"))
        hist = list(st.get("post_deploy_history") or []) + [entry]
        _update_review_state(review_dir, post_deploy=entry, post_deploy_history=hist)
        lines.append(f"  review : {review_dir.name} post_deploy={status} (V7={entry['layers'].get('V7')}, V8={entry['layers'].get('V8')})")
        if status == "DEPLOY_FAILED":
            lines.append(f"  → 복구 절차: python -m iacpatch recover --review {review_dir.name} (미리보기) → --execute (사람 승인)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 복구
# ---------------------------------------------------------------------------
def _baseline_from_review(review_dir: Path) -> Dict[str, str]:
    """review 기록의 original/ (패치 전 원본 사본) → {상대경로: 내용}. sha256.json 은 제외."""
    orig = review_dir / "original"
    files: Dict[str, str] = {}
    for p in sorted(orig.rglob("*")):
        if p.is_file() and p.name != "sha256.json":
            files[str(p.relative_to(orig))] = p.read_text(encoding="utf-8")
    return files


def run_recover(settings: Settings, run_id: Optional[str], execute: bool, tf_dir: Optional[str], review_id: Optional[str] = None) -> int:
    review_dir: Optional[Path] = None
    if review_id:
        review_dir, st, rerr = load_review_record(settings, review_id)
        if review_dir is None:
            print(rerr)
            return 2
        tf_dir = tf_dir or st.get("tf_dir")
        if not tf_dir:
            print("review record has no tf_dir — pass --tf-dir")
            return 2
        baseline_files = _baseline_from_review(review_dir)
        if not baseline_files:
            print(f"no original/ snapshot in {review_dir}")
            return 2
        label_id = review_dir.name
    else:
        if not run_id or not tf_dir:
            print("--run <id> --tf-dir <dir> 또는 --review <id> 가 필요하다")
            return 2
        run_dir = settings.path(settings.data_dir) / run_id
        snap = run_dir / "baseline_files.json"
        if not snap.exists():
            print(f"no baseline snapshot in {run_dir}")
            return 2
        baseline_files = json.loads(snap.read_text(encoding="utf-8"))
        label_id = run_id
    target = settings.path(tf_dir)
    tf = TerraformAdapter(settings.terraform_bin, settings.aws_region, template_dir=settings.tf_template_dir())
    rec = RunRecord(settings.path(settings.data_dir), label=f"recover:{label_id}")
    rec.summary["linked_run"] = run_id
    rec.summary["linked_review"] = review_dir.name if review_dir else None
    print(f"recovery for {'review' if review_dir else 'run'} {label_id} → {target}")
    print("step 1: restore pre-patch files (from run record) into the Terraform directory")
    for name in baseline_files:
        print(f"   - {target / name}")
    print("step 2: git commit as a revert (human)  →  step 3: terraform plan  →  step 4: terraform apply (human-approved)")
    print("step 5: terraform plan -detailed-exitcode must report NO changes, and describe-security-groups is recorded → RECOVERED")
    if not execute:
        rec.finish("RECOVERY_PENDING", note="preview only")
        if review_dir is not None:
            _update_review_state(review_dir, recovery={"run_id": rec.run_id, "at": _now(), "status": "RECOVERY_PENDING", "executed": False})
        print("preview only (--execute not given). Nothing was changed.")
        return 0
    for name, content in baseline_files.items():
        write_text_lf(target / name, content)   # 저장소 파일은 LF 로 (textio.py)
    rec.step("restore_files", "OK", ", ".join(baseline_files))
    init = tf.init(target)
    if not init.ok:
        rec.finish("RECOVERY_INCOMPLETE", note=f"init failed: {init.error}")
        if review_dir is not None:
            _update_review_state(review_dir, recovery={"run_id": rec.run_id, "at": _now(), "status": "RECOVERY_INCOMPLETE", "executed": True, "note": "init failed"})
        print("init failed:", init.error)
        return 1
    plan = tf.plan(target, plan_file="recover.tfplan")
    rec.step("plan", "OK" if plan.ok else "FAIL", plan.error[:300])
    if not plan.ok:
        rec.finish("RECOVERY_INCOMPLETE", note=f"plan failed: {plan.error}")
        if review_dir is not None:
            _update_review_state(review_dir, recovery={"run_id": rec.run_id, "at": _now(), "status": "RECOVERY_INCOMPLETE", "executed": True, "note": "plan failed"})
        print("plan failed:", plan.error)
        return 1
    print(plan.result.stdout[-2000:] if plan.result else "")
    apply = tf.apply(target, plan_file="recover.tfplan")
    rec.step("apply", "OK" if apply.ok else "FAIL", apply.error[:300])
    if not apply.ok:
        rec.finish("RECOVERY_INCOMPLETE", note=f"apply failed: {apply.error}")
        if review_dir is not None:
            _update_review_state(review_dir, recovery={"run_id": rec.run_id, "at": _now(), "status": "RECOVERY_INCOMPLETE", "executed": True, "note": "apply failed"})
        print("apply failed:", apply.error)
        return 1
    # 수렴 확인: 다시 plan 했을 때 변경이 없어야 한다
    check = tf._run(["plan", "-input=false", "-no-color", "-detailed-exitcode", "-lock=false"], target, 900)
    rc = check.result.returncode if check.result else -1
    converged = (rc == 0)
    rec.step("plan_after_apply", "NO_CHANGES" if converged else f"exit={rc}", "")
    cli = AwsCli(settings.aws_bin, settings.aws_profile or None, settings.aws_region)
    try:
        ids = sg_ids_from_state(tf, target)
        sgs = cli.describe_security_groups(list(ids.values())) if cli.available() else []
        rec.write_json("aws_after_recover.json", {"ids": ids, "security_groups": sgs})
        described = bool(sgs)
    except (RuntimeError, AwsError) as e:
        rec.step("describe_after_recover", "ERROR", str(e))
        described = False
    status = "RECOVERED" if (converged and described) else "RECOVERY_INCOMPLETE"
    rec.finish(status, converged=converged, described=described)
    if review_dir is not None:
        _update_review_state(review_dir, recovery={"run_id": rec.run_id, "at": _now(), "status": status, "executed": True,
                                                   "converged": converged, "described": described})
    print(f"{status} (plan converged={converged}, aws state recorded={described}) — record {rec.dir}")
    return 0 if status == "RECOVERED" else 1
