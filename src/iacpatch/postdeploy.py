"""배포 후 검증 (V7, V8) 과 복구 절차.

V7  실제 AWS 상태 실측: describe-security-groups + describe-network-interfaces(같은 ENI 의 SG 합산)
    + get-managed-prefix-list-entries(전개) → V6 와 **같은 오라클**로 판정. plan 주소 ↔ GroupId 매핑은
    terraform show -json(state) 또는 GroupName 으로 잡는다.
V8  통신 확인: 허용돼야 할 통신(승인 출처에서)이 성공하고, 금지된 통신(승인 밖 출처에서)이 실패하는지.
    금지 통신 확인은 승인 밖 **vantage(관측 지점)** 가 있어야 의미가 있다. 없으면 PASS 가 아니라 UNKNOWN.
복구  git 되돌리기만으로 "복구됨"이라고 하지 않는다. 원본 파일 복원 → plan → apply(사람 승인) → plan 재실행으로
    변경 없음(drift 없음) 확인 + describe 로 실측 기록 → 그때 RECOVERED.

--execute 없이 호출하면 실제 AWS 조회/통신/apply 를 하지 않고, 실행할 명령만 출력한다.
"""
from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import Settings, load_json
from .intent import try_load_intent
from .models import LayerResult, Verdict
from .runrecord import RunRecord
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
def run_postdeploy(settings: Settings, intent_path: str, sg_ids: List[str], v8_checks_path: Optional[str], execute: bool,
                   run_id: Optional[str] = None, tf_dir: Optional[str] = None) -> str:
    intent, err = try_load_intent(settings.path(intent_path))
    if intent is None:
        return f"intent unusable: {err}"
    rec = RunRecord(settings.path(settings.data_dir), label=f"postdeploy:{intent.intent_id}")
    rec.summary["linked_run"] = run_id
    cli = AwsCli(settings.aws_bin, settings.aws_profile or None, settings.aws_region)
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
    lines = [f"post-deploy run {rec.run_id}: {report.validity.value} — {report.summary}"]
    for l in report.layers:
        lines.append(f"  {l.layer} {l.verdict.value:8s} {l.summary[:300]}")
    if not execute:
        lines.append("  (preview only; re-run with --execute after a human approves AWS read access)")
    lines.append(f"  record: {rec.dir}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 복구
# ---------------------------------------------------------------------------
def run_recover(settings: Settings, run_id: str, execute: bool, tf_dir: str) -> int:
    run_dir = settings.path(settings.data_dir) / run_id
    snap = run_dir / "baseline_files.json"
    if not snap.exists():
        print(f"no baseline snapshot in {run_dir}")
        return 2
    baseline_files: Dict[str, str] = json.loads(snap.read_text(encoding="utf-8"))
    target = settings.path(tf_dir)
    tf = TerraformAdapter(settings.terraform_bin, settings.aws_region)
    rec = RunRecord(settings.path(settings.data_dir), label=f"recover:{run_id}")
    rec.summary["linked_run"] = run_id
    print(f"recovery for run {run_id} → {target}")
    print("step 1: restore pre-patch files (from run record) into the Terraform directory")
    for name in baseline_files:
        print(f"   - {target / name}")
    print("step 2: git commit as a revert (human)  →  step 3: terraform plan  →  step 4: terraform apply (human-approved)")
    print("step 5: terraform plan -detailed-exitcode must report NO changes, and describe-security-groups is recorded → RECOVERED")
    if not execute:
        rec.finish("RECOVERY_PENDING", note="preview only")
        print("preview only (--execute not given). Nothing was changed.")
        return 0
    for name, content in baseline_files.items():
        (target / name).write_text(content, encoding="utf-8")
    rec.step("restore_files", "OK", ", ".join(baseline_files))
    init = tf.init(target)
    if not init.ok:
        rec.finish("RECOVERY_INCOMPLETE", note=f"init failed: {init.error}")
        print("init failed:", init.error)
        return 1
    plan = tf.plan(target, plan_file="recover.tfplan")
    rec.step("plan", "OK" if plan.ok else "FAIL", plan.error[:300])
    if not plan.ok:
        rec.finish("RECOVERY_INCOMPLETE", note=f"plan failed: {plan.error}")
        print("plan failed:", plan.error)
        return 1
    print(plan.result.stdout[-2000:] if plan.result else "")
    apply = tf.apply(target, plan_file="recover.tfplan")
    rec.step("apply", "OK" if apply.ok else "FAIL", apply.error[:300])
    if not apply.ok:
        rec.finish("RECOVERY_INCOMPLETE", note=f"apply failed: {apply.error}")
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
    print(f"{status} (plan converged={converged}, aws state recorded={described}) — record {rec.dir}")
    return 0 if status == "RECOVERED" else 1
