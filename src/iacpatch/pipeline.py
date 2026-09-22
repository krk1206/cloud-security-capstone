"""파이프라인 오케스트레이터 (일반 Python 상태 흐름. LangChain/LangGraph 없음).

pre-deploy (운영 경로의 앞부분, 사람 승인 전까지):

    Trivy 스캔(원본) → 대상 finding 선택 → Intent 로딩(없으면 INSUFFICIENT_INFO, 생성기 호출 안 함)
    → 원본 plan → Evidence Bundle → 생성기(LLM/mock/rule-based) → 후보 (원본과 분리 저장)
    → Policy Validator → V1 V2 (Trivy 재스캔) → V3 V4 (validate/plan) → V5 (plan diff) → V6 (Intent Oracle)
    → 검증 종합 → (실패 시 제한 횟수 내 재생성: Observe→Reason→Act→Verify) → Risk Rubric → Gate → PR 본문

이 모듈은 절대로 terraform apply / git push / PR 생성 API 를 자동 호출하지 않는다.
(apply 는 사람이, PR 생성은 `iacpatch pr --execute` 로 사람이 명시적으로 실행한다.)
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import Settings, load_json
from .evidence import build_bundle, read_tf_files
from .generator.llm_generator import LLMPatchGenerator
from .generator.llm_providers import make_provider
from .generator.rule_based import RuleBasedGenerator
from .intent import IntentSpec, try_load_intent
from .models import Finding, GateAction, GateDecision, LayerResult, PatchCandidate, PolicyResult, RiskDecision, Validity, ValidityReport, Verdict
from .policy.gate import decide
from .policy.risk import score_risk
from .policy.validator import validate_candidate
from .report import console_summary, intent_summary_md, pr_body, unified_diff
from .runrecord import RunRecord
from .tools.terraform import TerraformAdapter
from .tools.trivy import TrivyAdapter, TrivyScan
from .verify.combine import combine
from .verify.layers import v1_target_finding, v2_finding_diff, v3_validate, v4_plan, v5_plan_diff
from .verify.plan_model import build_world, iter_planned_resources
from .verify.v6 import v6_intent_oracle


class PipelineResult:
    def __init__(self, run_id: str, run_dir: Path, status: str, gate: Optional[GateDecision] = None,
                 validity: Optional[ValidityReport] = None, candidate: Optional[PatchCandidate] = None, note: str = ""):
        self.run_id, self.run_dir, self.status, self.gate, self.validity, self.candidate, self.note = run_id, run_dir, status, gate, validity, candidate, note

    def console(self) -> str:
        return console_summary(self.run_id, self.status, self.gate, self.validity, self.candidate, self.note)


class AmbiguousTarget(ValueError):
    def __init__(self, matches: List[Finding]):
        super().__init__(f"{len(matches)} findings match; specify --resource (and --line if needed)")
        self.matches = matches


def select_target(findings: List[Finding], rule_id: str, resource: Optional[str] = None) -> Optional[Finding]:
    """대상 finding 1개. 여러 개면 임의로 첫 항목을 고르지 않고 AmbiguousTarget 을 던진다."""
    cands = [f for f in findings if f.rule_id == rule_id and f.status == "FAIL"]
    if resource:
        cands = [f for f in cands if f.resource == resource]
    cands.sort(key=lambda f: (f.filename, f.start_line))
    if len(cands) > 1:
        raise AmbiguousTarget(cands)
    return cands[0] if cands else None


def make_generator(settings: Settings, kind: str):
    if kind == "rule_based":
        return RuleBasedGenerator()
    if kind == "llm":
        kw: Dict[str, Any] = {}
        if settings.llm_provider == "mock":
            kw["fixture"] = settings.llm_mock_fixture
        else:
            if settings.llm_model:
                kw["model"] = settings.llm_model
            if settings.llm_base_url:
                kw["base_url"] = settings.llm_base_url
        provider = make_provider(settings.llm_provider, **kw)
        return LLMPatchGenerator(provider, prompt_version=settings.prompt_version)
    raise ValueError(f"unknown generator kind {kind!r} (llm|rule_based)")


def _resource_present(plan: Optional[Dict[str, Any]], address: str) -> Optional[bool]:
    if plan is None:
        return None
    return any(r.get("address") == address for r in iter_planned_resources(plan))


def run_predeploy(settings: Settings, target_dir: str, intent_path: str, scenario_id: str,
                  generator_kind: str = "llm", target_resource: Optional[str] = None,
                  workspace: Optional[str] = None, keep_workspace: bool = False,
                  intent_override: Optional[IntentSpec] = None) -> PipelineResult:
    rec = RunRecord(settings.path(settings.data_dir), label=f"predeploy:{scenario_id}")
    rec.write_json("settings.json", settings.to_dict())
    tf = TerraformAdapter(settings.terraform_bin, settings.aws_region)
    trivy = TrivyAdapter(settings.trivy_bin)
    policy = load_json(settings.path(settings.policy_file))
    rubric = load_json(settings.path(settings.rubric_file))
    cis = load_json(settings.path(settings.cis_file)) if settings.path(settings.cis_file).exists() else {}
    src_dir = settings.path(target_dir)
    tfinfo = tf.info()
    tool_versions = {
        "trivy": trivy.version() or "unavailable",
        "terraform": (f"{tfinfo.kind} {tfinfo.version}" if tfinfo.available else "unavailable"),
        "iacpatch": "0.1.0",
    }
    rec.summary.update({"scenario_id": scenario_id, "target_dir": target_dir, "intent_path": intent_path,
                        "generator": generator_kind, "tool_versions": tool_versions, "offline_plan": settings.offline_plan})
    ws_root = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix="iacpatch-"))
    ws_root.mkdir(parents=True, exist_ok=True)
    tf_tool_label = tool_versions["terraform"]
    var_file = settings.tf_var_file or None

    try:
        # 1) 원본 스캔
        rec.start_timer("scan_before")
        before = trivy.scan_dir(src_dir, rec.dir / "trivy_before.json", tf_vars=(str(src_dir / var_file) if var_file else None))
        rec.stop_timer("scan_before")
        if not before.ok:
            rec.step("trivy_before", "ERROR", before.error)
            rec.finish("TOOL_ERROR", error=f"trivy scan failed: {before.error}")
            return PipelineResult(rec.run_id, rec.dir, "TOOL_ERROR", note=before.error)
        rec.step("trivy_before", "OK", f"{before.summary}")
        supported = policy.get("supported_target_rules") or ["AVD-AWS-0107"]
        if settings.target_rule not in supported:
            rec.finish("UNSUPPORTED_RULE", note=f"{settings.target_rule} is not in supported_target_rules {supported}")
            return PipelineResult(rec.run_id, rec.dir, "UNSUPPORTED_RULE",
                                  note=f"{settings.target_rule} cannot be verified end-to-end by this pipeline yet (supported: {supported}); see docs/IAM_SCOPE.md")
        try:
            target = select_target(before.findings, settings.target_rule, target_resource)
        except AmbiguousTarget as e:
            rec.finish("AMBIGUOUS_FINDING", note=str(e), matches=[f.to_dict() for f in e.matches])
            return PipelineResult(rec.run_id, rec.dir, "AMBIGUOUS_FINDING",
                                  note=str(e) + ": " + "; ".join(f"{f.resource}:{f.start_line}" for f in e.matches))
        if target is None:
            rec.finish("NO_FINDING", note=f"{settings.target_rule} not found in {target_dir}")
            return PipelineResult(rec.run_id, rec.dir, "NO_FINDING", note=f"{settings.target_rule} not reported for {target_dir}; nothing to patch")
        rec.summary["target_finding"] = target.to_dict()

        # 2) Intent (없으면 생성기 호출 없이 종료)
        intent, intent_err = (intent_override, None) if intent_override else try_load_intent(settings.path(intent_path))
        if intent is None:
            rec.step("intent", "INSUFFICIENT_INFO", intent_err or "")
            rec.finish("INSUFFICIENT_INFO", note=intent_err)
            return PipelineResult(rec.run_id, rec.dir, "INSUFFICIENT_INFO",
                                  note=f"intent unusable → no patch generated (approved sources must be supplied by a human): {intent_err}")
        rec.step("intent", "OK", f"{intent.intent_id}")

        # 3) 원본 파일 스냅샷 + 원본 plan
        baseline_files = read_tf_files(src_dir, policy.get("editable_file_globs"))
        rec.write_json("baseline_files.json", baseline_files)
        rec.start_timer("plan_baseline")
        base_wd = tf.make_workdir(src_dir, ws_root / "baseline")
        base_steps = tf.plan_pipeline(base_wd, settings.offline_plan, var_file=var_file, write_plan_json_to=rec.dir / "plan_baseline.json")
        rec.stop_timer("plan_baseline")
        baseline_plan = base_steps["show"].data if base_steps.get("show") and base_steps["show"].ok else None
        rec.step("plan_baseline", "OK" if baseline_plan else "SKIPPED_OR_FAILED",
                 "" if baseline_plan else "; ".join(f"{k}:{v.error[:120]}" for k, v in base_steps.items() if not v.ok))

        # 4) Evidence Bundle
        bundle = build_bundle(scenario_id, target_dir, target, before.findings, baseline_files, intent.to_dict(), policy, cis, tool_versions)
        rec.write_json("bundle.json", bundle.to_dict())

        # 5) 생성 + 검증 루프
        generator = make_generator(settings, generator_kind)
        feedback: Optional[str] = None
        candidate: Optional[PatchCandidate] = None
        validity: Optional[ValidityReport] = None
        policy_res: Optional[PolicyResult] = None
        cand_plan: Optional[Dict[str, Any]] = None
        cand_files: Dict[str, str] = {}
        diff_stats: Dict[str, Any] = {}
        for attempt in range(1, max(1, settings.max_attempts) + 1):
            cdir = rec.candidate_dir(attempt)
            rec.start_timer("generate")
            candidate = generator.generate(bundle, feedback=feedback, attempt=attempt)
            rec.stop_timer("generate")
            raw = getattr(generator, "last_response", None)
            if raw is not None:
                (cdir / "llm_raw_response.txt").write_text(raw.text or "", encoding="utf-8")
                candidate.raw_response_path = str((cdir / "llm_raw_response.txt").relative_to(rec.dir))
                rec.write_json(str((cdir / "llm_meta.json").relative_to(rec.dir)),
                               {"provider": raw.provider, "model": raw.model, "truncated": raw.truncated, "stop_reason": raw.stop_reason,
                                "usage": raw.usage, "error": raw.error})
            rec.write_json(str((cdir / "candidate.json").relative_to(rec.dir)), candidate.to_dict())
            for name, content in candidate.files.items():
                p = cdir / "files" / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
            rec.step(f"generate[{attempt}]", candidate.status, candidate.error or candidate.rationale[:120])
            if candidate.status != "PATCH":
                break

            # 5a) Policy Validator
            policy_res = validate_candidate(candidate, baseline_files, policy, target_dir)
            rec.write_json(str((cdir / "policy.json").relative_to(rec.dir)), policy_res.to_dict())
            diff_stats = next((c for c in policy_res.checks if c.get("check") == "diff_stats"), {})
            if not policy_res.ok:
                rec.step(f"policy[{attempt}]", "VIOLATION", "; ".join(policy_res.violations[:3]))
                validity = ValidityReport("pre_deploy", [], Validity.INCOMPLETE, "verification not run: policy violation")
                feedback = "Policy violations:\n- " + "\n- ".join(policy_res.violations)
                if attempt < settings.max_attempts:
                    continue
                break
            rec.step(f"policy[{attempt}]", "OK")

            # 5b) 후보 작업 디렉터리 (원본 + 후보 파일 덮어쓰기; 원본은 그대로)
            cand_files = dict(baseline_files)
            cand_files.update(candidate.files)
            cand_wd = tf.make_workdir(src_dir, ws_root / f"candidate-{attempt:02d}", file_overrides=candidate.files)

            layers: List[LayerResult] = []
            # V1/V2
            rec.start_timer("scan_after")
            after = trivy.scan_dir(cand_wd, cdir / "trivy_after.json", tf_vars=(str(cand_wd / var_file) if var_file else None))
            rec.stop_timer("scan_after")
            # V3/V4
            rec.start_timer("plan_candidate")
            cand_steps = tf.plan_pipeline(cand_wd, settings.offline_plan, var_file=var_file, write_plan_json_to=cdir / "plan_candidate.json")
            rec.stop_timer("plan_candidate")
            cand_plan = cand_steps["show"].data if cand_steps.get("show") and cand_steps["show"].ok else None
            present = _resource_present(cand_plan, target.resource)
            layers.append(v1_target_finding(target, before, after, present))
            layers.append(v2_finding_diff(before, after, policy.get("v2_block_severities", ["CRITICAL", "HIGH"]), policy.get("v2_ignore_rules", [])))
            layers.append(v3_validate(cand_steps, tf_tool_label))
            layers.append(v4_plan(cand_steps, tf_tool_label, settings.offline_plan))
            layers.append(v5_plan_diff(baseline_plan, cand_plan, policy, tf_tool_label))
            layers.append(v6_intent_oracle(cand_plan, cand_files, intent))
            validity = combine("pre_deploy", layers)
            rec.write_json(str((cdir / "verification.json").relative_to(rec.dir)), validity.to_dict())
            rec.step(f"verify[{attempt}]", validity.validity.value, validity.summary[:200])
            if validity.validity == Validity.FAIL and attempt < settings.max_attempts:
                feedback = "\n".join(f"{l.layer} {l.name}: {l.summary}" for l in layers if l.verdict == Verdict.FAIL)
                continue
            break

        # 6) 종결 분기
        if candidate is None:
            rec.finish("GENERATION_FAILED", note="generator returned nothing")
            return PipelineResult(rec.run_id, rec.dir, "GENERATION_FAILED")
        if candidate.status != "PATCH":
            status = {"INSUFFICIENT_INFO": "INSUFFICIENT_INFO", "ABSTAIN": "ABSTAIN", "NOT_SUPPORTED": "NOT_SUPPORTED"}.get(candidate.status, "GENERATION_FAILED")
            rec.finish(status, candidate=candidate.to_dict(), gate={"action": GateAction.REPORT_ONLY.value, "reason": status})
            return PipelineResult(rec.run_id, rec.dir, status, candidate=candidate,
                                  note=f"no patch produced ({candidate.status}: {candidate.error or candidate.rationale[:200]}) → REPORT_ONLY")
        assert validity is not None and policy_res is not None

        # 7) Risk Rubric (검증 결과와 별개 축) + Gate
        v5 = validity.layer("V5")
        v6 = validity.layer("V6")
        world = None
        if cand_plan is not None:
            try:
                world = build_world(cand_plan, cand_files)
            except Exception:  # pragma: no cover - plan parse issues already surfaced in V6
                world = None
        risk: Optional[RiskDecision] = None
        if v5 is not None and v5.executed and v5.verdict != Verdict.SKIPPED:
            risk = score_risk(rubric, v5.details, world, diff_stats, v6.details if v6 else None, target_type=target.resource.split(".")[0])
            rec.write_json("risk.json", risk.to_dict())
        gate = decide(validity, policy_res, risk, candidate.proposed_autonomy)
        rec.write_json("gate.json", gate.to_dict())

        diff_text = unified_diff(baseline_files, candidate.files, target_dir)
        rec.write_text("candidate.diff", diff_text)
        body = pr_body(scenario_id, rec.run_id, candidate, validity, policy_res, risk, gate, diff_text, tool_versions, intent_summary_md(intent.to_dict()))
        rec.write_text("pr_body.md", body)
        rec.finish("DONE", candidate=candidate.to_dict(), validity=validity.to_dict(), gate=gate.to_dict(),
                   risk=(risk.to_dict() if risk else None), policy=policy_res.to_dict(), final_attempt=candidate.attempt)
        note = {
            GateAction.CREATE_PR_AUTO: "next: `iacpatch pr --run <id>` (creates branch+PR only with --execute; merge after lightweight human check; apply by human)",
            GateAction.CREATE_PR_APPROVAL: "next: `iacpatch pr --run <id>` → PR with full evidence; human approval required before merge/apply",
            GateAction.REPORT_ONLY: "no PR: report only (see pr_body.md)",
            GateAction.HOLD_FOR_HUMAN: "verification incomplete → no auto action; a human must review (see verification.json)",
            GateAction.BLOCK: "blocked → no PR created",
        }[gate.action]
        return PipelineResult(rec.run_id, rec.dir, "DONE", gate, validity, candidate, note)
    finally:
        if not keep_workspace and not workspace:
            shutil.rmtree(ws_root, ignore_errors=True)
