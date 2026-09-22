"""C 3~4주차 — 로컬 검토 흐름 (한 명령으로 입력 → 후보 → 기록 → 검증 연결 → 위험도 → 리포트).

    iacpatch review --tf-dir infrastructure/sg-baseline --trivy-json infrastructure/sg-baseline/baseline-scan.json \\
        --rule AVD-AWS-0107 --candidate mock:sg_baseline_ok --scenario demo

상태 전환 (state.json 의 history 에 기록):
    INPUT_READY → CANDIDATE_READY → VALIDATION_PENDING → REVIEW_REQUIRED
    오류/중단:  INPUT_ERROR / NO_FINDING / AMBIGUOUS_FINDING / CANDIDATE_INVALID / INFO_INSUFFICIENT / POLICY_BLOCKED / VALIDATION_FAILED

이 흐름은 기본적으로 외부 도구(trivy/terraform/aws/LLM API)를 실행하지 않는다. 모든 입력은 파일이다.
예외: --local-tools 를 주면 trivy/terraform 이 **있을 때만** V1~V4 를 로컬에서 실행한다 (review/local_verify.py). AWS·LLM 은 여전히 호출하지 않는다.
원본은 절대 덮어쓰지 않는다. 실행마다 data/reviews/<id>/ 를 새로 만든다.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Settings, load_json
from ..evidence import read_tf_files
from ..models import Finding, PatchCandidate, PolicyResult, ReviewLevel, ReviewState, RiskDecision, Validity, ValidityReport, Verdict
from ..policy.risk import score_risk
from ..policy.validator import validate_candidate
from ..report import unified_diff
from ..verify.combine import combine
from ..verify.plan_model import build_world, load_plan
from .candidates import CandidateSpec, load_candidate, validate_candidate_shape
from .inputs import FindingSelector, SourceCheck, TrivyInputError, check_source_consistency, list_findings, load_trivy_report, required_fields_missing, select_findings
from .level import decide_review_level
from .reports import render_pr_body, render_review
from .risk_text import diff_hcl, merge_with_plan_based, score_risk_text
from .verification_input import LinkedVerification, VerificationInputError, candidate_digest, link_verification


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds")


@dataclass
class ReviewOptions:
    tf_dir: str
    trivy_json: str
    candidate: str                      # "mock:<fixture>" | "manual:<path>"
    scenario: str
    rule: Optional[str] = None
    filename: Optional[str] = None
    resource: Optional[str] = None
    line: Optional[int] = None
    candidate_note: str = ""
    verification: Optional[str] = None  # A 의 검증 결과 JSON
    baseline_plan: Optional[str] = None
    candidate_plan: Optional[str] = None
    intent: Optional[str] = None
    out_dir: Optional[str] = None       # 기본 data/reviews
    mock_dir: Optional[str] = None
    local_tools: bool = False           # trivy/terraform 이 있으면 V1~V4 를 로컬에서 실행 (없으면 NOT_RUN). --verification 이 있으면 그쪽 우선


@dataclass
class ReviewResult:
    run_id: str
    run_dir: Path
    state: ReviewState
    level: Optional[ReviewLevel] = None
    message: str = ""
    validity: Optional[ValidityReport] = None
    candidate: Optional[PatchCandidate] = None
    risk: Optional[RiskDecision] = None
    ambiguous: List[Finding] = field(default_factory=list)

    def console(self) -> str:
        lines = [f"review {self.run_id}: {self.state.value}" + (f" / 검토 수준 {self.level.value}" if self.level else "")]
        if self.message:
            lines.append("  " + self.message)
        if self.validity:
            for l in self.validity.layers:
                lines.append(f"  {l.layer} {l.verdict.value:8s} {l.summary[:120]}")
        if self.risk:
            lines.append(f"  위험도 {self.risk.risk_level.value} (점수 {self.risk.score})")
        for f in self.ambiguous:
            lines.append(f"  후보 finding: --rule {f.rule_id} --file {f.filename} --resource {f.resource} --line {f.start_line}")
        lines.append(f"  기록: {self.run_dir}")
        return "\n".join(lines)


class _Run:
    """실행 폴더 + state.json 관리."""

    def __init__(self, root: Path, scenario: str):
        self.run_id = f"{_dt.datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        self.dir = root / self.run_id
        self.dir.mkdir(parents=True, exist_ok=False)
        self.state: Dict[str, Any] = {"run_id": self.run_id, "scenario": scenario, "state": None, "history": [], "errors": [],
                                      "started_at": _now(), "verification_status": "NOT_LINKED", "review_level": None,
                                      "note": "로컬 리포트 생성 성공은 패치 검증 성공이 아니다. verification_status 와 각 계층 상태를 볼 것"}
        self._flush()

    def transition(self, state: ReviewState, note: str = "") -> None:
        self.state["state"] = state.value
        self.state["history"].append({"state": state.value, "at": _now(), "note": note})
        self._flush()

    def error(self, msg: str) -> None:
        self.state["errors"].append(msg)
        self._flush()

    def set(self, **kw: Any) -> None:
        self.state.update(kw)
        self._flush()

    def _flush(self) -> None:
        (self.dir / "state.json").write_text(json.dumps(self.state, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    def write_json(self, rel: str, obj: Any) -> None:
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    def write_text(self, rel: str, text: str) -> None:
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def run_review(settings: Settings, opt: ReviewOptions) -> ReviewResult:
    root = Path(opt.out_dir) if opt.out_dir else settings.path("data/reviews")
    run = _Run(root, opt.scenario)
    run.set(tf_dir=opt.tf_dir)          # `iacpatch pr --review` 가 후보 파일을 되돌려 놓을 위치 (저장소 상대 경로)
    policy = load_json(settings.path(settings.policy_file))
    rubric = load_json(settings.path(settings.rubric_file))
    tf_dir = settings.path(opt.tf_dir)

    # ------------------------------------------------------------------ 1. 입력
    try:
        report = load_trivy_report(settings.path(opt.trivy_json))
    except TrivyInputError as e:
        run.error(str(e))
        run.transition(ReviewState.INPUT_ERROR, str(e))
        return ReviewResult(run.run_id, run.dir, ReviewState.INPUT_ERROR, message=str(e))
    if not tf_dir.is_dir():
        msg = f"원본 Terraform 디렉터리가 없다: {tf_dir}"
        run.error(msg)
        run.transition(ReviewState.INPUT_ERROR, msg)
        return ReviewResult(run.run_id, run.dir, ReviewState.INPUT_ERROR, message=msg)
    original = read_tf_files(tf_dir, policy.get("editable_file_globs"))
    if not original:
        msg = f"원본 디렉터리에 *.tf 가 없다: {tf_dir}"
        run.error(msg)
        run.transition(ReviewState.INPUT_ERROR, msg)
        return ReviewResult(run.run_id, run.dir, ReviewState.INPUT_ERROR, message=msg)
    (run.dir / "input").mkdir(exist_ok=True)
    shutil.copy(settings.path(opt.trivy_json), run.dir / "input" / "trivy.json")   # A 스캔 원문 사본
    findings = list_findings(report)
    run.write_json("input/findings.json", {"count": len(findings), "findings": [f.to_dict() for f in findings],
                                           "scan_created_at": report.get("CreatedAt"), "trivy_version": (report.get("Trivy") or {}).get("Version")})
    sel = FindingSelector(opt.rule, opt.filename, opt.resource, opt.line)
    matches = select_findings(findings, sel)
    if not matches:
        msg = f"조건({sel.describe()})에 맞는 FAIL finding 이 없다 (전체 {len(findings)}건)"
        run.transition(ReviewState.NO_FINDING, msg)
        return ReviewResult(run.run_id, run.dir, ReviewState.NO_FINDING, message=msg)
    if len(matches) > 1:
        msg = f"조건({sel.describe()})에 맞는 finding 이 {len(matches)}개다. --resource / --line 으로 하나를 지정해야 한다 (임의 선택하지 않음)"
        run.write_json("input/ambiguous.json", [f.to_dict() for f in matches])
        run.transition(ReviewState.AMBIGUOUS_FINDING, msg)
        return ReviewResult(run.run_id, run.dir, ReviewState.AMBIGUOUS_FINDING, message=msg, ambiguous=matches)
    target = matches[0]
    missing = required_fields_missing(target)
    if missing:
        msg = f"대상 finding 에 필수 정보가 없다: {missing}"
        run.error(msg)
        run.transition(ReviewState.INPUT_ERROR, msg)
        return ReviewResult(run.run_id, run.dir, ReviewState.INPUT_ERROR, message=msg)
    others = [f for f in findings if f.key != target.key]
    run.write_json("input/selected_finding.json", target.to_dict())
    src_check: SourceCheck = check_source_consistency(report, target, tf_dir, original)
    run.write_json("input/source_check.json", src_check.__dict__)
    if not src_check.ok:
        msg = "스캔 결과와 원본 코드가 일치하지 않는다 (지목된 줄 내용이 다름). 스캔을 다시 하거나 같은 시점의 원본을 써야 한다"
        run.error(msg)
        run.transition(ReviewState.INPUT_ERROR, msg)
        return ReviewResult(run.run_id, run.dir, ReviewState.INPUT_ERROR, message=msg)
    for name, text in original.items():
        run.write_text(f"original/{name}", text)
    run.write_json("original/sha256.json", src_check.file_sha256)
    run.transition(ReviewState.INPUT_READY, f"대상 {target.rule_id} @ {target.filename}:{target.start_line} {target.resource}")

    # ------------------------------------------------------------------ 2. 후보
    try:
        spec = CandidateSpec.parse(opt.candidate, opt.candidate_note)
    except ValueError as e:
        run.error(str(e))
        run.transition(ReviewState.CANDIDATE_INVALID, str(e))
        return ReviewResult(run.run_id, run.dir, ReviewState.CANDIDATE_INVALID, message=str(e))
    intent_raw = None
    if opt.intent:
        from ..iam_intent import try_load_any_intent
        ispec, _ikind, _ierr = try_load_any_intent(settings.path(opt.intent))
        intent_raw = ispec.to_dict() if ispec else None
    cand = load_candidate(spec, target, original, Path(opt.mock_dir) if opt.mock_dir else None, intent_raw, policy)
    shape, reasons = validate_candidate_shape(cand, original)
    run.write_json("candidate.json", cand.to_dict())
    if shape != "OK":
        st = ReviewState.CANDIDATE_INVALID if shape == "CANDIDATE_INVALID" else ReviewState.INFO_INSUFFICIENT
        run.error("; ".join(reasons))
        run.transition(st, "; ".join(reasons))
        return ReviewResult(run.run_id, run.dir, st, message="; ".join(reasons), candidate=cand)
    for name, text in cand.files.items():
        run.write_text(f"candidate/{name}", text)
    diff_text = unified_diff(original, cand.files, opt.tf_dir)
    run.write_text("candidate.diff", diff_text)
    run.set(candidate_sha256=candidate_digest(cand.files), candidate_origin=cand.origin, candidate_generator=cand.generator)
    pol: PolicyResult = validate_candidate(cand, original, policy, opt.tf_dir)
    run.write_json("policy.json", pol.to_dict())
    run.transition(ReviewState.CANDIDATE_READY, f"origin={cand.origin} files={list(cand.files)} policy={'OK' if pol.ok else 'VIOLATION'}")
    if not pol.ok:
        run.error("정책 위반: " + "; ".join(pol.violations))
        run.transition(ReviewState.POLICY_BLOCKED, "; ".join(pol.violations[:3]))
        validity = ValidityReport("pre_deploy", [], Validity.INCOMPLETE, "정책 위반으로 검증 연결을 진행하지 않음")
        # 차단돼도 텍스트 근거 위험도는 계산해 둔다 (왜 위험한 변경인지 리포트에 남기기 위함). 검증은 진행하지 않는다
        change = diff_hcl(original, cand.files)
        risk_blocked = score_risk_text(rubric, change, target_type=target.resource.split(".")[0])
        run.write_json("risk.json", {"decision": risk_blocked.to_dict(), "hcl_change": change.__dict__, "plan_based": None})
        level, lreasons = decide_review_level(validity, pol, risk_blocked, cand.needs_info)
        ctx = _ctx(opt, run, target, others, cand, pol, validity, risk_blocked, level, lreasons, src_check, [], change.__dict__, None, [])
        run.write_text("review.md", render_review(ctx))
        run.write_text("pr_body.md", render_pr_body(ctx, diff_text))
        run.set(review_level=level.value, finished_at=_now())
        return ReviewResult(run.run_id, run.dir, ReviewState.POLICY_BLOCKED, level, "; ".join(pol.violations[:3]), validity, cand, risk_blocked)

    # ------------------------------------------------------------------ 3. 검증 결과 연결
    cand_sources = dict(original)
    cand_sources.update(cand.files)
    verification_path, baseline_plan, candidate_plan = opt.verification, opt.baseline_plan, opt.candidate_plan
    local_notes: List[str] = []
    if opt.local_tools and not verification_path:
        # 도구가 있으면 V1~V4 를 지금 실행 (predeploy 와 같은 코드). 없으면 NOT_RUN 으로 기록된다
        from .local_verify import run_local_verification
        lv = run_local_verification(settings, tf_dir, cand.files, target, policy, run.dir / "local_verify", report)
        verification_path = str(lv.verification_path)
        if not baseline_plan and lv.baseline_plan:
            baseline_plan = str(lv.baseline_plan)
        if not candidate_plan and lv.candidate_plan:
            candidate_plan = str(lv.candidate_plan)
        local_notes = ["V1~V4 를 로컬 도구로 실행했다 (run 폴더 local_verify/). 도구가 없는 계층은 NOT_RUN"] + lv.notes
        run.set(local_tools=lv.tools)
    try:
        linked: LinkedVerification = link_verification(cand.files, verification_path, baseline_plan, candidate_plan, opt.intent,
                                                       policy, cand_sources)
    except VerificationInputError as e:
        run.error(str(e))
        linked = link_verification(cand.files, None, baseline_plan, candidate_plan, opt.intent, policy, cand_sources)
        linked.notes.append(f"검증 결과 파일을 쓰지 못했다: {e}")
    linked.notes = local_notes + linked.notes
    validity = combine("pre_deploy", linked.layers)
    run.write_json("verification.json", {"source": linked.source, "mismatch": linked.mismatch, "provided_layers": linked.provided_layers,
                                         "computed_layers": linked.computed_layers, "notes": linked.notes, "report": validity.to_dict()})
    vstatus = {"PASS": "COMPLETE", "FAIL": "FAILED", "INCOMPLETE": "PENDING"}[validity.validity.value]
    run.set(verification_status=vstatus, verification_source=linked.source)
    # 검증 연결 단계는 결과가 전부 있어도 한 번 거친다 (이력에 남기기 위함). 최종 상태는 아래에서 정한다
    run.transition(ReviewState.VALIDATION_PENDING, f"linked={linked.provided_layers + linked.computed_layers} validity={validity.validity.value}")

    # ------------------------------------------------------------------ 4. 위험도 (텍스트 근거 + plan 근거)
    change = diff_hcl(original, cand.files)
    risk_text = score_risk_text(rubric, change, target_type=target.resource.split(".")[0])
    plan_risk: Optional[RiskDecision] = None
    v5 = validity.layer("V5")
    if v5 is not None and v5.verdict not in (Verdict.NOT_RUN, Verdict.SKIPPED) and candidate_plan:
        try:
            world = build_world(load_plan(candidate_plan), cand_sources)
            diff_stats = next((c for c in pol.checks if c.get("check") == "diff_stats"), {})
            v6 = validity.layer("V6")
            plan_risk = score_risk(rubric, v5.details, world, diff_stats, v6.details if v6 else None, target_type=target.resource.split(".")[0])
        except Exception as e:  # plan 이 깨졌으면 텍스트 근거만
            linked.notes.append(f"plan 기반 위험도 계산 실패: {e}")
    risk = merge_with_plan_based(risk_text, plan_risk)
    run.write_json("risk.json", {"decision": risk.to_dict(), "hcl_change": change.__dict__, "plan_based": plan_risk.to_dict() if plan_risk else None})

    # ------------------------------------------------------------------ 5. 검토 수준 + 리포트
    level, lreasons = decide_review_level(validity, pol, risk, cand.needs_info)
    final_state = ReviewState.VALIDATION_FAILED if validity.validity == Validity.FAIL else ReviewState.REVIEW_REQUIRED
    run.set(review_level=level.value)
    run.transition(final_state, f"review_level={level.value}")
    unknowns = _unknowns(validity, linked, risk, src_check)
    checks = _human_checks(target, cand, validity, risk, level)
    ctx = _ctx(opt, run, target, others, cand, pol, validity, risk, level, lreasons, src_check, linked.notes, change.__dict__, None, checks, unknowns)
    run.write_text("review.md", render_review(ctx))
    run.write_text("pr_body.md", render_pr_body(ctx, diff_text))
    run.set(finished_at=_now())
    msg = "검토 자료 생성 완료" if final_state == ReviewState.REVIEW_REQUIRED else "연결된 검증 결과에 실패가 있어 후보를 반영하면 안 됨"
    if vstatus == "PENDING":
        msg += " — 검증 대기 계층이 있음 (패치 검증 완료 아님)"
    return ReviewResult(run.run_id, run.dir, final_state, level, msg, validity, cand, risk)


def _ctx(opt, run, target, others, cand, pol, validity, risk, level, lreasons, src_check, vnotes, hcl_change, tool_versions, checks, unknowns=None):
    changed = []
    for n, content in cand.files.items():
        orig = run.dir / "original" / n
        if not orig.exists() or orig.read_text(encoding="utf-8") != content:
            changed.append(n)
    return {
        "scenario": opt.scenario, "run_id": run.run_id, "state": run.state["state"], "finding": target, "other_findings": others,
        "candidate": cand, "policy": pol, "validity": validity, "risk": risk, "level": level, "level_reasons": lreasons,
        "diff_path": "candidate.diff", "files_changed": changed,
        "source_check": src_check.__dict__, "verification_notes": vnotes, "hcl_change": hcl_change,
        "tool_versions": tool_versions or {"iacpatch": "0.2.0 (review flow)"}, "human_checks": checks, "unknowns": unknowns or [],
    }


def _unknowns(validity: ValidityReport, linked: LinkedVerification, risk: Optional[RiskDecision], src_check: SourceCheck) -> List[str]:
    out: List[str] = []
    for l in validity.layers:
        if l.verdict == Verdict.NOT_RUN:
            out.append(f"{l.layer} {l.name}: {l.summary}")
        elif l.verdict == Verdict.UNKNOWN:
            out.append(f"{l.layer} 판정 불가: {l.summary[:160]}")
    if linked.mismatch:
        out.append("검증 결과 파일이 다른 후보의 것이라 사용하지 않았다")
    if risk is not None:
        for f in risk.factors:
            if f.get("factor") == "undetermined":
                out.append(f"위험도 미확정 항목: {f.get('value')}")
    if not src_check.ok or src_check.cause_lines_checked == 0:
        out.append("스캔-원본 동일 시점 여부를 완전히 확인하지 못했다 (A 가 source_commit 을 넘기면 확정 가능)")
    out.append("V7(실제 AWS 상태)·V8(통신 확인)은 배포 후에만 가능하며 이번 로컬 흐름에 없다")
    return out


def _human_checks(target: Finding, cand: PatchCandidate, validity: ValidityReport, risk: Optional[RiskDecision], level: ReviewLevel) -> List[str]:
    items = [
        f"diff 가 대상 finding({target.rule_id} @ {target.resource})만 다루는지 확인",
        "승인 출처(허용 CIDR 등)가 팀이 정한 값과 일치하는지 확인 (코드가 추측한 값이 아님)",
        "검증 표에 '검증 대기'·'판정 불가'·'실패' 가 없는지 확인 — 있으면 A 의 결과를 받아 다시 review 실행",
    ]
    if cand.needs_info:
        items.append("후보의 누락 정보 채우기: " + "; ".join(cand.needs_info))
    if risk is not None and any(f.get("factor") == "undetermined" for f in risk.factors):
        items.append("위험도 미확정 항목(같은 ENI 의 다른 SG, 실제 삭제/교체 여부)은 plan JSON 을 넘겨 다시 실행하거나 사람이 확인")
    items.append("이 후보를 반영할지 결정 — 반영하더라도 terraform apply 는 사람이 실행하고, 배포 후 V7/V8 을 기록")
    return items
