"""사람이 읽는 리포트 / PR 본문 생성 (Markdown)."""
from __future__ import annotations

import difflib
from typing import Any, Dict, List, Optional

from .models import GateDecision, PatchCandidate, PolicyResult, RiskDecision, ValidityReport, Verdict

_ICON = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "UNKNOWN": "❓", "SKIPPED": "⏭️", "ERROR": "💥"}


def unified_diff(baseline_files: Dict[str, str], candidate_files: Dict[str, str], target_dir: str) -> str:
    out: List[str] = []
    for name, new in candidate_files.items():
        old = baseline_files.get(name, "")
        diff = difflib.unified_diff(old.splitlines(), new.splitlines(), fromfile=f"a/{target_dir}/{name}", tofile=f"b/{target_dir}/{name}", lineterm="")
        out.extend(diff)
        out.append("")
    return "\n".join(out).strip() + "\n"


def layer_table(report: ValidityReport) -> str:
    rows = ["| 계층 | 내용 | 판정 | 요약 |", "|---|---|---|---|"]
    for l in report.layers:
        icon = _ICON.get(l.verdict.value, "")
        summ = l.summary.replace("|", "\\|").replace("\n", " ")
        if len(summ) > 220:
            summ = summ[:217] + "…"
        rows.append(f"| {l.layer} | {l.name} | {icon} {l.verdict.value}{'' if l.executed else ' (not executed)'} | {summ} |")
    return "\n".join(rows)


def pr_body(scenario_id: str, run_id: str, candidate: PatchCandidate, validity: ValidityReport, policy: PolicyResult,
            risk: Optional[RiskDecision], gate: GateDecision, diff_text: str, tool_versions: Dict[str, str],
            intent_summary: str = "") -> str:
    lines: List[str] = []
    lines.append(f"## iacpatch 패치 후보 — `{scenario_id}`")
    lines.append("")
    lines.append(f"- run: `{run_id}`  |  후보: `{candidate.candidate_id}`  |  생성기: `{candidate.generator}` (origin=`{candidate.origin}`)")
    lines.append(f"- 프롬프트 버전: `{candidate.prompt_version or '-'}`  |  모델: `{candidate.model or '-'}`  |  시도: {candidate.attempt}")
    lines.append(f"- 도구: " + ", ".join(f"{k} {v}" for k, v in tool_versions.items()))
    lines.append("")
    lines.append(f"### 게이트 결정: **{gate.action.value}**")
    lines.append("")
    lines.append(f"- 검증(Validity): **{gate.validity.value}** — {validity.summary}")
    lines.append(f"- 정책(Policy): **{'OK' if gate.policy_ok else 'VIOLATION'}**" + ("" if gate.policy_ok else " — " + "; ".join(policy.violations[:3])))
    if risk is not None:
        lines.append(f"- 위험도(Risk): **{risk.risk_level.value}** (score {risk.score}) → 자율성 상한 **{risk.autonomy_cap.value}**")
    if gate.llm_proposed_autonomy is not None:
        lines.append(f"- LLM 제안 자율성: {gate.llm_proposed_autonomy.value} (하향 전용)")
    if gate.final_autonomy is not None:
        lines.append(f"- 최종 자율성: **{gate.final_autonomy.value}**")
    for r in gate.reasons:
        lines.append(f"  - {r}")
    lines.append("")
    lines.append("> 검증 축과 위험도 축은 별개다. 검증이 FAIL/INCOMPLETE 면 위험도와 무관하게 자동 승인되지 않는다.")
    lines.append("> V6 는 SG 규칙상 허용 집합만 증명한다. 실제 인터넷 도달 가능성은 배포 후 V7/V8 로 확인한다 (그마저도 제한적).")
    lines.append("")
    lines.append("### 검증 계층")
    lines.append("")
    lines.append(layer_table(validity))
    lines.append("")
    v6 = validity.layer("V6")
    if v6 is not None and v6.details.get("targets"):
        lines.append("<details><summary>V6 Intent Oracle 상세</summary>")
        lines.append("")
        for t in v6.details["targets"]:
            lines.append(f"- 대상 `{t['target']}` → {t['verdict']}" + (f" — {t['reason']}" if t.get("reason") else ""))
            for sc in t.get("scopes", []):
                lines.append(f"  - 범위 `{sc['scope_id']}` ({sc['scope_kind']}; SGs: {', '.join(sc['security_groups'])}) → {sc['verdict']}")
                for s in sc.get("services", []):
                    lines.append(f"    - {s['label']}: {s['verdict']} | 실효 v4 {s['effective_v4']} v6 {s['effective_v6']} sg {s['effective_sg_refs']} | 승인 v4 {s['approved_v4']} v6 {s['approved_v6']}")
                    if s.get("excess_v4") or s.get("excess_v6") or s.get("excess_sg_refs"):
                        lines.append(f"      - EXCESS v4 {s['excess_v4'][:6]}{'…' if len(s['excess_v4']) > 6 else ''} v6 {s['excess_v6']} sg {s['excess_sg_refs']}")
                    for u in s.get("unknown_reasons", []):
                        lines.append(f"      - UNKNOWN: {u}")
                for r in sc.get("required", []):
                    lines.append(f"    - required {r['label']} ({r['source_cidr']} → {r['service_id']}): {r['verdict']} — {r['reason']}")
                for c in sc.get("caveats", []):
                    lines.append(f"    - caveat: {c}")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    if intent_summary:
        lines.append("### Intent (사람이 정의한 승인 출처)")
        lines.append("")
        lines.append(intent_summary)
        lines.append("")
    if candidate.rationale:
        lines.append("### 생성기 설명 (검증되지 않은 주장 — 참고용)")
        lines.append("")
        lines.append(candidate.rationale.strip())
        if candidate.assumptions:
            lines.append("")
            lines.append("가정: " + "; ".join(candidate.assumptions))
        lines.append("")
    lines.append("### 변경 내용 (diff)")
    lines.append("")
    lines.append("```diff")
    lines.append(diff_text.rstrip())
    lines.append("```")
    lines.append("")
    if risk is not None:
        lines.append("<details><summary>Risk Rubric 산출 근거</summary>")
        lines.append("")
        lines.append(f"rubric: {risk.rubric_version}")
        lines.append("")
        lines.append("| 요인 | 값 | 점수 | 비고 |")
        lines.append("|---|---|---|---|")
        for f in risk.factors:
            lines.append(f"| {f['factor']} | {str(f['value'])[:60]} | {f['points']} | {f.get('note','')} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    lines.append("---")
    lines.append("승인 체크리스트 (사람): ① Intent 의 승인 출처가 실제 업무 요구와 맞는가 ② diff 가 대상 finding 만 다루는가 "
                 "③ 검증 표에 FAIL/UNKNOWN 이 없는가 ④ 병합 후 apply 는 사람이 실행하고, V7/V8 결과를 이 PR 에 댓글로 남긴다.")
    return "\n".join(lines) + "\n"


def intent_summary_md(intent_raw: Dict[str, Any]) -> str:
    if not intent_raw:
        return "_(intent 없음)_"
    out = [f"- intent `{intent_raw.get('intent_id')}` (v{intent_raw.get('intent_version')}) — 대상 {intent_raw.get('targets', {}).get('security_groups')}"]
    for g in intent_raw.get("guarded_services", []):
        ap = g.get("approved_sources", {})
        out.append(f"- {g.get('label')}: {g.get('direction')}/{g.get('protocol')}/{g.get('from_port')}-{g.get('to_port')} ← v4 {ap.get('cidrs_v4')} v6 {ap.get('cidrs_v6')} sg {ap.get('security_group_refs')} pl {ap.get('prefix_list_refs')}")
    for r in intent_raw.get("required_access", []):
        out.append(f"- required: {r.get('label')} {r.get('source_cidr')} → {r.get('protocol')}/{r.get('from_port')}")
    return "\n".join(out)


def console_summary(run_id: str, status: str, gate: Optional[GateDecision], validity: Optional[ValidityReport],
                    candidate: Optional[PatchCandidate], note: str = "") -> str:
    lines = [f"run {run_id}: {status}"]
    if candidate is not None:
        lines.append(f"  candidate: {candidate.candidate_id} status={candidate.status} origin={candidate.origin} generator={candidate.generator}")
        if candidate.error:
            lines.append(f"  generation error: {candidate.error}")
    if validity is not None:
        for l in validity.layers:
            lines.append(f"  {l.layer} {l.verdict.value:8s} {l.summary[:140]}")
        lines.append(f"  validity: {validity.validity.value} — {validity.summary[:200]}")
    if gate is not None:
        lines.append(f"  gate: {gate.action.value} (risk={gate.risk_level.value if gate.risk_level else '-'}, cap={gate.autonomy_cap.value if gate.autonomy_cap else '-'}, final={gate.final_autonomy.value if gate.final_autonomy else '-'})")
    if note:
        lines.append("  " + note)
    return "\n".join(lines)
