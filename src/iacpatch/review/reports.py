"""C 3주차 — 로컬 검토 리포트(review.md)와 PR 본문 초안(pr_body.md). 템플릿 + 입력 데이터만으로 만든다.

이 문서들은 "입력과 확인된 결과를 정리한 리포트" 다. 모델의 분석 결과가 아니며, 그렇게 부르지 않는다.
검증 결과가 없는 단계는 '미검증' 으로 눈에 띄게 표시한다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models import Finding, PatchCandidate, PolicyResult, ReviewLevel, RiskDecision, ValidityReport, Verdict

_ICON = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "UNKNOWN": "❓", "SKIPPED": "⏭️", "ERROR": "💥", "NOT_RUN": "⏳"}
_KO = {"PASS": "통과", "WARN": "통과(경고)", "FAIL": "실패", "UNKNOWN": "판정 불가", "SKIPPED": "미실행(도구 없음)", "ERROR": "오류", "NOT_RUN": "미검증"}
_LEVEL_KO = {
    ReviewLevel.PENDING: "미검증 — 검토 수준 결정 불가",
    ReviewLevel.LIGHT_REVIEW: "경량 검토 — 사람 1인 확인 후 진행 (자동 반영 아님)",
    ReviewLevel.FULL_REVIEW: "정식 검토 — 승인자가 diff·검증·위험도 근거 검토 후 판단",
    ReviewLevel.REPORT_ONLY: "리포트만 — 패치 반영 금지",
    ReviewLevel.BLOCKED: "차단 — 후보 폐기",
}
_ORIGIN_KO = {"mock": "mock fixture (사전 작성한 고정 응답 — LLM 출력 아님)", "manual": "수동 입력 (사람이 준비한 파일 — 프로그램 생성 아님)",
              "rule_based": "규칙 기반 생성기 (리터럴 CIDR 치환 코드 — LLM 아님, 비교 실험의 기준선)", "llm": "LLM 응답", "seeded": "seeded 예제"}


def _v(lr) -> str:
    return f"{_ICON.get(lr.verdict.value, '')} {_KO.get(lr.verdict.value, lr.verdict.value)}"


def _pending_banner(validity: ValidityReport) -> List[str]:
    pending = [l.layer for l in validity.layers if l.verdict in (Verdict.NOT_RUN, Verdict.SKIPPED, Verdict.UNKNOWN, Verdict.ERROR)]
    fails = [l.layer for l in validity.layers if l.verdict == Verdict.FAIL]
    if fails:
        return [f"> ❌ **검증 실패: {', '.join(fails)}** — 반영 불가 후보.", ""]
    if pending:
        return [f"> ⏳ **미검증: {', '.join(pending)}** — 검증 결과가 없는 단계 존재. 리포트 생성은 패치 검증 완료를 의미하지 **않음**.", ""]
    return ["> ✅ 필수 검증 단계 결과 확보 (결과 출처는 아래 표 참조). 최종 판단은 사람이 수행.", ""]


def layer_table(validity: ValidityReport) -> List[str]:
    rows = ["| 단계 | 내용 | 상태 | 요약 | 결과 출처 |", "|---|---|---|---|---|"]
    for l in validity.layers:
        src = str(l.details.get("result_source", "") or ("-" if l.verdict == Verdict.NOT_RUN else ""))
        summ = (l.summary or "").replace("|", "\\|").replace("\n", " ")
        if len(summ) > 200:
            summ = summ[:197] + "…"
        rows.append(f"| {l.layer} | {l.name} | {_v(l)} | {summ} | {src} |")
    return rows


def _risk_rows(risk: Optional[RiskDecision]) -> List[str]:
    if risk is None:
        return ["_(위험도 판정 없음)_"]
    rows = [f"- 위험도: **{risk.risk_level.value}** (점수 {risk.score}) — 기준표: {risk.rubric_version}",
            "- 위험도는 변경 실패 시 영향 범위의 척도이며 검증 통과 여부와 별개. 위험도 LOW 가 자동 반영을 의미하지 않음.", "",
            "| 항목 | 값 | 점수 | 근거 종류 | 비고 |", "|---|---|---|---|---|"]
    for f in risk.factors:
        rows.append(f"| {f.get('factor')} | {str(f.get('value'))[:110]} | {f.get('points')} | {f.get('basis', '')} | {f.get('note', '')} |")
    return rows


def render_review(ctx: Dict[str, Any]) -> str:
    """ctx 키: scenario, run_id, state, finding(Finding), other_findings(list), candidate(PatchCandidate), policy(PolicyResult|None),
    validity(ValidityReport), risk(RiskDecision|None), level(ReviewLevel), level_reasons, diff_path, files_changed, source_check(dict),
    verification_notes(list), tool_versions(dict), unknowns(list), human_checks(list)"""
    f: Finding = ctx["finding"]
    c: PatchCandidate = ctx["candidate"]
    validity: ValidityReport = ctx["validity"]
    L: List[str] = []
    L.append(f"# 로컬 검토 리포트 — {ctx.get('display') or ctx['scenario']} ({ctx['run_id']})")
    L.append("")
    L.append("_이 문서는 입력(Trivy 결과·원본·수정 후보)과 확인된 검증 결과를 템플릿으로 정리한 것이다. 모델이 분석한 결과가 아니다._")
    L.append("")
    L.extend(_pending_banner(validity))
    L.append(f"- 상태: **{ctx['state']}**  |  검토 수준: **{ctx['level'].value}** — {_LEVEL_KO[ctx['level']]}")
    for r in ctx.get("level_reasons", []):
        L.append(f"  - {r}")
    L.append("")
    L.append("## 1. 수정 대상과 이유")
    L.append("")
    L.append(f"- 대상 finding: `{f.rule_id}` ({f.severity}) — {f.title}")
    L.append(f"- 위치: `{f.filename}:{f.start_line}` 리소스 `{f.resource}`")
    L.append(f"- Trivy 메시지: {f.message}")
    if f.resolution:
        L.append(f"- Trivy 권고: {f.resolution}")
    others = ctx.get("other_findings") or []
    if others:
        L.append(f"- 같은 디렉터리의 다른 finding (이번 대상 아님): " + ", ".join(f"`{o.rule_id}`@{o.resource}:{o.start_line}" for o in others))
    L.append(f"- 수정 이유(후보 작성자 기재): {c.rationale.strip() if c.rationale.strip() else '_미기재_'}")
    if c.assumptions:
        L.append("- 후보 작성자의 가정: " + "; ".join(c.assumptions))
    L.append("")
    L.append("## 2. 변경 요약과 diff 위치")
    L.append("")
    L.append(f"- 변경 파일: {', '.join('`' + x + '`' for x in ctx.get('files_changed', [])) or '_(없음)_'}")
    L.append(f"- diff: `{ctx['diff_path']}`  (원본 사본 `original/`, 후보 `candidate/`)")
    hc = ctx.get("hcl_change") or {}
    if hc:
        L.append(f"- 리소스 블록 변경(텍스트 근거): 변경 {hc.get('changed_resources')} / 추가 {hc.get('added_resources')} / 삭제 의심 {hc.get('removed_resources')} / 타입 변경 {hc.get('type_changed')} / 리소스 밖 블록 {hc.get('non_resource_blocks_changed')}")
    L.append("")
    L.append("## 3. 후보 출처")
    L.append("")
    L.append(f"- origin: **{c.origin}** — {_ORIGIN_KO.get(c.origin, c.origin)}")
    L.append(f"- generator: `{c.generator}`  |  후보 ID: `{c.candidate_id}`")
    L.append(f"- 출처 설명(사람 기재): {c.provenance or '_없음_'}")
    if c.needs_info:
        L.append("- ⚠️ 검토 전 채워야 할 정보: " + "; ".join(c.needs_info))
    L.append("")
    L.append("## 4. 검증별 상태")
    L.append("")
    L.extend(layer_table(validity))
    L.append("")
    L.append(f"- 종합: **{validity.validity.value}** — {validity.summary}")
    for n in ctx.get("verification_notes", []):
        L.append(f"- {n}")
    L.append("")
    L.append("## 5. 위험도와 판정 근거 (잠정 기준표)")
    L.append("")
    L.extend(_risk_rows(ctx.get("risk")))
    L.append("")
    L.append("## 6. 사람이 확인할 항목")
    L.append("")
    for i, item in enumerate(ctx.get("human_checks", []), 1):
        L.append(f"{i}. [ ] {item}")
    L.append("")
    L.append("## 7. 미확인 사항")
    L.append("")
    for u in ctx.get("unknowns", []):
        L.append(f"- {u}")
    if not ctx.get("unknowns"):
        L.append("- (없음)")
    L.append("")
    L.append("## 부록. 입력 정합 확인")
    L.append("")
    sc = ctx.get("source_check") or {}
    L.append(f"- 방법: {sc.get('method', '-')}  |  결과: {'일치' if sc.get('ok') else '불일치/미확인'}  |  확인한 원인 줄 수: {sc.get('cause_lines_checked', 0)}")
    for n in sc.get("notes", []):
        L.append(f"- {n}")
    for m in sc.get("mismatches", []):
        L.append(f"- 줄 {m['line']}: 스캔 `{m['scan_content']}` vs 파일 `{m['file_content']}`")
    tv = ctx.get("tool_versions") or {}
    if tv:
        L.append("- 도구: " + ", ".join(f"{k} {v}" for k, v in tv.items()))
    return "\n".join(L) + "\n"


def render_pr_body(ctx: Dict[str, Any], diff_text: str) -> str:
    f: Finding = ctx["finding"]
    c: PatchCandidate = ctx["candidate"]
    validity: ValidityReport = ctx["validity"]
    risk: Optional[RiskDecision] = ctx.get("risk")
    L: List[str] = []
    L.append(f"## [초안] {f.rule_id} 수정 — `{f.resource}` ({ctx.get('display') or ctx['scenario']})")
    L.append("")
    L.append("> 로컬에서 생성한 PR 초안. PR 게시·병합·terraform apply 는 사람이 수행.")
    L.append("")
    L.extend(_pending_banner(validity))
    L.append(f"- 검토 수준: **{ctx['level'].value}** — {_LEVEL_KO[ctx['level']]}")
    L.append(f"- 위험도: **{risk.risk_level.value if risk else '-'}**" + (f" (점수 {risk.score}, 기준표 {risk.rubric_version})" if risk else ""))
    L.append(f"- 후보 출처: **{c.origin}** — {_ORIGIN_KO.get(c.origin, c.origin)}" + (f"; {c.provenance}" if c.provenance else ""))
    L.append("")
    L.append("### 수정 대상")
    L.append("")
    L.append(f"- `{f.filename}:{f.start_line}` `{f.resource}` — {f.title} ({f.severity})")
    L.append(f"- 수정 근거: {c.rationale.strip() or '_미기재 — 사람이 작성 필요_'}")
    L.append("")
    L.append("### 검증 결과")
    L.append("")
    L.extend(layer_table(validity))
    L.append("")
    L.append("### 변경 내용")
    L.append("")
    L.append("```diff")
    L.append(diff_text.rstrip())
    L.append("```")
    L.append("")
    L.append("### 승인 전 확인 항목 (사람)")
    L.append("")
    for item in ctx.get("human_checks", []):
        L.append(f"- [ ] {item}")
    L.append("")
    L.append(f"_run: {ctx['run_id']} · 상태: {ctx['state']}_")
    return "\n".join(L) + "\n"
