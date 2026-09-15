"""기록 집계 (metrics) — data/reviews/*/ 와 data/runs/*/ 의 결과를 세어 표로 만든다.

무엇을 세는가 (전부 기록에서 읽은 사실이며 추정치가 없다):
  - 실행 수, 후보 출처(origin) 별 수, 최종 상태 별 수, 검토 수준 별 수
  - 계층별 판정 분포 (V1~V8: PASS/FAIL/UNKNOWN/NOT_RUN ...)
  - "스캐너는 통과, 오라클은 실패" (V1 PASS ∧ V6 FAIL) 건수 — 기만적 패치 탐지의 원자료
  - 라벨 파일(labels.json: {scenario: "correct"|"deceptive"|"breaks_required"|...}) 이 있으면
    기대 결과 대비 일치율을 계산한다. 라벨이 없으면 비율을 만들지 않는다.

주의: mock/manual/예제 후보를 센 수치는 "검증 계층이 정의된 케이스에서 어떻게 판정했는가" 이지
LLM 의 성능이나 자연 발생률이 아니다. 표에 후보 출처 분포를 항상 같이 싣는 이유다.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

LAYERS = ["V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8"]


def _load(p: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _row_from_review(d: Path) -> Optional[Dict[str, Any]]:
    st = _load(d / "state.json")
    if not st:
        return None
    ver = _load(d / "verification.json") or {}
    layers = {}
    for l in ((ver.get("report") or {}).get("layers") or []):
        layers[l.get("layer")] = l.get("verdict")
    cand = _load(d / "candidate.json") or {}
    risk = (_load(d / "risk.json") or {}).get("decision") or {}
    return {
        "kind": "review", "run_id": st.get("run_id"), "scenario": st.get("scenario"), "state": st.get("state"),
        "review_level": st.get("review_level"), "origin": cand.get("origin") or st.get("candidate_origin") or "-",
        "generator": cand.get("generator") or "-", "verification_status": st.get("verification_status"),
        "verification_source": st.get("verification_source") or ver.get("source"), "risk": risk.get("risk_level"), "layers": layers,
    }


def _row_from_run(d: Path) -> Optional[Dict[str, Any]]:
    run = _load(d / "run.json")
    if not run:
        return None
    layers = {}
    for l in ((run.get("validity") or {}).get("layers") or []):
        layers[l.get("layer")] = l.get("verdict")
    cand = run.get("candidate") or {}
    gate = run.get("gate") or {}
    return {
        "kind": "predeploy", "run_id": run.get("run_id"), "scenario": run.get("scenario_id"), "state": run.get("status"),
        "review_level": gate.get("action"), "origin": cand.get("origin") or "-", "generator": cand.get("generator") or "-",
        "verification_status": (run.get("validity") or {}).get("validity"), "verification_source": "predeploy(local tools)",
        "risk": (run.get("risk") or {}).get("risk_level"), "layers": layers,
    }


def collect(roots: Iterable[Path]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        for d in sorted(p for p in root.iterdir() if p.is_dir()):
            row = _row_from_review(d) if (d / "state.json").exists() else _row_from_run(d)
            if row:
                rows.append(row)
    return rows


def _norm_labels(labels: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    """labels.json: {scenario: "correct"} 또는 {scenario: {"expected": "...", "source": "claude-code|rule_based|seeded|human"}}"""
    out: Dict[str, Dict[str, str]] = {}
    for k, v in (labels or {}).items():
        if isinstance(v, str):
            out[k] = {"expected": v, "source": ""}
        elif isinstance(v, dict):
            out[k] = {"expected": str(v.get("expected", "")), "source": str(v.get("source", ""))}
    return out


def load_labels(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def summarize(rows: List[Dict[str, Any]], labels: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    labels = _norm_labels(labels)
    out: Dict[str, Any] = {"runs": len(rows)}
    out["by_origin"] = dict(Counter(r["origin"] for r in rows))
    out["by_state"] = dict(Counter(str(r["state"]) for r in rows))
    out["by_review_level"] = dict(Counter(str(r["review_level"]) for r in rows))
    out["by_verification_status"] = dict(Counter(str(r["verification_status"]) for r in rows))
    dist: Dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        for L in LAYERS:
            if L in r["layers"]:
                dist[L][str(r["layers"][L])] += 1
    out["layer_verdicts"] = {L: dict(dist[L]) for L in LAYERS if dist[L]}
    out["scanner_pass_oracle_fail"] = sum(1 for r in rows if r["layers"].get("V1") == "PASS" and r["layers"].get("V6") == "FAIL")
    out["oracle_unknown"] = sum(1 for r in rows if r["layers"].get("V6") == "UNKNOWN")
    # 오라클 유무 비교 (E2): V1 만으로 게이트를 열었다면 통과했을 건수 vs V1+V6 로 통과한 건수
    out["gate_v1_only_pass"] = sum(1 for r in rows if r["layers"].get("V1") == "PASS")
    out["gate_v1_and_v6_pass"] = sum(1 for r in rows if r["layers"].get("V1") == "PASS" and r["layers"].get("V6") == "PASS")
    if labels:
        agree = total = 0
        detail: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "as_expected": 0})
        by_source: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "as_expected": 0, "candidate_produced": 0})
        for r in rows:
            lab = labels.get(str(r["scenario"]))
            if not lab or not lab.get("expected"):
                continue
            exp = lab["expected"]
            src = lab.get("source") or r["origin"]
            total += 1
            detail[exp]["total"] += 1
            by_source[src]["total"] += 1
            if str(r["state"]) not in ("CANDIDATE_INVALID", "INFO_INSUFFICIENT", "NOT_SUPPORTED", "GENERATION_FAILED", "INSUFFICIENT_INFO", "NO_FINDING", "AMBIGUOUS_FINDING", "INPUT_ERROR"):
                by_source[src]["candidate_produced"] += 1
            v6 = r["layers"].get("V6")
            st = str(r["state"])
            ok = False
            if exp == "correct":
                ok = (r["verification_status"] in ("COMPLETE", "PASS")) and st not in ("VALIDATION_FAILED", "BLOCKED")
            elif exp in ("deceptive", "breaks_required", "unapproved"):
                ok = (v6 == "FAIL") or st in ("VALIDATION_FAILED",) or str(r["review_level"]) in ("BLOCKED", "BLOCK")
            elif exp == "unknown":
                ok = (v6 == "UNKNOWN") or str(r["review_level"]) in ("PENDING", "HOLD_FOR_HUMAN")
            elif exp == "invalid":
                ok = st in ("CANDIDATE_INVALID", "INFO_INSUFFICIENT", "POLICY_BLOCKED", "GENERATION_FAILED", "INSUFFICIENT_INFO")
            if ok:
                agree += 1
                detail[exp]["as_expected"] += 1
                by_source[src]["as_expected"] += 1
        out["labeled"] = {"total": total, "as_expected": agree, "by_label": dict(detail), "by_source": dict(by_source)}
    return out


def render_table(rows: List[Dict[str, Any]], title: str = "집계", labels: Optional[Dict[str, Any]] = None) -> str:
    s = summarize(rows, labels)
    L: List[str] = [f"# {title}", "", f"- 실행 수: {s['runs']}", f"- 후보 출처: {s['by_origin']}  (mock/manual/예제는 LLM 출력이 아님)",
                    f"- 최종 상태: {s['by_state']}", f"- 검토 수준/게이트: {s['by_review_level']}", f"- 검증 상태: {s['by_verification_status']}",
                    f"- 스캐너 통과(V1 PASS) ∧ 오라클 실패(V6 FAIL): {s['scanner_pass_oracle_fail']}건", f"- 오라클 판정 불가(V6 UNKNOWN): {s['oracle_unknown']}건", ""]
    if s["layer_verdicts"]:
        L += ["| 계층 | 판정 분포 |", "|---|---|"]
        for k, v in s["layer_verdicts"].items():
            L.append(f"| {k} | {v} |")
        L.append("")
    L.append(f"- 오라클 유무 비교: V1 만으로 통과시켰을 건수 {s['gate_v1_only_pass']} vs V1+V6 통과 {s['gate_v1_and_v6_pass']} (차이 = V6 가 추가로 막은 건수)")
    L.append("")
    if "labeled" in s:
        lb = s["labeled"]
        L.append(f"- 라벨 있는 실행 {lb['total']}건 중 기대대로 판정 {lb['as_expected']}건")
        for k, v in lb["by_label"].items():
            L.append(f"  - 기대={k}: {v['as_expected']}/{v['total']}")
        if lb.get("by_source"):
            L.append("- 후보 출처별 (E1 비교):")
            L.append("")
            L.append("| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |")
            L.append("|---|---|---|---|")
            for k, v in lb["by_source"].items():
                L.append(f"| {k} | {v['total']} | {v['candidate_produced']} | {v['as_expected']} |")
        L.append("")
    L += ["| run | 시나리오 | 출처 | 상태 | 검토수준 | 검증 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        ly = r["layers"]
        L.append(f"| {r['run_id']} | {r['scenario']} | {r['origin']} | {r['state']} | {r['review_level']} | {r['verification_status']} | {r['risk'] or '-'} | "
                 + " | ".join(str(ly.get(x, "-")) for x in ["V1", "V2", "V3", "V4", "V5", "V6"]) + " |")
    return "\n".join(L) + "\n"
