"""4주차 — 위험도 기준표(Risk Rubric) 데모 계산. 도구(trivy/terraform)·네트워크 없이 파일만으로 돈다.

세 가지를 만든다 (웹 화면 4주차 탭과 tests/unit/test_rubric_demo.py 가 같은 함수를 쓴다):
  1. rubric_view()        : policy/risk_rubric.json 을 사람이 읽는 표로 (항목·점수·임계값·hard/floor 조건)
  2. calc_risk()          : 목업 입력(바뀐 리소스 수·삭제·IAM·부착 지점 …) → 진짜 score_risk → 점수·등급. 기준표를 눈으로 익히는 계산기
  3. cap_enforcement_check(): 위험도 3등급 × LLM 제안 4종(없음/LOW/MEDIUM/HIGH) × 검증/정책 상태 를 전수로 넣어
                            "최종 자율성 ≤ 상한" 과 "제안은 낮추는 방향으로만" 이 항상 성립하는지 기계로 확인. 위반 0건이어야 한다
  4. labeled_matrix()     : 후보 세트 manifest 의 라벨 25건을 **실제 검토 흐름(run_review)** 으로 다시 돌린다 — 단 도구 없이:
                            V1~V4 는 NOT_RUN, V5/V6/위험도는 커밋된 plan 쌍(tests/fixtures/plan-pairs)으로 계산. expected_risk 와 대조.
  + label_agreement()     : 같은 라벨을 data/reviews 의 (도구로 돌린) 기록과 대조. 기록이 없으면 '미실행'.
                            사람(B) 손 검산 여부는 manifest 의 expected_risk_verified_by 로만 세며, 없으면 0 으로 정직하게 보인다.

여기서 "High 자율성" 은 "안전하다" 가 아니라 "사전에 정한 위험 기준상 상대적으로 자동화 가능한 범위" 다 (docs/RISK_RUBRIC_V2.md).
"""
from __future__ import annotations

import itertools
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    AUTONOMY_ORDER,
    RISK_TO_AUTONOMY_CAP,
    AutonomyLevel,
    GateAction,
    LayerResult,
    PolicyResult,
    RiskDecision,
    RiskLevel,
    Validity,
    ValidityReport,
    Verdict,
)
from .policy.gate import decide
from .policy.risk import score_risk

# 기준표 항목의 한국어 설명 (policy/risk_rubric.json 의 points 키와 1:1). 값(점수)은 JSON 이 원본이고 여기는 설명만.
FACTOR_KO: Dict[str, str] = {
    "resources_touched_2_to_3": "바뀐 리소스가 2~3개",
    "resources_touched_over_3": "바뀐 리소스가 4개 이상",
    "new_resource_created_each": "새 리소스 생성 1개당",
    "new_resource_created_cap": "새 리소스 생성 점수 상한",
    "attachment_points_1": "바뀐 SG 가 붙은 부착 지점(인스턴스/ENI) 1개",
    "attachment_points_2_or_more": "부착 지점 2개 이상 (영향 범위 큼)",
    "attachment_has_external_or_unknown_sg": "같은 부착 지점에 plan 밖 SG 또는 미확정 SG 가 있음",
    "egress_changed": "finding 방향이 아닌 egress 규칙까지 바뀜",
    "replace_forcing_attribute_changed_text_basis": "교체(destroy+create)를 유발하는 속성 변경 의심 (텍스트 근거)",
    "non_resource_block_changed": "resource 가 아닌 블록(variable/locals/data 등) 변경",
    "oracle_partial_rules_or_caveats": "오라클이 일부 규칙을 확정하지 못함 (증거 부족)",
    "patch_lines_over_40": "패치 diff 가 40줄 초과",
    "multiple_files_changed": "여러 파일 변경",
    "outside_target_family_touched": "대상 가족(SG 계열/IAM 계열) 밖의 리소스 타입까지 변경",
    "non_core_attribute_changed": "finding 을 고치는 데 필요 없는 속성 변경",
    # score_risk 가 실제로 내는 요인 이름 (위 점수 키를 합친 것)
    "resources_touched": "바뀐 리소스 수",
    "new_resources_created": "새로 만든 리소스 수",
    "attachment_points": "바뀐 SG 가 붙은 부착 지점 수",
    "patch_lines": "패치 diff 줄 수",
    "files_changed": "바뀐 파일 수",
    "insufficient_basis": "판정 근거 부족 (HCL 구조를 읽지 못함)",
    "undetermined": "텍스트 근거로는 미확정 (plan 필요)",
    "replace_forcing_attribute_changed": "교체 유발 속성 변경 의심",
    "new_resource_blocks": "새 resource 블록 수 (텍스트 근거)",
    "resource_blocks_touched": "바뀐 resource 블록 수 (텍스트 근거)",
    "non_resource_block_changed": "resource 가 아닌 블록 변경",
}
HARD_KO: Dict[str, str] = {
    "iam_resource_touched": "IAM 리소스 변경",
    "iam_trust_policy_changed": "신뢰 정책(assume_role_policy) 변경 또는 새 역할",
    "resource_deleted": "리소스 삭제",
    "resource_replaced": "리소스 교체(destroy+create)",
    "provider_config_changed": "provider 설정 변경",
}
LEVEL_KO = {"LOW": "낮음", "MEDIUM": "중간", "HIGH": "높음"}
ACTION_KO = {
    "CREATE_PR_AUTO": "PR 자동 생성 → 병합 전 경량 확인 (apply 는 사람)",
    "CREATE_PR_APPROVAL": "PR 생성 + 검증 표 첨부 → 사람 승인 필수",
    "REPORT_ONLY": "패치 반영 금지, 분석 리포트만",
    "BLOCK": "차단 (정책 위반 또는 검증 실패)",
    "HOLD_FOR_HUMAN": "보류 — 검증이 다 끝나기 전엔 등급을 정하지 않음",
}

def _root() -> Path:
    from .app import ROOT
    return ROOT


def load_policy_and_rubric(root: Optional[Path] = None) -> tuple:
    root = root or _root()
    policy = json.loads((root / "policy" / "patch_policy.json").read_text(encoding="utf-8"))
    rubric = json.loads((root / "policy" / "risk_rubric.json").read_text(encoding="utf-8"))
    return policy, rubric


# ----------------------------------------------------------------------------- 1. 기준표
def rubric_view(rubric: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if rubric is None:
        _, rubric = load_policy_and_rubric()
    pts = rubric.get("points") or {}
    th = rubric.get("thresholds") or {}
    rows = [{"key": k, "label": FACTOR_KO.get(k, k), "points": v} for k, v in pts.items()]
    hard = [{"key": k, "label": HARD_KO.get(k, k), "on": bool(v)} for k, v in (rubric.get("hard_high_conditions") or {}).items()]
    floor = [{"key": k, "label": HARD_KO.get(k, k), "on": bool(v)} for k, v in (rubric.get("medium_floor_conditions") or {}).items()]
    return {
        "version": rubric.get("rubric_version", ""),
        "thresholds": {"low_max": th.get("low_max"), "medium_max": th.get("medium_max")},
        "points": rows, "hard_high": hard, "medium_floor": floor,
        "autonomy_cap": {k.value: v.value for k, v in RISK_TO_AUTONOMY_CAP.items()},
        "text_basis_undetermined": rubric.get("text_basis_undetermined") or [],
        "notes": [rubric.get("_medium_floor_note", ""), rubric.get("_merge_note", "")],
    }


# ----------------------------------------------------------------------------- 2. 기준표 계산기 (목업 입력 → 점수 → 등급)
class _FakeAP:
    def __init__(self, i: int, external: bool):
        self.address = f"aws_instance.demo{i}"
        self.external_sg_ids = ["sg-external"] if external else []
        self.unknown = False


class _FakeWorld:
    """score_risk 가 부착 지점을 셀 때 쓰는 최소 인터페이스만 흉내 낸 목업 (계산기 전용, 판정 코드는 진짜)."""
    def __init__(self, n_ap: int, external: bool):
        self.security_groups: Dict[str, Any] = {}
        self._aps = [_FakeAP(i, external and i == 0) for i in range(n_ap)]

    def attachments_of(self, sg_addr: str):
        return list(self._aps)


CALC_FIELDS = [
    ("target_kind", "대상 유형", "SG|IAM", "SG"),
    ("changed_attrs", "바뀐 속성 (쉼표)", "text", "ingress"),
    ("resources_touched", "바뀐 리소스 수", "int", 1),
    ("new_resources", "새로 만든 리소스 수", "int", 0),
    ("deleted", "리소스 삭제 있음", "bool", False),
    ("replaced", "리소스 교체(destroy+create) 있음", "bool", False),
    ("trust_policy", "신뢰 정책(assume_role_policy) 변경", "bool", False),
    ("provider_changed", "provider 설정 변경", "bool", False),
    ("attachment_points", "바뀐 SG 가 붙은 부착 지점 수", "int", 0),
    ("external_sg", "부착 지점에 plan 밖 SG 있음", "bool", False),
    ("outside_family", "대상 가족 밖 리소스 타입 변경", "bool", False),
    ("oracle_partial", "오라클이 일부 규칙 미확정", "bool", False),
    ("lines", "diff 줄 수", "int", 2),
    ("files", "바뀐 파일 수", "int", 1),
]


def calc_risk(inputs: Dict[str, Any], rubric: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """목업 입력(체크박스/숫자) → 실제 score_risk. '이 조합이면 몇 점·무슨 등급' 을 눈으로 확인하는 학습용."""
    if rubric is None:
        _, rubric = load_policy_and_rubric()
    g = lambda k, d=None: inputs.get(k, d)
    kind = str(g("target_kind", "SG")).upper()
    target_type = "aws_iam_policy" if kind == "IAM" else "aws_security_group"
    addr = "aws_iam_policy.demo" if kind == "IAM" else "aws_security_group.demo"
    attrs = [a.strip() for a in str(g("changed_attrs", "ingress" if kind == "SG" else "policy")).split(",") if a.strip()]
    n_touched = max(int(g("resources_touched", 1) or 1), 1)
    changed = {addr: attrs}
    for i in range(1, n_touched):
        extra_type = "aws_instance" if g("outside_family") else ("aws_security_group_rule" if kind == "SG" else "aws_iam_role_policy")
        changed[f"{extra_type}.extra{i}"] = ["description"] if extra_type != "aws_instance" else ["tags"]
    added = [{"address": f"aws_security_group_rule.new{i}", "type": "aws_security_group_rule"} for i in range(int(g("new_resources", 0) or 0))]
    if g("trust_policy"):
        changed["aws_iam_role.demo"] = ["assume_role_policy"]
    details = {"removed": ["aws_security_group.gone"] if g("deleted") else [], "added": added, "changed": changed,
               "plan_actions_delete": [], "plan_actions_replace": [addr] if g("replaced") else [],
               "provider_config_diff": ["region"] if g("provider_changed") else []}
    world = _FakeWorld(int(g("attachment_points", 0) or 0), bool(g("external_sg"))) if kind == "SG" else None
    v6 = {"targets": [{"scopes": [{"services": [{"partial_rules": True}], "caveats": []}]}]} if g("oracle_partial") else None
    stats = {"added_lines": int(g("lines", 2) or 0), "removed_lines": 0, "files": int(g("files", 1) or 1)}
    r = score_risk(rubric, details, world, stats, v6, target_type=target_type)
    return {"level": r.risk_level.value, "cap": r.autonomy_cap.value, "score": r.score,
            "factors": [{"factor": f["factor"], "label": FACTOR_KO.get(f["factor"], HARD_KO.get(f["factor"], f["factor"])), "value": f.get("value"),
                         "points": f.get("points", 0), "note": f.get("note", "")} for f in r.factors],
            "thresholds": rubric.get("thresholds"), "inputs": inputs}


# ----------------------------------------------------------------------------- 3. 상한 강제 전수 검사
def _validity(v: str) -> ValidityReport:
    verdict = {"PASS": Verdict.PASS, "FAIL": Verdict.FAIL, "INCOMPLETE": Verdict.NOT_RUN}[v]
    return ValidityReport("pre_deploy", [LayerResult("V6", "intent oracle", verdict, "demo")], Validity(v), f"demo {v}")


def gate_demo(risk_level: str, proposal: Optional[str], validity: str = "PASS", policy_ok: bool = True,
              score: int = 0) -> Dict[str, Any]:
    """게이트 한 번: 위험도(코드가 정함) + LLM 제안(있으면) → 최종 자율성·동작. 이유는 코드가 내는 문장 그대로."""
    rl = RiskLevel(risk_level)
    risk = RiskDecision(rl, RISK_TO_AUTONOMY_CAP[rl], score, [], "demo")
    pol = PolicyResult(policy_ok, [] if policy_ok else ["demo policy violation"], [], "demo")
    g = decide(_validity(validity), pol, risk, proposal)
    return {
        "risk_level": rl.value, "cap": risk.autonomy_cap.value, "proposal": proposal,
        "final": g.final_autonomy.value if g.final_autonomy else None, "action": g.action.value,
        "action_ko": ACTION_KO.get(g.action.value, g.action.value), "reasons": g.reasons,
        "validity": validity, "policy_ok": policy_ok,
        "forced_down": bool(proposal and g.final_autonomy and AUTONOMY_ORDER.get(AutonomyLevel(proposal), 99) > AUTONOMY_ORDER[g.final_autonomy]),
    }


def cap_enforcement_check() -> Dict[str, Any]:
    """전수: 위험도 3 × 제안 4 × 검증 3 × 정책 2 = 72 조합. 불변식 위반이 있으면 목록으로 (0 이어야 한다)."""
    rows: List[Dict[str, Any]] = []
    violations: List[str] = []
    for rl, prop, val, pol in itertools.product(["LOW", "MEDIUM", "HIGH"], [None, "LOW", "MEDIUM", "HIGH"], ["PASS", "FAIL", "INCOMPLETE"], [True, False]):
        r = gate_demo(rl, prop, val, pol)
        rows.append(r)
        cap = AutonomyLevel(r["cap"])
        if not pol:
            if r["action"] != GateAction.BLOCK.value:
                violations.append(f"정책 위반인데 차단이 아님: {r}")
            continue
        if val == "FAIL":
            if r["action"] != GateAction.BLOCK.value:
                violations.append(f"검증 실패인데 차단이 아님: {r}")
            continue
        if val == "INCOMPLETE":
            if r["action"] != GateAction.HOLD_FOR_HUMAN.value or r["final"] is not None:
                violations.append(f"검증 미완인데 보류가 아님: {r}")
            continue
        final = AutonomyLevel(r["final"])
        if AUTONOMY_ORDER[final] > AUTONOMY_ORDER[cap]:
            violations.append(f"최종 자율성이 상한을 넘음: {r}")
        expect = cap if prop is None else min(cap, AutonomyLevel(prop), key=lambda a: AUTONOMY_ORDER[a])
        if final != expect:
            violations.append(f"최종 자율성 ≠ min(상한, 제안): {r}")
    return {"total": len(rows), "violations": violations, "rows": rows,
            "invariants": ["정책 위반 → 항상 BLOCK (등급 무관)", "검증 FAIL → 항상 BLOCK (등급 무관)", "검증 미완(NOT_RUN/UNKNOWN 남음) → 항상 보류, 최종 등급 없음",
                           "검증 PASS → 최종 자율성 = min(위험도 상한, LLM 제안). 제안이 상한보다 높으면 무시하고 기록"]}


# ----------------------------------------------------------------------------- 4. 라벨 일치 (기록 기반)
def label_agreement(root: Optional[Path] = None) -> Dict[str, Any]:
    """manifest 의 expected_risk vs data/reviews 최신 기록의 코드 판정. 기록이 없으면 '미실행'. 사람 검산 수는 verified_by 가 있는 항목만."""
    root = root or _root()
    sets_dir = root / "experiments" / "candidate-sets"
    reviews = root / "data" / "reviews"
    latest: Dict[str, Path] = {}
    if reviews.is_dir():
        for d in sorted(reviews.iterdir()):
            st = d / "state.json"
            if not st.exists():
                continue
            try:
                s = json.loads(st.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if s.get("state") == "INPUT_ERROR":
                continue
            latest[str(s.get("scenario"))] = d
    rows: List[Dict[str, Any]] = []
    for m in sorted(sets_dir.glob("*/manifest.json")):
        try:
            man = json.loads(m.read_text(encoding="utf-8"))
        except ValueError:
            continue
        set_id = man.get("set_id") or m.parent.name
        if man.get("week4_label_replay") is False:     # 4주차 라벨 표(25건, 2026-09-22 고정) 밖의 세트 — 자기 results.md 에서 도구 있는 실행으로 잰다
            continue
        for c in man.get("candidates") or []:
            exp = c.get("expected_risk")
            if not exp:
                continue
            scen = f"{set_id}/{c.get('id')}"
            rec = latest.get(scen)
            actual = None; score = None
            if rec and (rec / "risk.json").exists():
                try:
                    rj = json.loads((rec / "risk.json").read_text(encoding="utf-8"))
                    dec = rj.get("decision") or {}
                    actual = dec.get("risk_level"); score = dec.get("score")
                except ValueError:
                    pass
            rows.append({"scenario": scen, "expected": exp, "basis": c.get("expected_risk_basis", ""), "actual": actual, "score": score,
                         "agree": (actual == exp) if actual else None, "verified_by": c.get("expected_risk_verified_by", ""),
                         "record": rec.name if rec else None})
    total = len(rows)
    judged = [r for r in rows if r["actual"]]
    agree = sum(1 for r in judged if r["agree"])
    verified = sum(1 for r in rows if r["verified_by"])
    return {"rows": rows, "total": total, "judged": len(judged), "agree": agree, "human_verified": verified,
            "note": "expected_risk 는 기준표를 코드와 별도로 읽고 적은 값 (작성: B 의 Claude 세션, 2026-09-22). 사람 검산은 manifest 에 expected_risk_verified_by 를 적은 항목만 센다."}



def _compact_factors(factors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """화면용 요약: 점수가 있는 요인 + hard/floor 조건 + 미확정 표시 1줄. 텍스트/plan 두 경로가 합쳐져 생긴 중복은 제거."""
    out: List[Dict[str, Any]] = []
    seen = set()
    undetermined = False
    for f in factors:
        name = str(f.get("factor"))
        note = str(f.get("note", ""))
        pts = int(f.get("points", 0) or 0)
        if name == "undetermined":
            undetermined = True
            continue
        if not pts and not ("hard" in note or "floor" in note):
            continue
        key = (name, pts, "hard" in note, "floor" in note)
        if key in seen:
            continue
        seen.add(key)
        short = "무조건 HIGH" if "hard" in note else ("최소 MEDIUM" if "floor" in note else "")
        out.append({"factor": name, "label": FACTOR_KO.get(name, HARD_KO.get(name, name)), "points": pts, "note": short})
    if undetermined:
        out.append({"factor": "undetermined", "label": FACTOR_KO["undetermined"], "points": 0, "note": "텍스트 근거"})
    return out

# ----------------------------------------------------------------------------- 5. 라벨 25건을 실제 흐름으로 (도구 없이)
def _resolve(p: Optional[str], set_dir: Path) -> Optional[str]:
    if not p or Path(p).is_absolute():
        return p
    return str(set_dir / p) if (set_dir / p).exists() else p


def labeled_matrix(root: Optional[Path] = None, out_dir: Optional[Path] = None) -> Dict[str, Any]:
    """manifest 의 expected_risk 가 있는 후보마다 run_review 를 도구 없이 실행 (plan 쌍은 fixtures). 기록은 임시 폴더에."""
    from .config import load_settings
    from .review.flow import ReviewOptions, run_review
    root = root or _root()
    settings = load_settings(str(root))
    pairs = root / "tests" / "fixtures" / "plan-pairs"
    tmp = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix="iacpatch-rubric-"))
    rows: List[Dict[str, Any]] = []
    for m in sorted((root / "experiments" / "candidate-sets").glob("*/manifest.json")):
        man = json.loads(m.read_text(encoding="utf-8"))
        set_dir = m.parent
        set_id = man.get("set_id") or set_dir.name
        if man.get("week4_label_replay") is False:     # plan 쌍 fixture 가 없는 새 세트(아키텍처 등)는 4주차 25건 재계산에 넣지 않는다
            continue

        def pick(c, key, default=None):
            return c[key] if key in c else man.get(key, default)

        for c in man.get("candidates") or []:
            exp = c.get("expected_risk")
            if not exp:
                continue
            cid = c["id"]
            scenario = f"{set_id}/{cid}"
            cand = c["candidate"]
            if cand.startswith("manual:"):
                cand = "manual:" + str(_resolve(cand[7:], set_dir))
            pair = pairs / set_id / cid
            bp = str(pair / "plan_baseline.json") if (pair / "plan_baseline.json").exists() else None
            cp = str(pair / "plan_candidate.json") if (pair / "plan_candidate.json").exists() else None
            opt = ReviewOptions(tf_dir=pick(c, "tf_dir"), trivy_json=_resolve(pick(c, "trivy_json"), set_dir), candidate=cand, scenario=scenario,
                                rule=pick(c, "rule", "AVD-AWS-0107"), filename=pick(c, "file"), resource=pick(c, "resource"), line=pick(c, "line"),
                                candidate_note=c.get("note", ""), verification=None, baseline_plan=bp, candidate_plan=cp,
                                intent=_resolve(pick(c, "intent"), set_dir), out_dir=str(tmp), local_tools=False)
            try:
                res = run_review(settings, opt)
            except Exception as e:  # 한 건이 깨져도 표는 나온다
                rows.append({"scenario": scenario, "expected": exp, "basis": c.get("expected_risk_basis", ""), "error": f"{type(e).__name__}: {e}"})
                continue
            risk = res.risk
            layers = {l.layer: l.verdict.value for l in (res.validity.layers if res.validity else [])}
            rows.append({
                "scenario": scenario, "expected": exp, "basis": c.get("expected_risk_basis", ""),
                "actual": risk.risk_level.value if risk else None, "cap": risk.autonomy_cap.value if risk else None,
                "score": risk.score if risk else None,
                "factors": _compact_factors(risk.factors if risk else []),
                "agree": (risk.risk_level.value == exp) if risk else None,
                "state": res.state.value, "level": res.level.value if res.level else None,
                "basis_kind": "plan+텍스트" if (bp and cp and res.state.value != "POLICY_BLOCKED") else "텍스트만(정책 차단)" if res.state.value == "POLICY_BLOCKED" else "텍스트만(plan 쌍 없음)",
                "v5": layers.get("V5", "-"), "v6": layers.get("V6", "-"),
                "verified_by": c.get("expected_risk_verified_by", ""),
            })
    judged = [r for r in rows if r.get("actual")]
    agree = sum(1 for r in judged if r["agree"])
    dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for r in judged:
        dist[r["actual"]] += 1
    return {"rows": rows, "total": len(rows), "judged": len(judged), "agree": agree, "distribution": dist,
            "human_verified": sum(1 for r in rows if r.get("verified_by")), "tmp_dir": str(tmp),
            "note": "V1~V4 는 도구가 없어 NOT_RUN(검토 수준은 PENDING). 위험도는 실제 흐름과 같은 코드(V5·V6·기준표)로 계산했다. "
                    "expected_risk 는 B 의 Claude 세션이 기준표를 읽고 적은 값 — 사람 검산 수는 expected_risk_verified_by 가 있는 항목만 센다."}
