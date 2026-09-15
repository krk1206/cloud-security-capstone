"""검증 결과 연결 — A 가 실행한 V1~V4·V7 결과(파일) 를 받아 계층별 상태로 만든다. 없으면 NOT_RUN(검증 대기).

입력 파일 형식 (docs/IO_SPEC_A_B_C.md 의 "verification-v1"):
    {
      "schema": "iacpatch-verification-v1",
      "source": "누가 어떻게 만든 결과인지 (예: 'A: trivy 재스캔 + terraform validate/plan', 'example-fixture')",
      "candidate_sha256": "<선택> candidate_digest() 값. 있으면 현재 후보와 대조하고, 다르면 결과를 쓰지 않는다",
      "layers": [
        {"layer": "V1", "verdict": "PASS|WARN|FAIL|UNKNOWN|SKIPPED|ERROR|NOT_RUN", "summary": "...", "details": {}, "tool": "...", "executed": true}
      ]
    }
`predeploy` 가 만든 verification.json (`{"phase":..., "layers":[...]}`) 도 같은 layer 객체를 쓰므로 그대로 읽힌다.

여기서 로컬로 **계산할 수 있는** 계층:
    - V5 (plan 구조 비교): 원본 plan JSON + 후보 plan JSON 이 주어지면 verify/layers.v5_plan_diff 로 계산 (terraform 실행 없음)
    - V6 (Intent Oracle):  후보 plan JSON + intent 가 주어지면 verify/v6 로 계산
그 외(V1~V4, V7, V8)는 도구/AWS 가 필요하므로 파일로 받은 결과만 쓴다.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..intent import try_load_intent
from ..models import LayerResult, Verdict
from ..verify.layers import v5_plan_diff
from ..verify.plan_model import PlanParseError, load_plan
from ..verify.v6 import v6_intent_oracle

LAYER_NAMES = {
    "V1": "대상 finding 제거 (Trivy 재스캔)",
    "V2": "새 finding 발생 여부 (Trivy 전후 비교)",
    "V3": "terraform validate",
    "V4": "terraform plan",
    "V5": "plan 구조 비교 (허용 범위)",
    "V6": "Intent Oracle (실효 허용 집합)",
    "V7": "배포 후 실제 AWS 상태",
    "V8": "허용 통신 성공 / 금지 통신 실패",
}
PRE_DEPLOY = ["V1", "V2", "V3", "V4", "V5", "V6"]
POST_DEPLOY = ["V7", "V8"]


class VerificationInputError(ValueError):
    pass


def candidate_digest(files: Dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode("utf-8") + b"\n" + files[name].encode("utf-8") + b"\n")
    return h.hexdigest()


@dataclass
class LinkedVerification:
    layers: List[LayerResult]
    source: str
    notes: List[str] = field(default_factory=list)
    mismatch: bool = False           # 결과 파일의 후보 해시가 현재 후보와 다름 → 결과를 쓰지 않았다
    provided_layers: List[str] = field(default_factory=list)
    computed_layers: List[str] = field(default_factory=list)


def _not_run(layer: str, why: str) -> LayerResult:
    return LayerResult(layer, LAYER_NAMES.get(layer, layer), Verdict.NOT_RUN, f"검증 대기 — {why}", {}, executed=False, tool="")


def load_verification_file(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise VerificationInputError(f"검증 결과 파일이 없다: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise VerificationInputError(f"검증 결과 파일을 읽을 수 없다 ({p}): {e}")
    if not isinstance(data, dict) or not isinstance(data.get("layers"), list):
        raise VerificationInputError(f"검증 결과 형식 오류 (layers 리스트 필요): {p}")
    return data


def _layer_from_obj(obj: Dict[str, Any], source: str) -> LayerResult:
    layer = str(obj.get("layer") or "").upper()
    if layer not in LAYER_NAMES:
        raise VerificationInputError(f"알 수 없는 계층 이름 {obj.get('layer')!r} (V1~V8)")
    try:
        verdict = Verdict(str(obj.get("verdict") or "").upper())
    except ValueError:
        raise VerificationInputError(f"{layer}: 알 수 없는 verdict {obj.get('verdict')!r}")
    details = obj.get("details") if isinstance(obj.get("details"), dict) else {}
    details = dict(details)
    details.setdefault("result_source", source)
    return LayerResult(layer, str(obj.get("name") or LAYER_NAMES[layer]), verdict, str(obj.get("summary") or ""), details,
                       executed=bool(obj.get("executed", verdict not in (Verdict.NOT_RUN, Verdict.SKIPPED))), tool=str(obj.get("tool") or ""))


def link_verification(candidate_files: Dict[str, str], verification_path: Optional[str], baseline_plan: Optional[str],
                      candidate_plan: Optional[str], intent_path: Optional[str], policy: Dict[str, Any],
                      candidate_sources: Optional[Dict[str, str]] = None, phase_layers: Optional[List[str]] = None) -> LinkedVerification:
    wanted = phase_layers or PRE_DEPLOY
    results: Dict[str, LayerResult] = {}
    notes: List[str] = []
    provided: List[str] = []
    computed: List[str] = []
    source = "없음"
    mismatch = False

    if verification_path:
        data = load_verification_file(verification_path)
        source = str(data.get("source") or Path(verification_path).name)
        want_digest = data.get("candidate_sha256")
        if want_digest and want_digest != candidate_digest(candidate_files):
            mismatch = True
            notes.append(f"검증 결과 파일({Path(verification_path).name})의 candidate_sha256 이 현재 후보와 다르다 → 다른 후보에 대한 결과이므로 사용하지 않음")
        else:
            for obj in data["layers"]:
                lr = _layer_from_obj(obj, source)
                results[lr.layer] = lr
                provided.append(lr.layer)
            if not want_digest:
                notes.append("검증 결과 파일에 candidate_sha256 이 없어 이 후보에 대한 결과인지 대조하지 못했다 (A 가 해시를 넣어 주면 자동 대조됨)")

    # 로컬 계산 가능 계층
    if baseline_plan and candidate_plan:
        try:
            bp, cp = load_plan(baseline_plan), load_plan(candidate_plan)
            lr = v5_plan_diff(bp, cp, policy, tool="iacpatch(local, plan json 입력)")
            lr.details["result_source"] = "local:v5_plan_diff"
            if "V5" in results:
                notes.append("V5: 파일로 받은 결과 대신 로컬 계산 결과를 사용 (파일 값은 details.file_result 에 보존)")
                lr.details["file_result"] = results["V5"].to_dict()
            results["V5"] = lr
            computed.append("V5")
        except PlanParseError as e:
            notes.append(f"V5 로컬 계산 실패 (plan JSON 문제): {e}")
    if candidate_plan and intent_path:
        intent, err = try_load_intent(intent_path)
        try:
            cp = load_plan(candidate_plan)
        except PlanParseError as e:
            cp = None
            notes.append(f"V6 로컬 계산 실패 (plan JSON 문제): {e}")
        if cp is not None:
            lr = v6_intent_oracle(cp, candidate_sources or {}, intent, err)
            lr.details["result_source"] = "local:v6_intent_oracle"
            if "V6" in results:
                lr.details["file_result"] = results["V6"].to_dict()
            results["V6"] = lr
            computed.append("V6")

    layers: List[LayerResult] = []
    for name in wanted:
        if name in results:
            layers.append(results[name])
        else:
            why = {"V1": "A 의 Trivy 재스캔 결과 없음", "V2": "A 의 Trivy 전후 비교 결과 없음", "V3": "A 의 terraform validate 결과 없음",
                   "V4": "A 의 terraform plan 결과 없음", "V5": "원본/후보 plan JSON 없음", "V6": "후보 plan JSON 또는 intent 없음",
                   "V7": "배포 후 실측 없음", "V8": "통신 확인 없음"}.get(name, "결과 없음")
            layers.append(_not_run(name, why))
    # 파일에 있지만 이번 phase 에 없는 계층(예: V7)도 보존
    for name, lr in results.items():
        if name not in wanted:
            layers.append(lr)
    return LinkedVerification(layers, source, notes, mismatch, provided, computed)
