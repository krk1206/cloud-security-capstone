"""B 3주차 — 수정 후보 입력 (mock / manual) 을 같은 내부 형식(PatchCandidate)으로.

후보 출처 지정 문자열:
    mock:<fixture>      tests/fixtures/mock_llm/<fixture>.json (사람이 미리 만든 고정 응답). origin="mock"
    manual:<path>       사람이 준비한 파일. origin="manual"
                          - *.json : LLM 응답 계약과 같은 형식 {"status","files":[{"path","content"}],"rationale",...}
                          - *.tf   : 대상 finding 이 가리키는 파일의 **전체 내용**으로 사용 (파일 하나만 바꾸는 경우)
                          - 디렉터리: 안의 *.tf 를 같은 이름의 원본 파일 대체본으로 사용

둘 다 "프로그램이 자동 생성한 결과"가 아니다. 리포트에는 origin 과 provenance(사람이 적은 출처 설명)를 그대로 싣는다.
LLM API 호출 코드는 여기 없다. 나중에 실제 공급자가 생기면 같은 PatchCandidate 를 돌려주는 함수를 하나 더 붙이면 된다
(generator/llm_generator.py 의 인터페이스 참고).

후보 검사 (validate_candidate_shape):
    - 파일 없음/읽기 불가/JSON 오류/스키마 위반 → CANDIDATE_INVALID
    - status 가 INSUFFICIENT_INFO / ABSTAIN → INFO_INSUFFICIENT (후보 없음이 정상 결과)
    - 파일 목록 비어 있음, 내용 전부 빈 문자열 → CANDIDATE_INVALID("빈 후보")
    - 모든 파일이 원본과 동일 → CANDIDATE_INVALID("원본과 동일")
    - 원본에 없는 파일명 → CANDIDATE_INVALID (새 파일은 정책상 허용하지 않음. Policy Validator 도 막는다)
    - 수정 이유(rationale) 없음 → needs_info 에 기록 (검토 전 사람이 채움). 흐름은 계속
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..generator.base import GenerationError, LLMResponse, parse_llm_output
from ..models import Finding, PatchCandidate

MOCK_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "mock_llm"


class CandidateSourceError(ValueError):
    pass


@dataclass
class CandidateSpec:
    kind: str            # "mock" | "manual"
    ref: str             # fixture 이름 또는 경로
    note: str = ""       # --candidate-note (사람이 적는 출처 설명)

    @classmethod
    def parse(cls, spec: str, note: str = "") -> "CandidateSpec":
        if ":" not in spec:
            raise CandidateSourceError("후보 지정 형식은 mock:<fixture> 또는 manual:<path> 이다")
        kind, ref = spec.split(":", 1)
        kind = kind.strip().lower()
        if kind not in ("mock", "manual") or not ref.strip():
            raise CandidateSourceError(f"알 수 없는 후보 출처 {spec!r} (mock:<fixture> | manual:<path>)")
        return cls(kind, ref.strip(), note)


def _new_id() -> str:
    return f"cand-{uuid.uuid4().hex[:8]}"


def load_mock_candidate(fixture: str, note: str = "", mock_dir: Optional[Path] = None) -> PatchCandidate:
    d = mock_dir or MOCK_DIR
    p = d / f"{fixture}.json"
    base = dict(candidate_id=_new_id(), origin="mock", generator=f"mock:{fixture}", model="",
                provenance=note or "mock fixture (사람이 미리 작성한 고정 응답; LLM 출력 아님)")
    if not p.exists():
        return PatchCandidate(status="GENERATION_FAILED", files={}, error=f"mock fixture 없음: {p}", **base)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return PatchCandidate(status="GENERATION_FAILED", files={}, error=f"mock fixture 를 읽을 수 없다: {e}", **base)
    if data.get("_note"):
        base["provenance"] = (note + " | " if note else "") + f"fixture note: {data['_note']}"
    text = data.get("text")
    if text is None and "response" in data:
        text = json.dumps(data["response"], ensure_ascii=False)
    resp = LLMResponse(str(text or ""), str(data.get("model") or "mock"), "mock",
                       truncated=bool(data.get("truncated", False)), stop_reason=str(data.get("stop_reason", "end_turn")))
    return _from_response(resp, base)


def load_manual_candidate(path: str | Path, target: Finding, original_files: Dict[str, str], note: str = "") -> PatchCandidate:
    p = Path(path)
    base = dict(candidate_id=_new_id(), origin="manual", generator=f"manual:{p.name}", model="",
                provenance=note or "사람이 준비한 수정 파일 (프로그램이 생성하지 않음)")
    if not p.exists():
        return PatchCandidate(status="GENERATION_FAILED", files={}, error=f"수동 후보 파일이 없다: {p}", **base)
    try:
        if p.is_dir():
            files = {}
            for tf in sorted(p.glob("*.tf")):
                files[tf.name] = tf.read_text(encoding="utf-8")
            if not files:
                return PatchCandidate(status="GENERATION_FAILED", files={}, error=f"디렉터리에 *.tf 가 없다: {p}", **base)
            rationale = ""
            meta = p / "candidate.json"
            if meta.exists():
                m = json.loads(meta.read_text(encoding="utf-8"))
                rationale = str(m.get("rationale", ""))
                if m.get("provenance"):
                    base["provenance"] = str(m["provenance"])
            return PatchCandidate(status="PATCH", files=files, rationale=rationale, **base)
        if p.suffix.lower() == ".json":
            text = p.read_text(encoding="utf-8")
            resp = LLMResponse(text, "manual", "manual")
            try:
                obj = json.loads(text)
                if isinstance(obj, dict) and obj.get("provenance"):
                    base["provenance"] = str(obj["provenance"])
            except json.JSONDecodeError:
                pass
            return _from_response(resp, base)
        # 단일 파일: 대상 finding 의 파일을 통째로 대체
        content = p.read_text(encoding="utf-8")
        return PatchCandidate(status="PATCH", files={target.filename: content}, rationale="", **base)
    except OSError as e:
        return PatchCandidate(status="GENERATION_FAILED", files={}, error=f"수동 후보를 읽을 수 없다: {e}", **base)
    except UnicodeDecodeError as e:
        return PatchCandidate(status="GENERATION_FAILED", files={}, error=f"수동 후보가 UTF-8 텍스트가 아니다: {e}", **base)


def _from_response(resp: LLMResponse, base: dict) -> PatchCandidate:
    try:
        parsed = parse_llm_output(resp, [])
    except GenerationError as e:
        return PatchCandidate(status="GENERATION_FAILED", files={}, error=str(e), **base)
    return PatchCandidate(status=parsed["status"], files=parsed["files"], rationale=parsed["rationale"],
                          proposed_autonomy=parsed["proposed_autonomy"], assumptions=parsed["assumptions"], **base)


def load_candidate(spec: CandidateSpec, target: Finding, original_files: Dict[str, str], mock_dir: Optional[Path] = None) -> PatchCandidate:
    if spec.kind == "mock":
        return load_mock_candidate(spec.ref, spec.note, mock_dir)
    return load_manual_candidate(spec.ref, target, original_files, spec.note)


# ---------------------------------------------------------------------------
# 후보 형식·필수 정보 확인
# ---------------------------------------------------------------------------
def validate_candidate_shape(cand: PatchCandidate, original_files: Dict[str, str]) -> Tuple[str, List[str]]:
    """returns (state, reasons). state ∈ {"OK", "CANDIDATE_INVALID", "INFO_INSUFFICIENT"}."""
    if cand.status == "GENERATION_FAILED":
        return "CANDIDATE_INVALID", [cand.error or "후보를 만들지 못했다"]
    if cand.status in ("INSUFFICIENT_INFO", "ABSTAIN", "NOT_SUPPORTED"):
        return "INFO_INSUFFICIENT", [f"후보 상태 {cand.status}: {cand.rationale or cand.error or '이유 없음'}"]
    if cand.status != "PATCH":
        return "CANDIDATE_INVALID", [f"알 수 없는 후보 상태 {cand.status}"]
    if not cand.files:
        return "CANDIDATE_INVALID", ["빈 후보: 파일 목록이 없다"]
    if all(not (c or "").strip() for c in cand.files.values()):
        return "CANDIDATE_INVALID", ["빈 후보: 모든 파일 내용이 비어 있다"]
    unknown = [f for f in cand.files if f not in original_files]
    if unknown:
        return "CANDIDATE_INVALID", [f"원본에 없는 파일: {unknown} (새 파일 생성은 허용하지 않는다)"]
    identical = [f for f, c in cand.files.items() if original_files.get(f) == c]
    if len(identical) == len(cand.files):
        return "CANDIDATE_INVALID", ["원본과 동일한 후보: 변경된 내용이 없다"]
    if not (cand.rationale or "").strip():
        cand.needs_info.append("수정 이유(rationale) 미기재 — 검토 전에 사람이 적어야 한다")
    return "OK", []
