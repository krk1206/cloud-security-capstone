"""생성기 공통: 출력 스키마, 응답 파싱(잘림/오류 처리), 인터페이스.

LLM 응답 계약 (JSON 객체 하나):
    {
      "status": "PATCH" | "INSUFFICIENT_INFO" | "ABSTAIN",
      "files": [{"path": "main.tf", "content": "<파일 전체 내용>"}],   # PATCH 일 때만
      "rationale": "왜 이렇게 고쳤는가 (사람이 읽는 설명)",
      "proposed_autonomy": "HIGH" | "MEDIUM" | "LOW" | null,            # 하향 제안 전용. 없어도 됨
      "assumptions": ["..."]
    }

파싱 규칙:
  - 응답이 max_tokens 로 잘렸다고 API 가 표시하면(stop_reason) 내용과 무관하게 GENERATION_FAILED.
  - 앞뒤 잡담/코드펜스는 벗겨내고 첫 번째 균형 잡힌 JSON 객체만 읽는다.
  - 스키마 위반(status 값, files 형식, path 문자열 아님 등) → GENERATION_FAILED.
  - 파일 경로 정책 위반은 여기서 거르지 않는다 (Policy Validator 가 한다). 단 dict 구조는 보장한다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from ..models import EvidenceBundle, PatchCandidate

VALID_STATUS = {"PATCH", "INSUFFICIENT_INFO", "ABSTAIN"}
VALID_AUTONOMY = {"HIGH", "MEDIUM", "LOW"}


class GenerationError(Exception):
    pass


@dataclass
class LLMResponse:
    text: str
    model: str
    provider: str
    truncated: bool = False            # stop_reason == max_tokens / finish_reason == length
    stop_reason: str = ""
    usage: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    error: str = ""                    # HTTP/전송 오류


class LLMProvider(Protocol):
    name: str
    model: str

    def complete(self, system: str, user: str, max_tokens: int, temperature: float) -> LLMResponse: ...


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def extract_json_object(text: str) -> Dict[str, Any]:
    """텍스트에서 첫 번째 균형 잡힌 JSON 객체를 추출한다. 실패하면 GenerationError."""
    if not isinstance(text, str) or not text.strip():
        raise GenerationError("empty response")
    candidates: List[str] = []
    for m in _FENCE_RE.finditer(text):
        candidates.append(m.group(1))
    candidates.append(text)
    for cand in candidates:
        start = cand.find("{")
        while start != -1:
            depth = 0
            in_str = False
            esc = False
            for i in range(start, len(cand)):
                ch = cand[i]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                else:
                    if ch == '"':
                        in_str = True
                    elif ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            chunk = cand[start:i + 1]
                            try:
                                obj = json.loads(chunk)
                            except json.JSONDecodeError:
                                break
                            if isinstance(obj, dict):
                                return obj
                            break
            else:
                # 끝까지 갔는데 depth>0 → 잘린 JSON
                raise GenerationError("unbalanced JSON (response appears truncated)")
            start = cand.find("{", start + 1)
    raise GenerationError("no JSON object found in response")


def parse_llm_output(resp: LLMResponse, editable_files: List[str]) -> Dict[str, Any]:
    """LLMResponse → 정규화된 dict {status, files{path:content}, rationale, proposed_autonomy, assumptions}."""
    if resp.error:
        raise GenerationError(f"provider error: {resp.error}")
    if resp.truncated:
        raise GenerationError(f"response truncated by the API (stop_reason={resp.stop_reason}); refusing to parse partial output")
    obj = extract_json_object(resp.text)
    status = str(obj.get("status", "")).strip().upper()
    if status not in VALID_STATUS:
        raise GenerationError(f"invalid status {obj.get('status')!r}; expected one of {sorted(VALID_STATUS)}")
    files: Dict[str, str] = {}
    if status == "PATCH":
        raw_files = obj.get("files")
        if not isinstance(raw_files, list) or not raw_files:
            raise GenerationError("status=PATCH but 'files' is missing or empty")
        for i, f in enumerate(raw_files):
            if not isinstance(f, dict) or not isinstance(f.get("path"), str) or not isinstance(f.get("content"), str):
                raise GenerationError(f"files[{i}] must be {{path: str, content: str}}")
            path = f["path"].strip().replace("\\", "/")
            if path in files:
                raise GenerationError(f"duplicate file path {path}")
            files[path] = f["content"]
    pa = obj.get("proposed_autonomy")
    if pa is not None:
        pa = str(pa).strip().upper()
        if pa not in VALID_AUTONOMY:
            pa = None  # 잘못된 값은 제안 없음으로 (gate 에 기록)
    assumptions = obj.get("assumptions") or []
    if not isinstance(assumptions, list):
        assumptions = [str(assumptions)]
    return {
        "status": status,
        "files": files,
        "rationale": str(obj.get("rationale", "")),
        "proposed_autonomy": pa,
        "assumptions": [str(a) for a in assumptions],
    }


class PatchGenerator(Protocol):
    name: str

    def generate(self, bundle: EvidenceBundle, feedback: Optional[str] = None, attempt: int = 1) -> PatchCandidate: ...
