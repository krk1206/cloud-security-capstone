"""LLM 패치 생성기.

- 프롬프트는 prompts/<version>.md 파일에서 읽는다 (## SYSTEM / ## USER 섹션). 버전과 SHA-256 을 후보에 기록한다.
- 제공자(provider)는 교체 가능 (mock / anthropic / openai / openai_compatible).
- 생성기는 판정하지 않는다. 응답을 파싱해 PatchCandidate 로 돌려줄 뿐이며, 파일 경로/정책/검증은 뒤 단계가 한다.
- feedback: 이전 시도의 결정론적 실패 메시지(validate 오류, plan 오류, 오라클 EXCESS 등)를 다음 시도에 넘긴다 (Observe→Reason→Act→Verify 루프).
"""
from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Optional

from ..evidence import bundle_to_prompt_json
from ..models import EvidenceBundle, PatchCandidate
from .base import GenerationError, LLMProvider, parse_llm_output

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"
DEFAULT_PROMPT_VERSION = "sg_v1"


def load_prompt(version: str) -> "tuple[str, str]":
    text = (PROMPT_DIR / f"{version}.md").read_text(encoding="utf-8")
    if "## SYSTEM" not in text or "## USER" not in text:
        raise ValueError(f"prompt {version} must contain '## SYSTEM' and '## USER' sections")
    _, rest = text.split("## SYSTEM", 1)
    system, user = rest.split("## USER", 1)
    return system.strip(), user.strip()


class LLMPatchGenerator:
    name = "llm"

    def __init__(self, provider: LLMProvider, prompt_version: str = DEFAULT_PROMPT_VERSION,
                 max_tokens: int = 4000, temperature: float = 0.0):
        self.provider = provider
        self.prompt_version = prompt_version
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.last_response = None  # 파이프라인이 원문을 저장할 수 있게 보관

    def render(self, bundle: EvidenceBundle, feedback: Optional[str]) -> "tuple[str, str]":
        system, user_t = load_prompt(self.prompt_version)
        fb = ""
        if feedback:
            fb = ("Previous attempt was rejected by deterministic verification. Fix the following and try again "
                  "(do not argue with the verifier; it is authoritative):\n" + feedback.strip())
        user = user_t.replace("{{BUNDLE_JSON}}", bundle_to_prompt_json(bundle)).replace("{{FEEDBACK}}", fb)
        return system, user

    def generate(self, bundle: EvidenceBundle, feedback: Optional[str] = None, attempt: int = 1) -> PatchCandidate:
        system, user = self.render(bundle, feedback)
        sha = hashlib.sha256((system + "\n---\n" + user).encode("utf-8")).hexdigest()
        cid = f"cand-{uuid.uuid4().hex[:8]}"
        resp = self.provider.complete(system, user, self.max_tokens, self.temperature)
        self.last_response = resp
        origin = "mock" if getattr(self.provider, "name", "") == "mock" else "llm"
        gen_name = f"{origin}:{getattr(self.provider, 'name', '?')}:{resp.model or getattr(self.provider, 'model', '?')}"
        base = dict(candidate_id=cid, origin=origin, generator=gen_name, prompt_version=self.prompt_version,
                    prompt_sha256=sha, model=resp.model or getattr(self.provider, "model", ""), attempt=attempt)
        try:
            parsed = parse_llm_output(resp, bundle.editable_files)
        except GenerationError as e:
            return PatchCandidate(status="GENERATION_FAILED", files={}, error=str(e), **base)
        return PatchCandidate(status=parsed["status"], files=parsed["files"], rationale=parsed["rationale"],
                              proposed_autonomy=parsed["proposed_autonomy"], assumptions=parsed["assumptions"], **base)
