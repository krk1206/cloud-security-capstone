"""LLM 제공자 어댑터 (교체 가능). 표준 라이브러리 urllib 만 사용한다.

    mock               키 없이 실행. tests/fixtures/mock_llm/*.json 의 canned 응답을 돌려준다 (origin=mock).
    anthropic          Messages API  (환경변수 ANTHROPIC_API_KEY 또는 LLM_API_KEY)
    openai             Chat Completions (OPENAI_API_KEY 또는 LLM_API_KEY)
    openai_compatible  OpenAI 호환 엔드포인트 (LLM_BASE_URL 필요; 로컬 모델/타 벤더용)

API 키는 환경변수에서만 읽고, 어디에도 기록하지 않는다 (run record 에는 provider/model 이름만 남긴다).
실제 API 호출은 이 저장소 안에서 아직 실행·검증되지 않았다 (docs/STATUS.md 참조). mock 성공 ≠ API 연동 성공.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from .base import LLMResponse

DEFAULT_TIMEOUT = 120


def _post_json(url: str, headers: Dict[str, str], body: Dict[str, Any], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec - URL is provider endpoint
        return json.loads(r.read().decode("utf-8"))


def _key(*names: str) -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    raise RuntimeError(f"API key not set (expected one of: {', '.join(names)}). Set it as an environment variable; never put it in files.")


class MockProvider:
    """canned 응답 제공자. fixture 이름은 생성자 인자 또는 환경변수 LLM_MOCK_FIXTURE 로 정한다.

    fixture JSON 형식:
      {"text": "<모델이 돌려줬다고 가정하는 원문>", "truncated": false, "stop_reason": "end_turn", "model": "mock"}
    또는 {"response": {...LLM 응답 객체...}} (text 로 직렬화됨)
    """
    name = "mock"

    def __init__(self, fixture: Optional[str] = None, fixture_dir: Optional[str] = None):
        self.fixture = fixture or os.environ.get("LLM_MOCK_FIXTURE") or "sg_baseline_ok"
        self.fixture_dir = Path(fixture_dir or os.environ.get("LLM_MOCK_DIR") or Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "mock_llm")
        self.model = f"mock:{self.fixture}"

    def complete(self, system: str, user: str, max_tokens: int, temperature: float) -> LLMResponse:
        p = self.fixture_dir / f"{self.fixture}.json"
        if not p.exists():
            return LLMResponse("", self.model, self.name, error=f"mock fixture not found: {p}")
        d = json.loads(p.read_text(encoding="utf-8"))
        text = d.get("text")
        if text is None and "response" in d:
            text = json.dumps(d["response"], ensure_ascii=False, indent=2)
        return LLMResponse(str(text or ""), str(d.get("model") or self.model), self.name,
                           truncated=bool(d.get("truncated", False)), stop_reason=str(d.get("stop_reason", "end_turn")),
                           usage={"mock": True}, raw={"fixture": str(p)})


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None):
        self.model = model or os.environ.get("LLM_MODEL") or "claude-sonnet-4-5"
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL") or "https://api.anthropic.com").rstrip("/")

    def complete(self, system: str, user: str, max_tokens: int, temperature: float) -> LLMResponse:
        try:
            key = _key("ANTHROPIC_API_KEY", "LLM_API_KEY")
        except RuntimeError as e:
            return LLMResponse("", self.model, self.name, error=str(e))
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                "system": system, "messages": [{"role": "user", "content": user}]}
        try:
            d = _post_json(f"{self.base_url}/v1/messages", {"x-api-key": key, "anthropic-version": "2023-06-01"}, body)
        except urllib.error.HTTPError as e:
            return LLMResponse("", self.model, self.name, error=f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:500]}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return LLMResponse("", self.model, self.name, error=f"transport error: {e}")
        text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
        stop = str(d.get("stop_reason", ""))
        return LLMResponse(text, str(d.get("model", self.model)), self.name, truncated=(stop == "max_tokens"),
                           stop_reason=stop, usage=d.get("usage", {}), raw={"id": d.get("id")})


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None, key_env: str = "LLM_API_KEY"):
        self.model = model or os.environ.get("LLM_MODEL") or ""
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL") or "").rstrip("/")
        self.key_env = key_env

    def complete(self, system: str, user: str, max_tokens: int, temperature: float) -> LLMResponse:
        if not self.base_url:
            return LLMResponse("", self.model, self.name, error="LLM_BASE_URL not set")
        if not self.model:
            return LLMResponse("", self.model, self.name, error="LLM_MODEL not set")
        try:
            key = _key(self.key_env, "LLM_API_KEY")
        except RuntimeError as e:
            return LLMResponse("", self.model, self.name, error=str(e))
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        try:
            d = _post_json(f"{self.base_url}/chat/completions", {"Authorization": f"Bearer {key}"}, body)
        except urllib.error.HTTPError as e:
            return LLMResponse("", self.model, self.name, error=f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:500]}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return LLMResponse("", self.model, self.name, error=f"transport error: {e}")
        choices = d.get("choices") or []
        if not choices:
            return LLMResponse("", self.model, self.name, error="no choices in response", raw=d)
        c0 = choices[0]
        text = ((c0.get("message") or {}).get("content")) or ""
        finish = str(c0.get("finish_reason", ""))
        return LLMResponse(str(text), str(d.get("model", self.model)), self.name, truncated=(finish == "length"),
                           stop_reason=finish, usage=d.get("usage", {}), raw={"id": d.get("id")})


class OpenAIProvider(OpenAICompatibleProvider):
    name = "openai"

    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None):
        super().__init__(model or os.environ.get("LLM_MODEL") or "gpt-4o", base_url or os.environ.get("LLM_BASE_URL") or "https://api.openai.com/v1", key_env="OPENAI_API_KEY")


def make_provider(name: Optional[str] = None, **kw: Any):
    name = (name or os.environ.get("LLM_PROVIDER") or "mock").lower()
    if name == "mock":
        return MockProvider(**kw)
    if name == "anthropic":
        return AnthropicProvider(**kw)
    if name == "openai":
        return OpenAIProvider(**kw)
    if name in ("openai_compatible", "compatible"):
        return OpenAICompatibleProvider(**kw)
    raise ValueError(f"unknown LLM provider {name!r} (mock|anthropic|openai|openai_compatible)")
