"""OpenAI-compatible model client with JSON repair and mock mode."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..errors import ConfigurationError
from ..utils.json import parse_jsonish


@dataclass
class LLMUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0

    def add(self, prompt: str, completion: str) -> None:
        self.calls += 1
        # Approximate token accounting when the provider omits usage.
        self.input_tokens += max(1, len(prompt) // 4)
        self.output_tokens += max(1, len(completion) // 4)


@dataclass
class LLMResponse:
    text: str
    parsed: Any = None
    provider: str = ""
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


class LLMClient:
    """Small, dependency-free client.

    Supported providers:
    - ``openrouter`` / ``openai``: ``/chat/completions``
    - ``anthropic``: ``/messages``
    - ``mock``: deterministic no-key mode
    """

    def __init__(self, config: Config | None = None, mock: bool | None = None):
        self.config = config or Config.load()
        settings = self.config.llm
        self.provider = str(settings.get("provider", "openrouter")).lower()
        self.base_url = str(settings.get("base_url", "https://openrouter.ai/api/v1")).rstrip("/")
        self.model = str(settings.get("model", "deepseek/deepseek-chat-v3.1"))
        self.timeout = int(settings.get("timeout_seconds", 90))
        self.temperature = float(settings.get("temperature", 0.1))
        self.max_tokens = int(settings.get("max_tokens", 2400))
        self.retries = int(settings.get("retries", 2))
        key_env = str(settings.get("api_key_env", "OPENROUTER_API_KEY"))
        self.api_key = os.environ.get(key_env, "")
        self.mock = bool(settings.get("mock_when_missing_key", True) and not self.api_key)
        if mock is not None:
            self.mock = mock
        self.usage = LLMUsage()

    # ------------------------------------------------------------------
    def available(self) -> bool:
        return not self.mock and bool(self.api_key)

    def chat(
        self,
        system: str,
        user: str,
        *,
        schema: dict[str, Any] | None = None,
        json_mode: bool = True,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        if self.mock:
            return self._mock(system, user, schema)
        if not self.api_key:
            raise ConfigurationError(
                "no API key found; set OPENROUTER_API_KEY or run with --no-llm"
            )
        prompt = user
        if schema is not None:
            prompt += (
                "\n\nReturn only a JSON object that validates against this schema:\n"
                + json.dumps(schema, ensure_ascii=False, indent=2)
            )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                response = self._request(system, prompt, max_tokens or self.max_tokens)
                text = response.text
                parsed = None
                if json_mode:
                    try:
                        parsed = parse_jsonish(text)
                    except Exception as exc:  # noqa: BLE001
                        last_error = exc
                        prompt = (
                            "Your previous response was not valid JSON. Return only a JSON object, "
                            "without markdown fences or prose.\n\n"
                            + user
                        )
                        continue
                self.usage.add(prompt, text)
                return LLMResponse(
                    text=text,
                    parsed=parsed,
                    provider=self.provider,
                    model=self.model,
                    usage={
                        "input_tokens": self.usage.input_tokens,
                        "output_tokens": self.usage.output_tokens,
                    },
                    raw=response.raw,
                )
            except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as exc:
                last_error = exc
                time.sleep(min(2**attempt, 4))
        raise RuntimeError(f"LLM call failed after retries: {last_error}")

    # ------------------------------------------------------------------
    def _request(self, system: str, user: str, max_tokens: int) -> LLMResponse:
        if self.provider == "anthropic":
            url = self.base_url if self.base_url.endswith("/messages") else self.base_url + "/v1/messages"
            payload = {
                "model": self.model,
                "max_tokens": max_tokens,
                "temperature": self.temperature,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }
            raw = self._post(url, payload, {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"})
            parts = raw.get("content", [])
            text = "\n".join(p.get("text", "") for p in parts if isinstance(p, dict))
            usage = raw.get("usage", {})
            return LLMResponse(
                text=text,
                raw=raw,
                provider=self.provider,
                model=self.model,
                usage={
                    "input_tokens": int(usage.get("input_tokens", 0)),
                    "output_tokens": int(usage.get("output_tokens", 0)),
                },
            )

        url = self.base_url
        if not url.endswith("/chat/completions"):
            url = url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        raw = self._post(
            url,
            payload,
            {
                "Authorization": f"Bearer {self.api_key}",
                "HTTP-Referer": "https://github.com/obli-rca/obli-rca",
                "X-Title": "ObliRCA",
            },
        )
        choice = (raw.get("choices") or [{}])[0]
        text = (choice.get("message") or {}).get("content", "")
        usage = raw.get("usage", {})
        return LLMResponse(
            text=text,
            raw=raw,
            provider=self.provider,
            model=self.model,
            usage={
                "input_tokens": int(usage.get("prompt_tokens", 0)),
                "output_tokens": int(usage.get("completion_tokens", 0)),
            },
        )

    def _post(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", **headers},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))

    # ------------------------------------------------------------------
    def _mock(self, system: str, user: str, schema: dict[str, Any] | None) -> LLMResponse:
        """Return a deterministic placeholder so the pipeline remains testable."""
        lowered = (system + "\n" + user).lower()
        if "extract" in lowered or "candidate obligation" in lowered:
            parsed: Any = {
                "entry": {
                    "id": "candidate-mock",
                    "category": "Memory Bounds",
                    "summary": "mock candidate entry from offline extraction",
                    "roles": {
                        "data": {"name": "data", "description": "external buffer", "kind": "object"},
                        "length": {"name": "length", "description": "declared length", "kind": "value"},
                    },
                    "graphs": [
                        {
                            "id": "G1",
                            "description": "mock object organization",
                            "nodes": [
                                {"id": "n1", "role": "data", "kind": "object", "description": ""},
                                {"id": "n2", "role": "length", "kind": "value", "description": ""},
                            ],
                            "edges": [
                                {"src": "n2", "dst": "n1", "relation": "bounds", "description": ""}
                            ],
                        }
                    ],
                    "conditions": {
                        "pre": ["external data is about to be consumed"],
                        "must": ["the read range is within the valid range"],
                        "stage": ["before the read"],
                        "scope": ["until the read completes"],
                    },
                    "query_manual": [
                        {
                            "id": "Q1",
                            "what": "where does the valid range come from?",
                            "where": "definition and updates of the length value",
                            "interpret": "a bound check before the read answers the question",
                            "next": "continue to the sink if the range is established",
                        }
                    ],
                }
            }
        elif "hypothes" in lowered:
            parsed = {"hypotheses": []}
        elif "verif" in lowered:
            parsed = {"status": "needs_revision", "notes": "mock verification"}
        elif "rank" in lowered or "explain" in lowered:
            parsed = {"ranked": []}
        else:
            parsed = {"status": "mock", "text": "no model configured"}
        text = json.dumps(parsed, ensure_ascii=False)
        self.usage.add(system + user, text)
        return LLMResponse(text=text, parsed=parsed, provider="mock", model="mock")
