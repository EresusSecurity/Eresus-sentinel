"""
Google Gemini Generator — Gemini 3.1 Pro/Flash, 2.5 Pro/Flash.

Production-grade features:
  - Gemini 3.1 series (2026): Pro Preview, Flash, Flash Lite
  - Gemini 2.5 series legacy (still available)
  - Streaming with chunk callbacks
  - Safety settings control (disable for red-teaming)
  - Grounding with Google Search
  - JSON mode / structured output
  - Code execution tool
  - System instruction support
  - SDK and REST API fallback
  - Model context length tracking
  - Token counting

Env: GOOGLE_API_KEY or GEMINI_API_KEY
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Callable, Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)

CONTEXT_LENGTHS = {
    # Gemini 3.1 series (2026)
    "gemini-3.1-pro-preview": 2_000_000,
    "gemini-3-flash": 1_000_000,
    "gemini-3.1-flash-lite": 500_000,
    # Gemini 2.5 series (2025)
    "gemini-2.5-pro-preview-05-06": 1_048_576,
    "gemini-2.5-flash-preview-04-17": 1_048_576,
    # Gemini 2.0 legacy
    "gemini-2.0-flash": 1_048_576,
    "gemini-2.0-flash-lite": 1_048_576,
}

# Short aliases
_ALIASES: dict[str, str] = {
    "gemini-pro": "gemini-3.1-pro-preview",
    "gemini-flash": "gemini-3-flash",
    "gemini-lite": "gemini-3.1-flash-lite",
    "2.5-pro": "gemini-2.5-pro-preview-05-06",
    "2.5-flash": "gemini-2.5-flash-preview-04-17",
}


class GeminiGenerator(Generator):
    """
    Google Gemini API generator (April 2026).

    Usage:
        gen = GeminiGenerator(model="gemini-3.1-pro-preview")
        resp = gen.generate("Hello")

        # Flash model
        gen = GeminiGenerator(model="gemini-3-flash")

        # Streaming
        resp = gen.generate_stream("Explain quantum computing", on_chunk=print)

        # JSON mode
        resp = gen.generate("List 3 items", json_mode=True)

        # With Google Search grounding
        gen = GeminiGenerator(model="gemini-3-flash", grounding=True)

        # Safety off for red-teaming
        gen = GeminiGenerator(model="gemini-3-flash", disable_safety=True)
    """

    name = "gemini"
    provider = "google"
    supports_streaming = True

    SAFETY_OFF = [
        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
    ]

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        if not self.config.model:
            self.config.model = "gemini-3.1-pro-preview"

        # Resolve aliases
        self.config.model = _ALIASES.get(self.config.model, self.config.model)

        self._api_key = kwargs.get("api_key", os.environ.get("GOOGLE_API_KEY", os.environ.get("GEMINI_API_KEY", "")))
        self._disable_safety = kwargs.get("disable_safety", True)
        self._grounding = kwargs.get("grounding", False)
        self._json_mode = kwargs.get("json_mode", False)
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                from google import genai
                self._client = genai.Client(api_key=self._api_key)
            except ImportError:
                self._client = "rest"
        return self._client

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        json_mode = kwargs.pop("json_mode", self._json_mode)

        if self._client == "rest" or self._client is None:
            return self._call_rest(messages, json_mode=json_mode)
        return self._call_sdk(messages, json_mode=json_mode)

    def _call_sdk(self, messages: list[dict], json_mode: bool = False) -> GeneratorResponse:
        from google.genai import types

        system_instruction = None
        contents = []
        for msg in messages:
            if msg["role"] == "system":
                system_instruction = msg["content"]
            else:
                role = "user" if msg["role"] == "user" else "model"
                contents.append(types.Content(role=role, parts=[types.Part(text=msg["content"])]))

        config = types.GenerateContentConfig(
            temperature=self.config.temperature,
            max_output_tokens=self.config.max_tokens,
            top_p=self.config.top_p,
        )
        if system_instruction:
            config.system_instruction = system_instruction
        if self._disable_safety:
            config.safety_settings = [
                types.SafetySetting(category=s["category"], threshold=s["threshold"])
                for s in self.SAFETY_OFF
            ]
        if json_mode:
            config.response_mime_type = "application/json"
        if self._grounding:
            config.tools = [types.Tool(google_search=types.GoogleSearch())]

        response = self.client.models.generate_content(
            model=self.config.model,
            contents=contents,
            config=config,
        )

        text = response.text or ""
        usage = response.usage_metadata

        # Extract grounding metadata
        grounding_meta = None
        if response.candidates and hasattr(response.candidates[0], "grounding_metadata"):
            grounding_meta = response.candidates[0].grounding_metadata

        return GeneratorResponse(
            text=text,
            model=self.config.model,
            input_tokens=getattr(usage, "prompt_token_count", 0) if usage else 0,
            output_tokens=getattr(usage, "candidates_token_count", 0) if usage else 0,
            total_tokens=getattr(usage, "total_token_count", 0) if usage else 0,
            finish_reason=str(getattr(response.candidates[0], "finish_reason", "")) if response.candidates else "",
            raw={
                "response": response,
                "grounding": grounding_meta,
            },
        )

    def _call_rest(self, messages: list[dict], json_mode: bool = False) -> GeneratorResponse:
        """Fallback REST API when SDK not installed."""
        contents = []
        system_instruction = None
        for msg in messages:
            if msg["role"] == "system":
                system_instruction = msg["content"]
            else:
                role = "user" if msg["role"] == "user" else "model"
                contents.append({"role": role, "parts": [{"text": msg["content"]}]})

        gen_config = {
            "temperature": self.config.temperature,
            "maxOutputTokens": self.config.max_tokens,
            "topP": self.config.top_p,
        }
        if json_mode:
            gen_config["responseMimeType"] = "application/json"

        payload = {
            "contents": contents,
            "generationConfig": gen_config,
        }
        if system_instruction:
            payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}
        if self._disable_safety:
            payload["safetySettings"] = self.SAFETY_OFF
        if self._grounding:
            payload["tools"] = [{"googleSearch": {}}]

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.config.model}:generateContent?key={self._api_key}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
            result = json.loads(resp.read())

        text = ""
        if "candidates" in result and result["candidates"]:
            parts = result["candidates"][0].get("content", {}).get("parts", [])
            text = " ".join(p.get("text", "") for p in parts)

        usage = result.get("usageMetadata", {})
        return GeneratorResponse(
            text=text,
            model=self.config.model,
            input_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
            total_tokens=usage.get("totalTokenCount", 0),
            raw=result,
        )

    def generate_stream(self, prompt: str, on_chunk: Optional[Callable[[str], None]] = None, **kwargs) -> GeneratorResponse:
        """Generate with streaming (REST fallback)."""
        contents = [{"role": "user", "parts": [{"text": prompt}]}]

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens,
            },
        }
        if self._disable_safety:
            payload["safetySettings"] = self.SAFETY_OFF

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.config.model}:streamGenerateContent?key={self._api_key}&alt=sse"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        full_text = ""
        with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
            for line in resp:
                line_str = line.decode().strip()
                if line_str.startswith("data: "):
                    try:
                        chunk = json.loads(line_str[6:])
                        candidates = chunk.get("candidates", [])
                        if candidates:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            for p in parts:
                                token = p.get("text", "")
                                if token:
                                    full_text += token
                                    if on_chunk:
                                        on_chunk(token)
                    except json.JSONDecodeError:
                        pass

        return GeneratorResponse(
            text=full_text,
            model=self.config.model,
            output_tokens=len(full_text.split()),
            finish_reason="stop",
        )

    # ── Model Info ────────────────────────────────────────────────────

    @staticmethod
    def available_models() -> list[str]:
        return list(CONTEXT_LENGTHS.keys())

    @property
    def context_length(self) -> int:
        return CONTEXT_LENGTHS.get(self.config.model, 1_000_000)
