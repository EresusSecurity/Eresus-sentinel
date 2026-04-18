"""
Generic REST API Generator.

Connect to any LLM behind a REST API with configurable:
  - Request template (JSON with $INPUT placeholder)
  - Response JSON path extraction
  - Custom headers with $KEY substitution
  - HTTP method selection
  - Proxy and SSL settings

Supports JSONPath,
custom auth schemes, and response transformation.

Env: REST_API_KEY
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from typing import Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)


class RESTGenerator(Generator):
    """
    Generic REST API generator.

    Usage:
        gen = RESTGenerator(
            uri="https://my-llm.example.com/v1/generate",
            request_template='{"prompt": "$INPUT", "max_tokens": 100}',
            response_json_path="$.choices[0].text",
            headers={"Authorization": "Bearer $KEY"},
        )
        resp = gen.generate("Hello, world!")
    """

    name = "rest"
    provider = "rest"

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        super().__init__(config, **kwargs)

        self._uri = kwargs.get("uri", "")
        self._method = kwargs.get("method", "POST").upper()
        self._headers = kwargs.get("headers", {"Content-Type": "application/json"})
        self._request_template = kwargs.get("request_template", '{"prompt": "$INPUT", "max_tokens": $MAX_TOKENS}')
        self._response_json_path = kwargs.get("response_json_path", None)
        self._response_text_field = kwargs.get("response_text_field", None)
        self._api_key = kwargs.get("api_key", os.environ.get("REST_API_KEY", ""))
        self._verify_ssl = kwargs.get("verify_ssl", True)
        self._proxy = kwargs.get("proxy", None)
        self._rate_limit_codes = kwargs.get("rate_limit_codes", [429])

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        # Build prompt from messages
        prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages)

        # Build request body
        body = self._request_template
        body = body.replace("$INPUT", self._json_escape(prompt))
        body = body.replace("$KEY", self._api_key)
        body = body.replace("$MAX_TOKENS", str(self.config.max_tokens))
        body = body.replace("$TEMPERATURE", str(self.config.temperature))

        # Build headers
        headers = {}
        for k, v in self._headers.items():
            headers[k] = v.replace("$KEY", self._api_key)

        data = body.encode("utf-8")
        req = urllib.request.Request(self._uri, data=data, headers=headers, method=self._method)

        if not self._verify_ssl:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            resp_obj = urllib.request.urlopen(req, timeout=self.config.timeout, context=ctx)
        else:
            resp_obj = urllib.request.urlopen(req, timeout=self.config.timeout)

        with resp_obj as resp:
            raw_text = resp.read().decode("utf-8")

        # Parse response
        text = raw_text
        raw = None

        try:
            raw = json.loads(raw_text)
        except json.JSONDecodeError:
            return GeneratorResponse(text=raw_text.strip(), model="rest", raw=raw_text)

        # Extract text from JSON
        if self._response_json_path:
            text = self._extract_jsonpath(raw, self._response_json_path)
        elif self._response_text_field:
            text = self._extract_field(raw, self._response_text_field)
        elif isinstance(raw, dict):
            # Auto-detect common response formats
            text = self._auto_extract(raw)
        elif isinstance(raw, list) and raw:
            text = str(raw[0].get("generated_text", raw[0]))

        return GeneratorResponse(text=str(text).strip(), model="rest", raw=raw)

    @staticmethod
    def _json_escape(text: str) -> str:
        return json.dumps(text)[1:-1]

    @staticmethod
    def _extract_field(data: dict, field_path: str) -> str:
        """Extract nested field using dot notation: 'choices.0.text'"""
        parts = field_path.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part, "")
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return ""
            else:
                return str(current)
        return str(current)

    @staticmethod
    def _extract_jsonpath(data: dict, path: str) -> str:
        """Simple JSONPath extraction (supports $.field.subfield[0].text)."""
        # Strip leading $.
        path = re.sub(r"^\$\.?", "", path)
        parts = re.split(r"\.|\[(\d+)\]", path)
        parts = [p for p in parts if p is not None and p != ""]

        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part, "")
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return ""
            else:
                return str(current)
        return str(current)

    @staticmethod
    def _auto_extract(data: dict) -> str:
        """Auto-detect common response formats."""
        # OpenAI-compatible
        if "choices" in data and data["choices"]:
            choice = data["choices"][0]
            if "message" in choice:
                return choice["message"].get("content", "")
            if "text" in choice:
                return choice["text"]

        # Simple text field
        for field in ["text", "output", "response", "result", "generated_text", "content"]:
            if field in data:
                return str(data[field])

        return json.dumps(data)
