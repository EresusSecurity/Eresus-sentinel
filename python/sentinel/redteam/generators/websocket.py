"""WebSocket Target Generator.

Sends attack prompts over a WebSocket connection and collects responses.
Suitable for testing real-time chat APIs, streaming endpoints, and
WebSocket-based LLM interfaces.

Protocol support:
  - JSON message framing (OpenAI-style streaming)
  - Plain text framing
  - Custom message builders

Requires: pip install websocket-client
Async support: pip install websockets (optional, for asyncio mode)

Env:
  WS_TARGET_URL   — WebSocket endpoint URL (ws:// or wss://)
  WS_API_KEY      — Authorization token (sent as header or first message)
  WS_TIMEOUT      — Socket timeout in seconds (default 30)
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Callable
from urllib.parse import urlparse

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)


def _validate_ws_url(url: str) -> str:
    """Validate WebSocket URL scheme and host."""
    parsed = urlparse(url)
    if parsed.scheme not in ("ws", "wss"):
        raise ValueError(
            f"WebSocketGenerator: URL scheme '{parsed.scheme}' not allowed. Use ws:// or wss://."
        )
    host = parsed.hostname or ""
    _BLOCKED = ("localhost", "127.", "0.0.0.0", "169.254.", "metadata.google.internal")
    for blocked in _BLOCKED:
        if host.startswith(blocked) or host == blocked.rstrip("."):
            raise ValueError(
                f"WebSocketGenerator: Host '{host}' is a private/loopback address — SSRF protection."
            )
    return url


class WebSocketGenerator(Generator):
    """Sends prompts via WebSocket and returns streamed/batched responses.

    Args:
        url:            WebSocket endpoint (e.g., wss://api.example.com/chat).
        api_key:        Authorization token (sent as Bearer header if supported).
        message_builder: Callable(prompt, api_key) -> dict/str to send.
        response_parser: Callable(raw_message) -> str to extract text.
        framing:        'json' (default) | 'text' for plain string messages.
        config:         Standard GeneratorConfig for retries/timeout.
    """

    name = "websocket"
    provider = "websocket"
    supports_system_prompt = False
    supports_streaming = True

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        message_builder: Callable | None = None,
        response_parser: Callable | None = None,
        framing: str = "json",
        config: GeneratorConfig | None = None,
        **kwargs,
    ) -> None:
        super().__init__(config, **kwargs)
        raw_url = url or os.environ.get("WS_TARGET_URL", "")
        if raw_url:
            self._url = _validate_ws_url(raw_url)
        else:
            self._url = ""
        self._api_key = api_key or os.environ.get("WS_API_KEY", "")
        self._framing = framing
        self._message_builder = message_builder or self._default_builder
        self._response_parser = response_parser or self._default_parser
        self._timeout = int(os.environ.get("WS_TIMEOUT", str(self.config.timeout)))

    def _default_builder(self, prompt: str, api_key: str) -> dict:
        """OpenAI-style WebSocket message."""
        return {
            "type": "message",
            "role": "user",
            "content": prompt,
        }

    def _default_parser(self, raw: str) -> str:
        """Extract text from JSON streaming chunks or return raw."""
        try:
            data = json.loads(raw)
            return (
                data.get("text")
                or data.get("content")
                or data.get("delta", {}).get("content", "")
                or data.get("message", {}).get("content", "")
                or raw
            )
        except json.JSONDecodeError:
            return raw

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        if not self._url:
            raise RuntimeError(
                "WebSocketGenerator: no URL configured. "
                "Set url= or WS_TARGET_URL environment variable."
            )

        prompt = " ".join(m.get("content", "") for m in messages if m.get("role") == "user")

        try:
            import websocket  # type: ignore[import]
        except ImportError:
            raise RuntimeError(
                "websocket-client is required: pip install websocket-client"
            )

        collected: list[str] = []
        errors: list[str] = []
        done_event: list[bool] = [False]
        start = time.monotonic()

        def on_message(ws, message):
            text = self._response_parser(message)
            if text:
                collected.append(text)
            if '"finish_reason"' in message or '"done": true' in message.lower():
                done_event[0] = True
                ws.close()

        def on_error(ws, error):
            errors.append(str(error))
            ws.close()

        def on_open(ws):
            msg = self._message_builder(prompt, self._api_key)
            if isinstance(msg, dict):
                ws.send(json.dumps(msg))
            else:
                ws.send(str(msg))

        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        ws = websocket.WebSocketApp(
            self._url,
            header=headers,
            on_message=on_message,
            on_error=on_error,
            on_open=on_open,
        )

        import threading
        thread = threading.Thread(target=ws.run_forever, daemon=True)
        thread.start()
        thread.join(timeout=self._timeout)

        if not thread.is_alive():
            ws.close()

        latency_ms = (time.monotonic() - start) * 1000
        full_text = "".join(collected)

        if errors and not full_text:
            raise RuntimeError(f"WebSocket error: {'; '.join(errors)}")

        return GeneratorResponse(
            text=full_text,
            model=self._url,
            provider="websocket",
            latency_ms=latency_ms,
        )
