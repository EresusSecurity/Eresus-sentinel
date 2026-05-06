"""
Playwright Browser Target Generator.

Drives real browser-based LLM UIs (ChatGPT, Claude.ai, Gemini Live,
Copilot) via Playwright automation. Enables testing of browser-side
safety mechanisms and UI-level injection attacks.

Supported targets:
  - ChatGPT   (chat.openai.com)
  - Claude    (claude.ai)
  - Gemini    (gemini.google.com)
  - Copilot   (copilot.microsoft.com)
  - Custom    (any web chat with configurable selectors)

Environment variables:
  PLAYWRIGHT_HEADLESS   — "true" (default) | "false"
  PLAYWRIGHT_TIMEOUT_MS — Page timeout in ms (default 30000)
"""
from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_ALLOWED_SCHEMES = frozenset({"https"})
_BLOCKED_HOSTS = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0"
    r"|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+"
    r"|metadata\.google\.internal|fd[0-9a-f]{2}:)",
    re.IGNORECASE,
)


def _validate_url(url: str) -> str:
    """Validate URL is external HTTPS — raises ValueError for SSRF-risk targets."""
    if not url:
        return url
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"BrowserGenerator: URL scheme '{parsed.scheme}' not allowed (only https). "
            f"Set PLAYWRIGHT_ALLOW_HTTP=1 to override for testing."
        )
    host = parsed.hostname or ""
    if _BLOCKED_HOSTS.match(host):
        raise ValueError(
            f"BrowserGenerator: URL host '{host}' is a private/loopback address — "
            "SSRF protection blocked this request."
        )
    return url


_DEFAULT_SELECTORS: dict[str, dict[str, str]] = {
    "chatgpt": {
        "input": "textarea[data-id='prompt-textarea'], #prompt-textarea, textarea[placeholder]",
        "send": "button[data-testid='send-button'], button[aria-label='Send message']",
        "response": "[data-message-author-role='assistant'] .markdown, .agent-turn .markdown",
        "url": "https://chat.openai.com/",
    },
    "claude": {
        "input": "div[contenteditable='true'], textarea[placeholder]",
        "send": "button[aria-label='Send Message'], button[type='submit']",
        "response": ".prose, [data-testid='message-content']",
        "url": "https://claude.ai/new",
    },
    "gemini": {
        "input": "rich-textarea .ql-editor, textarea[aria-label]",
        "send": "button[aria-label='Send message'], mat-icon[fonticon='send']",
        "response": "message-content .markdown",
        "url": "https://gemini.google.com/app",
    },
    "copilot": {
        "input": "textarea[name='q'], cib-text-input textarea",
        "send": "button[type='submit'], cib-icon-button[aria-label='Submit']",
        "response": "cib-message-group[source='bot'] cib-message",
        "url": "https://copilot.microsoft.com/",
    },
}


@dataclass
class BrowserConfig:
    """Configuration for a browser target."""
    target: str = "custom"
    url: str = ""
    input_selector: str = ""
    send_selector: str = ""
    response_selector: str = ""
    headless: bool = True
    timeout_ms: int = 30_000
    response_wait_ms: int = 8_000
    screenshot_on_response: bool = False
    extra_headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)


class BrowserGeneratorResponse:
    """Response from a browser-based LLM interaction."""
    def __init__(self, text: str, screenshot: bytes | None = None,
                 latency_ms: float = 0.0, metadata: dict | None = None) -> None:
        self.text = text
        self.screenshot = screenshot
        self.latency_ms = latency_ms
        self.output_tokens = len(text.split())
        self.metadata = metadata or {}


class PlaywrightBrowserGenerator:
    """Drives a browser UI to send prompts and capture responses.

    This generator is stateful — it maintains a single browser context
    across multiple calls. Call :meth:`close` when done.

    Args:
        config: BrowserConfig instance or preset name (chatgpt, claude, etc.)
    """

    def __init__(self, config: BrowserConfig | str = "chatgpt") -> None:
        if isinstance(config, str):
            preset = _DEFAULT_SELECTORS.get(config, {})
            self._config = BrowserConfig(
                target=config,
                url=preset.get("url", ""),
                input_selector=preset.get("input", ""),
                send_selector=preset.get("send", ""),
                response_selector=preset.get("response", ""),
                headless=os.environ.get("PLAYWRIGHT_HEADLESS", "true").lower() == "true",
                timeout_ms=int(os.environ.get("PLAYWRIGHT_TIMEOUT_MS", "30000")),
            )
        else:
            self._config = config

        self._playwright: Any = None
        self._browser: Any = None
        self._page: Any = None

    def _ensure_browser(self) -> None:
        """Lazily initialise Playwright browser."""
        if self._page is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError(
                "playwright is required for BrowserGenerator. "
                "Install with: pip install playwright && playwright install chromium"
            ) from exc

        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=self._config.headless)
        ctx_kwargs: dict[str, Any] = {}
        if self._config.extra_headers:
            ctx_kwargs["extra_http_headers"] = self._config.extra_headers
        context = self._browser.new_context(**ctx_kwargs)
        if self._config.cookies:
            context.add_cookies(self._config.cookies)
        self._page = context.new_page()
        self._page.set_default_timeout(self._config.timeout_ms)
        if self._config.url:
            safe_url = _validate_url(self._config.url)
            self._page.goto(safe_url, wait_until="networkidle")
            time.sleep(1)

    def generate(self, prompt: str) -> BrowserGeneratorResponse:
        """Send *prompt* to the browser UI and return the response text."""
        self._ensure_browser()
        page = self._page
        start = time.time()

        try:
            # Locate and fill input
            input_el = page.locator(self._config.input_selector).first
            input_el.wait_for(state="visible", timeout=self._config.timeout_ms)
            input_el.click()
            input_el.fill(prompt)

            # Submit
            send_el = page.locator(self._config.send_selector).first
            send_el.click()

            # Wait for response
            page.wait_for_timeout(self._config.response_wait_ms)

            # Try waiting for network idle (response streaming finished)
            try:
                page.wait_for_load_state("networkidle", timeout=self._config.response_wait_ms)
            except Exception:
                pass

            # Extract response text
            response_els = page.locator(self._config.response_selector).all()
            texts = [el.inner_text() for el in response_els]
            response_text = "\n".join(texts).strip() if texts else ""

            latency_ms = (time.time() - start) * 1000

            screenshot = None
            if self._config.screenshot_on_response:
                screenshot = page.screenshot()

            return BrowserGeneratorResponse(
                text=response_text,
                screenshot=screenshot,
                latency_ms=latency_ms,
                metadata={"target": self._config.target, "url": self._config.url},
            )

        except Exception as exc:
            logger.error("Browser generator error: %s", exc)
            return BrowserGeneratorResponse(
                text="",
                latency_ms=(time.time() - start) * 1000,
                metadata={"error": str(exc)},
            )

    def close(self) -> None:
        """Clean up browser resources."""
        try:
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception as exc:
            logger.debug("Browser cleanup error: %s", exc)

    def __enter__(self) -> "PlaywrightBrowserGenerator":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
