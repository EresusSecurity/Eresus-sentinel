"""
Red Team Generator Adapters.

Adapters for communicating with target LLM systems.
Each adapter handles the protocol specifics for different backends.

Capabilities:
- Adapter-based design for different LLM backends
- Supports local (ollama/llama.cpp) and API (OpenAI/Anthropic) targets
- Handles conversation state for multi-turn probes
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Optional

from sentinel.redteam.attempt import Attempt, AttemptStatus

logger = logging.getLogger(__name__)


class Generator(ABC):
    """
    Base class for target LLM adapters.

    Generators send attack prompts to target LLMs and capture responses.
    Each backend (OpenAI, Anthropic, Ollama, etc.) has its own adapter.
    """

    generator_name: str = "base"

    @abstractmethod
    def generate(self, attempt: Attempt) -> Attempt:
        """
        Send the probe prompt to the target LLM and capture the response.

        Args:
            attempt: Attempt with prompt to send.

        Returns:
            Updated Attempt with response filled in.
        """
        pass

    def generate_batch(self, attempts: list[Attempt]) -> list[Attempt]:
        """Generate responses for multiple attempts."""
        return [self.generate(a) for a in attempts]


class OllamaGenerator(Generator):
    """
    Generator for Ollama local inference.
    Connects to a running Ollama instance.
    """

    generator_name = "ollama"

    def __init__(
        self,
        model: str = "llama3.2",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.7,
    ):
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._temperature = temperature

    def generate(self, attempt: Attempt) -> Attempt:
        try:
            import urllib.request

            messages = [
                {"role": m.role, "content": m.content}
                for m in attempt.conversation
            ]

            payload = json.dumps({
                "model": self._model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": self._temperature},
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self._base_url}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read())

            response_text = result.get("message", {}).get("content", "")
            attempt.response = response_text
            attempt.status = AttemptStatus.RECEIVED
            attempt.add_assistant_message(response_text)

        except Exception as e:
            logger.error("Ollama generation failed: %s", e)
            attempt.status = AttemptStatus.FAILED
            attempt.metadata["error"] = str(e)

        return attempt


class OpenAIGenerator(Generator):
    """
    Generator for OpenAI API.
    Requires OPENAI_API_KEY environment variable.
    """

    generator_name = "openai"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        temperature: float = 0.7,
    ):
        import os
        self._model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._base_url = base_url.rstrip("/")
        self._temperature = temperature

    def generate(self, attempt: Attempt) -> Attempt:
        if not self._api_key:
            attempt.status = AttemptStatus.FAILED
            attempt.metadata["error"] = "OPENAI_API_KEY not set"
            return attempt

        try:
            import urllib.request

            messages = [
                {"role": m.role, "content": m.content}
                for m in attempt.conversation
            ]

            payload = json.dumps({
                "model": self._model,
                "messages": messages,
                "temperature": self._temperature,
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self._base_url}/chat/completions",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._api_key}",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read())

            response_text = result["choices"][0]["message"]["content"]
            attempt.response = response_text
            attempt.status = AttemptStatus.RECEIVED
            attempt.add_assistant_message(response_text)

        except Exception as e:
            logger.error("OpenAI generation failed: %s", e)
            attempt.status = AttemptStatus.FAILED
            attempt.metadata["error"] = str(e)

        return attempt


class EchoGenerator(Generator):
    """
    Test generator that echoes the prompt.
    Useful for testing probe/detector pipelines.
    """

    generator_name = "echo"

    def generate(self, attempt: Attempt) -> Attempt:
        attempt.response = f"Echo: {attempt.prompt}"
        attempt.status = AttemptStatus.RECEIVED
        attempt.add_assistant_message(attempt.response)
        return attempt
