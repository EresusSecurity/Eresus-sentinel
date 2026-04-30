"""
Ollama Generator — production-grade local LLM inference.

Features:
  - Full Ollama REST API support (/api/chat, /api/generate)
  - Model management (pull, list, show, delete)
  - Streaming support with chunk callbacks
  - System prompt injection
  - Context window management (num_ctx)
  - GPU layer control (num_gpu)
  - Keep-alive management
  - Multimodal support (images)
  - Performance metrics (eval rate, load time)
  - Health check and connection validation

Env: OLLAMA_HOST (default: http://localhost:11434)
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Callable, Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)

# Model context window sizes (common models)
_MODEL_CONTEXTS: dict[str, int] = {
    "llama3.3": 128_000, "llama3.1": 128_000, "llama3": 8_192,
    "llama4-scout": 512_000, "llama4-maverick": 1_048_576,
    "qwen3": 40_960, "qwen2.5": 32_768,
    "gemma3": 128_000, "gemma2": 8_192,
    "deepseek-r1": 65_536, "deepseek-v3": 65_536,
    "phi4": 16_384, "phi3": 128_000,
    "mistral": 32_768, "mixtral": 32_768,
    "codellama": 16_384, "starcoder2": 16_384,
    "command-r": 128_000, "command-r-plus": 128_000,
}


class OllamaGenerator(Generator):
    """
    Production-grade local LLM inference via Ollama.

    Usage:
        gen = OllamaGenerator(model="llama3.3")
        resp = gen.generate("Explain quantum computing")

        # With custom settings
        gen = OllamaGenerator(
            model="deepseek-r1:14b",
            num_ctx=32768,
            num_gpu=99,
            system="You are a security researcher.",
        )

        # Auto-pull model if not available
        gen = OllamaGenerator(model="qwen3:8b", auto_pull=True)

        # Streaming with callback
        gen = OllamaGenerator(model="llama3.3")
        resp = gen.generate_stream("Hello", on_chunk=print)
    """

    name = "ollama"
    provider = "ollama"
    supports_streaming = True

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        if not self.config.model:
            self.config.model = "llama3.3"

        self._base_url = kwargs.get("base_url", os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
        self._base_url = self._base_url.rstrip("/")
        self._num_ctx = kwargs.get("num_ctx", None)
        self._num_gpu = kwargs.get("num_gpu", None)
        self._system = kwargs.get("system", None)
        self._keep_alive = kwargs.get("keep_alive", "5m")
        self._auto_pull = kwargs.get("auto_pull", False)
        self._images = kwargs.get("images", None)  # For multimodal
        self._mirostat = kwargs.get("mirostat", 0)
        self._repeat_penalty = kwargs.get("repeat_penalty", 1.1)

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        # Prepend system prompt if configured
        if self._system and not any(m.get("role") == "system" for m in messages):
            messages = [{"role": "system", "content": self._system}] + messages

        # Add images to last message if multimodal
        if self._images and messages:
            messages[-1]["images"] = self._images

        options = {
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "num_predict": self.config.max_tokens,
            "repeat_penalty": self._repeat_penalty,
        }
        if self._mirostat:
            options["mirostat"] = self._mirostat
        if self.config.stop:
            options["stop"] = self.config.stop
        if self.config.seed is not None:
            options["seed"] = self.config.seed
        if self._num_ctx:
            options["num_ctx"] = self._num_ctx
        if self._num_gpu is not None:
            options["num_gpu"] = self._num_gpu

        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": options,
            "keep_alive": self._keep_alive,
        }

        try:
            result = self._post("/api/chat", payload)
        except urllib.error.HTTPError as e:
            if e.code == 404 and self._auto_pull:
                logger.info("Model %s not found, pulling...", self.config.model)
                self.pull_model(self.config.model)
                result = self._post("/api/chat", payload)
            else:
                raise

        text = result.get("message", {}).get("content", "")
        eval_count = result.get("eval_count", 0)
        prompt_count = result.get("prompt_eval_count", 0)

        # Performance metrics
        eval_duration = result.get("eval_duration", 0)
        load_duration = result.get("load_duration", 0)
        total_duration = result.get("total_duration", 0)
        tokens_per_sec = (eval_count / (eval_duration / 1e9)) if eval_duration > 0 else 0

        return GeneratorResponse(
            text=text,
            model=result.get("model", self.config.model),
            input_tokens=prompt_count,
            output_tokens=eval_count,
            total_tokens=prompt_count + eval_count,
            finish_reason=result.get("done_reason", ""),
            raw={
                **result,
                "_perf": {
                    "tokens_per_sec": round(tokens_per_sec, 2),
                    "load_ms": round(load_duration / 1e6, 2) if load_duration else 0,
                    "total_ms": round(total_duration / 1e6, 2) if total_duration else 0,
                },
            },
        )

    def generate_stream(self, prompt: str, on_chunk: Optional[Callable[[str], None]] = None, **kwargs) -> GeneratorResponse:
        """Generate with streaming — calls on_chunk for each token."""
        messages = [{"role": "user", "content": prompt}]
        if self._system:
            messages = [{"role": "system", "content": self._system}] + messages

        options = {
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "num_predict": self.config.max_tokens,
        }
        if self.config.seed is not None:
            options["seed"] = self.config.seed

        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": True,
            "options": options,
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self._base_url}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
        )

        full_text = ""
        final_result = {}

        with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
            for line in resp:
                chunk = json.loads(line)
                if "message" in chunk:
                    token = chunk["message"].get("content", "")
                    full_text += token
                    if on_chunk:
                        on_chunk(token)
                if chunk.get("done"):
                    final_result = chunk

        eval_count = final_result.get("eval_count", len(full_text.split()))
        prompt_count = final_result.get("prompt_eval_count", 0)

        return GeneratorResponse(
            text=full_text,
            model=self.config.model,
            input_tokens=prompt_count,
            output_tokens=eval_count,
            total_tokens=prompt_count + eval_count,
            finish_reason=final_result.get("done_reason", "stop"),
            raw=final_result,
        )

    # ── Model Management ─────────────────────────────────────────────

    def pull_model(self, model: str) -> dict:
        """Pull a model from Ollama registry."""
        logger.info("Pulling model: %s", model)
        return self._post("/api/pull", {"name": model, "stream": False})

    def list_models(self) -> list[dict]:
        """List all locally available models."""
        result = self._get("/api/tags")
        return result.get("models", [])

    def show_model(self, model: str | None = None) -> dict:
        """Show model details (parameters, template, license)."""
        return self._post("/api/show", {"name": model or self.config.model})

    def delete_model(self, model: str) -> bool:
        """Delete a local model."""
        try:
            req = urllib.request.Request(
                f"{self._base_url}/api/delete",
                data=json.dumps({"name": model}).encode(),
                headers={"Content-Type": "application/json"},
                method="DELETE",
            )
            urllib.request.urlopen(req, timeout=10)
            return True
        except Exception as e:
            logger.error("Failed to delete model %s: %s", model, e)
            return False

    # ── Health Check ──────────────────────────────────────────────────

    def is_healthy(self) -> bool:
        """Check if Ollama server is reachable."""
        try:
            req = urllib.request.Request(f"{self._base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5):
                return True
        except Exception:
            return False

    def get_context_length(self, model: str | None = None) -> int:
        """Get context window size for a model."""
        m = (model or self.config.model).split(":")[0]
        return _MODEL_CONTEXTS.get(m, 4096)

    # ── HTTP Helpers ──────────────────────────────────────────────────

    def _post(self, path: str, payload: dict) -> dict:
        """Send POST request to Ollama API."""
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self._base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
            return json.loads(resp.read())

    def _get(self, path: str) -> dict:
        """Send GET request to Ollama API."""
        req = urllib.request.Request(f"{self._base_url}{path}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
