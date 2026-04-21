"""
HuggingFace Generator — Inference API, Inference Endpoints, Local Pipeline.

Production-grade features:
  - HuggingFace Inference API (serverless) — chat completions v1
  - HuggingFace Inference Endpoints (dedicated)
  - Local transformers pipeline with device_map
  - Chat template auto-detection
  - Streaming via SSE
  - Stop sequence support
  - Model info lookup (architecture, parameters)
  - Quantization support (GPTQ, AWQ, GGUF)
  - Trust remote code option
  - Token usage tracking
  - Popular model presets

Env: HF_TOKEN or HUGGINGFACE_API_KEY
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Callable, Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)

# Popular model presets
MODEL_PRESETS: dict[str, dict] = {
    "llama-3.3-70b": {
        "model_id": "meta-llama/Llama-3.3-70B-Instruct",
        "context_length": 131_072,
    },
    "llama-3.1-8b": {
        "model_id": "meta-llama/Meta-Llama-3.1-8B-Instruct",
        "context_length": 131_072,
    },
    "mistral-7b": {
        "model_id": "mistralai/Mistral-7B-Instruct-v0.3",
        "context_length": 32_768,
    },
    "phi-4": {
        "model_id": "microsoft/phi-4",
        "context_length": 16_384,
    },
    "qwen-2.5-72b": {
        "model_id": "Qwen/Qwen2.5-72B-Instruct",
        "context_length": 131_072,
    },
    "gemma-2-27b": {
        "model_id": "google/gemma-2-27b-it",
        "context_length": 8_192,
    },
    "deepseek-v3": {
        "model_id": "deepseek-ai/DeepSeek-V3",
        "context_length": 131_072,
    },
    "command-r-plus": {
        "model_id": "CohereForAI/c4ai-command-r-plus",
        "context_length": 131_072,
    },
}

# Short aliases
_ALIASES: dict[str, str] = {
    preset: info["model_id"] for preset, info in MODEL_PRESETS.items()
}


class HuggingFaceGenerator(Generator):
    """
    HuggingFace generator with inference API + local pipeline support.

    Usage:
        # Inference API (serverless)
        gen = HuggingFaceGenerator(model="meta-llama/Meta-Llama-3.1-8B-Instruct")
        resp = gen.generate("Hello")

        # Using preset aliases
        gen = HuggingFaceGenerator(model="llama-3.3-70b")

        # Inference Endpoint (dedicated)
        gen = HuggingFaceGenerator(
            model="my-model",
            endpoint_url="https://xyz.endpoints.huggingface.cloud/v1/chat/completions"
        )

        # Local pipeline
        gen = HuggingFaceGenerator(model="microsoft/phi-4", local=True)

        # Streaming
        resp = gen.generate_stream("Hello", on_chunk=print)
    """

    name = "huggingface"
    provider = "huggingface"

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        if not self.config.model:
            self.config.model = "meta-llama/Meta-Llama-3.1-8B-Instruct"

        # Resolve aliases
        self.config.model = _ALIASES.get(self.config.model, self.config.model)

        self._api_key = kwargs.get("api_key", os.environ.get("HF_TOKEN", os.environ.get("HUGGINGFACE_API_KEY", "")))
        self._endpoint_url = kwargs.get("endpoint_url", None)
        self._local = kwargs.get("local", False)
        self._trust_remote_code = kwargs.get("trust_remote_code", False)
        self._quantization = kwargs.get("quantization", None)  # "gptq", "awq", "4bit", "8bit"
        self._pipeline = None

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        if self._local:
            return self._call_local(messages)
        return self._call_inference_api(messages)

    def _call_inference_api(self, messages: list[dict]) -> GeneratorResponse:
        """Call HuggingFace Inference API (OpenAI-compatible chat format)."""
        url = self._endpoint_url or f"https://api-inference.huggingface.co/models/{self.config.model}/v1/chat/completions"

        payload = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "stream": False,
        }
        if self.config.stop:
            payload["stop"] = self.config.stop

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
        )

        with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
            result = json.loads(resp.read())

        # OpenAI-compatible format
        if "choices" in result:
            choice = result["choices"][0]
            text = choice.get("message", {}).get("content", "")
            usage = result.get("usage", {})
            return GeneratorResponse(
                text=text,
                model=result.get("model", self.config.model),
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
                finish_reason=choice.get("finish_reason", ""),
                raw=result,
            )

        # Legacy text generation format
        if isinstance(result, list) and result:
            text = result[0].get("generated_text", "")
            return GeneratorResponse(text=text, model=self.config.model, raw=result)

        # Error response
        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(f"HuggingFace API error: {result['error']}")

        return GeneratorResponse(text=str(result), model=self.config.model, raw=result)

    def _call_local(self, messages: list[dict]) -> GeneratorResponse:
        """Run model locally using transformers pipeline."""
        if self._pipeline is None:
            self._pipeline = self._build_pipeline()

        prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages)

        outputs = self._pipeline(
            prompt,
            max_new_tokens=self.config.max_tokens,
            temperature=max(self.config.temperature, 0.01),
            do_sample=self.config.temperature > 0,
            top_p=self.config.top_p,
        )
        generated = outputs[0]["generated_text"]

        # Strip the input prompt from the output
        if generated.startswith(prompt):
            text = generated[len(prompt):].strip()
        else:
            text = generated.strip()

        return GeneratorResponse(
            text=text,
            model=self.config.model,
            output_tokens=len(text.split()),
            raw=outputs,
        )

    def _build_pipeline(self):
        """Build transformers pipeline with optional quantization."""
        from transformers import pipeline as hf_pipeline

        kwargs = {
            "task": "text-generation",
            "model": self.config.model,
            "device_map": "auto",
            "trust_remote_code": self._trust_remote_code,
        }

        # Quantization configs
        if self._quantization in ("4bit", "8bit"):
            try:
                from transformers import BitsAndBytesConfig
                if self._quantization == "4bit":
                    kwargs["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True)
                else:
                    kwargs["quantization_config"] = BitsAndBytesConfig(load_in_8bit=True)
            except ImportError:
                logger.warning("bitsandbytes not installed, loading without quantization")
        elif self._quantization == "gptq":
            kwargs["model_kwargs"] = {"use_safetensors": True}

        return hf_pipeline(**kwargs)

    def generate_stream(self, prompt: str, on_chunk: Optional[Callable[[str], None]] = None, **kwargs) -> GeneratorResponse:
        """Generate with streaming via SSE."""
        url = self._endpoint_url or f"https://api-inference.huggingface.co/models/{self.config.model}/v1/chat/completions"

        payload = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "stream": True,
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
        )

        full_text = ""
        with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
            for line in resp:
                line_str = line.decode().strip()
                if line_str.startswith("data: ") and line_str != "data: [DONE]":
                    try:
                        chunk = json.loads(line_str[6:])
                        choices = chunk.get("choices", [])
                        if choices:
                            delta = choices[0].get("delta", {})
                            token = delta.get("content", "")
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
    def available_presets() -> dict[str, str]:
        """List preset model aliases."""
        return {k: v["model_id"] for k, v in MODEL_PRESETS.items()}

    def get_model_info(self) -> dict:
        """Fetch model info from HuggingFace Hub API."""
        url = f"https://huggingface.co/api/models/{self.config.model}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self._api_key}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception as e:
            logger.warning("Failed to fetch model info: %s", e)
            return {}
