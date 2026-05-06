"""
Eresus Sentinel — Red Team Generators Package.

Generator adapters for connecting to target LLMs during red-team assessments.
Each generator provides a unified interface for sending prompts and receiving responses.

Supported backends (14):
  - OpenAI (GPT-5.4, GPT-5.4-pro/mini/nano, GPT-5.3-Codex, GPT-OSS, o3/o4-mini)
  - Anthropic (Claude Opus 4.6, Sonnet 4.6, Haiku 4.5)
  - Azure OpenAI (Azure-hosted GPT-5.4 deployments)
  - Google Gemini (Gemini 3.1 Pro, Gemini 3 Flash, 3.1 Flash-Lite)
  - HuggingFace Inference API + local transformers pipeline
  - Ollama (local — Llama 3.3, Qwen3, Gemma3, etc.)
  - Groq (Llama 4 Scout, Llama 3.3, GPT-OSS, Qwen3)
  - Together AI (DeepSeek-V3.1, DeepSeek-R1, Qwen3.5-397B)
  - LiteLLM (universal proxy — 100+ providers)
  - Generic REST API (any OpenAI-compatible endpoint)
  - Echo (testing)
  - Function (custom callable)
  - WebSocket (streaming WebSocket target)
  - OpenRouter (300+ models via single API key)
"""

from sentinel.redteam.generators.anthropic import AnthropicGenerator
from sentinel.redteam.generators.azure import AzureOpenAIGenerator
from sentinel.redteam.generators.base import Generator, GeneratorResponse
from sentinel.redteam.generators.echo import EchoGenerator
from sentinel.redteam.generators.function import FunctionGenerator
from sentinel.redteam.generators.gemini import GeminiGenerator
from sentinel.redteam.generators.groq import GroqGenerator
from sentinel.redteam.generators.huggingface import HuggingFaceGenerator
from sentinel.redteam.generators.litellm import LiteLLMGenerator
from sentinel.redteam.generators.ollama import OllamaGenerator
from sentinel.redteam.generators.openai import OpenAIGenerator
from sentinel.redteam.generators.rest import RESTGenerator
from sentinel.redteam.generators.openrouter import OpenRouterGenerator
from sentinel.redteam.generators.together import TogetherGenerator
from sentinel.redteam.generators.websocket import WebSocketGenerator

__all__ = [
    "Generator", "GeneratorResponse",
    "OpenAIGenerator", "AnthropicGenerator", "AzureOpenAIGenerator",
    "GeminiGenerator", "HuggingFaceGenerator", "OllamaGenerator",
    "GroqGenerator", "TogetherGenerator", "LiteLLMGenerator",
    "RESTGenerator", "EchoGenerator", "FunctionGenerator",
    "WebSocketGenerator", "OpenRouterGenerator",
]

GENERATOR_REGISTRY = {
    "openai": OpenAIGenerator,
    "anthropic": AnthropicGenerator,
    "azure": AzureOpenAIGenerator,
    "gemini": GeminiGenerator,
    "huggingface": HuggingFaceGenerator,
    "ollama": OllamaGenerator,
    "groq": GroqGenerator,
    "together": TogetherGenerator,
    "litellm": LiteLLMGenerator,
    "rest": RESTGenerator,
    "echo": EchoGenerator,
    "function": FunctionGenerator,
    "websocket": WebSocketGenerator,
    "openrouter": OpenRouterGenerator,
}


def get_generator(name: str, **kwargs) -> Generator:
    """Factory function to get a generator by name."""
    cls = GENERATOR_REGISTRY.get(name.lower())
    if cls is None:
        raise ValueError(f"Unknown generator: {name}. Available: {list(GENERATOR_REGISTRY.keys())}")
    return cls(**kwargs)
