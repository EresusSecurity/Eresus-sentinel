"""Classify LLM provider endpoints found in configuration or source."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_PROVIDERS = [
    (r"api\.openai\.com", "openai"),
    (r"api\.anthropic\.com", "anthropic"),
    (r"generativelanguage\.googleapis\.com", "google"),
    (r"api\.cohere\.com", "cohere"),
    (r"api\.mistral\.ai", "mistral"),
    (r"api\.together\.xyz", "together"),
    (r"api\.groq\.com", "groq"),
    (r"api\.x\.ai", "xai"),
    (r"api\.replicate\.com", "replicate"),
    (r"localhost:11434", "ollama"),
    (r"api-inference\.huggingface\.co", "huggingface"),
    (r"bedrock-runtime", "bedrock"),
    (r"openai\.azure\.com", "azure-openai"),
]


class EndpointClassifier(BaseAIBOMScanner):
    name = "endpoint-classifier"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        seen: set[str] = set()
        for p in self._iter_files(root):
            if p.suffix.lower() not in {".py", ".env", ".toml", ".yml", ".yaml", ".json", ".md"}:
                continue
            text = self._read(p)
            for pattern, provider in _PROVIDERS:
                if re.search(pattern, text):
                    key = f"{provider}|{p}"
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(AIComponent(
                        type=AIComponentType.ENDPOINT,
                        name=provider,
                        path=str(p),
                        description=f"LLM endpoint: {provider}",
                        evidence=[pattern],
                    ))
        return out
