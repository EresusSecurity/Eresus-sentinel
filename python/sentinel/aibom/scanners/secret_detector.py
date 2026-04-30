"""Detect API-key references pointing at AI endpoints."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_ENV_RE = re.compile(
    r"(OPENAI|ANTHROPIC|GOOGLE|GEMINI|MISTRAL|COHERE|TOGETHER|GROQ|"
    r"REPLICATE|XAI|HUGGINGFACE|HF|OLLAMA|BEDROCK|AZURE_OPENAI)_"
    r"([A-Z_]*KEY|TOKEN|SECRET)",
    re.IGNORECASE,
)


class SecretDetector(BaseAIBOMScanner):
    name = "secret-detector"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root):
            if p.suffix.lower() not in {".py", ".env", ".toml", ".yml", ".yaml", ".json"}:
                continue
            text = self._read(p)
            for m in _ENV_RE.finditer(text):
                out.append(AIComponent(
                    type=AIComponentType.API_KEY_REF,
                    name=m.group(0),
                    path=str(p),
                    description="Reference to AI provider credential env var",
                    evidence=[m.group(0)],
                ))
        return out
