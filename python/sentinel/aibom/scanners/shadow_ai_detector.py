"""Detect unauthorized / shadow-AI usage: LLM calls outside of configured providers."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_SHADOW_HINTS = re.compile(
    r"(requests\.post\(.*(openai|anthropic|generativelanguage|huggingface))"
    r"|httpx\.post\(.*(openai|anthropic)"
    r"|urllib\.request\.urlopen\(.*(openai|anthropic)",
    re.IGNORECASE,
)


class ShadowAIDetector(BaseAIBOMScanner):
    name = "shadow-ai-detector"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root, suffixes=(".py",)):
            text = self._read(p)
            if _SHADOW_HINTS.search(text):
                out.append(AIComponent(
                    type=AIComponentType.SHADOW_AI,
                    name=p.stem,
                    path=str(p),
                    description="Direct HTTP call to AI provider bypassing SDK",
                    evidence=["raw HTTP to AI endpoint"],
                    risks=["unsanctioned AI usage"],
                ))
        return out
