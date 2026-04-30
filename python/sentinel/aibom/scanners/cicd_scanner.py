"""Detect AI usage in CI/CD workflow files."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_AI_HINT = re.compile(
    r"(openai|anthropic|huggingface|langchain|promptfoo|sentinel\s+redteam|"
    r"sentinel\s+scan|ai-defense|modelscan)",
    re.IGNORECASE,
)


class CICDScanner(BaseAIBOMScanner):
    name = "cicd-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root):
            if ".github/workflows" in str(p) or ".gitlab-ci" in p.name or p.name in ("Jenkinsfile", "azure-pipelines.yml"):
                text = self._read(p)
                if _AI_HINT.search(text):
                    out.append(AIComponent(
                        type=AIComponentType.CI_PIPELINE,
                        name=p.name,
                        path=str(p),
                        description="CI/CD pipeline with AI steps",
                        evidence=["ai keyword"],
                    ))
        return out
