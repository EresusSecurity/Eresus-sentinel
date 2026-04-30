"""Multi-repo input model for scanning multiple repositories into a unified BOM."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.aibom.models import AIBOMResult

logger = logging.getLogger(__name__)


@dataclass
class RepoInput:
    path: Path
    name: str = ""
    ref: str = ""  # git ref (branch, tag, commit)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.path.name


@dataclass
class MultiRepoConfig:
    repos: list[RepoInput] = field(default_factory=list)
    merge_strategy: str = "union"  # "union" or "independent"
    dedup_cross_repo: bool = True

    def add(self, path: Path, name: str = "", ref: str = "") -> None:
        self.repos.append(RepoInput(path=path, name=name, ref=ref))

    @property
    def repo_count(self) -> int:
        return len(self.repos)


def merge_results(results: dict[str, AIBOMResult], config: MultiRepoConfig) -> AIBOMResult:
    """Merge multiple per-repo AIBOM results into a single unified result."""
    merged = AIBOMResult()
    merged.metadata["multi_repo"] = True
    merged.metadata["repo_count"] = len(results)
    merged.metadata["repos"] = list(results.keys())

    seen_keys: set[str] = set()

    for repo_name, result in results.items():
        for comp in result.components:
            comp.properties["source_repo"] = repo_name
            if config.dedup_cross_repo:
                key = f"{comp.type.value}:{comp.name}:{comp.version}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)
            merged.add(comp)
        merged.relationships.extend(result.relationships)

    logger.info("Merged %d repos: %d components, %d relationships",
                len(results), len(merged.components), len(merged.relationships))
    return merged
