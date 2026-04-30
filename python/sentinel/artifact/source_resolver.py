"""Source resolver interface — local, HuggingFace, cloud storage backends."""
from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ResolvedArtifact:
    local_path: Path
    source: str  # "local", "huggingface", "s3", "gcs", "http"
    metadata: dict[str, Any] = field(default_factory=dict)
    is_temporary: bool = False


class SourceResolver(ABC):
    """Abstract source resolver for artifact scanning."""

    @abstractmethod
    def can_resolve(self, uri: str) -> bool: ...

    @abstractmethod
    def resolve(self, uri: str) -> ResolvedArtifact: ...

    def cleanup(self, artifact: ResolvedArtifact) -> None:
        pass


class LocalResolver(SourceResolver):
    def can_resolve(self, uri: str) -> bool:
        return not uri.startswith(("http://", "https://", "s3://", "gs://", "hf://"))

    def resolve(self, uri: str) -> ResolvedArtifact:
        path = Path(uri).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Local path not found: {uri}")
        return ResolvedArtifact(local_path=path, source="local")


class HuggingFaceResolver(SourceResolver):
    def can_resolve(self, uri: str) -> bool:
        return uri.startswith("hf://") or "/" in uri and not uri.startswith(("http", "s3:", "gs:"))

    def resolve(self, uri: str) -> ResolvedArtifact:
        repo_id = uri.removeprefix("hf://")
        token = os.environ.get("HF_TOKEN", "")
        logger.info("Resolving HuggingFace repo: %s (token=%s)", repo_id, "set" if token else "unset")
        raise NotImplementedError("HuggingFace resolver requires huggingface_hub — install and set HF_TOKEN")


class HTTPResolver(SourceResolver):
    def can_resolve(self, uri: str) -> bool:
        return uri.startswith(("http://", "https://"))

    def resolve(self, uri: str) -> ResolvedArtifact:
        raise NotImplementedError("HTTP resolver is a stub — implement with httpx or requests")


class ResolverChain:
    """Chain of resolvers — tries each in order."""

    def __init__(self) -> None:
        self._resolvers: list[SourceResolver] = [
            LocalResolver(),
            HuggingFaceResolver(),
            HTTPResolver(),
        ]

    def add(self, resolver: SourceResolver) -> None:
        self._resolvers.insert(0, resolver)

    def resolve(self, uri: str) -> ResolvedArtifact:
        for resolver in self._resolvers:
            if resolver.can_resolve(uri):
                return resolver.resolve(uri)
        raise ValueError(f"No resolver found for: {uri}")
