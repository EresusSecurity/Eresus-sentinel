"""Base AIBOM reporter."""
from __future__ import annotations

from abc import ABC, abstractmethod

from sentinel.aibom.models import AIBOMResult


class BaseAIBOMReporter(ABC):
    name: str = "base"
    extension: str = "txt"

    @abstractmethod
    def render(self, result: AIBOMResult) -> str:
        ...
