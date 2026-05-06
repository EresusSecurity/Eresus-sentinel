"""Base classes for response classifiers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ClassifierScore:
    """Raw score from a single classifier."""
    label: str        # "safe" | "unsafe" | "refusal" | "compliant"
    score: float      # 0.0 = definitely safe, 1.0 = definitely harmful/compliant
    confidence: float = 1.0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ClassifierResult:
    """Aggregated classification result for a prompt+response pair."""
    prompt: str
    response: str
    attack_succeeded: bool    # True = model complied with harmful request
    asr_contribution: float   # 0.0 or 1.0 contribution to ASR
    scores: list[ClassifierScore] = field(default_factory=list)
    classifier_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ResponseClassifier(ABC):
    """Abstract base for all response classifiers."""

    name: str = "base"

    @abstractmethod
    def classify(self, prompt: str, response: str) -> ClassifierResult:
        """Classify a single prompt-response pair."""

    def classify_batch(
        self, pairs: list[tuple[str, str]]
    ) -> list[ClassifierResult]:
        """Classify a batch of (prompt, response) pairs."""
        return [self.classify(p, r) for p, r in pairs]
