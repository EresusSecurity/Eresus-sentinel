"""Generic base classes for the fuzzer infrastructure."""

from __future__ import annotations

import enum
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


class PayloadCategory(str, enum.Enum):
    """Universal payload categories across all fuzzer backends."""
    RCE = "rce"
    SSTI = "ssti"
    DESERIALIZATION = "deserialization"
    CODE_INJECTION = "code_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    PROMPT_INJECTION = "prompt_injection"
    TOOL_ABUSE = "tool_abuse"
    DATA_EXFILTRATION = "data_exfiltration"
    RAG_POISONING = "rag_poisoning"
    JAILBREAK = "jailbreak"
    OBFUSCATION = "obfuscation"
    EVASION = "evasion"
    BENIGN = "benign"


@dataclass
class Payload:
    """A single fuzz payload."""
    name: str
    category: PayloadCategory
    data: bytes
    description: str = ""
    severity_expected: str = "CRITICAL"
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    @property
    def is_malicious(self) -> bool:
        return self.category != PayloadCategory.BENIGN

    def __repr__(self) -> str:
        return (
            f"Payload(name={self.name!r}, category={self.category.value}, "
            f"size={len(self.data)}, malicious={self.is_malicious})"
        )


@dataclass
class FuzzConfig:
    """Configuration for a fuzzing session."""
    # Generation
    samples: int = 10000
    seed: Optional[int] = None
    min_opcodes: int = 10
    max_opcodes: int = 300

    # Mutation
    mutation_rate: float = 0.1
    mutators: list[str] = field(default_factory=lambda: ["all"])
    unsafe_mutations: bool = False

    # Output
    output_dir: Optional[str] = None
    output_file: Optional[str] = None

    # Protocol (pickle-specific, but generic enough)
    protocol: Optional[int] = None  # None = random

    # Pipeline
    scan_after_generate: bool = False
    store_results: bool = True

    # Flags
    allow_ext: bool = False
    allow_buffer: bool = False
    allow_persistent_ids: bool = False


@dataclass
class FuzzResult:
    """Result of fuzzing a single payload through the detection pipeline."""
    payload: Payload
    detected: bool = False
    findings_count: int = 0
    max_severity: str = "NONE"
    detection_time_ms: float = 0.0
    scanner_crashed: bool = False
    error: Optional[str] = None

    @property
    def is_bypass(self) -> bool:
        """Malicious payload that was NOT detected — a scanner gap."""
        return self.payload.is_malicious and not self.detected

    @property
    def is_false_positive(self) -> bool:
        """Benign payload that WAS detected — noisy scanner."""
        return not self.payload.is_malicious and self.detected


class Generator(ABC):
    """Abstract base for format-specific sample generators."""

    @abstractmethod
    def generate(self, seed: Optional[int] = None) -> bytes:
        """Generate a single random valid sample."""
        ...

    @abstractmethod
    def generate_from_bytes(self, data: bytes) -> bytes:
        """Deterministic generation from fuzzer input bytes."""
        ...

    def generate_batch(self, count: int, seed: Optional[int] = None) -> list[bytes]:
        """Generate multiple samples. Override for parallelism."""
        import random as _random
        rng = _random.Random(seed)
        results = []
        for _i in range(count):
            sample_seed = rng.randint(0, 2**64 - 1)
            results.append(self.generate(seed=sample_seed))
        return results


class Mutator(ABC):
    """Abstract base for format-specific mutators."""

    @abstractmethod
    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        """Apply mutations to an existing sample."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable mutator name (e.g. 'bitflip')."""
        ...
