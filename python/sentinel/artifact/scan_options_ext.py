"""Extended scan options: timeout, max_files, archive_depth, byte_budget."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ExtendedScanOptions:
    timeout_seconds: int = 300
    max_files: int = 10_000
    max_file_size_bytes: int = 100_000_000  # 100MB
    archive_max_depth: int = 3
    byte_budget: int = 1_000_000_000  # 1GB total
    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    strict_mode: bool = False
    compute_hashes: bool = True
    hash_algorithms: list[str] = field(default_factory=lambda: ["sha256"])
    enable_entropy_analysis: bool = False
    enable_network_detection: bool = True
    parallel_workers: int = 1

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.timeout_seconds <= 0:
            errors.append("timeout_seconds must be positive")
        if self.max_files <= 0:
            errors.append("max_files must be positive")
        if self.max_file_size_bytes <= 0:
            errors.append("max_file_size_bytes must be positive")
        if self.archive_max_depth < 0:
            errors.append("archive_max_depth must be non-negative")
        if self.byte_budget <= 0:
            errors.append("byte_budget must be positive")
        for algo in self.hash_algorithms:
            if algo not in ("sha256", "sha512", "sha1", "md5", "blake2b"):
                errors.append(f"unsupported hash algorithm: {algo}")
        return errors
