"""CVE pattern detector for known model/artifact vulnerabilities."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sentinel.finding import Finding, Severity


@dataclass
class CVEPattern:
    cve_id: str
    description: str
    severity: Severity
    file_patterns: list[str] = field(default_factory=list)
    content_patterns: list[str] = field(default_factory=list)
    framework: str = ""


_KNOWN_CVE_PATTERNS: list[CVEPattern] = [
    CVEPattern(
        cve_id="CVE-2024-3660",
        description="Keras Lambda layer arbitrary code execution",
        severity=Severity.CRITICAL,
        content_patterns=[r'"class_name"\s*:\s*"Lambda"', r"keras.*Lambda\s*\("],
        framework="keras",
    ),
    CVEPattern(
        cve_id="CVE-2024-5480",
        description="PyTorch torch.load arbitrary code execution via pickle",
        severity=Severity.HIGH,
        content_patterns=[r"torch\.load\s*\("],
        file_patterns=[r"\.pt$", r"\.pth$", r"\.pkl$"],
        framework="pytorch",
    ),
    CVEPattern(
        cve_id="CVE-2023-47248",
        description="PyArrow IPC deserialization vulnerability",
        severity=Severity.HIGH,
        content_patterns=[r"pyarrow\.ipc", r"pa\.ipc\.open_file"],
        framework="pyarrow",
    ),
    CVEPattern(
        cve_id="CVE-2024-34359",
        description="llama.cpp GGUF parser buffer overflow",
        severity=Severity.HIGH,
        file_patterns=[r"\.gguf$"],
        framework="llama-cpp",
    ),
]


class CVEPatternDetector:
    """Detect known CVE patterns in artifact files."""

    def __init__(self, patterns: list[CVEPattern] | None = None) -> None:
        self._patterns = patterns or list(_KNOWN_CVE_PATTERNS)
        self._compiled: list[tuple[CVEPattern, list[re.Pattern], list[re.Pattern]]] = []
        for p in self._patterns:
            content_rx = [re.compile(rx) for rx in p.content_patterns]
            file_rx = [re.compile(rx) for rx in p.file_patterns]
            self._compiled.append((p, content_rx, file_rx))

    def check_file(self, filepath: str, content: str | bytes | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, content_rxs, file_rxs in self._compiled:
            file_match = any(rx.search(filepath) for rx in file_rxs) if file_rxs else False
            content_match = False
            if content and content_rxs:
                text = content if isinstance(content, str) else content.decode("utf-8", errors="replace")
                content_match = any(rx.search(text) for rx in content_rxs)

            if file_match or content_match:
                findings.append(Finding.artifact(
                    rule_id=f"CVE-{pattern.cve_id}",
                    title=pattern.cve_id,
                    description=f"{pattern.cve_id}: {pattern.description}",
                    severity=pattern.severity,
                    confidence=0.85 if content_match else 0.5,
                    target=filepath,
                ))
        return findings

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)
