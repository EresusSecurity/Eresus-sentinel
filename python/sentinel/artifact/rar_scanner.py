"""RAR archive scanner.

Python's standard library cannot inspect RAR contents. Treat RAR model
containers as fail-closed so they are never silently skipped.
"""

from __future__ import annotations

from pathlib import Path

from ..finding import Finding, Severity

RAR_MAGIC = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")


class RARScanner:
    """Emit fail-closed findings for unsupported RAR archives."""

    def scan_file(self, filepath: str) -> list[Finding]:
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() != ".rar":
            return []

        try:
            header = path.read_bytes()[:8]
        except OSError as exc:
            return [
                Finding.artifact(
                    rule_id="RAR-002",
                    title="RAR archive could not be read",
                    description=str(exc),
                    severity=Severity.HIGH,
                    target=filepath,
                    confidence=0.9,
                )
            ]

        if not any(header.startswith(magic) for magic in RAR_MAGIC):
            return [
                Finding.artifact(
                    rule_id="RAR-001",
                    title="Invalid or obfuscated RAR archive",
                    description="The file uses a .rar extension but does not expose a valid RAR signature.",
                    severity=Severity.HIGH,
                    target=filepath,
                    evidence=header.hex(),
                    confidence=0.85,
                )
            ]

        return [
            Finding.artifact(
                rule_id="RAR-UNSUPPORTED",
                title="RAR archive scanning is unsupported",
                description=(
                    "RAR archives can hide model artifacts and executable payloads, "
                    "but no safe RAR extractor is configured. Treat this artifact as "
                    "inconclusive until it is unpacked in a sandbox and rescanned."
                ),
                severity=Severity.HIGH,
                target=filepath,
                evidence=header.hex(),
                cwe_ids=["CWE-502"],
                confidence=0.95,
            )
        ]
