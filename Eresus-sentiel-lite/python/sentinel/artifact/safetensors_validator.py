"""
Safetensors Header Validator.

Validates .safetensors model files for:
- Oversized headers (DoS vector)
- Suspicious metadata keys
- Non-standard tensor names
- Header JSON injection

Safetensors is designed as a safe serialization format, but the
metadata header (JSON) can still contain injected strings.
"""

from __future__ import annotations

import json
import logging
import struct
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity, Location

logger = logging.getLogger(__name__)

# Safetensors format: 8-byte LE header size + JSON header + tensor data
HEADER_SIZE_BYTES = 8
MAX_SAFE_HEADER_SIZE = 100 * 1024 * 1024  # 100 MB — anything larger is suspicious
WARN_HEADER_SIZE = 10 * 1024 * 1024       # 10 MB — generate a warning

# Suspicious metadata keys that shouldn't appear in legitimate models
SUSPICIOUS_METADATA_KEYS = {
    "exec", "eval", "system", "cmd", "command", "shell",
    "script", "payload", "exploit", "backdoor", "inject",
    "password", "secret", "token", "api_key", "credential",
}

# Known legitimate metadata keys
KNOWN_METADATA_KEYS = {
    "format", "dtype", "shape", "data_offsets",
    "__metadata__",
}


class SafetensorsValidator:
    """
    Validates safetensors model files for header anomalies.

    While safetensors prevents code execution by design (no pickle),
    the JSON header can still be maliciously crafted:
    - Oversized headers (memory DoS)
    - Injected metadata strings
    - Prompt injection via tensor name fields
    """

    def __init__(
        self,
        max_header_size: int = MAX_SAFE_HEADER_SIZE,
        warn_header_size: int = WARN_HEADER_SIZE,
    ):
        self._max_header_size = max_header_size
        self._warn_header_size = warn_header_size

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        """
        Validate a safetensors file.

        Args:
            file_path: Path to the .safetensors file.

        Returns:
            List of Finding objects (empty if file is clean).
        """
        path = Path(file_path)
        if not path.exists():
            logger.warning("File not found: %s", path)
            return []

        findings: list[Finding] = []
        source = str(path)

        # Read header size (first 8 bytes)
        with open(path, "rb") as f:
            size_bytes = f.read(HEADER_SIZE_BYTES)
            if len(size_bytes) < HEADER_SIZE_BYTES:
                findings.append(Finding.artifact(
                    rule_id="ARTIFACT-030",
                    title="Truncated safetensors file",
                    description=f"File '{source}' is too short to contain a valid safetensors header.",
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"File size: {path.stat().st_size} bytes, expected at least {HEADER_SIZE_BYTES}",
                ))
                return findings

            header_size = struct.unpack("<Q", size_bytes)[0]

            # Check header size
            if header_size > self._max_header_size:
                findings.append(Finding.artifact(
                    rule_id="ARTIFACT-031",
                    title="Oversized safetensors header (potential DoS)",
                    description=(
                        f"File '{source}' has a header size of {header_size:,} bytes "
                        f"(max allowed: {self._max_header_size:,}). This could cause "
                        f"out-of-memory conditions when loading the model."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"Header size: {header_size:,} bytes",
                    remediation="Verify the model file integrity. Regenerate from source if corrupted.",
                ))
                return findings

            if header_size > self._warn_header_size:
                findings.append(Finding.artifact(
                    rule_id="ARTIFACT-032",
                    title="Large safetensors header",
                    description=(
                        f"File '{source}' has an unusually large header ({header_size:,} bytes). "
                        f"While not necessarily malicious, this warrants inspection."
                    ),
                    severity=Severity.LOW,
                    target=source,
                    evidence=f"Header size: {header_size:,} bytes",
                ))

            # Read and parse header JSON
            header_bytes = f.read(header_size)
            if len(header_bytes) < header_size:
                findings.append(Finding.artifact(
                    rule_id="ARTIFACT-033",
                    title="Truncated safetensors header",
                    description=f"Header declares {header_size} bytes but only {len(header_bytes)} available.",
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"Declared: {header_size}, actual: {len(header_bytes)}",
                ))
                return findings

        # Parse header JSON
        try:
            header = json.loads(header_bytes)
        except json.JSONDecodeError as e:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-034",
                title="Invalid safetensors header JSON",
                description=f"Failed to parse header JSON in '{source}': {e}",
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"JSON error: {e}",
            ))
            return findings

        # Validate header content
        findings.extend(self._validate_header(header, source))

        return findings

    def _validate_header(self, header: dict, source: str) -> list[Finding]:
        """Validate the parsed safetensors header for suspicious content."""
        findings: list[Finding] = []

        # Check metadata section
        metadata = header.get("__metadata__", {})
        if metadata:
            findings.extend(self._check_metadata(metadata, source))

        # Check tensor names for injection patterns
        for key in header:
            if key == "__metadata__":
                continue

            # Tensor names should be simple identifiers
            if self._is_suspicious_tensor_name(key):
                findings.append(Finding.artifact(
                    rule_id="ARTIFACT-036",
                    title="Suspicious tensor name in safetensors",
                    description=(
                        f"Tensor name '{key[:100]}' in '{source}' contains patterns "
                        f"that could be used for prompt injection or social engineering "
                        f"when the model structure is printed/logged."
                    ),
                    severity=Severity.LOW,
                    target=source,
                    evidence=f"Tensor name: {key[:200]}",
                ))

        return findings

    def _check_metadata(self, metadata: dict, source: str) -> list[Finding]:
        """Check metadata section for suspicious keys/values."""
        findings: list[Finding] = []

        for key, value in metadata.items():
            key_lower = key.lower()

            # Check for suspicious key names
            if key_lower in SUSPICIOUS_METADATA_KEYS:
                findings.append(Finding.artifact(
                    rule_id="ARTIFACT-035",
                    title=f"Suspicious metadata key: {key}",
                    description=(
                        f"Metadata key '{key}' in '{source}' matches a suspicious "
                        f"pattern. While safetensors prevents code execution, "
                        f"metadata can carry injected instructions."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"Key: {key}, Value: {str(value)[:200]}",
                ))

            # Check for very long values (potential injection payload)
            if isinstance(value, str) and len(value) > 10000:
                findings.append(Finding.artifact(
                    rule_id="ARTIFACT-037",
                    title="Oversized metadata value in safetensors",
                    description=(
                        f"Metadata key '{key}' has a value of {len(value):,} characters. "
                        f"Unusually large metadata values may contain injected content."
                    ),
                    severity=Severity.LOW,
                    target=source,
                    evidence=f"Key: {key}, Value length: {len(value):,} chars",
                ))

        return findings

    def _is_suspicious_tensor_name(self, name: str) -> bool:
        """Check if a tensor name contains injection patterns."""
        suspicious_patterns = [
            "ignore", "system:", "assistant:", "user:",
            "<script", "javascript:", "eval(", "exec(",
            "\\n\\n", "IMPORTANT:", "INSTRUCTION:",
        ]
        name_lower = name.lower()
        return any(p.lower() in name_lower for p in suspicious_patterns)
