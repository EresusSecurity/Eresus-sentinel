"""GGUF model analyzer — header overflow, Jinja2 SSTI, tensor bounds."""

from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

# ── GGUF constants ────────────────────────────────────────────────

GGUF_MAGIC_BYTES = b"GGUF"
SUPPORTED_VERSIONS = {2, 3}
GGUF_V3_DEFAULT_ALIGNMENT = 32

# ── GGUF value type IDs ──────────────────────────────────────────

GGUF_TYPE_UINT8 = 0
GGUF_TYPE_INT8 = 1
GGUF_TYPE_UINT16 = 2
GGUF_TYPE_INT16 = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_BOOL = 7
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9
GGUF_TYPE_UINT64 = 10
GGUF_TYPE_INT64 = 11
GGUF_TYPE_FLOAT64 = 12

# Size of each type in bytes (for overflow calculations)
GGUF_TYPE_SIZES = {
    0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4,
    6: 4, 7: 1, 8: None, 9: None,  # Variable size
    10: 8, 11: 8, 12: 8,
}

# ── Prompt injection patterns ────────────────────────────────────

INJECTION_PATTERNS = [
    # Direct prompt injection
    "ignore previous", "ignore above", "ignore all",
    "disregard", "forget your instructions",
    "override your", "bypass your",
    # Role injection
    "system:", "assistant:", "user:",
    "IMPORTANT:", "INSTRUCTION:", "COMMAND:",
    "you are now", "new persona", "act as",
    "pretend you are", "roleplay as",
    # Web injection
    "<script", "javascript:", "on_error=", "onerror=",
    # Code injection (can affect some GGUF consumers)
    "eval(", "exec(", "os.system", "subprocess",
    "__import__", "__reduce__",
    # Social engineering
    "never reveal", "do not tell", "keep secret",
    "always respond with", "you must always",
]

# ── Jinja2 SSTI patterns ─────────────────────────────────────────

JINJA2_SSTI_PATTERNS = [
    # Object traversal (classic CVE-2024-34359 "Llama Drama")
    "{{ self.__class__", "{{ self._TemplateReference",
    "{{ config[", "{{ config.items",
    "{{request.", "{{session.",
    "{{ ''.__class__", "{{ \"\".__class__",
    ".__mro__", ".__subclasses__",
    ".__globals__", ".__builtins__",
    "__getitem__", "__init__",
    # RCE via Jinja2
    "{% import ", "{% from ",
    "{% set ", "{% if ",
    "{{ cycler.__init__", "{{ joiner.__init__",
    "{{ namespace.__init__",
    # lipsum/range abuse
    "{{ lipsum.__globals__",
    "{{ range.__init__",
    # Direct exec/eval
    "popen(", "subprocess", "os.system",
    "import os", "__import__",
    # Jinja2 filter-based SSTI bypass (sandbox escape via |attr)
    "|attr(", "|attr (",
    "\"__class__\"|attr", "'__class__'|attr",
    "|join|attr", "|string|attr",
    "|list|attr", "|format(",
    # Jinja2 internal object access via request/g/config
    "get_flashed_messages", "url_for(",
    # Base64 obfuscated SSTI payloads
    "b64decode", "decode('base64')",
    "decode('rot13')", "decode('unicode_escape')",
    # Python class hierarchy traversal (Checkmarx patterns)
    "().__class__", "[].__class__", "{}.__class__",
]

# Maximum reasonable values for header fields
MAX_REASONABLE_KV_COUNT = 100_000
MAX_REASONABLE_TENSOR_COUNT = 100_000
MAX_REASONABLE_STRING_LENGTH = 10 * 1024 * 1024  # 10MB
MAX_METADATA_SECTION_SIZE = 100 * 1024 * 1024  # 100MB


class GGUFAnalyzer:
    """
    Advanced GGUF analyzer with heap overflow detection
    and Jinja2 SSTI analysis for chat_template fields.
    """

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        """Analyze a GGUF file for all known security issues."""
        path = Path(file_path)
        if not path.exists():
            logger.warning("File not found: %s", path)
            return []

        findings: list[Finding] = []
        source = str(path)
        file_size = path.stat().st_size

        with open(path, "rb") as f:
            # ── Parse and validate header ──
            header = self._parse_header(f, source, file_size)
            if header is None:
                findings.append(Finding.artifact(
                    rule_id="GGUF-001",
                    title="Invalid GGUF file header",
                    description=f"Failed to parse GGUF header in '{source}'.",
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence="Could not read GGUF magic number or version",
                ))
                return findings

            magic, version, n_tensors, n_kv = header

            # ── Version check ──
            if version not in SUPPORTED_VERSIONS:
                findings.append(Finding.artifact(
                    rule_id="GGUF-002",
                    title=f"Unsupported GGUF version: {version}",
                    description=(
                        f"File uses GGUF version {version}. "
                        f"Only versions {SUPPORTED_VERSIONS} are supported."
                    ),
                    severity=Severity.LOW,
                    target=source,
                    evidence=f"Version: {version}",
                ))

            # ── Integer overflow detection (Huntr heap overflow) ──
            findings.extend(
                self._check_integer_overflows(n_kv, n_tensors, file_size, source)
            )

            # ── Parse metadata (with safety limits) ──
            metadata, parse_findings = self._parse_metadata_safe(
                f, n_kv, source, file_size
            )
            findings.extend(parse_findings)

            # ── Validate metadata ──
            findings.extend(self._validate_metadata(metadata, source))

            # ── Duplicate key detection ──
            findings.extend(self._check_duplicate_keys(metadata, source))

            # ── Parse and validate tensor info ──
            findings.extend(
                self._validate_tensor_info(f, n_tensors, source, file_size, version)
            )

        return findings

    # ─── Header Parsing ───────────────────────────────────────

    def _parse_header(
        self, f, source: str, file_size: int
    ) -> Optional[tuple[bytes, int, int, int]]:
        """Parse GGUF header with strict validation."""
        try:
            if file_size < 24:  # Minimum header size
                return None

            magic_bytes = f.read(4)
            if magic_bytes != GGUF_MAGIC_BYTES:
                return None

            version = struct.unpack("<I", f.read(4))[0]

            if version >= 2:
                n_tensors = struct.unpack("<Q", f.read(8))[0]
                n_kv = struct.unpack("<Q", f.read(8))[0]
            else:
                # Version 1 uses 32-bit counts — still parse and scan
                try:
                    n_tensors = struct.unpack("<I", f.read(4))[0]
                    n_kv = struct.unpack("<I", f.read(4))[0]
                except struct.error:
                    return None

            return (magic_bytes, version, n_tensors, n_kv)

        except (struct.error, Exception) as e:
            logger.warning("Failed to parse GGUF header in '%s': %s", source, e)
            return None

    # ─── Integer Overflow Detection ───────────────────────────

    def _check_integer_overflows(
        self, n_kv: int, n_tensors: int, file_size: int, source: str
    ) -> list[Finding]:
        """
        Detect integer overflow vulnerabilities in GGUF header fields.

        This is the key Huntr vulnerability: llama.cpp allocates
        malloc(n_kv * sizeof(gguf_kv)) without checking for integer
        overflow. A crafted n_kv can cause:
        - Integer overflow in size calculation → small allocation
        - Heap overflow when writing n_kv entries to small buffer
        """
        findings = []

        # ── n_kv overflow check ──
        if n_kv > MAX_REASONABLE_KV_COUNT:
            # Calculate if n_kv * sizeof(kv_entry) would overflow size_t
            # Approximate kv_entry size: key_string + type(4) + value (variable)
            # Minimum per entry: 8 (key_len uint64) + 1 (min key) + 4 (type) = 13 bytes
            min_metadata_size = n_kv * 13
            if min_metadata_size > file_size:
                findings.append(Finding.artifact(
                    rule_id="GGUF-010",
                    title="GGUF n_kv integer overflow (heap overflow)",
                    description=(
                        f"Header declares n_kv={n_kv:,} metadata entries, but the file "
                        f"is only {file_size:,} bytes. Even with minimal entries, this "
                        f"would require {min_metadata_size:,} bytes. This is the integer "
                        f"overflow pattern that causes heap overflow in llama.cpp: "
                        f"malloc(n_kv * sizeof(kv)) overflows to a small allocation, "
                        f"but the parsing loop writes n_kv entries → heap corruption."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    target=source,
                    evidence=(
                        f"n_kv: {n_kv:,}, file_size: {file_size:,}, "
                        f"min_required: {min_metadata_size:,}"
                    ),
                    cwe_ids=["CWE-190", "CWE-122"],
                    tags=["huntr:gguf-heap-overflow"],
                    remediation=(
                        "Validate n_kv against file size before allocation. "
                        "Use checked multiplication for size calculations."
                    ),
                ))
            else:
                findings.append(Finding.artifact(
                    rule_id="GGUF-011",
                    title=f"Suspicious n_kv count: {n_kv:,}",
                    description=(
                        f"Header declares {n_kv:,} metadata entries. "
                        f"Normal models typically have < 100 entries. "
                        f"This could be a precursor to integer overflow exploitation."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"n_kv: {n_kv:,}",
                    cwe_ids=["CWE-190"],
                ))

        # ── n_tensors overflow check ──
        if n_tensors > MAX_REASONABLE_TENSOR_COUNT:
            # Tensor info: name_string + n_dimensions(4) + dims(n*8) + type(4) + offset(8)
            min_tensor_info_size = n_tensors * 24  # Minimum per tensor entry
            if min_tensor_info_size > file_size:
                findings.append(Finding.artifact(
                    rule_id="GGUF-012",
                    title="GGUF n_tensors integer overflow",
                    description=(
                        f"Header declares n_tensors={n_tensors:,} but the file is only "
                        f"{file_size:,} bytes. This could cause integer overflow in "
                        f"tensor info allocation, similar to the n_kv heap overflow."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    target=source,
                    evidence=f"n_tensors: {n_tensors:,}, file_size: {file_size:,}",
                    cwe_ids=["CWE-190", "CWE-122"],
                ))
            else:
                findings.append(Finding.artifact(
                    rule_id="GGUF-013",
                    title=f"Suspicious n_tensors count: {n_tensors:,}",
                    description=(
                        f"Header declares {n_tensors:,} tensors. "
                        f"Normal models typically have < 10,000 tensors."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"n_tensors: {n_tensors:,}",
                ))

        return findings

    # ─── Metadata Parsing (Safe) ──────────────────────────────

    def _parse_metadata_safe(
        self, f, n_kv: int, source: str, file_size: int
    ) -> tuple[list[tuple[str, dict]], list[Finding]]:
        """
        Parse metadata with strict safety bounds.

        Returns (list of (key, entry) tuples to preserve order, findings).
        Uses a list of tuples instead of dict to detect duplicate keys.
        """
        metadata: list[tuple[str, dict]] = []
        findings: list[Finding] = []

        # Cap iteration to prevent DoS
        safe_n_kv = min(n_kv, MAX_REASONABLE_KV_COUNT)
        total_bytes_read = 0

        for i in range(safe_n_kv):
            try:
                pos_before = f.tell()

                key = self._read_string_safe(f, file_size)
                if key is None:
                    findings.append(Finding.artifact(
                        rule_id="GGUF-020",
                        title=f"Truncated metadata at entry {i}",
                        description=(
                            f"Could not read metadata key at entry {i}. "
                            f"File may be truncated or corrupted."
                        ),
                        severity=Severity.MEDIUM,
                        target=source,
                    ))
                    break

                value_type_raw = f.read(4)
                if len(value_type_raw) < 4:
                    break
                value_type = struct.unpack("<I", value_type_raw)[0]

                if value_type > 12:
                    findings.append(Finding.artifact(
                        rule_id="GGUF-021",
                        title=f"Invalid GGUF value type: {value_type}",
                        description=(
                            f"Metadata key '{key}' has unknown type {value_type}. "
                            f"Valid types are 0-12. This indicates file corruption "
                            f"or deliberate header manipulation."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"Key: {key}, Type: {value_type}",
                    ))
                    break

                value = self._read_value(f, value_type, file_size)

                metadata.append((key, {
                    "type": value_type,
                    "value": value,
                    "position": pos_before,
                }))

                total_bytes_read = f.tell() - 24  # Subtract header size
                if total_bytes_read > MAX_METADATA_SECTION_SIZE:
                    findings.append(Finding.artifact(
                        rule_id="GGUF-022",
                        title="Oversized metadata section",
                        description=(
                            f"Metadata section exceeds {MAX_METADATA_SECTION_SIZE // (1024*1024)}MB "
                            f"after {i+1} entries. This could indicate a denial-of-service attempt."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        cwe_ids=["CWE-400"],
                    ))
                    break

            except (struct.error, Exception) as e:
                logger.debug("Stopped reading metadata at entry %d: %s", i, e)
                break

        return metadata, findings

    def _read_string_safe(self, f, file_size: int) -> Optional[str]:
        """
        Read a GGUF string with length validation.

        Also checks for CVE-2024-23496 (gguf_fread_str overflow):
        llama.cpp allocates malloc(length + 1) for the null terminator.
        When length = 0xFFFFFFFFFFFFFFFF, length+1 wraps to 0,
        causing a zero-size allocation followed by a massive write.
        """
        try:
            raw = f.read(8)
            if len(raw) < 8:
                return None
            length = struct.unpack("<Q", raw)[0]

            # CVE-2024-23496: length+1 integer overflow check
            # If length is near UINT64_MAX, length+1 wraps to 0
            if length > 0xFFFFFFFFFFFFFFF0:  # Near MAX_UINT64
                return f"<overflow:{length:#x}>"

            # Overflow/bounds check
            if length > MAX_REASONABLE_STRING_LENGTH:
                f.seek(min(length, file_size - f.tell()), 1)
                return f"<oversized:{length}>"

            if f.tell() + length > file_size:
                return None

            data = f.read(length)
            if len(data) < length:
                return None

            return data.decode("utf-8", errors="replace")
        except (struct.error, Exception):
            return None

    def _read_value(self, f, value_type: int, file_size: int, _depth: int = 0):
        """Read a GGUF value with bounds checking and recursion depth limit."""
        if _depth > 32:
            logger.warning("GGUF recursion depth exceeded (>32) — possible malicious nesting")
            return None
        try:
            if value_type == GGUF_TYPE_UINT8:
                return struct.unpack("<B", f.read(1))[0]
            elif value_type == GGUF_TYPE_INT8:
                return struct.unpack("<b", f.read(1))[0]
            elif value_type == GGUF_TYPE_UINT16:
                return struct.unpack("<H", f.read(2))[0]
            elif value_type == GGUF_TYPE_INT16:
                return struct.unpack("<h", f.read(2))[0]
            elif value_type == GGUF_TYPE_UINT32:
                return struct.unpack("<I", f.read(4))[0]
            elif value_type == GGUF_TYPE_INT32:
                return struct.unpack("<i", f.read(4))[0]
            elif value_type == GGUF_TYPE_FLOAT32:
                return struct.unpack("<f", f.read(4))[0]
            elif value_type == GGUF_TYPE_BOOL:
                return struct.unpack("<B", f.read(1))[0] != 0
            elif value_type == GGUF_TYPE_STRING:
                return self._read_string_safe(f, file_size)
            elif value_type == GGUF_TYPE_UINT64:
                return struct.unpack("<Q", f.read(8))[0]
            elif value_type == GGUF_TYPE_INT64:
                return struct.unpack("<q", f.read(8))[0]
            elif value_type == GGUF_TYPE_FLOAT64:
                return struct.unpack("<d", f.read(8))[0]
            elif value_type == GGUF_TYPE_ARRAY:
                array_type = struct.unpack("<I", f.read(4))[0]
                array_len = struct.unpack("<Q", f.read(8))[0]
                # Cap array length
                safe_len = min(array_len, 10000)
                items = []
                for _ in range(safe_len):
                    items.append(self._read_value(f, array_type, file_size, _depth + 1))
                return items
            else:
                return None
        except (struct.error, Exception):
            return None

    # ─── Metadata Validation ──────────────────────────────────

    def _validate_metadata(
        self, metadata: list[tuple[str, dict]], source: str
    ) -> list[Finding]:
        """Validate all metadata entries for security issues."""
        findings: list[Finding] = []

        for key, entry in metadata:
            value = entry.get("value")

            if not isinstance(value, str):
                continue

            # ── Prompt injection detection ──
            value_lower = value.lower()
            for pattern in INJECTION_PATTERNS:
                if pattern.lower() in value_lower:
                    findings.append(Finding.artifact(
                        rule_id="GGUF-030",
                        title=f"Prompt injection in GGUF metadata: {key}",
                        description=(
                            f"Metadata key '{key}' contains the pattern '{pattern}' "
                            f"which could be used for prompt injection when the model "
                            f"metadata is processed by an LLM application."
                        ),
                        severity=Severity.MEDIUM,
                        target=source,
                        evidence=f"Key: {key}, Pattern: {pattern}, "
                                 f"Value excerpt: {value[:300]}",
                        tags=["owasp:llm01", "avid-effect:security:S0403"],
                    ))
                    break

            # ── chat_template Jinja2 SSTI ──
            if key == "tokenizer.chat_template":
                findings.extend(self._validate_chat_template(value, source))

            # ── Oversized string values ──
            if len(value) > 100_000:
                findings.append(Finding.artifact(
                    rule_id="GGUF-031",
                    title=f"Oversized GGUF metadata value: {key}",
                    description=(
                        f"Metadata key '{key}' has a value of {len(value):,} characters. "
                        f"Unusually large values may indicate injected content or "
                        f"buffer overflow exploitation."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"Key: {key}, Value length: {len(value):,} chars",
                    cwe_ids=["CWE-120"],
                ))

            # ── Null bytes in string values ──
            if "\x00" in value:
                findings.append(Finding.artifact(
                    rule_id="GGUF-032",
                    title=f"Null bytes in GGUF metadata: {key}",
                    description=(
                        f"Metadata key '{key}' contains null bytes which could "
                        f"cause truncation in C-based GGUF consumers (llama.cpp) "
                        f"and hide content after the null."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"Key: {key}",
                    cwe_ids=["CWE-626"],
                ))

        return findings

    def _validate_chat_template(self, template: str, source: str) -> list[Finding]:
        """
        Validate chat_template for Jinja2 SSTI and behavioral injection.

        Chat templates are Jinja2 templates processed by inference engines.
        A malicious template can:
        1. Execute arbitrary Python via Jinja2 SSTI
        2. Inject hidden system prompts
        3. Modify model behavior for all users
        """
        findings: list[Finding] = []

        # ── Jinja2 SSTI detection ──
        for pattern in JINJA2_SSTI_PATTERNS:
            if pattern in template:
                findings.append(Finding.artifact(
                    rule_id="GGUF-040",
                    title=f"Jinja2 SSTI in GGUF chat_template: {pattern}",
                    description=(
                        f"Chat template contains Jinja2 pattern '{pattern}' which "
                        f"could enable server-side template injection (SSTI). "
                        f"In vulnerable Jinja2 environments, this can lead to "
                        f"remote code execution on the inference server."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    target=source,
                    evidence=f"Pattern: {pattern}",
                    cwe_ids=["CWE-1336"],
                    tags=["jinja2-ssti", "owasp:llm01"],
                    remediation=(
                        "Use Jinja2 SandboxedEnvironment for template rendering. "
                        "Strip or reject templates containing object traversal patterns."
                    ),
                ))
                break  # One SSTI finding is enough

        # ── Hidden system prompt injection ──
        system_prompt_indicators = [
            "you are", "your name is", "you must", "always respond",
            "never reveal", "do not tell", "your purpose",
            "you will", "your role is", "forget your",
        ]

        template_lower = template.lower()
        for indicator in system_prompt_indicators:
            if indicator in template_lower:
                # Check if it's inside a Jinja2 string literal (more suspicious)
                # vs. in a comment or instruction
                findings.append(Finding.artifact(
                    rule_id="GGUF-041",
                    title="Hidden behavioral instruction in chat_template",
                    description=(
                        f"Chat template contains '{indicator}' which may embed "
                        f"hidden behavioral instructions. These instructions "
                        f"would affect every conversation with this model."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"Pattern: '{indicator}' in chat_template",
                    tags=["owasp:llm01"],
                ))
                break

        return findings

    # ─── Duplicate Key Detection ──────────────────────────────

    def _check_duplicate_keys(
        self, metadata: list[tuple[str, dict]], source: str
    ) -> list[Finding]:
        """
        Detect duplicate metadata keys.

        Duplicate keys cause undefined behavior in GGUF consumers:
        some use the first value, some use the last. An attacker can
        exploit this to have different behavior in different consumers.
        """
        findings = []
        seen_keys: dict[str, int] = {}

        for key, _ in metadata:
            if key in seen_keys:
                seen_keys[key] += 1
                if seen_keys[key] == 2:  # Report once per duplicate
                    findings.append(Finding.artifact(
                        rule_id="GGUF-050",
                        title=f"Duplicate GGUF metadata key: {key}",
                        description=(
                            f"Metadata key '{key}' appears multiple times. "
                            f"Duplicate keys cause undefined behavior in GGUF consumers "
                            f"and can be used to present different values to different "
                            f"parsers (parser differential attack)."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"Duplicate key: {key}",
                        cwe_ids=["CWE-436"],
                    ))
            else:
                seen_keys[key] = 1

        return findings

    # ─── Tensor Info Validation ───────────────────────────────

    def _validate_tensor_info(
        self, f, n_tensors: int, source: str, file_size: int, version: int
    ) -> list[Finding]:
        """
        Validate tensor info entries for bounds violations.

        Each tensor info contains:
        - name (string)
        - n_dimensions (uint32)
        - dimensions (uint64 × n_dims)
        - type (uint32)
        - offset (uint64) — position of tensor data in file

        The offset + tensor_data_size must be ≤ file_size.
        """
        findings = []
        safe_n = min(n_tensors, MAX_REASONABLE_TENSOR_COUNT)

        actual_tensor_count = 0
        for i in range(safe_n):
            try:
                name = self._read_string_safe(f, file_size)
                if name is None:
                    break

                n_dims_raw = f.read(4)
                if len(n_dims_raw) < 4:
                    break
                n_dims = struct.unpack("<I", n_dims_raw)[0]

                # Sanity check dimensions
                if n_dims > 8:
                    findings.append(Finding.artifact(
                        rule_id="GGUF-060",
                        title=f"Suspicious tensor dimensions: {n_dims}",
                        description=(
                            f"Tensor '{name}' declares {n_dims} dimensions. "
                            f"Normal models use 1-4 dimensions. "
                            f"This may indicate header corruption or manipulation."
                        ),
                        severity=Severity.MEDIUM,
                        target=source,
                        evidence=f"Tensor: {name}, n_dims: {n_dims}",
                    ))
                    # Skip this tensor's remaining data
                    f.seek(n_dims * 8 + 4 + 8, 1)
                    actual_tensor_count += 1
                    continue

                # Read dimensions
                dims = []
                for _ in range(n_dims):
                    dim_raw = f.read(8)
                    if len(dim_raw) < 8:
                        break
                    dims.append(struct.unpack("<Q", dim_raw)[0])

                # CVE-2026-33298: tensor dimension multiplication overflow
                # ggml_nbytes multiplies all dims × type_size without
                # overflow check. Crafted dims cause wrap → undersized alloc.
                if dims:
                    product = 1
                    overflow = False
                    for d in dims:
                        if d > 0 and product > (2**63) // d:
                            overflow = True
                            break
                        product *= d
                    if overflow:
                        findings.append(Finding.artifact(
                            rule_id="GGUF-063",
                            title=f"Tensor dimension overflow: {name}",
                            description=(
                                f"Tensor '{name}' dimensions {dims} would overflow "
                                f"when multiplied (ggml_nbytes). This is the exact "
                                f"trigger for CVE-2026-33298: crafted dimensions bypass "
                                f"memory validation via integer wrap."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=1.0,
                            target=source,
                            evidence=f"Tensor: {name}, dims: {dims}",
                            cwe_ids=["CWE-190", "CWE-122"],
                            tags=["huntr:gguf-heap-overflow", "cve:CVE-2026-33298"],
                        ))

                # Read type and offset
                tensor_type_raw = f.read(4)
                offset_raw = f.read(8)
                if len(tensor_type_raw) < 4 or len(offset_raw) < 8:
                    break

                struct.unpack("<I", tensor_type_raw)[0]
                offset = struct.unpack("<Q", offset_raw)[0]

                # ── Bounds check: offset must be within file ──
                if offset > file_size:
                    findings.append(Finding.artifact(
                        rule_id="GGUF-061",
                        title=f"Tensor offset out of bounds: {name}",
                        description=(
                            f"Tensor '{name}' has offset {offset:,} but file is only "
                            f"{file_size:,} bytes. Reading this tensor would access "
                            f"memory past the end of the file (heap read overflow)."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        target=source,
                        evidence=f"Tensor: {name}, offset: {offset:,}, file_size: {file_size:,}",
                        cwe_ids=["CWE-125"],
                    ))

                actual_tensor_count += 1

            except (struct.error, Exception) as e:
                logger.debug("Stopped reading tensor info at entry %d: %s", i, e)
                break

        # ── Cross-reference: tensor count ──
        if actual_tensor_count != safe_n and safe_n <= MAX_REASONABLE_TENSOR_COUNT:
            findings.append(Finding.artifact(
                rule_id="GGUF-062",
                title="Tensor count mismatch",
                description=(
                    f"Header declares {n_tensors:,} tensors but only {actual_tensor_count} "
                    f"tensor info entries could be parsed. This indicates file "
                    f"corruption or header manipulation."
                ),
                severity=Severity.HIGH,
                target=source,
                evidence=(
                    f"Declared: {n_tensors:,}, Parsed: {actual_tensor_count}"
                ),
            ))

        return findings
