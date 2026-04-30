"""
Eresus Sentinel — GGUF Format Reverse Engineering Engine.

Byte-level GGUF parser: header, metadata KV pairs, tensor info,
quantization types, chat template injection detection.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List

from ..finding import Finding, Severity
from .format_common import FormatReport, TensorInfo

GGUF_MAGIC = 0x46475547  # "GGUF" in little-endian
GGUF_MAGIC_BYTES = b"GGUF"


class GGUFValueType(IntEnum):
    UINT8   = 0
    INT8    = 1
    UINT16  = 2
    INT16   = 3
    UINT32  = 4
    INT32   = 5
    FLOAT32 = 6
    BOOL    = 7
    STRING  = 8
    ARRAY   = 9
    UINT64  = 10
    INT64   = 11
    FLOAT64 = 12


GGUF_TYPE_SIZES = {
    GGUFValueType.UINT8:   1,
    GGUFValueType.INT8:    1,
    GGUFValueType.UINT16:  2,
    GGUFValueType.INT16:   2,
    GGUFValueType.UINT32:  4,
    GGUFValueType.INT32:   4,
    GGUFValueType.FLOAT32: 4,
    GGUFValueType.BOOL:    1,
    GGUFValueType.UINT64:  8,
    GGUFValueType.INT64:   8,
    GGUFValueType.FLOAT64: 8,
}

GGUF_QUANT_TYPES = {
    0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1",
    6: "Q5_0", 7: "Q5_1", 8: "Q8_0", 9: "Q8_1",
    10: "Q2_K", 11: "Q3_K_S", 12: "Q3_K_M", 13: "Q3_K_L",
    14: "Q4_K_S", 15: "Q4_K_M", 16: "Q5_K_S", 17: "Q5_K_M",
    18: "Q6_K", 19: "Q8_K", 20: "IQ2_XXS", 21: "IQ2_XS",
    22: "IQ3_XXS", 23: "IQ1_S", 24: "IQ4_NL", 25: "IQ3_S",
    26: "IQ2_S", 27: "IQ4_XS", 28: "I8", 29: "I16",
    30: "I32", 31: "I64", 32: "F64", 33: "IQ1_M",
}


@dataclass
class GGUFHeader:
    """Parsed GGUF file header."""
    magic: int = 0
    version: int = 0
    tensor_count: int = 0
    metadata_kv_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class GGUFReverseEngine:
    """Deep-inspect GGUF model files at the byte level."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def analyze(self, filepath: str) -> FormatReport:
        self.findings = []
        path = Path(filepath)
        report = FormatReport(
            format_name="GGUF",
            file_path=filepath,
            file_size=path.stat().st_size if path.exists() else 0,
        )

        if not path.exists():
            self.findings.append(Finding.artifact(
                rule_id="FMT-001", title="File not found",
                description=f"GGUF file not found: {filepath}",
                severity=Severity.HIGH, target=filepath,
            ))
            report.findings = self.findings
            return report

        try:
            with open(filepath, "rb") as f:
                header = self._parse_header(f, filepath)
                report.header = header

                if header.magic != GGUF_MAGIC:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-010", title="Invalid GGUF magic bytes",
                        description=f"Expected magic 0x{GGUF_MAGIC:08X}, got 0x{header.magic:08X}.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"magic=0x{header.magic:08X}",
                    ))
                    report.findings = self.findings
                    return report

                metadata = self._parse_metadata(f, header, filepath)
                report.metadata = metadata
                header.metadata = metadata

                tensors = self._parse_tensor_info(f, header, filepath)
                report.tensors = tensors

                self._analyze_metadata_security(metadata, filepath)
                self._analyze_tensor_anomalies(tensors, report.file_size, filepath)
                self._analyze_architecture(metadata, filepath)

        except Exception as e:
            self.findings.append(Finding.artifact(
                rule_id="FMT-002", title="GGUF parse error",
                description=f"Failed to parse GGUF file: {e}",
                severity=Severity.MEDIUM, target=filepath, evidence=str(e),
            ))

        report.findings = self.findings
        return report

    def _parse_header(self, f, filepath: str) -> GGUFHeader:
        header = GGUFHeader()
        header.magic = struct.unpack("<I", f.read(4))[0]
        header.version = struct.unpack("<I", f.read(4))[0]
        header.tensor_count = struct.unpack("<Q", f.read(8))[0]
        header.metadata_kv_count = struct.unpack("<Q", f.read(8))[0]

        if header.version not in (2, 3):
            self.findings.append(Finding.artifact(
                rule_id="FMT-011", title=f"Unusual GGUF version: {header.version}",
                description=f"GGUF version {header.version} is unusual. Expected 2 or 3.",
                severity=Severity.LOW, target=filepath,
                evidence=f"version={header.version}",
            ))

        if header.tensor_count > 10000:
            self.findings.append(Finding.artifact(
                rule_id="FMT-012", title=f"Unusually high tensor count: {header.tensor_count}",
                description=f"GGUF reports {header.tensor_count} tensors — may indicate corruption.",
                severity=Severity.MEDIUM, target=filepath,
                evidence=f"tensor_count={header.tensor_count}",
            ))

        # n_kv heap overflow detection — CVE pattern:
        # Loaders allocate `n_kv * sizeof(gguf_kv)` bytes. If n_kv is
        # manipulated to a huge value, the allocation overflows or the
        # subsequent loop writes past the buffer boundary.
        if header.metadata_kv_count > 100_000:
            self.findings.append(Finding.artifact(
                rule_id="FMT-013",
                title=f"GGUF n_kv heap overflow risk: {header.metadata_kv_count}",
                description=(
                    f"Header claims {header.metadata_kv_count:,} metadata key-value pairs. "
                    f"Native GGUF loaders (ggml, llama.cpp) allocate n_kv * sizeof(gguf_kv) "
                    f"bytes — a manipulated n_kv causes heap buffer overflow when the "
                    f"loader iterates past the allocated array. This file should be "
                    f"rejected before loading."
                ),
                severity=Severity.CRITICAL, target=filepath,
                evidence=f"metadata_kv_count={header.metadata_kv_count}",
                cwe_ids=["CWE-122", "CWE-190"],
                remediation=(
                    "Reject GGUF files with n_kv exceeding a reasonable threshold "
                    "(e.g. 10,000). Ensure loaders validate n_kv against file size "
                    "before allocation."
                ),
            ))
        elif header.metadata_kv_count > 10000:
            self.findings.append(Finding.artifact(
                rule_id="FMT-013",
                title=f"High GGUF metadata count: {header.metadata_kv_count}",
                description=(
                    f"Header claims {header.metadata_kv_count:,} metadata entries — "
                    f"legitimate models rarely exceed 100. High counts may indicate "
                    f"corruption, fuzzing payload, or heap overflow attempt."
                ),
                severity=Severity.HIGH, target=filepath,
                evidence=f"metadata_kv_count={header.metadata_kv_count}",
                cwe_ids=["CWE-122"],
            ))

        # Integer overflow check: n_kv * estimated_kv_size
        # A typical gguf_kv struct is ~40 bytes minimum
        estimated_alloc = header.metadata_kv_count * 40
        if estimated_alloc > 4_000_000_000:  # >4GB allocation attempt
            self.findings.append(Finding.artifact(
                rule_id="FMT-014",
                title=f"GGUF integer overflow in allocation: {estimated_alloc / 1e9:.1f}GB",
                description=(
                    f"n_kv={header.metadata_kv_count} × ~40 bytes = "
                    f"{estimated_alloc / 1e9:.1f}GB estimated allocation. "
                    f"This exceeds reasonable memory and will cause integer "
                    f"overflow on 32-bit systems or OOM on 64-bit systems."
                ),
                severity=Severity.CRITICAL, target=filepath,
                evidence=f"n_kv={header.metadata_kv_count}, estimated_alloc={estimated_alloc}",
                cwe_ids=["CWE-190"],
            ))

        return header

    def _read_gguf_string(self, f) -> str:
        length = struct.unpack("<Q", f.read(8))[0]
        if length > 1_000_000:
            return f"<oversized string: {length} bytes>"
        return f.read(length).decode("utf-8", errors="replace")

    def _read_gguf_value(self, f, value_type: int) -> Any:
        if value_type == GGUFValueType.STRING:
            return self._read_gguf_string(f)
        elif value_type == GGUFValueType.BOOL:
            return struct.unpack("<?", f.read(1))[0]
        elif value_type == GGUFValueType.UINT8:
            return struct.unpack("<B", f.read(1))[0]
        elif value_type == GGUFValueType.INT8:
            return struct.unpack("<b", f.read(1))[0]
        elif value_type == GGUFValueType.UINT16:
            return struct.unpack("<H", f.read(2))[0]
        elif value_type == GGUFValueType.INT16:
            return struct.unpack("<h", f.read(2))[0]
        elif value_type == GGUFValueType.UINT32:
            return struct.unpack("<I", f.read(4))[0]
        elif value_type == GGUFValueType.INT32:
            return struct.unpack("<i", f.read(4))[0]
        elif value_type == GGUFValueType.UINT64:
            return struct.unpack("<Q", f.read(8))[0]
        elif value_type == GGUFValueType.INT64:
            return struct.unpack("<q", f.read(8))[0]
        elif value_type == GGUFValueType.FLOAT32:
            return struct.unpack("<f", f.read(4))[0]
        elif value_type == GGUFValueType.FLOAT64:
            return struct.unpack("<d", f.read(8))[0]
        elif value_type == GGUFValueType.ARRAY:
            arr_type = struct.unpack("<I", f.read(4))[0]
            arr_len = struct.unpack("<Q", f.read(8))[0]
            if arr_len > 100_000:
                return f"<array of {arr_len} elements>"
            return [self._read_gguf_value(f, arr_type) for _ in range(arr_len)]
        return None

    def _parse_metadata(self, f, header: GGUFHeader, filepath: str) -> Dict[str, Any]:
        metadata = {}
        for i in range(min(header.metadata_kv_count, 10000)):
            try:
                key = self._read_gguf_string(f)
                value_type = struct.unpack("<I", f.read(4))[0]
                value = self._read_gguf_value(f, value_type)
                metadata[key] = value
            except (struct.error, UnicodeDecodeError, EOFError):
                self.findings.append(Finding.artifact(
                    rule_id="FMT-020",
                    title=f"Metadata parse error at entry {i}",
                    description=f"Failed to parse metadata entry {i}/{header.metadata_kv_count}.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"entry_index={i}",
                ))
                break
        return metadata

    def _parse_tensor_info(self, f, header: GGUFHeader, filepath: str) -> List[TensorInfo]:
        tensors = []
        for i in range(min(header.tensor_count, 10000)):
            try:
                name = self._read_gguf_string(f)
                n_dims = struct.unpack("<I", f.read(4))[0]
                shape = [struct.unpack("<Q", f.read(8))[0] for _ in range(n_dims)]
                dtype_id = struct.unpack("<I", f.read(4))[0]
                offset = struct.unpack("<Q", f.read(8))[0]
                dtype_name = GGUF_QUANT_TYPES.get(dtype_id, f"unknown({dtype_id})")
                tensors.append(TensorInfo(
                    name=name, n_dims=n_dims, shape=shape,
                    dtype=dtype_name, offset=offset,
                ))
            except (struct.error, EOFError):
                self.findings.append(Finding.artifact(
                    rule_id="FMT-021",
                    title=f"Tensor info parse error at entry {i}",
                    description=f"Failed to parse tensor entry {i}/{header.tensor_count}.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"tensor_index={i}",
                ))
                break
        return tensors

    def _analyze_metadata_security(self, metadata: Dict[str, Any], filepath: str) -> None:
        suspicious_keys = [
            "general.url", "general.source.url",
            "tokenizer.ggml.pre", "tokenizer.chat_template",
        ]
        for key in suspicious_keys:
            if key in metadata:
                val = str(metadata[key])
                if any(ind in val.lower() for ind in [
                    "eval(", "exec(", "import ", "__import__",
                    "os.system", "subprocess", "<script",
                    "javascript:", "data:text/html",
                ]):
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-030",
                        title=f"Suspicious content in GGUF metadata: {key}",
                        description=f"Metadata key '{key}' contains potentially dangerous content.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"key={key}, value_preview={val[:200]}",
                    ))

        chat_template = metadata.get("tokenizer.chat_template", "")
        if isinstance(chat_template, str) and len(chat_template) > 0:
            if any(danger in chat_template.lower() for danger in [
                "import os", "subprocess", "__import__",
                "eval(", "exec(", "open(",
            ]):
                self.findings.append(Finding.artifact(
                    rule_id="FMT-031",
                    title="Code injection in chat template",
                    description="GGUF chat template contains Python code execution patterns.",
                    severity=Severity.CRITICAL, target=filepath,
                    evidence=f"template_preview={chat_template[:300]}",
                ))

            # Jinja2 SSTI detection — chat templates use Jinja2, not raw Python
            _JINJA2_SSTI_PATTERNS = [
                "__class__", "__mro__", "__subclasses__", "__globals__",
                "__builtins__", "__init__", "__dict__", "__base__",
                "__getattr__", "_module", "__reduce__",
                "config.items", "self._", "self.__",
                "lipsum.__globals__", "cycler.__init__",
                "joiner.__init__", "namespace.__init__",
                "| attr(", "| format(", "| map(",
                "popen(", ".read()", "getattr(",
            ]
            template_lower = chat_template.lower()
            matched_ssti = [p for p in _JINJA2_SSTI_PATTERNS if p.lower() in template_lower]
            if matched_ssti:
                self.findings.append(Finding.artifact(
                    rule_id="FMT-032",
                    title="Jinja2 SSTI in GGUF chat template",
                    description=(
                        f"Chat template contains Jinja2 Server-Side Template Injection patterns: "
                        f"{', '.join(matched_ssti[:5])}. GGUF chat templates are rendered by Jinja2 — "
                        f"these patterns can achieve arbitrary code execution when the template is "
                        f"processed by llama.cpp, vLLM, or any Jinja2-enabled inference engine."
                    ),
                    severity=Severity.CRITICAL, target=filepath,
                    evidence=f"patterns={matched_ssti}, template_preview={chat_template[:300]}",
                    cwe_ids=["CWE-1336"],
                    remediation="Sanitize the chat template or use a sandboxed Jinja2 environment.",
                ))

            # Detect template-level prompt injection via role manipulation
            if any(marker in chat_template for marker in [
                "{% set ns.role", "{% set role", "{%- set system",
                "{% if message.role == 'tool'", "{% raw %}",
            ]):
                # Not inherently dangerous, but worth flagging for review
                pass  # informational only

        # URL validation for metadata callback/source URLs
        for url_key in ("general.url", "general.source.url"):
            url_val = str(metadata.get(url_key, ""))
            if url_val:
                url_lower = url_val.lower().strip()
                if any(url_lower.startswith(scheme) for scheme in [
                    "file://", "ftp://", "gopher://", "data:", "javascript:",
                ]):
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-033",
                        title=f"Suspicious URL scheme in GGUF metadata: {url_key}",
                        description=(
                            f"Metadata '{url_key}' uses a dangerous URL scheme: {url_lower[:80]}. "
                            f"This could be used for SSRF or local file access when the URL "
                            f"is followed by tooling."
                        ),
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"key={url_key}, url={url_lower[:200]}",
                        cwe_ids=["CWE-918"],
                    ))

    def _analyze_tensor_anomalies(self, tensors: List[TensorInfo], file_size: int, filepath: str) -> None:
        if not tensors:
            return
        suspicious_names = ["backdoor", "trojan", "payload", "inject", "exploit", "shell"]
        for t in tensors:
            name_lower = t.name.lower()
            for sus in suspicious_names:
                if sus in name_lower:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-040",
                        title=f"Suspicious tensor name: {t.name}",
                        description=f"Tensor '{t.name}' has a suspicious name.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"tensor={t.name}, shape={t.shape}, dtype={t.dtype}",
                    ))
                    break
            if "unknown" in t.dtype:
                self.findings.append(Finding.artifact(
                    rule_id="FMT-041",
                    title=f"Unknown quantization type in tensor: {t.name}",
                    description=f"Tensor '{t.name}' uses unrecognized type '{t.dtype}'.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"tensor={t.name}, dtype={t.dtype}",
                ))
            if t.offset > file_size:
                self.findings.append(Finding.artifact(
                    rule_id="FMT-042",
                    title=f"Tensor offset beyond file size: {t.name}",
                    description=f"Tensor '{t.name}' offset {t.offset} exceeds file size {file_size}.",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"tensor={t.name}, offset={t.offset}, file_size={file_size}",
                ))

    def _analyze_architecture(self, metadata: Dict[str, Any], filepath: str) -> None:
        arch = metadata.get("general.architecture", "")
        if not arch:
            self.findings.append(Finding.artifact(
                rule_id="FMT-050", title="Missing architecture metadata",
                description="GGUF file is missing 'general.architecture' metadata.",
                severity=Severity.LOW, target=filepath,
            ))
