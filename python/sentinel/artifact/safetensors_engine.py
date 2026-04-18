"""
Eresus Sentinel — SafeTensors Reverse Engine.

Parses header JSON, validates tensor layout, detects data overlap
and suspicious metadata.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any, Dict, List

from ..finding import Finding, Severity
from .format_common import TensorInfo, FormatReport


class SafeTensorsReverseEngine:
    """Deep-inspect SafeTensors files."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def analyze(self, filepath: str) -> FormatReport:
        self.findings = []
        path = Path(filepath)
        report = FormatReport(
            format_name="SafeTensors", file_path=filepath,
            file_size=path.stat().st_size if path.exists() else 0,
        )

        if not path.exists():
            self.findings.append(Finding.artifact(
                rule_id="FMT-100", title="File not found",
                description=f"SafeTensors file not found: {filepath}",
                severity=Severity.HIGH, target=filepath,
            ))
            report.findings = self.findings
            return report

        try:
            with open(filepath, "rb") as f:
                header_size_bytes = f.read(8)
                if len(header_size_bytes) < 8:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-101", title="File too small for SafeTensors",
                        description="File smaller than minimum SafeTensors header (8 bytes).",
                        severity=Severity.HIGH, target=filepath,
                    ))
                    report.findings = self.findings
                    return report

                header_size = struct.unpack("<Q", header_size_bytes)[0]

                if header_size > 100_000_000:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-110", title=f"Oversized SafeTensors header: {header_size}",
                        description=f"Header claims {header_size} bytes — possible DoS vector.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"header_size={header_size}",
                    ))
                    report.findings = self.findings
                    return report

                if header_size > report.file_size - 8:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-111", title="Header size exceeds file size",
                        description=f"Header claims {header_size} bytes, file is {report.file_size}.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"header_size={header_size}, file_size={report.file_size}",
                    ))
                    report.findings = self.findings
                    return report

                header_bytes = f.read(header_size)
                try:
                    header = json.loads(header_bytes)
                except json.JSONDecodeError as e:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-112", title="Invalid SafeTensors header JSON",
                        description=f"Failed to parse header JSON: {e}",
                        severity=Severity.HIGH, target=filepath, evidence=str(e),
                    ))
                    report.findings = self.findings
                    return report

                report.metadata = {"__header_size__": header_size}

                for tensor_name, tensor_meta in header.items():
                    if tensor_name == "__metadata__":
                        report.metadata.update(tensor_meta if isinstance(tensor_meta, dict) else {})
                        continue
                    if not isinstance(tensor_meta, dict):
                        continue

                    dtype = tensor_meta.get("dtype", "unknown")
                    shape = tensor_meta.get("shape", [])
                    offsets = tensor_meta.get("data_offsets", [0, 0])
                    size_bytes = offsets[1] - offsets[0] if len(offsets) == 2 else 0

                    report.tensors.append(TensorInfo(
                        name=tensor_name, n_dims=len(shape), shape=shape,
                        dtype=dtype, offset=offsets[0] if offsets else 0,
                        size_bytes=size_bytes,
                    ))

                self._analyze_tensor_overlaps(report.tensors, filepath)
                self._analyze_tensor_names(report.tensors, filepath)
                self._analyze_metadata_security(report.metadata, filepath)

                # Out-of-bounds tensor data — offset+size must not exceed file
                data_start = 8 + header_size
                for t in report.tensors:
                    abs_start = data_start + t.offset
                    abs_end = abs_start + t.size_bytes
                    if t.size_bytes < 0 or t.offset < 0:
                        self.findings.append(Finding.artifact(
                            rule_id="FMT-122",
                            title=f"Negative offset/size in tensor: {t.name}",
                            description=(
                                f"Tensor '{t.name}' has negative offset ({t.offset}) "
                                f"or size ({t.size_bytes}) — malformed file."
                            ),
                            severity=Severity.HIGH, target=filepath,
                            evidence=f"tensor={t.name}, offset={t.offset}, size={t.size_bytes}",
                        ))
                    elif abs_end > report.file_size:
                        self.findings.append(Finding.artifact(
                            rule_id="FMT-123",
                            title=f"Tensor data beyond file boundary: {t.name}",
                            description=(
                                f"Tensor '{t.name}' claims data at offset {t.offset} "
                                f"with size {t.size_bytes}, extending to byte {abs_end} "
                                f"but file is only {report.file_size} bytes."
                            ),
                            severity=Severity.HIGH, target=filepath,
                            evidence=(
                                f"tensor={t.name}, data_end={abs_end}, "
                                f"file_size={report.file_size}"
                            ),
                        ))

                # Zero-dimension tensor with non-zero data allocation
                for t in report.tensors:
                    if 0 in t.shape and t.size_bytes > 0:
                        self.findings.append(Finding.artifact(
                            rule_id="FMT-124",
                            title=f"Zero-dimension tensor with data: {t.name}",
                            description=(
                                f"Tensor '{t.name}' has shape {t.shape} (contains 0) "
                                f"but claims {t.size_bytes} bytes of data — anomaly."
                            ),
                            severity=Severity.MEDIUM, target=filepath,
                            evidence=f"tensor={t.name}, shape={t.shape}, size={t.size_bytes}",
                        ))

                # Excess header key count
                tensor_count = len(report.tensors)
                total_keys = len(header) - (1 if "__metadata__" in header else 0)
                if total_keys > 0 and tensor_count > 0 and total_keys > tensor_count * 2:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-113",
                        title=f"Excess header keys: {total_keys} keys for {tensor_count} tensors",
                        description=(
                            f"Header contains {total_keys} keys for only {tensor_count} tensors. "
                            f"Extra keys may indicate hidden data or tampered headers."
                        ),
                        severity=Severity.LOW, target=filepath,
                        evidence=f"keys={total_keys}, tensors={tensor_count}",
                    ))


        except Exception as e:
            self.findings.append(Finding.artifact(
                rule_id="FMT-102", title="SafeTensors parse error",
                description=f"Failed to parse SafeTensors file: {e}",
                severity=Severity.MEDIUM, target=filepath, evidence=str(e),
            ))

        report.findings = self.findings
        return report

    def _analyze_tensor_overlaps(self, tensors: List[TensorInfo], filepath: str) -> None:
        sorted_tensors = sorted(tensors, key=lambda t: t.offset)
        for i in range(len(sorted_tensors) - 1):
            curr = sorted_tensors[i]
            next_t = sorted_tensors[i + 1]
            curr_end = curr.offset + curr.size_bytes
            if curr_end > next_t.offset and curr.size_bytes > 0:
                self.findings.append(Finding.artifact(
                    rule_id="FMT-120",
                    title=f"Overlapping tensor data: {curr.name} / {next_t.name}",
                    description=f"Tensors '{curr.name}' and '{next_t.name}' overlap — possible tampering.",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"tensor1={curr.name}[{curr.offset}:{curr_end}], tensor2={next_t.name}[{next_t.offset}:]",
                ))

    def _analyze_tensor_names(self, tensors: List[TensorInfo], filepath: str) -> None:
        suspicious = ["backdoor", "trojan", "payload", "inject", "exploit", "hidden_layer", "secret"]
        for t in tensors:
            name_lower = t.name.lower()
            for sus in suspicious:
                if sus in name_lower:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-121", title=f"Suspicious tensor name: {t.name}",
                        description=f"Tensor '{t.name}' has a suspicious name.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"tensor={t.name}, shape={t.shape}, dtype={t.dtype}",
                    ))
                    break

    def _analyze_metadata_security(self, metadata: Dict[str, Any], filepath: str) -> None:
        for key, value in metadata.items():
            if key.startswith("__"):
                continue
            val_str = str(value).lower()
            if any(d in val_str for d in [
                "eval(", "exec(", "import os", "subprocess",
                "__import__", "os.system", "<script",
            ]):
                self.findings.append(Finding.artifact(
                    rule_id="FMT-130", title=f"Suspicious metadata in SafeTensors: {key}",
                    description=f"Metadata key '{key}' contains code execution patterns.",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"key={key}, value={str(value)[:200]}",
                ))
