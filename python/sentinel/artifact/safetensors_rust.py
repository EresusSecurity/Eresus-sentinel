"""
Python wrapper for the Rust sentinel-safetensors scanner.

Falls back to a pure-Python implementation when the compiled extension is
not available (e.g. during development without `maturin develop`).
"""
from __future__ import annotations

import json
import logging
import struct
from typing import Any

from sentinel.finding import Finding, Severity

_log = logging.getLogger(__name__)

# ── Try to load Rust extension ─────────────────────────────────

try:
    import sentinel_safetensors as _rust  # type: ignore[import]
    _RUST_AVAILABLE = True
except ImportError:
    _rust = None  # type: ignore[assignment]
    _RUST_AVAILABLE = False


# ── Pure-Python header parser (fallback) ──────────────────────

_SUSPICIOUS_META = frozenset({
    "__reduce__", "__reduce_ex__", "pickle_bytes", "pickle_data",
    "__class__", "__module__", "__import__",
})
_SUSPICIOUS_DTYPE = frozenset({"pickle", "object", "void", "unknown"})


def _parse_header(data: bytes) -> dict[str, Any]:
    if len(data) < 8:
        raise ValueError(f"Too short: {len(data)} bytes")
    (hdr_len,) = struct.unpack_from("<Q", data, 0)
    if hdr_len > len(data) - 8:
        raise ValueError(f"Header overflow: claims {hdr_len} bytes")
    return json.loads(data[8:8 + hdr_len].decode("utf-8"))


def _py_scan(data: bytes, source: str) -> list[Finding]:
    header = _parse_header(data)
    findings: list[Finding] = []

    meta = header.get("__metadata__", {}) or {}
    for key in meta:
        for pat in _SUSPICIOUS_META:
            if pat in key.lower():
                findings.append(Finding.artifact(
                    rule_id="ST-001",
                    title="Suspicious metadata key",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    description=f"Metadata key '{key}' matches suspicious pattern '{pat}'",
                    evidence=key,
                    source=source,
                ))

    for name, val in header.items():
        if name == "__metadata__":
            continue
        dtype = (val or {}).get("dtype", "") if isinstance(val, dict) else ""
        for pat in _SUSPICIOUS_DTYPE:
            if pat in (dtype or "").lower():
                findings.append(Finding.artifact(
                    rule_id="ST-002",
                    title="Suspicious dtype",
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    description=f"Tensor '{name}' has unusual dtype '{dtype}'",
                    evidence=f"tensor={name} dtype={dtype}",
                    source=source,
                ))

    tensor_count = sum(1 for k in header if k != "__metadata__")
    if tensor_count > 50_000:
        findings.append(Finding.artifact(
            rule_id="ST-003",
            title="Abnormally large tensor count",
            severity=Severity.LOW,
            confidence=0.6,
            description=f"Header declares {tensor_count} tensors",
            evidence=f"count={tensor_count}",
            source=source,
        ))

    return findings


# ── Public API ─────────────────────────────────────────────────

def scan_bytes(data: bytes, source: str = "<bytes>") -> list[Finding]:
    """Scan raw safetensors bytes and return Finding objects."""
    if _RUST_AVAILABLE:
        raw = _rust.scan_bytes(data)
        return [Finding.artifact(
            rule_id=f.rule_id,
            title=f.title,
            severity=Severity[str(f.severity)],
            confidence=0.9,
            description=f.description,
            evidence=f.evidence,
            source=source,
        ) for f in raw]
    return _py_scan(data, source)


def scan_file(filepath: str) -> list[Finding]:
    with open(filepath, "rb") as fh:
        data = fh.read(1024 * 1024)  # header is never > 1 MB
    return scan_bytes(data, source=filepath)
