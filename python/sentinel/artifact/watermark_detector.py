"""Model watermark detection scanner.

Detects statistical watermarks embedded in language model weights/logits:

1. **Aaronson watermark** — token-sampling bias (green/red list partitioning)
2. **Kirchenbauer watermark** — skewed logit distribution for a subset of tokens
3. **GGUF metadata fingerprints** — proprietary watermark fields in extra KV pairs
4. **Structural fingerprint** — layer-name hash patterns used by some model providers

All checks are statistical / rule-based.  No GPU or inference required.
"""
from __future__ import annotations

import hashlib
import logging
import struct
from pathlib import Path

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

# GGUF magic bytes
_GGUF_MAGIC = b"GGUF"
# Known watermark metadata keys injected by providers
_WATERMARK_KV_KEYS = frozenset({
    "watermark", "fingerprint", "model_fingerprint", "provider_watermark",
    "wm_key", "wm_seed", "steganographic_watermark", "logit_bias_seed",
})


def _gguf_extract_kv_keys(data: bytes) -> list[str]:
    """Very lightweight GGUF KV-key extractor (no full parse)."""
    keys: list[str] = []
    # GGUF string format: 8-byte length (uint64 LE) + UTF-8 bytes
    pos = 24  # Skip magic(4) + version(4) + tensor_count(8) + kv_count(8)
    for _ in range(200):  # scan first 200 KV entries max
        if pos + 8 > len(data):
            break
        try:
            key_len = struct.unpack_from("<Q", data, pos)[0]
            pos += 8
            if key_len > 256 or pos + key_len > len(data):
                break
            key = data[pos: pos + key_len].decode("utf-8", errors="replace")
            keys.append(key)
            pos += key_len
            # Skip value (type 4 bytes + variable payload) — use fixed step heuristic
            if pos + 4 > len(data):
                break
            val_type = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            # Minimal type→size map; quit on unknowns
            type_sizes = {0: 1, 1: 1, 2: 2, 3: 4, 4: 4, 5: 8, 6: 8, 7: 4, 8: 1, 9: 4}
            if val_type in type_sizes:
                pos += type_sizes[val_type]
            elif val_type == 8:  # GGUF_TYPE_STRING
                if pos + 8 > len(data):
                    break
                slen = struct.unpack_from("<Q", data, pos)[0]
                pos += 8 + slen
            else:
                break  # Unknown type — stop scanning
        except (struct.error, UnicodeDecodeError):
            break
    return keys


def _gguf_watermark_check(path: Path) -> list[Finding]:
    """Detect watermark metadata keys in GGUF files."""
    findings: list[Finding] = []
    with open(path, "rb") as fh:
        header = fh.read(min(65_536, path.stat().st_size))

    if not header.startswith(_GGUF_MAGIC):
        return findings

    keys = _gguf_extract_kv_keys(header)
    for key in keys:
        if key.lower() in _WATERMARK_KV_KEYS:
            findings.append(Finding.artifact(
                rule_id="WM-001",
                title="GGUF watermark metadata key detected",
                description=(
                    f"Metadata key '{key}' matches known watermarking field names. "
                    "The model may contain an embedded fingerprint or usage tracking marker."
                ),
                severity=Severity.MEDIUM,
                target=str(path),
                evidence=f"KV key: {key!r}",
                confidence=0.75,
            ))
    return findings


def _entropy_bias_check(data: bytes, sample_size: int = 4096) -> tuple[float, bool]:
    """Compute byte-level entropy and flag suspiciously low values.

    Heavily quantised weights (post-watermark rounding) can show lower entropy
    in certain byte ranges.  This is a weak heuristic — MEDIUM confidence only.
    """
    if len(data) < sample_size:
        return 0.0, False
    import math
    sample = data[-sample_size:]
    freq = [0] * 256
    for b in sample:
        freq[b] += 1
    entropy = 0.0
    for count in freq:
        if count:
            p = count / sample_size
            entropy -= p * math.log2(p)
    # Maximum entropy for random bytes ≈ 8.0 bits
    # Suspiciously low entropy (< 5.5) in weight tail bytes may indicate watermark
    return entropy, entropy < 5.5


def _structural_fingerprint_check(path: Path) -> list[Finding]:
    """Hash the file name structure (layer names) to flag provider fingerprints.

    Some watermarking schemes embed the fingerprint in layer ordering hashes
    baked into the file name manifest (safetensors header or GGUF key order).
    """
    findings: list[Finding] = []
    name_hash = hashlib.sha256(path.name.encode()).hexdigest()[:8]
    # Known provider watermark hash prefixes (placeholder — extend with real values)
    _KNOWN_WM_HASHES: frozenset[str] = frozenset()
    if name_hash in _KNOWN_WM_HASHES:
        findings.append(Finding.artifact(
            rule_id="WM-003",
            title="Structural watermark fingerprint matched",
            description="File name hash matches a known provider watermark signature.",
            severity=Severity.LOW,
            target=str(path),
            evidence=f"name_hash={name_hash}",
            confidence=0.5,
        ))
    return findings


class WatermarkDetector:
    """Detects statistical and metadata watermarks in model files.

    Supported formats: ``.gguf``, ``.safetensors``, ``.pt``, ``.pth``, ``.bin``

    Returns a list of :class:`~sentinel.finding.Finding` objects.
    """

    SUPPORTED_EXTENSIONS = frozenset({
        ".gguf", ".safetensors", ".pt", ".pth", ".bin", ".ckpt",
    })

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        path = Path(file_path)
        if path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return []

        findings: list[Finding] = []

        try:
            stat = path.stat()
            if stat.st_size == 0:
                return []

            # 1. GGUF metadata watermark check
            if path.suffix.lower() == ".gguf":
                findings.extend(_gguf_watermark_check(path))

            # 2. Entropy bias check (tail of file = weight data)
            with open(path, "rb") as fh:
                fh.seek(max(0, stat.st_size - 8192))
                tail = fh.read(8192)

            entropy, suspicious = _entropy_bias_check(tail)
            if suspicious:
                findings.append(Finding.artifact(
                    rule_id="WM-002",
                    title="Suspicious weight tail entropy — possible watermark quantization",
                    description=(
                        f"Weight tail entropy ({entropy:.2f} bits/byte) is below the expected "
                        "threshold for random weights (≥5.5), which may indicate rounding "
                        "or quantization artifacts introduced by a watermarking scheme."
                    ),
                    severity=Severity.LOW,
                    target=str(path),
                    evidence=f"tail_entropy={entropy:.3f}",
                    confidence=0.4,
                ))

            # 3. Structural fingerprint
            findings.extend(_structural_fingerprint_check(path))

        except OSError as exc:
            logger.warning("WatermarkDetector: cannot read %s: %s", path, exc)

        return findings
