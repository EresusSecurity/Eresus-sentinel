"""Entropy-based analysis for detecting anomalous model weights and hidden payloads."""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class EntropyResult:
    overall_entropy: float
    block_entropies: list[float]
    max_entropy: float
    min_entropy: float
    suspicious_blocks: list[int]
    file_size: int = 0


def compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of byte data (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def analyze_file_entropy(
    data: bytes,
    block_size: int = 65536,
    high_entropy_threshold: float = 7.5,
) -> EntropyResult:
    """Analyze entropy of a file by blocks to detect hidden payloads."""
    if not data:
        return EntropyResult(
            overall_entropy=0.0,
            block_entropies=[],
            max_entropy=0.0,
            min_entropy=0.0,
            suspicious_blocks=[],
            file_size=0,
        )

    overall = compute_entropy(data)
    blocks: list[float] = []
    suspicious: list[int] = []

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        ent = compute_entropy(block)
        blocks.append(ent)
        if ent > high_entropy_threshold:
            suspicious.append(len(blocks) - 1)

    return EntropyResult(
        overall_entropy=overall,
        block_entropies=blocks,
        max_entropy=max(blocks) if blocks else 0.0,
        min_entropy=min(blocks) if blocks else 0.0,
        suspicious_blocks=suspicious,
        file_size=len(data),
    )


def is_encrypted_or_compressed(data: bytes) -> bool:
    """Heuristic: high entropy throughout suggests encryption or compression."""
    if len(data) < 1024:
        return False
    entropy = compute_entropy(data)
    return entropy > 7.8
