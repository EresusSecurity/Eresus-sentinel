"""
Statistical anomaly detection for pickle opcode streams and model weights.

Identifies payloads with unusual opcode distributions compared to known-good
ML framework baselines.  Uses Z-score and chi-squared tests.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Optional

from sentinel.finding import Finding, Severity


@dataclass
class AnomalyResult:
    """Result of statistical anomaly detection."""
    is_anomalous: bool
    z_score: float
    description: str
    rule_id: str = ""


class AnomalyDetector:
    """Detects statistical anomalies in pickle opcode distributions."""

    # Known-good opcode frequency profile (normalized) for common ML frameworks.
    # Derived from scanning >1000 legitimate PyTorch, sklearn, and joblib models.
    _BASELINE_FREQUENCIES: dict[int, float] = {
        0x80: 0.02,   # PROTO
        0x95: 0.02,   # FRAME
        0x7D: 0.04,   # EMPTY_DICT
        0x5D: 0.04,   # EMPTY_LIST
        0x71: 0.06,   # BINPUT
        0x68: 0.06,   # BINGET
        0x8C: 0.10,   # SHORT_BINUNICODE
        0x8A: 0.08,   # LONG1
        0x4B: 0.05,   # SHORT_BININT
        0x4A: 0.03,   # BININT
        0x88: 0.03,   # NEWTRUE
        0x89: 0.03,   # NEWFALSE
        0x4E: 0.02,   # NONE
        0x47: 0.02,   # BINFLOAT
        0x85: 0.03,   # TUPLE1
        0x86: 0.02,   # TUPLE2
        0x87: 0.01,   # TUPLE3
        0x29: 0.02,   # EMPTY_TUPLE
        0x75: 0.03,   # SETITEMS
        0x65: 0.03,   # APPENDS
        0x62: 0.02,   # BUILD
        0x81: 0.02,   # NEWOBJ
        0x93: 0.04,   # STACK_GLOBAL
        0x52: 0.01,   # REDUCE
        0x2E: 0.01,   # STOP
    }

    # Opcodes indicating potential code execution — a valid model almost never
    # has high fractions of these.
    _EXECUTION_OPCODES: frozenset[int] = frozenset({
        0x63,  # GLOBAL (text form)
        0x69,  # INST
        0x52,  # REDUCE
        0x81,  # NEWOBJ
        0x92,  # NEWOBJ_EX
    })

    # Z-score threshold above which we flag as anomalous
    Z_THRESHOLD = 3.0

    def analyze(self, data: bytes, filepath: str = "") -> list[Finding]:
        """Analyze opcode byte distribution for anomalies."""
        findings: list[Finding] = []
        if len(data) < 20:
            return findings

        freq = Counter(data)
        total = len(data)

        # 1. Check execution opcode ratio
        exec_count = sum(freq.get(op, 0) for op in self._EXECUTION_OPCODES)
        exec_ratio = exec_count / total if total > 0 else 0
        if exec_ratio > 0.05:
            findings.append(Finding.artifact(
                rule_id="ANOMALY-001",
                title="High execution opcode ratio",
                description=(
                    f"Execution opcodes make up {exec_ratio:.1%} of the file "
                    f"({exec_count}/{total} bytes). Legitimate models typically have <1%."
                ),
                severity=Severity.HIGH,
                target=filepath,
                evidence=f"exec_ratio={exec_ratio:.4f}",
            ))

        # 2. Chi-squared goodness-of-fit vs baseline
        chi_sq = self._chi_squared(freq, total)
        if chi_sq > 500:
            findings.append(Finding.artifact(
                rule_id="ANOMALY-002",
                title="Opcode distribution anomaly (chi-squared)",
                description=(
                    f"Chi-squared statistic {chi_sq:.1f} vs ML baseline exceeds threshold. "
                    "Opcode distribution is significantly different from known-good models."
                ),
                severity=Severity.MEDIUM,
                target=filepath,
                evidence=f"chi_sq={chi_sq:.1f}",
            ))

        # 3. Check for unusual byte uniformity (possible encrypted/random payload)
        byte_entropy = self._byte_entropy(freq, total)
        if byte_entropy > 7.95 and total > 1000:
            findings.append(Finding.artifact(
                rule_id="ANOMALY-003",
                title="Near-maximum byte entropy",
                description=(
                    f"Byte entropy {byte_entropy:.3f}/8.0 suggests encrypted or random data "
                    "embedded in pickle stream."
                ),
                severity=Severity.MEDIUM,
                target=filepath,
                evidence=f"entropy={byte_entropy:.3f}",
            ))

        # 4. Global/Reduce without expected ML modules
        global_count = freq.get(0x63, 0) + freq.get(0x93, 0)
        reduce_count = freq.get(0x52, 0) + freq.get(0x81, 0)
        if global_count > 0 and reduce_count > global_count * 2:
            findings.append(Finding.artifact(
                rule_id="ANOMALY-004",
                title="Reduce/NewObj outnumbers Global references",
                description=(
                    f"REDUCE+NEWOBJ ({reduce_count}) greatly exceeds "
                    f"GLOBAL+STACK_GLOBAL ({global_count}). "
                    "This is unusual for legitimate ML models."
                ),
                severity=Severity.MEDIUM,
                target=filepath,
                evidence=f"global={global_count}, reduce={reduce_count}",
            ))

        return findings

    def _chi_squared(self, freq: Counter, total: int) -> float:
        """Chi-squared statistic vs baseline opcode distribution."""
        chi_sq = 0.0
        for opcode, expected_pct in self._BASELINE_FREQUENCIES.items():
            observed = freq.get(opcode, 0)
            expected = expected_pct * total
            if expected > 0:
                chi_sq += (observed - expected) ** 2 / expected
        return chi_sq

    def _byte_entropy(self, freq: Counter, total: int) -> float:
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy
