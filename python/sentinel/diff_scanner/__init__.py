"""
Eresus Sentinel — Diff Scanner Module.

Scans git diffs, PRs, and commits for ML-specific security anti-patterns.
Catches security regressions before they reach the main branch.

Modules:
    diff_parser  — Unified diff format parser
    ml_patterns  — 20 ML security anti-pattern rules
    scanner      — Main scanning engine with git integration
"""

from sentinel.diff_scanner.diff_parser import (
    DiffLine,
    FileDiff,
    Hunk,
    LineType,
    parse_unified_diff,
)
from sentinel.diff_scanner.ml_patterns import (
    ALL_PATTERNS,
    CODE_EXECUTION,
    CREDENTIAL_EXPOSURE,
    PATTERN_BY_ID,
    SAFETY_FLAG_WEAKENING,
    SUPPLY_CHAIN,
    TRUST_REMOTE_CODE,
    UNSAFE_DESERIALIZATION,
    MLPattern,
)
from sentinel.diff_scanner.scanner import DiffScanner

__all__ = [
    "DiffScanner",
    "parse_unified_diff",
    "FileDiff",
    "Hunk",
    "DiffLine",
    "LineType",
    "MLPattern",
    "ALL_PATTERNS",
    "PATTERN_BY_ID",
    "UNSAFE_DESERIALIZATION",
    "TRUST_REMOTE_CODE",
    "SAFETY_FLAG_WEAKENING",
    "CODE_EXECUTION",
    "SUPPLY_CHAIN",
    "CREDENTIAL_EXPOSURE",
]
