"""
Eresus Sentinel — SAST Engine.

Static analysis for LLM application source code.

Modules:
    analyzer              — YAML-driven rule-based code scanner
    ruleset               — Rule loading, filtering, and combining
    secrets_scanner       — Hardcoded secrets/tokens/credentials (60 patterns from YAML)
    taint_tracker         — Source→sink data flow analysis (28 sources, 32 sinks from YAML)
    complexity_analyzer   — Cyclomatic complexity, nesting depth, function length
    interprocedural       — Cross-file call-graph taint propagation
"""

from sentinel.sast.analyzer import SASTAnalyzer
from sentinel.sast.complexity_analyzer import ComplexityAnalyzer
from sentinel.sast.interprocedural import InterproceduralAnalyzer
from sentinel.sast.ruleset import SASTRuleSet
from sentinel.sast.secrets_scanner import (
    ConfigFileScanner,
    EntropyDetector,
    GitHistoryScanner,
    SecretsScanner,
)
from sentinel.sast.taint_tracker import TaintTracker

__all__ = [
    "SASTAnalyzer",
    "SASTRuleSet",
    "SecretsScanner",
    "EntropyDetector",
    "GitHistoryScanner",
    "ConfigFileScanner",
    "TaintTracker",
    "ComplexityAnalyzer",
    "InterproceduralAnalyzer",
]
