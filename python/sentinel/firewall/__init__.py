"""
Eresus Sentinel — Firewall Package.

LLM Input/Output guardrail engine with multi-layer defense.

Sub-packages:
    input/  — 22 input scanners + 4 layered defense components (injection, toxicity, PII, encoding, canary, prompt leak...)
    output/ — 24 output scanners (sensitive, bias, copyright, watermark, compliance, citation...)
    base    — Base scanner classes and pipeline infrastructure
    heuristic_detector — Combinatorial prompt injection detection (8,800+ phrase matching)
    pii_detector — PII detection with 30+ entity types (US/EU/UK/IN/AU/SG)
    yara_scanner — YARA rule-based prompt scanning
"""

from sentinel.firewall.base import InputScanner, OutputScanner, ScanAction, ScanResult
from sentinel.firewall.heuristic_detector import CanaryWordGuard, HeuristicInjectionDetector
from sentinel.firewall.pii_detector import PIIDetector, PIIEntity
from sentinel.firewall.yara_scanner import YaraPromptScanner

__all__ = [
    "InputScanner",
    "OutputScanner",
    "ScanResult",
    "ScanAction",
    "HeuristicInjectionDetector",
    "CanaryWordGuard",
    "PIIDetector",
    "PIIEntity",
    "YaraPromptScanner",
]
