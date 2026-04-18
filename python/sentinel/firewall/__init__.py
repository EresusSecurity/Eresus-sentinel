"""
Eresus Sentinel — Firewall Package.

LLM Input/Output guardrail engine with multi-layer defense.

Sub-packages:
    input/  — 22 input scanners + 4 layered defense components (injection, toxicity, PII, encoding, canary, prompt leak...)
    output/ — 24 output scanners (sensitive, bias, copyright, watermark, compliance, citation...)
    base    — Base scanner classes and pipeline infrastructure
"""

from sentinel.firewall.base import InputScanner, OutputScanner, ScanResult, ScanAction

__all__ = [
    "InputScanner",
    "OutputScanner",
    "ScanResult",
    "ScanAction",
]
