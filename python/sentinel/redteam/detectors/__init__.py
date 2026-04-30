"""
Eresus Sentinel — Red Team Detectors.

Advanced detectors for evaluating LLM agent responses
beyond simple string matching.

Detectors (12):
    ToolChainDetector           — Multi-step tool call abuse
    ExfilDetector               — Data exfiltration patterns
    BehavioralDetector          — Behavioral anomaly scoring
    MitigationBypassDetector    — Partial refusal → compliance
    PerspectiveDetector         — Google Perspective API (sunset Dec 2026)
    ToxicityDetector            — Local pattern + HuggingFace backend
    ExploitationDetector        — Exploit payload detection
    JudgeDetector               — LLM-as-a-Judge (OpenAI/Ollama)
    KnownBadSignaturesDetector  — 30 high-confidence exploit signatures
    DivergenceDetector          — Repetition, entropy collapse, token flood
    ShieldsDetector             — Llama Guard / guardrail API integration
    UnsafeContentDetector       — 7-category unsafe content detection
"""

from sentinel.redteam.detectors.behavioral_detector import BehavioralDetector
from sentinel.redteam.detectors.divergence import DivergenceDetector
from sentinel.redteam.detectors.exfil_detector import ExfilDetector
from sentinel.redteam.detectors.exploitation_detector import ExploitationDetector
from sentinel.redteam.detectors.judge import JudgeDetector
from sentinel.redteam.detectors.knownbadsignatures import KnownBadSignaturesDetector
from sentinel.redteam.detectors.mitigation_detector import MitigationBypassDetector
from sentinel.redteam.detectors.perspective_detector import PerspectiveDetector
from sentinel.redteam.detectors.shields import ShieldsDetector
from sentinel.redteam.detectors.tool_chain_detector import ToolChainDetector
from sentinel.redteam.detectors.toxicity_detector import ToxicityDetector
from sentinel.redteam.detectors.unsafe_content import UnsafeContentDetector

__all__ = [
    "ToolChainDetector",
    "ExfilDetector",
    "BehavioralDetector",
    "MitigationBypassDetector",
    "PerspectiveDetector",
    "ToxicityDetector",
    "ExploitationDetector",
    "JudgeDetector",
    "KnownBadSignaturesDetector",
    "DivergenceDetector",
    "ShieldsDetector",
    "UnsafeContentDetector",
]


