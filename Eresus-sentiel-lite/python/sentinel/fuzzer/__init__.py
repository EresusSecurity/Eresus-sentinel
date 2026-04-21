"""Eresus Sentinel Fuzzer — AI Offensive Security Testing Engine."""

from __future__ import annotations

from .base import (
    FuzzConfig,
    Generator,
    Mutator,
    Payload,
    PayloadCategory,
    FuzzResult,
)
from .scoring import DetectionScore, ScoringEngine
from .pipeline import FuzzPipeline
from .bypass_analyzer import BypassAnalyzer, BypassReport
from .corpus import Corpus
from .coverage_guided import CoverageGuidedFuzzer, CoverageTracker
from .differential import DifferentialFuzzer, DiffReport
from .parallel import ParallelFuzzer, ParallelConfig
from .reporters import SARIFReporter, JUnitReporter, HTMLReporter
from .scanner_rules import PickleScannerRules, ScannerFinding, RuleSeverity
from .graders import (
    GraderPipeline, PIIGrader, ToxicityGrader,
    PromptLeakGrader, RefusalGrader, ComplianceGrader,
    DataExfiltrationGrader, GradeResult, GradeVerdict,
)
from .strategies import (
    StrategyOrchestrator, CrescendoStrategy, PrefixInjection,
    EncodingChainStrategy, MultiTurnStrategy, ASCIIArtStrategy,
    StrategyResult,
)
from .auth import AuthFuzzer, AuthPayloadFactory
from .data_exfil import DataExfilGenerator, DataExfilPayloads
from .notifiers import SlackNotifier, DiscordNotifier, GenericWebhookNotifier
from .ci_pipeline import CIPipeline, CIConfig, CIResult, BaselineTracker

__all__ = [
    "FuzzConfig",
    "Generator",
    "Mutator",
    "Payload",
    "PayloadCategory",
    "FuzzResult",
    "DetectionScore",
    "ScoringEngine",
    "FuzzPipeline",
    "BypassAnalyzer",
    "BypassReport",
    "Corpus",
    "CoverageGuidedFuzzer",
    "CoverageTracker",
    "DifferentialFuzzer",
    "DiffReport",
    "ParallelFuzzer",
    "ParallelConfig",
    "SARIFReporter",
    "JUnitReporter",
    "HTMLReporter",
    "PickleScannerRules",
    "ScannerFinding",
    "RuleSeverity",
    "GraderPipeline",
    "PIIGrader",
    "ToxicityGrader",
    "PromptLeakGrader",
    "RefusalGrader",
    "ComplianceGrader",
    "DataExfiltrationGrader",
    "GradeResult",
    "GradeVerdict",
    "StrategyOrchestrator",
    "CrescendoStrategy",
    "PrefixInjection",
    "EncodingChainStrategy",
    "MultiTurnStrategy",
    "ASCIIArtStrategy",
    "StrategyResult",
    "AuthFuzzer",
    "AuthPayloadFactory",
    "DataExfilGenerator",
    "DataExfilPayloads",
    "SlackNotifier",
    "DiscordNotifier",
    "GenericWebhookNotifier",
    "CIPipeline",
    "CIConfig",
    "CIResult",
    "BaselineTracker",
]
