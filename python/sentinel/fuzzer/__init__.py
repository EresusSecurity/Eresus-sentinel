"""Eresus Sentinel Fuzzer — AI Offensive Security Testing Engine."""

from __future__ import annotations

from .aibom import AIBOMFuzzerGenerator, AIBOMPayloadFactory
from .auth import AuthFuzzer, AuthPayloadFactory
from .base import (
    FuzzConfig,
    FuzzResult,
    Generator,
    Mutator,
    Payload,
    PayloadCategory,
)
from .bypass_analyzer import BypassAnalyzer, BypassReport
from .ci_pipeline import BaselineTracker, CIConfig, CIPipeline, CIResult
from .corpus import Corpus
from .coverage_guided import CoverageGuidedFuzzer, CoverageTracker
from .data_exfil import DataExfilGenerator, DataExfilPayloads
from .differential import (
    DifferentialFuzzer,
    DiffReport,
    FunctionScannerAdapter,
    SubprocessScannerAdapter,
)
from .graders import (
    ComplianceGrader,
    DataExfiltrationGrader,
    GradeResult,
    GraderPipeline,
    GradeVerdict,
    PIIGrader,
    PromptLeakGrader,
    RefusalGrader,
    ToxicityGrader,
)
from .mcp import StatefulMCPFuzzer

# ── Enterprise additions ───────────────────────────────────────────────
from .mutation_engine import bit_flip, byte_flip, havoc, insert_magic, splice, truncate
from .notifiers import DiscordNotifier, GenericWebhookNotifier, SlackNotifier
from .pair_strategy import PAIRIteration, PAIRStrategy
from .parallel import ParallelConfig, ParallelFuzzer
from .payload_minimizer import PayloadMinimizer
from .pipeline import FuzzPipeline
from .prompt_mutator import PromptMutator
from .regression_suite import RegressionCase, RegressionRunResult, RegressionSuite
from .reporters import HTMLReporter, JUnitReporter, SARIFReporter
from .rule_suggester import RuleSuggester, RuleSuggestion
from .scanner_rules import PickleScannerRules, RuleSeverity, ScannerFinding
from .scoring import DetectionScore, ScoringEngine
from .seed_scheduler import SeedEntry, SeedScheduler
from .session_manager import FuzzSession, SessionSummary
from .skill import SkillBundleGenerator, SkillPayloadFactory
from .strategies import (
    ASCIIArtStrategy,
    CrescendoStrategy,
    EncodingChainStrategy,
    MultiTurnStrategy,
    PrefixInjection,
    StrategyOrchestrator,
    StrategyResult,
)
from .tap_strategy import TAPNode, TAPStrategy
from .trend_tracker import MetricSnapshot, TrendAlert, TrendTracker

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
    "FunctionScannerAdapter",
    "SubprocessScannerAdapter",
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
    "AIBOMFuzzerGenerator",
    "AIBOMPayloadFactory",
    "StatefulMCPFuzzer",
    "SkillBundleGenerator",
    "SkillPayloadFactory",
    # Enterprise additions
    "bit_flip",
    "byte_flip",
    "insert_magic",
    "splice",
    "havoc",
    "truncate",
    "PayloadMinimizer",
    "SeedScheduler",
    "SeedEntry",
    "RuleSuggester",
    "RuleSuggestion",
    "FuzzSession",
    "SessionSummary",
    "RegressionSuite",
    "RegressionCase",
    "RegressionRunResult",
    "TrendTracker",
    "MetricSnapshot",
    "TrendAlert",
    "TAPStrategy",
    "TAPNode",
    "PAIRStrategy",
    "PAIRIteration",
    "PromptMutator",
]
