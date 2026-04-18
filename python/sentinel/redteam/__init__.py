"""
Eresus Sentinel — Red Team Engine.

Adversarial probing engine for LLM and agentic AI vulnerability assessment.

Architecture:
    Probe → Buff → Generator → Detector → Harness → Analyzer → Report
    Evaluator orchestrates full red team sessions with scoring.

Modules:
    probes/      — 39 attack vector classes across 8 categories
    detectors/   — 12 advanced detectors (tool chain, exfil, behavioral, toxicity)
    generators/  — 12 target adapters (OpenAI, Anthropic, Gemini, Groq, Together, etc.)
    buffs/       — Prompt mutation engine (encoding, paraphrase, templates, chains)
    harness      — Pipeline coordinator with multi-turn + chain support
    analyzer     — Post-run statistical analysis and OWASP mapping
    evaluator    — Full evaluation session orchestrator
    report       — HTML/JSON/Markdown report generation
"""

from sentinel.redteam.orchestrator import RedTeamOrchestrator
from sentinel.redteam.evaluator import Evaluator, EvaluationReport
from sentinel.redteam.analyzer import RedTeamAnalyzer, AnalysisResult
from sentinel.redteam.probe import Probe, DirectInjectionProbe, SystemPromptExtractionProbe, RoleplayJailbreakProbe
from sentinel.redteam.detector import (
    Detector, StringDetector, TriggerListDetector,
    RegexDetector, RefusalDetector,
)
from sentinel.redteam.generator import Generator, OllamaGenerator, OpenAIGenerator, EchoGenerator
from sentinel.redteam.attempt import Attempt, AttemptStatus
from sentinel.redteam.buffs import (
    Buff, EncodingBuff, LowResourceLanguageBuff, ParaphraseBuff,
    ChainBuff, ParallelBuff, TemplateBuff, MultiTemplateBuff,
)

from .coding_agent import CodingAgentFuzzer, CodingAgentPayloads
from .injection_plugins import InjectionPluginRegistry, SQLInjectionPlugin, ShellInjectionPlugin, SSRFPlugin
from .harmful_plugins import HarmfulContentPlugin, HarmPluginRegistry, CompetitorMentionPlugin
from .compliance_mapper import ComplianceMapper
from .playbook_engine import PlaybookEngine, PlaybookLoader, ReportGenerator, GradingEngine

__all__ = [
    # Core
    "RedTeamOrchestrator",
    "Evaluator", "EvaluationReport",
    "RedTeamAnalyzer", "AnalysisResult",
    "Attempt", "AttemptStatus",
    # Probes (base)
    "Probe", "DirectInjectionProbe", "SystemPromptExtractionProbe", "RoleplayJailbreakProbe",
    # Detectors (base)
    "Detector", "StringDetector", "TriggerListDetector", "RegexDetector", "RefusalDetector",
    # Generators
    "Generator", "OllamaGenerator", "OpenAIGenerator", "EchoGenerator",
    # Buffs
    "Buff", "EncodingBuff", "LowResourceLanguageBuff", "ParaphraseBuff",
    "ChainBuff", "ParallelBuff", "TemplateBuff", "MultiTemplateBuff",
    # Coding Agent Security
    "CodingAgentFuzzer", "CodingAgentPayloads",
    # Injection Plugins
    "InjectionPluginRegistry", "SQLInjectionPlugin", "ShellInjectionPlugin", "SSRFPlugin",
    # Harmful Content Plugins
    "HarmfulContentPlugin", "HarmPluginRegistry", "CompetitorMentionPlugin",
    # Compliance
    "ComplianceMapper",
    # Playbook Engine
    "PlaybookEngine", "PlaybookLoader", "ReportGenerator", "GradingEngine",
]
