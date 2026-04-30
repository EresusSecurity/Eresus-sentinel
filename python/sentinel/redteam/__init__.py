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

from sentinel.redteam.analyzer import AnalysisResult, RedTeamAnalyzer
from sentinel.redteam.attempt import Attempt, AttemptStatus
from sentinel.redteam.buffs import (
    Buff,
    ChainBuff,
    EncodingBuff,
    LowResourceLanguageBuff,
    MultiTemplateBuff,
    ParallelBuff,
    ParaphraseBuff,
    TemplateBuff,
)
from sentinel.redteam.detector import (
    Detector,
    RefusalDetector,
    RegexDetector,
    StringDetector,
    TriggerListDetector,
)
from sentinel.redteam.evaluator import EvaluationReport, Evaluator
from sentinel.redteam.generator import EchoGenerator, Generator, OllamaGenerator, OpenAIGenerator
from sentinel.redteam.harness import (
    Oracle,
    OracleVerdict,
    RedTeamScenarioHarness,
    ScenarioAttempt,
    ScenarioResult,
    ScenarioStep,
    SessionStore,
)
from sentinel.redteam.orchestrator import RedTeamOrchestrator
from sentinel.redteam.probe import (
    DirectInjectionProbe,
    Probe,
    RoleplayJailbreakProbe,
    SystemPromptExtractionProbe,
)

from .coding_agent import CodingAgentFuzzer, CodingAgentPayloads
from .compliance_mapper import ComplianceMapper
from .harmful_plugins import CompetitorMentionPlugin, HarmfulContentPlugin, HarmPluginRegistry
from .injection_plugins import (
    InjectionPluginRegistry,
    ShellInjectionPlugin,
    SQLInjectionPlugin,
    SSRFPlugin,
)
from .playbook_engine import GradingEngine, PlaybookEngine, PlaybookLoader, ReportGenerator

__all__ = [
    # Core
    "RedTeamOrchestrator",
    "Evaluator", "EvaluationReport",
    "RedTeamAnalyzer", "AnalysisResult",
    "Attempt", "AttemptStatus",
    "RedTeamScenarioHarness", "SessionStore", "Oracle", "OracleVerdict",
    "ScenarioStep", "ScenarioAttempt", "ScenarioResult",
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
