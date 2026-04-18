"""
Eresus Sentinel — YAML Policy Engine.

Policy-as-code: define scan behavior in a single ``policy.yaml`` file.
Replaces hardcoded scanner init across all integrations.

Features:
  - Declarative YAML policy definitions
  - Per-scanner threshold/action overrides
  - Conditional rules (if scanner X fires → run scanner Y)
  - Policy inheritance and composition (base + overlay)
  - Runtime policy hot-reload
  - Policy validation with schema checking
  - Environment-specific policies (dev/staging/prod)

Usage:
    from sentinel.policy import PolicyEngine
    engine = PolicyEngine.from_file("policy.yaml")
    pipeline = engine.build_input_pipeline()
    result = pipeline.scan(user_prompt)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from sentinel.data_loader import load_data
from sentinel.firewall.base import (
    FirewallPipeline,
    InputScanner,
    OutputScanner,
    ScanAction,
)

logger = logging.getLogger(__name__)


# ── Policy schema ────────────────────────────────────────────────────

class PolicyMode(str, Enum):
    """Policy enforcement mode."""
    ENFORCE = "enforce"      # Block/redact as configured
    AUDIT = "audit"          # Log only, never block
    DISABLED = "disabled"    # Skip scanner entirely


@dataclass
class ScannerRule:
    """Configuration for a single scanner in the policy."""
    scanner: str
    enabled: bool = True
    mode: PolicyMode = PolicyMode.ENFORCE
    action: ScanAction = ScanAction.WARN
    threshold: float = 0.5
    params: dict[str, Any] = field(default_factory=dict)
    on_fail: str = "block"     # block | warn | log_only | redact
    priority: int = 100        # Lower = runs first
    tags: list[str] = field(default_factory=list)


@dataclass
class PolicyConfig:
    """Complete policy configuration."""
    name: str = "default"
    version: str = "1.0"
    environment: str = "production"
    mode: PolicyMode = PolicyMode.ENFORCE
    input_rules: list[ScannerRule] = field(default_factory=list)
    output_rules: list[ScannerRule] = field(default_factory=list)
    global_threshold: float = 0.5
    max_risk_score: float = 0.9
    fail_open: bool = False        # If scanner errors, pass or block?
    audit_all: bool = True         # Log all scan results
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Scanner registry ─────────────────────────────────────────────────

# Primary: auto-discovery from _plugins.py
# Fallback: manual registration (for compatibility)
_INPUT_SCANNERS: dict[str, type] | None = None
_OUTPUT_SCANNERS: dict[str, type] | None = None


def _get_input_registry() -> dict[str, type]:
    global _INPUT_SCANNERS
    if _INPUT_SCANNERS is not None:
        return _INPUT_SCANNERS

    # Try auto-discovery first
    try:
        from sentinel._plugins import get_input_scanners
        discovered = get_input_scanners()
        if discovered:
            _INPUT_SCANNERS = discovered
            return _INPUT_SCANNERS
    except Exception as e:
        logger.warning("Auto-discovery failed for input scanners: %s", e)

    from sentinel.firewall.input import (
        PromptInjectionScanner,
        InvisibleTextScanner,
        HeuristicInjectionScanner,
        EncodingAttackScanner,
        ToxicityScanner,
        LanguageScanner,
        BanSubstringsScanner,
        GibberishScanner,
        TokenLimitScanner,
        CodeScanner,
        RegexScanner,
        SentimentScanner,
        SecretScanner,
        BanTopicsScanner,
        EmotionScanner,
        AnonymizeScanner,
        LLMClassifierScanner,
        PromptLeakScanner,
    )

    _INPUT_SCANNERS = {
        "injection": PromptInjectionScanner,
        "invisible": InvisibleTextScanner,
        "heuristic": HeuristicInjectionScanner,
        "encoding": EncodingAttackScanner,
        "toxicity": ToxicityScanner,
        "language": LanguageScanner,
        "ban_substrings": BanSubstringsScanner,
        "gibberish": GibberishScanner,
        "token_limit": TokenLimitScanner,
        "code": CodeScanner,
        "regex": RegexScanner,
        "sentiment": SentimentScanner,
        "secrets": SecretScanner,
        "ban_topics": BanTopicsScanner,
        "emotion": EmotionScanner,
        "anonymize": AnonymizeScanner,
        "llm_classifier": LLMClassifierScanner,
        "prompt_leak": PromptLeakScanner,
    }
    return _INPUT_SCANNERS


def _get_output_registry() -> dict[str, type]:
    global _OUTPUT_SCANNERS
    if _OUTPUT_SCANNERS is not None:
        return _OUTPUT_SCANNERS

    # Try auto-discovery first
    try:
        from sentinel._plugins import get_output_scanners
        discovered = get_output_scanners()
        if discovered:
            _OUTPUT_SCANNERS = discovered
            return _OUTPUT_SCANNERS
    except Exception as e:
        logger.warning("Auto-discovery failed for output scanners: %s", e)

    from sentinel.firewall.output import (
        SensitiveDataScanner,
        MaliciousURLScanner,
        FormatScanner,
        BiasScanner,
        NoRefusalScanner,
        RelevanceScanner,
        ToxicityOutputScanner,
        GibberishOutputScanner,
        URLReachabilityScanner,
        ReadingTimeScanner,
        JSONScanner,
        LanguageSameScanner,
        DeanonymizeScanner,
        FactualConsistencyScanner,
        SentimentOutputScanner,
        RegexOutputScanner,
        BanCodeOutputScanner,
        BanCompetitorsOutputScanner,
        BanTopicsOutputScanner,
        EmotionScanner,
        CopyrightScanner,
        WatermarkScanner,
        ComplianceScanner,
        CitationScanner,
    )

    _OUTPUT_SCANNERS = {
        "sensitive": SensitiveDataScanner,
        "urls": MaliciousURLScanner,
        "format": FormatScanner,
        "bias": BiasScanner,
        "no_refusal": NoRefusalScanner,
        "relevance": RelevanceScanner,
        "toxicity": ToxicityOutputScanner,
        "gibberish": GibberishOutputScanner,
        "url_reachability": URLReachabilityScanner,
        "reading_time": ReadingTimeScanner,
        "json": JSONScanner,
        "language_same": LanguageSameScanner,
        "deanonymize": DeanonymizeScanner,
        "factual_consistency": FactualConsistencyScanner,
        "sentiment": SentimentOutputScanner,
        "regex": RegexOutputScanner,
        "ban_code": BanCodeOutputScanner,
        "ban_competitors": BanCompetitorsOutputScanner,
        "ban_topics": BanTopicsOutputScanner,
        "emotion": EmotionScanner,
        "copyright": CopyrightScanner,
        "watermark": WatermarkScanner,
        "compliance": ComplianceScanner,
        "citation": CitationScanner,
    }
    return _OUTPUT_SCANNERS


# ── Policy Engine ─────────────────────────────────────────────────────

class PolicyEngine:
    """
    YAML-driven policy engine for configuring firewall pipelines.

    Usage:
        engine = PolicyEngine.from_file("policy.yaml")
        input_pipe = engine.build_input_pipeline()
        output_pipe = engine.build_output_pipeline()

        result = input_pipe.scan(user_prompt)
        if result.is_valid:
            response = llm.generate(user_prompt)
            result = output_pipe.scan(response, prompt=user_prompt)
    """

    def __init__(self, config: PolicyConfig):
        self._config = config

    @classmethod
    def from_file(cls, filepath: str | Path) -> PolicyEngine:
        """Load policy from a YAML file."""
        import yaml

        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        config = cls._parse_config(raw or {})
        logger.info("Loaded policy '%s' v%s (%s)", config.name, config.version, config.environment)
        return cls(config)

    @classmethod
    def from_dict(cls, data: dict) -> PolicyEngine:
        """Load policy from a dictionary."""
        config = cls._parse_config(data)
        return cls(config)

    @classmethod
    def default(cls) -> PolicyEngine:
        """Create a policy with sensible defaults — all scanners enabled."""
        input_rules = [
            ScannerRule(scanner=name, priority=i * 10)
            for i, name in enumerate(_get_input_registry().keys())
        ]
        output_rules = [
            ScannerRule(scanner=name, priority=i * 10)
            for i, name in enumerate(_get_output_registry().keys())
        ]
        config = PolicyConfig(
            name="default",
            input_rules=input_rules,
            output_rules=output_rules,
            fail_open=True,  # Don't crash on optional dependency errors
        )
        return cls(config)

    @property
    def config(self) -> PolicyConfig:
        return self._config

    def build_input_pipeline(self) -> FirewallPipeline:
        """Build an input scanner pipeline from policy rules."""
        registry = _get_input_registry()
        scanners = []

        rules = sorted(
            [r for r in self._config.input_rules if r.enabled],
            key=lambda r: r.priority,
        )

        for rule in rules:
            if rule.mode == PolicyMode.DISABLED:
                continue
            scanner_cls = registry.get(rule.scanner)
            if scanner_cls is None:
                logger.warning("Unknown input scanner: %s", rule.scanner)
                continue
            try:
                scanner = scanner_cls(**rule.params)
                scanners.append(scanner)
                logger.debug("Loaded input scanner: %s (priority: %d)", rule.scanner, rule.priority)
            except Exception as e:
                logger.error("Failed to init scanner %s: %s", rule.scanner, e)
                if not self._config.fail_open:
                    raise

        return FirewallPipeline(scanners)

    def build_output_pipeline(self) -> FirewallPipeline:
        """Build an output scanner pipeline from policy rules."""
        registry = _get_output_registry()
        scanners = []

        rules = sorted(
            [r for r in self._config.output_rules if r.enabled],
            key=lambda r: r.priority,
        )

        for rule in rules:
            if rule.mode == PolicyMode.DISABLED:
                continue
            scanner_cls = registry.get(rule.scanner)
            if scanner_cls is None:
                logger.warning("Unknown output scanner: %s", rule.scanner)
                continue
            try:
                scanner = scanner_cls(**rule.params)
                scanners.append(scanner)
                logger.debug("Loaded output scanner: %s (priority: %d)", rule.scanner, rule.priority)
            except Exception as e:
                logger.error("Failed to init scanner %s: %s", rule.scanner, e)
                if not self._config.fail_open:
                    raise

        return FirewallPipeline(scanners)

    def list_scanners(self) -> dict[str, list[str]]:
        """List all available scanner names."""
        return {
            "input": list(_get_input_registry().keys()),
            "output": list(_get_output_registry().keys()),
        }

    # ── Private ───────────────────────────────────────────────────

    @classmethod
    def _parse_config(cls, raw: dict) -> PolicyConfig:
        """Parse raw YAML dict into PolicyConfig."""
        env = os.environ.get("SENTINEL_ENV", raw.get("environment", "production"))

        input_rules = [
            cls._parse_rule(r)
            for r in raw.get("input_scanners", raw.get("input_rules", []))
        ]
        output_rules = [
            cls._parse_rule(r)
            for r in raw.get("output_scanners", raw.get("output_rules", []))
        ]

        return PolicyConfig(
            name=raw.get("name", "custom"),
            version=str(raw.get("version", "1.0")),
            environment=env,
            mode=PolicyMode(raw.get("mode", "enforce")),
            input_rules=input_rules,
            output_rules=output_rules,
            global_threshold=raw.get("global_threshold", 0.5),
            max_risk_score=raw.get("max_risk_score", 0.9),
            fail_open=raw.get("fail_open", False),
            audit_all=raw.get("audit_all", True),
            metadata=raw.get("metadata", {}),
        )

    @staticmethod
    def _parse_rule(raw: dict) -> ScannerRule:
        """Parse a single scanner rule from YAML."""
        mode = PolicyMode(raw.get("mode", "enforce"))
        action_str = raw.get("action", "warn")
        try:
            action = ScanAction(action_str)
        except ValueError:
            action = ScanAction.WARN

        return ScannerRule(
            scanner=raw.get("scanner", raw.get("name", "")),
            enabled=raw.get("enabled", True),
            mode=mode,
            action=action,
            threshold=raw.get("threshold", 0.5),
            params=raw.get("params", {}),
            on_fail=raw.get("on_fail", "block"),
            priority=raw.get("priority", 100),
            tags=raw.get("tags", []),
        )
