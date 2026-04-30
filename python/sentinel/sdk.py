"""
Eresus Sentinel — Python SDK.

One-liner integration for the entire security platform.

Features:
  - Policy-driven pipe construction
  - Scan input, scan output, scan both
  - Batch scanning
  - Integrated audit logging + metrics
  - Cost tracking
  - Red-team harness access
  - Artifact scanning

Usage:
    from sentinel.sdk import Sentinel

    # Quick start (all scanners, default thresholds)
    s = Sentinel()
    result = s.scan_input("user prompt")
    result = s.scan_output("user prompt", "model response")

    # Policy-driven
    s = Sentinel.from_policy("policy.yaml")

    # Full pipeline
    result = s.scan_conversation("prompt", "response")
    if result.blocked:
        print("Blocked:", result.reason)
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.firewall.base import (
    ScanAction,
    ScanResult,
)

logger = logging.getLogger(__name__)


@dataclass
class ConversationResult:
    """Combined input + output scan result."""
    input_result: ScanResult | None = None
    output_result: ScanResult | None = None
    blocked: bool = False
    reason: str = ""
    risk_score: float = 0.0
    total_findings: int = 0
    latency_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


def _scan_conversation_pair(args):
    """Top-level helper for ProcessPoolExecutor (must be picklable)."""
    sentinel_instance, prompt, output = args
    return sentinel_instance.scan_conversation(prompt, output)


class Sentinel:
    """
    Main entry point for Eresus Sentinel.

    Usage:
        # All defaults
        s = Sentinel()
        result = s.scan_output(prompt, response)

        # Policy file
        s = Sentinel.from_policy("policy.yaml")

        # Selective scanners
        s = Sentinel(input_scanners=["injection", "toxicity", "secrets"])

        # Full-featured
        s = Sentinel(
            input_scanners=["injection", "secrets"],
            output_scanners=["toxicity", "sensitive"],
            audit_path="audit.jsonl",
            enable_metrics=True,
            vault_enabled=True,
            parallel=True,
            budget_usd=50.0,
        )

        # Artifact scan
        findings = s.scan_artifact("model.pkl")

        # HuggingFace guard
        assessment = s.hf_assess("microsoft/phi-2")
    """

    def __init__(
        self,
        input_scanners: list[str] | None = None,
        output_scanners: list[str] | None = None,
        audit_path: str | Path | None = None,
        enable_metrics: bool = False,
        budget_usd: float | None = None,
        vault_enabled: bool = False,
        parallel: bool = False,
    ):
        # Lazy imports to avoid circular deps
        from sentinel.policy import PolicyConfig, PolicyEngine, ScannerRule

        self._parallel = parallel

        # Build auto policy from scanner lists
        config = PolicyConfig(name="sdk")
        if input_scanners:
            config.input_rules = [
                ScannerRule(scanner=s, priority=i * 10)
                for i, s in enumerate(input_scanners)
            ]
        if output_scanners:
            config.output_rules = [
                ScannerRule(scanner=s, priority=i * 10)
                for i, s in enumerate(output_scanners)
            ]

        engine = PolicyEngine(config)

        if input_scanners:
            self._input_pipe = engine.build_input_pipeline()
        else:
            self._input_pipe = None

        if output_scanners:
            self._output_pipe = engine.build_output_pipeline()
        else:
            self._output_pipe = None

        # Observability
        self._audit = None
        if audit_path:
            from sentinel.audit import AuditLogger
            self._audit = AuditLogger(path=audit_path)

        self._metrics = None
        if enable_metrics:
            from sentinel.metrics import MetricsCollector
            self._metrics = MetricsCollector()

        self._cost_guard = None
        if budget_usd:
            from sentinel.cost_guard import CostGuard
            self._cost_guard = CostGuard(budget_usd=budget_usd)

        # Vault integration
        self._vault = None
        if vault_enabled:
            from sentinel.vault import Vault
            self._vault = Vault()

        # Session stats
        self._stats = {
            "total_scans": 0,
            "total_blocks": 0,
            "total_findings": 0,
            "total_latency_ms": 0.0,
        }

    @classmethod
    def from_policy(cls, filepath: str | Path) -> Sentinel:
        """Create Sentinel from a YAML policy file."""
        from sentinel.policy import PolicyEngine

        engine = PolicyEngine.from_file(filepath)
        instance = cls.__new__(cls)
        instance._input_pipe = engine.build_input_pipeline()
        instance._output_pipe = engine.build_output_pipeline()
        instance._audit = None
        instance._metrics = None
        instance._cost_guard = None
        instance._vault = None
        instance._parallel = False
        instance._stats = {"total_scans": 0, "total_blocks": 0, "total_findings": 0, "total_latency_ms": 0.0}
        return instance

    @classmethod
    def default(cls) -> Sentinel:
        """Create Sentinel with all scanners using default config."""
        from sentinel.policy import PolicyEngine

        engine = PolicyEngine.default()
        instance = cls.__new__(cls)
        instance._input_pipe = engine.build_input_pipeline()
        instance._output_pipe = engine.build_output_pipeline()
        instance._audit = None
        instance._metrics = None
        instance._cost_guard = None
        instance._vault = None
        instance._parallel = False
        instance._stats = {"total_scans": 0, "total_blocks": 0, "total_findings": 0, "total_latency_ms": 0.0}
        return instance

    # ── Core Scanning ─────────────────────────────────────────────

    def scan_input(self, prompt: str) -> ScanResult:
        """Scan user input through the input pipeline."""
        if self._input_pipe is None:
            from sentinel.policy import PolicyEngine
            engine = PolicyEngine.default()
            self._input_pipe = engine.build_input_pipeline()

        # Vault redact before scanning
        if self._vault:
            prompt = self._vault.redact(prompt, "input")

        start = time.perf_counter()
        result = self._input_pipe.scan(prompt)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Track stats
        self._stats["total_scans"] += 1
        self._stats["total_findings"] += len(result.findings)
        self._stats["total_latency_ms"] += elapsed_ms
        if result.action == ScanAction.BLOCK:
            self._stats["total_blocks"] += 1

        # Observability
        if self._audit:
            self._audit.log_result("input_pipeline", "input", result, latency_ms=elapsed_ms,
                                   prompt_hash=hashlib.sha256(prompt.encode()).hexdigest()[:16])
        if self._metrics:
            self._metrics.record_result("input_pipeline", "input", result, duration_seconds=elapsed_ms / 1000)

        return result

    def scan_output(self, prompt: str, output: str) -> ScanResult:
        """Scan model output through the output pipeline."""
        if self._output_pipe is None:
            from sentinel.policy import PolicyEngine
            engine = PolicyEngine.default()
            self._output_pipe = engine.build_output_pipeline()

        start = time.perf_counter()
        result = self._output_pipe.scan(output, prompt=prompt)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Vault restore if needed
        if self._vault and result.sanitized:
            result.sanitized = self._vault.restore(result.sanitized)

        # Track stats
        self._stats["total_scans"] += 1
        self._stats["total_findings"] += len(result.findings)
        self._stats["total_latency_ms"] += elapsed_ms
        if result.action == ScanAction.BLOCK:
            self._stats["total_blocks"] += 1

        # Observability
        if self._audit:
            self._audit.log_result("output_pipeline", "output", result, latency_ms=elapsed_ms,
                                   prompt_hash=hashlib.sha256(prompt.encode()).hexdigest()[:16])
        if self._metrics:
            self._metrics.record_result("output_pipeline", "output", result, duration_seconds=elapsed_ms / 1000)

        return result

    def scan_conversation(self, prompt: str, output: str) -> ConversationResult:
        """Scan both input and output in one call."""
        start = time.perf_counter()

        # Input scan
        input_result = self.scan_input(prompt)
        if input_result.action == ScanAction.BLOCK:
            return ConversationResult(
                input_result=input_result,
                blocked=True,
                reason=f"Input blocked: {len(input_result.findings)} findings",
                risk_score=input_result.risk_score,
                total_findings=len(input_result.findings),
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        # Output scan
        output_result = self.scan_output(prompt, output)
        total_findings = len(input_result.findings) + len(output_result.findings)
        max_risk = max(input_result.risk_score, output_result.risk_score)

        blocked = output_result.action == ScanAction.BLOCK
        reason = ""
        if blocked:
            reason = f"Output blocked: {len(output_result.findings)} findings"

        return ConversationResult(
            input_result=input_result,
            output_result=output_result,
            blocked=blocked,
            reason=reason,
            risk_score=max_risk,
            total_findings=total_findings,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    # ── Batch Scanning ────────────────────────────────────────────

    def scan_batch(
        self,
        items: list[tuple[str, str]],
        max_workers: int = 4,
    ) -> list[ConversationResult]:
        """
        Scan a batch of (prompt, output) pairs.

        Uses concurrent.futures for parallel execution when self._parallel is True.
        """
        if self._parallel and len(items) > 1:
            from concurrent.futures import ProcessPoolExecutor
            with ProcessPoolExecutor(max_workers=max_workers) as pool:
                results = list(pool.map(_scan_conversation_pair, [(self, p, o) for p, o in items]))
            return results

        return [self.scan_conversation(p, o) for p, o in items]

    # ── Artifact Scanning ─────────────────────────────────────────

    def scan_artifact(self, path: str | Path) -> list:
        """
        Scan a model artifact file for security issues.

        Args:
            path: Path to model file (.pkl, .pt, .onnx, .safetensors, etc.)

        Returns:
            List of Finding objects.
        """
        from sentinel.cli_dispatch import _scan_single_artifact
        return _scan_single_artifact(Path(path))

    def scan_directory(self, directory: str | Path, recursive: bool = True) -> list:
        """
        Scan all model artifacts in a directory.

        Returns:
            List of Finding objects from all scanned files.
        """
        from sentinel.cli_dispatch import _scan_single_artifact
        target = Path(directory)
        if not target.is_dir():
            raise ValueError(f"Not a directory: {target}")

        findings = []
        pattern = "**/*" if recursive else "*"
        for child in target.glob(pattern):
            if child.is_file():
                try:
                    file_findings = _scan_single_artifact(child)
                    findings.extend(file_findings)
                except Exception as e:
                    logger.warning("Failed to scan %s: %s", child, e)

        return findings

    # ── HuggingFace Guard ─────────────────────────────────────────

    def hf_assess(self, repo_id: str, revision: str = "main") -> Any:
        """
        Pre-download risk assessment for a HuggingFace model repo.

        Returns:
            HFAssessment object with risk analysis.
        """
        from sentinel.hf_guard import HFGuard
        guard = HFGuard()
        return guard.assess(repo_id, revision)

    def hf_scan(self, repo_id: str, revision: str = "main") -> list:
        """
        Full scan of a HuggingFace model repo (downloads + scans).

        Returns:
            List of Finding objects.
        """
        from sentinel.hf_guard import HFGuard
        guard = HFGuard()
        return guard.scan(repo_id, revision)

    # ── Evaluator ─────────────────────────────────────────────────

    def evaluate_scanners(self) -> list:
        """
        Evaluate all registered input scanners for effectiveness.

        Returns:
            List of EvalResult objects with precision/recall/F1.
        """
        from sentinel.evaluator import ScannerEvaluator
        evaluator = ScannerEvaluator()
        return evaluator.evaluate_all_input()

    # ── Export ─────────────────────────────────────────────────────

    def findings_to_sarif(self, findings: list) -> dict:
        """
        Convert findings list to SARIF 2.1.0 format.

        Useful for GitHub Code Scanning integration.
        """
        from sentinel import __version__
        rules = {}
        results = []

        for f in findings:
            rule_id = getattr(f, "rule_id", "UNKNOWN")
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": getattr(f, "title", rule_id),
                    "shortDescription": {"text": getattr(f, "title", "")},
                    "helpUri": "https://eresussec.com/docs",
                    "properties": {
                        "tags": getattr(f, "tags", []),
                    },
                }

            severity = getattr(f, "severity", None)
            level = "warning"
            if severity:
                sev_val = severity.value if hasattr(severity, "value") else str(severity)
                level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                         "LOW": "note", "INFO": "note"}.get(sev_val, "warning")

            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": getattr(f, "description", "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": getattr(f, "target", "unknown"),
                        },
                    },
                }],
            })

        return {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Eresus Sentinel",
                        "version": __version__,
                        "informationUri": "https://eresussec.com",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
            }],
        }

    # ── Observability ─────────────────────────────────────────────

    @property
    def metrics(self):
        return self._metrics

    @property
    def audit(self):
        return self._audit

    @property
    def cost_guard(self):
        return self._cost_guard

    @property
    def vault(self):
        return self._vault

    @property
    def stats(self) -> dict:
        """Session-level scanning statistics."""
        return dict(self._stats)

    def track_cost(self, model: str, input_tokens: int, output_tokens: int) -> None:
        """Track LLM API cost if cost guard is active."""
        if self._cost_guard:
            self._cost_guard.track(model, input_tokens, output_tokens)

    def health(self) -> dict:
        """Return health status of all sentinel components."""
        from sentinel import __version__
        return {
            "version": __version__,
            "input_pipeline": self._input_pipe is not None,
            "output_pipeline": self._output_pipe is not None,
            "audit": self._audit is not None,
            "metrics": self._metrics is not None,
            "vault": self._vault is not None,
            "cost_guard": self._cost_guard is not None,
            "parallel": self._parallel,
            "stats": self.stats,
        }

