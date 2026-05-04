"""
Input/Output Firewall Base Interface.

Defines the scanner contract all firewall scanners implement.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional

_log = logging.getLogger(__name__)

from sentinel.finding import Finding, Severity


class ScanAction(str, Enum):
    """Action to take based on scan result."""
    PASS = "pass"        # Input is clean
    BLOCK = "block"      # Input should be rejected
    REDACT = "redact"    # Sensitive parts should be removed
    WARN = "warn"        # Input is suspicious but allowed


class ScanResult:
    """
    Result of a firewall scan.

    Attributes:
        sanitized: The (possibly modified) text after scanning.
        action: Whether to pass, block, redact, or warn.
        risk_score: 0.0 (safe) to 1.0 (definitely malicious).
        findings: Any security findings generated.
    """

    def __init__(
        self,
        sanitized: str,
        action: ScanAction,
        risk_score: float,
        findings: Optional[list[Finding]] = None,
        metadata: Optional[dict] = None,
    ):
        self.sanitized = sanitized
        self.action = action
        self.risk_score = risk_score
        self.findings = findings or []
        self.metadata = metadata or {}

    @property
    def is_valid(self) -> bool:
        return self.action in (ScanAction.PASS, ScanAction.WARN)

    def __repr__(self) -> str:
        meta = f", metadata={len(self.metadata)}" if self.metadata else ""
        return (
            f"ScanResult(action={self.action.value}, "
            f"risk_score={self.risk_score:.3f}, "
            f"findings={len(self.findings)}{meta})"
        )


class InputScanner(ABC):
    """
    Base class for input (prompt) scanners.

    Scanners analyze user prompts before they are sent to the LLM.
    Each scanner focuses on a specific threat category.

    Returns (sanitized, is_valid, risk_score) per the firewall scanner contract.
    """

    @abstractmethod
    def scan(self, prompt: str) -> ScanResult:
        """
        Scan a prompt for security issues.

        Args:
            prompt: The user's input prompt.

        Returns:
            ScanResult with action, risk score, and findings.
        """
        pass

    @staticmethod
    def _check_encoding_bypass(text: str) -> ScanResult | None:
        """Detect encoding bypass attacks in successfully-decoded text.

        UTF-16-LE/BE of ASCII text decodes as valid UTF-8 with null bytes
        interspersed. Latin-1 of ASCII is identical to UTF-8. Both are
        classic encoding-bypass techniques that defeat keyword scanning.
        """
        if not text:
            return None
        null_count = text.count("\x00")
        if null_count > 0 and null_count / len(text) > 0.10:
            _log.warning("Encoding bypass detected: %.0f%% null bytes (likely UTF-16)",
                         100 * null_count / len(text))
            finding = Finding.firewall_input(
                rule_id="FIREWALL-INPUT-ENC-003",
                title="UTF-16 encoding bypass attempt detected",
                description=(
                    f"Input decoded as UTF-8 but contains {null_count} null bytes "
                    f"({100*null_count/len(text):.0f}% of content). This is a classic "
                    "UTF-16-LE/BE re-encoding attack to bypass keyword scanners."
                ),
                severity=Severity.HIGH,
                confidence=0.95,
                target="<prompt>",
                evidence=f"null_byte_ratio={null_count/len(text):.2f}",
                cwe_ids=["CWE-116"],
                remediation="Input must be plain UTF-8 text without null bytes.",
            )
            stripped = text.replace("\x00", "")
            return ScanResult(sanitized=stripped, action=ScanAction.WARN, risk_score=0.7, findings=[finding])
        return None

    def _rescan_stripped(self, stripped: str, enc_finding: "Finding") -> "ScanResult":
        """Rescan null-stripped content and escalate to BLOCK if injection found."""
        try:
            inner = self.scan(stripped)
        except Exception:
            return ScanResult(sanitized=stripped, action=ScanAction.WARN, risk_score=0.7, findings=[enc_finding])
        merged_findings = [enc_finding] + list(inner.findings)
        if inner.action == ScanAction.BLOCK or inner.risk_score >= 0.7:
            return ScanResult(
                sanitized=inner.sanitized,
                action=ScanAction.BLOCK,
                risk_score=max(0.9, inner.risk_score),
                findings=merged_findings,
            )
        return ScanResult(
            sanitized=inner.sanitized,
            action=ScanAction.WARN,
            risk_score=max(0.7, inner.risk_score),
            findings=merged_findings,
        )

    def safe_scan(self, prompt: str | bytes) -> ScanResult:
        """Wrapper that handles binary/non-UTF-8 data gracefully."""
        if isinstance(prompt, bytes):
            try:
                prompt = prompt.decode("utf-8")
            except UnicodeDecodeError:
                _log.warning("%s: binary/non-UTF-8 input blocked", type(self).__name__)
                finding = Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-ENC-001",
                    title="Binary/non-UTF-8 input rejected",
                    description="Input could not be decoded as UTF-8. Non-text encodings are blocked to prevent encoding-bypass attacks.",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    target="<prompt>",
                    evidence="Input bytes are not valid UTF-8",
                    cwe_ids=["CWE-116"],
                    remediation="Ensure all input is UTF-8 encoded.",
                )
                return ScanResult(sanitized="", action=ScanAction.BLOCK, risk_score=0.9, findings=[finding])
        enc_finding_result = self._check_encoding_bypass(prompt)
        if enc_finding_result is not None:
            enc_finding = enc_finding_result.findings[0]
            stripped = enc_finding_result.sanitized
            return self._rescan_stripped(stripped, enc_finding)
        try:
            return self.scan(prompt)
        except (UnicodeDecodeError, UnicodeEncodeError) as exc:
            _log.warning("%s: encoding error during scan — treating as suspicious: %s", type(self).__name__, exc)
            finding = Finding.firewall_input(
                rule_id="FIREWALL-INPUT-ENC-002",
                title="Encoding error during scan",
                description="A Unicode encoding error occurred while scanning. Input flagged as suspicious.",
                severity=Severity.MEDIUM,
                confidence=0.7,
                target="<prompt>",
                evidence=str(exc)[:200],
                cwe_ids=["CWE-116"],
                remediation="Review input for unusual Unicode sequences.",
            )
            return ScanResult(sanitized=prompt, action=ScanAction.WARN, risk_score=0.6, findings=[finding])


class OutputScanner(ABC):
    """
    Base class for output (response) scanners.

    Scanners analyze LLM responses before they are returned to the user.
    Each scanner focuses on a specific threat category.

    Returns (sanitized, is_valid, risk_score) per the firewall scanner contract.
    """

    @abstractmethod
    def scan(self, prompt: str, output: str) -> ScanResult:
        """
        Scan an LLM output for security issues.

        Args:
            prompt: The original user prompt (for context).
            output: The LLM's response to scan.

        Returns:
            ScanResult with action, risk score, and findings.
        """
        pass

    def safe_scan(self, prompt: str | bytes, output: str | bytes) -> ScanResult:
        """Wrapper that handles binary/non-UTF-8 data gracefully."""
        if isinstance(prompt, bytes):
            try:
                prompt = prompt.decode("utf-8")
            except UnicodeDecodeError:
                prompt = prompt.decode("utf-8", errors="replace")
        if isinstance(output, bytes):
            try:
                output = output.decode("utf-8")
            except UnicodeDecodeError:
                _log.warning("%s: binary/non-UTF-8 output blocked", type(self).__name__)
                finding = Finding.firewall_input(
                    rule_id="FIREWALL-OUTPUT-ENC-001",
                    title="Binary/non-UTF-8 output rejected",
                    description="Output could not be decoded as UTF-8. Non-text encodings are blocked.",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    target="<output>",
                    evidence="Output bytes are not valid UTF-8",
                    cwe_ids=["CWE-116"],
                    remediation="Ensure all output is UTF-8 encoded.",
                )
                return ScanResult(sanitized="", action=ScanAction.BLOCK, risk_score=0.9, findings=[finding])
        try:
            return self.scan(prompt, output)
        except (UnicodeDecodeError, UnicodeEncodeError) as exc:
            _log.warning("%s: encoding error during output scan — treating as suspicious: %s", type(self).__name__, exc)
            finding = Finding.firewall_input(
                rule_id="FIREWALL-OUTPUT-ENC-002",
                title="Encoding error during output scan",
                description="A Unicode encoding error occurred while scanning output. Flagged as suspicious.",
                severity=Severity.MEDIUM,
                confidence=0.7,
                target="<output>",
                evidence=str(exc)[:200],
                cwe_ids=["CWE-116"],
                remediation="Review output for unusual Unicode sequences.",
            )
            return ScanResult(sanitized=output, action=ScanAction.WARN, risk_score=0.6, findings=[finding])


class FirewallPipeline:
    """
    Chains multiple scanners into a pipeline.

    Supports two execution modes:
    - Sequential (default): scanners run in order, REDACT results cascade
    - Parallel: independent scanners run concurrently for speed

    Features:
    - Short-circuit on BLOCK
    - REDACT cascading in sequential mode
    - Per-scanner timing metadata
    - Optional Vault integration for PII redact/restore
    - Fail-open/fail-closed behavior on scanner errors
    """

    def __init__(
        self,
        scanners: Optional[list] = None,
        parallel: bool = False,
        max_workers: int = 4,
        fail_open: bool = True,
        vault: Optional[object] = None,
    ):
        self._scanners = scanners or []
        self._parallel = parallel
        # Worker count: CLI/constructor > env var > cpu_count > fallback
        env_workers = os.environ.get("SENTINEL_MAX_WORKERS")
        if env_workers and env_workers.isdigit():
            self._max_workers = int(env_workers)
        else:
            self._max_workers = min(max_workers, os.cpu_count() or 4)
        self._fail_open = fail_open
        self._vault = vault

    def add_scanner(self, scanner) -> None:
        self._scanners.append(scanner)

    @property
    def scanner_count(self) -> int:
        return len(self._scanners)

    def scan(self, text: str | bytes, prompt: str = "") -> ScanResult:
        """
        Run text through all scanners in the pipeline.

        Args:
            text: The text to scan (prompt for input, response for output).
                  If bytes, decoded as UTF-8 with replacement.
            prompt: Original prompt (only used for output scanners).

        Returns:
            Aggregated ScanResult with all findings.
        """
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="replace")
        if isinstance(prompt, bytes):
            prompt = prompt.decode("utf-8", errors="replace")
        if self._parallel and not self._has_redact_scanners():
            return self._scan_parallel(text, prompt)
        return self._scan_sequential(text, prompt)

    def _scan_sequential(self, text: str, prompt: str) -> ScanResult:
        """Sequential scan — supports REDACT cascading."""
        import time as _time

        all_findings = []
        current_text = text
        max_risk = 0.0
        result_action = ScanAction.PASS
        scanner_timings = {}

        for scanner in self._scanners:
            scanner_name = type(scanner).__name__
            start = _time.perf_counter()

            try:
                if isinstance(scanner, InputScanner):
                    result = scanner.scan(current_text)
                elif isinstance(scanner, OutputScanner):
                    result = scanner.scan(prompt, current_text)
                else:
                    continue
            except Exception as e:
                elapsed_ms = (_time.perf_counter() - start) * 1000
                scanner_timings[scanner_name] = round(elapsed_ms, 2)
                if self._fail_open:
                    import logging
                    logging.getLogger(__name__).warning(
                        "Scanner %s failed (fail-open): %s", scanner_name, e
                    )
                    continue
                else:
                    raise

            elapsed_ms = (_time.perf_counter() - start) * 1000
            scanner_timings[scanner_name] = round(elapsed_ms, 2)

            all_findings.extend(result.findings)
            max_risk = max(max_risk, result.risk_score)

            # Handle actions
            if result.action == ScanAction.BLOCK:
                return ScanResult(
                    sanitized=current_text,
                    action=ScanAction.BLOCK,
                    risk_score=max_risk,
                    findings=all_findings,
                    metadata={"scanner_timings": scanner_timings},
                )

            if result.action == ScanAction.REDACT:
                current_text = result.sanitized
                result_action = ScanAction.REDACT

            if result.action == ScanAction.WARN and result_action == ScanAction.PASS:
                result_action = ScanAction.WARN

        return ScanResult(
            sanitized=current_text,
            action=result_action,
            risk_score=max_risk,
            findings=all_findings,
            metadata={"scanner_timings": scanner_timings},
        )

    def _scan_parallel(self, text: str, prompt: str) -> ScanResult:
        """Parallel scan — all scanners run concurrently using threads.

        Uses ThreadPoolExecutor (not ProcessPoolExecutor) because:
        1. Scanner objects are not picklable (closures, locks, ML models)
        2. Most scanners are IO-bound (regex, HTTP, model inference)
        3. Threads share memory safely for result aggregation
        """
        import time as _time
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from concurrent.futures import TimeoutError as FutureTimeout

        all_findings: list[Finding] = []
        max_risk = 0.0
        result_action = ScanAction.PASS
        scanner_timings: dict[str, float] = {}
        fail_open = self._fail_open
        max_workers = self._max_workers

        # Per-scanner timeout in seconds (env override supported)
        _scanner_timeout = float(os.environ.get("SENTINEL_SCANNER_TIMEOUT", "30"))

        def _run_one(scanner):
            scanner_name = type(scanner).__name__
            start = _time.perf_counter()
            try:
                if isinstance(scanner, InputScanner):
                    result = scanner.scan(text)
                elif isinstance(scanner, OutputScanner):
                    result = scanner.scan(prompt, text)
                else:
                    return None, scanner_name, 0.0
                elapsed_ms = (_time.perf_counter() - start) * 1000
                return result, scanner_name, elapsed_ms
            except Exception as e:
                elapsed_ms = (_time.perf_counter() - start) * 1000
                if fail_open:
                    _log.warning("Scanner %s failed (fail-open): %s", scanner_name, e)
                    return None, scanner_name, elapsed_ms
                raise

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(_run_one, s): s for s in self._scanners}
            for future in as_completed(future_map, timeout=_scanner_timeout * len(self._scanners)):
                try:
                    result, scanner_name, elapsed_ms = future.result(timeout=_scanner_timeout)
                except FutureTimeout:
                    scanner_name = type(future_map[future]).__name__
                    _log.error("Scanner %s timed out after %.0fs — skipping", scanner_name, _scanner_timeout)
                    scanner_timings[scanner_name] = _scanner_timeout * 1000
                    continue

                scanner_timings[scanner_name] = round(elapsed_ms, 2)

                if result is None:
                    continue

                all_findings.extend(result.findings)
                max_risk = max(max_risk, result.risk_score)

                if result.action == ScanAction.BLOCK:
                    result_action = ScanAction.BLOCK
                elif result.action == ScanAction.WARN and result_action == ScanAction.PASS:
                    result_action = ScanAction.WARN

        return ScanResult(
            sanitized=text,
            action=result_action,
            risk_score=max_risk,
            findings=all_findings,
            metadata={
                "scanner_timings": scanner_timings,
                "parallel": True,
                "workers": max_workers,
            },
        )

    def _has_redact_scanners(self) -> bool:
        """Check if any scanner may return REDACT action.

        Scanners that perform redaction should set class attribute
        ``supports_redact = True`` for reliable detection.
        Falls back to a name-based heuristic for legacy scanners.
        """
        for scanner in self._scanners:
            # Explicit marker — preferred
            if getattr(scanner, "supports_redact", False):
                return True
            # Legacy heuristic fallback
            name = type(scanner).__name__.lower()
            if "anonymize" in name or "sensitive" in name or "redact" in name or "pii" in name:
                return True
        return False

