"""
Input/Output Firewall Base Interface.

Defines the scanner contract all firewall scanners implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional

from sentinel.finding import Finding


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
        self._max_workers = max_workers
        self._fail_open = fail_open
        self._vault = vault

    def add_scanner(self, scanner) -> None:
        self._scanners.append(scanner)

    @property
    def scanner_count(self) -> int:
        return len(self._scanners)

    def scan(self, text: str, prompt: str = "") -> ScanResult:
        """
        Run text through all scanners in the pipeline.

        Args:
            text: The text to scan (prompt for input, response for output).
            prompt: Original prompt (only used for output scanners).

        Returns:
            Aggregated ScanResult with all findings.
        """
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
        """Parallel scan — all scanners run concurrently."""
        import time as _time
        from concurrent.futures import ThreadPoolExecutor, as_completed

        all_findings = []
        max_risk = 0.0
        result_action = ScanAction.PASS
        scanner_timings = {}

        def _run_scanner(scanner):
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
                if self._fail_open:
                    import logging
                    logging.getLogger(__name__).warning(
                        "Scanner %s failed (fail-open): %s", scanner_name, e
                    )
                    return None, scanner_name, elapsed_ms
                raise

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = [executor.submit(_run_scanner, s) for s in self._scanners]
            for future in as_completed(futures):
                result, scanner_name, elapsed_ms = future.result()
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
            metadata={"scanner_timings": scanner_timings, "parallel": True},
        )

    def _has_redact_scanners(self) -> bool:
        """Check if any scanner might return REDACT action."""
        # Heuristic: check if scanner class name contains 'Anonymize' or 'Sensitive'
        for scanner in self._scanners:
            name = type(scanner).__name__.lower()
            if "anonymize" in name or "sensitive" in name or "redact" in name:
                return True
        return False

