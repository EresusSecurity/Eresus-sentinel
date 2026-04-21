"""
Eresus Sentinel — Custom Exception Hierarchy.

Replaces generic stack traces with actionable, user-facing error messages.
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base exception for all Sentinel errors."""

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.hint = hint

    def user_message(self) -> str:
        msg = str(self)
        if self.hint:
            msg += f"\n  → {self.hint}"
        return msg


class DependencyMissing(SentinelError):
    """A required or optional dependency is not installed."""

    def __init__(self, package: str, feature: str = "", install_cmd: str = ""):
        self.package = package
        self.feature = feature
        hint = install_cmd or f"pip install {package}"
        msg = f"Missing dependency: {package}"
        if feature:
            msg += f" (required for {feature})"
        super().__init__(msg, hint=hint)


class UnsupportedFormat(SentinelError):
    """File format is not supported for scanning."""

    def __init__(self, filepath: str, detected: str = ""):
        info = f" (detected: {detected})" if detected else ""
        super().__init__(
            f"Unsupported file format: {filepath}{info}",
            hint="Use 'sentinel scanners' to see supported formats.",
        )


class CorruptFile(SentinelError):
    """File is corrupt or truncated and cannot be parsed."""

    def __init__(self, filepath: str, reason: str = ""):
        detail = f": {reason}" if reason else ""
        super().__init__(
            f"Corrupt or truncated file: {filepath}{detail}",
            hint="Verify the file is not damaged. Try re-downloading.",
        )


class ScanTimeout(SentinelError):
    """Scan exceeded the configured time limit."""

    def __init__(self, timeout_seconds: int, partial_results: int = 0):
        self.timeout_seconds = timeout_seconds
        self.partial_results = partial_results
        super().__init__(
            f"Scan timed out after {timeout_seconds}s ({partial_results} partial results available)",
            hint="Increase --timeout or use --mode quick for faster scans.",
        )


class RuleParseError(SentinelError):
    """A YAML rule file could not be parsed."""

    def __init__(self, rule_file: str, reason: str = ""):
        detail = f": {reason}" if reason else ""
        super().__init__(
            f"Failed to parse rule file: {rule_file}{detail}",
            hint="Run 'sentinel rules validate' to check all rule files.",
        )


class ConfigError(SentinelError):
    """Configuration file is invalid or missing required fields."""

    def __init__(self, config_file: str, reason: str = ""):
        detail = f": {reason}" if reason else ""
        super().__init__(
            f"Configuration error in {config_file}{detail}",
            hint="Check sentinel.toml format and required fields.",
        )


class WorkerError(SentinelError):
    """A scan worker process crashed or failed."""

    def __init__(self, worker_id: str = "", reason: str = ""):
        detail = f" ({reason})" if reason else ""
        super().__init__(
            f"Scan worker failed{detail}",
            hint="Try reducing --workers count or using --mode quick.",
        )
