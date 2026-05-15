from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SntlIssue:
    severity: str
    path: str
    message: str


@dataclass(frozen=True)
class SntlToken:
    line: int
    indent: int
    text: str


@dataclass(frozen=True)
class SntlDocument:
    source: str
    data: dict[str, Any]
    schema: str | None
    fingerprint: str
    issues: tuple[SntlIssue, ...]

    @property
    def ok(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    def require(self) -> SntlDocument:
        if not self.ok:
            raise SntlValidationError(self.issues)
        return self

    def canonical_json(self) -> str:
        from sentinel.sntl.canonical import canonical_json

        return canonical_json(self.data)

    def to_sntl(self) -> str:
        from sentinel.sntl.writer import dumps

        return dumps(self.data)


@dataclass(frozen=True)
class SntlBundle:
    data: dict[str, Any]
    fingerprint: str
    profile: str | None
    environment: str | None
    layers: tuple[dict[str, Any], ...]
    issues: tuple[SntlIssue, ...]

    @property
    def ok(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    def require(self) -> SntlBundle:
        if not self.ok:
            raise SntlValidationError(self.issues)
        return self

    def explain(self) -> dict[str, Any]:
        return {
            "schema_version": "sentinel.sntl.explain.v1",
            "fingerprint": self.fingerprint,
            "profile": self.profile,
            "environment": self.environment,
            "layers": list(self.layers),
            "effective_keys": sorted(self.data.keys()),
            "issues": [issue.__dict__ for issue in self.issues],
        }

    def simulate(self) -> dict[str, Any]:
        from sentinel.platform.config import simulate_config

        return simulate_config(self.data)


class SntlParseError(ValueError):
    def __init__(self, message: str, line: int = 0, column: int = 0):
        self.line = line
        self.column = column
        super().__init__(f"{line}:{column}: {message}" if line else message)


class SntlValidationError(ValueError):
    def __init__(self, issues: tuple[SntlIssue, ...]):
        self.issues = issues
        message = "; ".join(f"{issue.path}: {issue.message}" for issue in issues if issue.severity == "error")
        super().__init__(message or "sntl validation failed")
