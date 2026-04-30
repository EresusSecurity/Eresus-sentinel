"""Taint source / sink pattern catalog.

Intentionally small and explicit; project rules can extend via YAML
loaders elsewhere in the codebase.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from sentinel.finding import Severity

Kind = Literal["source", "sink"]


@dataclass
class TaintPattern:
    name: str
    pattern: re.Pattern
    kind: Kind
    description: str = ""


@dataclass
class SourcePattern(TaintPattern):
    kind: Kind = "source"


@dataclass
class SinkPattern(TaintPattern):
    severity: Severity = Severity.HIGH
    cwe: str = "CWE-20"
    kind: Kind = "sink"


def default_sources() -> list[SourcePattern]:
    return [
        SourcePattern("request.form", re.compile(r"\brequest\.(form|args|json|data|values|files)\b"),
                      description="HTTP request input"),
        SourcePattern("input()", re.compile(r"\binput\s*\("), description="stdin input"),
        SourcePattern("os.environ", re.compile(r"\bos\.environ\b"), description="environment variable"),
        SourcePattern("argv", re.compile(r"\bsys\.argv\b"), description="command-line argument"),
        SourcePattern("socket.recv", re.compile(r"\.recv\s*\("), description="network receive"),
        SourcePattern("open().read", re.compile(r"\.read\s*\("), description="file content read"),
        SourcePattern("Flask.request", re.compile(r"\bflask\.request\b"), description="Flask request"),
        SourcePattern("FastAPI.Request", re.compile(r"\bRequest\(\)"), description="FastAPI request"),
        SourcePattern("Django.request", re.compile(r"\brequest\.POST\b|\brequest\.GET\b"),
                      description="Django request"),
    ]


def default_sinks() -> list[SinkPattern]:
    return [
        SinkPattern("exec", re.compile(r"\bexec\s*\("), severity=Severity.CRITICAL, cwe="CWE-95",
                    description="Arbitrary code execution"),
        SinkPattern("eval", re.compile(r"\beval\s*\("), severity=Severity.CRITICAL, cwe="CWE-95",
                    description="Expression evaluation"),
        SinkPattern("subprocess", re.compile(r"\bsubprocess\.(call|run|Popen|check_output|check_call)\b"),
                    severity=Severity.HIGH, cwe="CWE-78", description="Shell command execution"),
        SinkPattern("os.system", re.compile(r"\bos\.system\b"), severity=Severity.HIGH, cwe="CWE-78",
                    description="Shell command"),
        SinkPattern("os.popen", re.compile(r"\bos\.popen\b"), severity=Severity.HIGH, cwe="CWE-78"),
        SinkPattern("pickle.loads", re.compile(r"\bpickle\.loads?\b"), severity=Severity.CRITICAL,
                    cwe="CWE-502", description="Unsafe deserialization"),
        SinkPattern("yaml.load", re.compile(r"\byaml\.load\s*\("), severity=Severity.HIGH, cwe="CWE-502"),
        SinkPattern("cursor.execute", re.compile(r"\.execute\s*\("), severity=Severity.HIGH, cwe="CWE-89",
                    description="SQL query"),
        SinkPattern("urlopen", re.compile(r"\burlopen\s*\("), severity=Severity.MEDIUM, cwe="CWE-918"),
        SinkPattern("requests.get", re.compile(r"\brequests\.(get|post|put|delete|head|patch)\b"),
                    severity=Severity.MEDIUM, cwe="CWE-918"),
    ]
