"""MCP static analysis engine — taint tracking, dataflow, and prompt defense.

YAML-driven detection engine. All sink/source/prompt patterns are loaded
from sentinel/config/static_analysis_patterns.yaml at module load time.

Provides taint tracking with labeled propagation, sink detection across
17 sink categories, and prompt injection/boundary analysis.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class TaintLabel(Enum):
    USER_INPUT = auto()
    TOOL_PARAM = auto()
    ENV_VAR = auto()
    FILE_CONTENT = auto()
    NETWORK_DATA = auto()
    PROMPT_DATA = auto()
    UNTRUSTED = auto()
    DATABASE_RESULT = auto()
    DESERIALIZED = auto()
    HEADER_VALUE = auto()
    COOKIE_VALUE = auto()
    CLI_ARG = auto()
    STDIN_DATA = auto()
    WEBSOCKET_MSG = auto()
    MCP_TOOL_RESULT = auto()
    LLM_RESPONSE = auto()


class SinkType(Enum):
    EXEC = auto()
    FILE_WRITE = auto()
    FILE_READ = auto()
    NETWORK_OUT = auto()
    SQL_QUERY = auto()
    EVAL = auto()
    SUBPROCESS = auto()
    DESERIALIZATION = auto()
    TEMPLATE_RENDER = auto()
    LDAP_QUERY = auto()
    XML_PARSE = auto()
    YAML_PARSE = auto()
    REDIRECT = auto()
    LOGGING_SINK = auto()
    CRYPTO_OPERATION = auto()
    REFLECTION = auto()
    PROCESS_SIGNAL = auto()


@dataclass
class TaintedValue:
    name: str
    labels: set[TaintLabel] = field(default_factory=set)
    source_location: str = ""
    chain: list[str] = field(default_factory=list)


@dataclass
class DataflowFinding:
    source: str
    sink: str
    sink_type: SinkType
    taint_labels: set[TaintLabel]
    path: list[str] = field(default_factory=list)
    severity: str = "HIGH"
    description: str = ""
    cwe: str = ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# YAML-DRIVEN PATTERN LOADING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_DEFAULT_YAML = Path(__file__).resolve().parent.parent / "config" / "static_analysis_patterns.yaml"
_CUSTOM_YAML_ENV = "SENTINEL_STATIC_PATTERNS_PATH"


def _load_patterns(yaml_path: Path | None = None) -> dict[str, Any]:
    """Load pattern registry from YAML."""
    import yaml  # type: ignore[import-untyped]

    path = yaml_path or Path(os.getenv(_CUSTOM_YAML_ENV, str(_DEFAULT_YAML)))
    if not path.is_file():
        logger.warning("Static analysis patterns YAML not found: %s — using empty registry", path)
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    logger.info("Loaded static analysis patterns from %s", path)
    return data


def _build_sink_registry(data: dict) -> dict[SinkType, list[tuple[str, str]]]:
    registry: dict[SinkType, list[tuple[str, str]]] = {}
    raw = data.get("dangerous_sinks", {})
    for sink_name, entries in raw.items():
        try:
            st = SinkType[sink_name]
        except KeyError:
            continue
        registry[st] = [(e["pattern"], e.get("cwe", "")) for e in entries]
    return registry


def _build_taint_sources(data: dict) -> dict[TaintLabel, list[str]]:
    registry: dict[TaintLabel, list[str]] = {}
    raw = data.get("taint_sources", {})
    for label_name, patterns in raw.items():
        try:
            label = TaintLabel[label_name]
        except KeyError:
            continue
        registry[label] = list(patterns)
    return registry


def _build_prompt_defense(data: dict) -> dict[str, Any]:
    return data.get("prompt_defense", {})


# Load everything at module import time
_RAW = _load_patterns()
DANGEROUS_SINKS: dict[SinkType, list[tuple[str, str]]] = _build_sink_registry(_RAW)
TAINT_SOURCES: dict[TaintLabel, list[str]] = _build_taint_sources(_RAW)
_PROMPT_DEFENSE: dict[str, Any] = _build_prompt_defense(_RAW)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAINT TRACKING ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TaintTracker:

    def __init__(self):
        self._tainted: dict[str, TaintedValue] = {}

    @property
    def tainted_vars(self) -> dict[str, TaintedValue]:
        return dict(self._tainted)

    def add_source(self, var: str, label: TaintLabel, loc: str = "") -> None:
        if var not in self._tainted:
            self._tainted[var] = TaintedValue(name=var, source_location=loc)
        self._tainted[var].labels.add(label)
        self._tainted[var].chain.append(f"SRC:{loc}")

    def propagate(self, src: str, dst: str, op: str = "") -> None:
        if src in self._tainted:
            s = self._tainted[src]
            if dst not in self._tainted:
                self._tainted[dst] = TaintedValue(
                    name=dst, labels=set(s.labels),
                    source_location=s.source_location, chain=list(s.chain),
                )
            else:
                self._tainted[dst].labels.update(s.labels)
            self._tainted[dst].chain.append(f"PROP:{op}")

    def is_tainted(self, var: str) -> bool:
        return var in self._tainted

    def check_sink(self, var: str, sink: SinkType, cwe: str = "") -> Optional[DataflowFinding]:
        if var in self._tainted:
            tv = self._tainted[var]
            critical_sinks = {
                SinkType.EXEC, SinkType.SUBPROCESS, SinkType.DESERIALIZATION,
                SinkType.REFLECTION,
            }
            return DataflowFinding(
                source=tv.source_location, sink=var,
                sink_type=sink, taint_labels=set(tv.labels),
                path=list(tv.chain),
                severity="CRITICAL" if sink in critical_sinks else "HIGH",
                description=f"Tainted '{var}' reaches {sink.name} sink",
                cwe=cwe,
            )
        return None

    def get_labels(self, var: str) -> set[TaintLabel]:
        if var in self._tainted:
            return set(self._tainted[var].labels)
        return set()

    def sanitize(self, var: str) -> None:
        self._tainted.pop(var, None)

    def clear(self) -> None:
        self._tainted.clear()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STATIC ANALYZER (uses YAML-loaded sinks and sources)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class StaticAnalyzer:

    def __init__(self):
        self._tracker = TaintTracker()
        self._findings: list[DataflowFinding] = []

    @property
    def findings(self) -> list[DataflowFinding]:
        return list(self._findings)

    def analyze_code(self, code: str, filename: str = "unknown") -> list[DataflowFinding]:
        self._findings = []
        self._tracker = TaintTracker()
        lines = code.split("\n")
        for lineno, line in enumerate(lines, 1):
            loc = f"{filename}:{lineno}"
            for label, patterns in TAINT_SOURCES.items():
                for pat in patterns:
                    if re.search(pat, line):
                        m = re.match(r"\s*(\w+)\s*=", line)
                        var = m.group(1) if m else f"_l{lineno}"
                        self._tracker.add_source(var, label, loc)
            m = re.match(r"\s*(\w+)\s*=\s*.*?(\w+)", line)
            if m:
                tgt, src = m.group(1), m.group(2)
                if self._tracker.is_tainted(src) and tgt != src:
                    self._tracker.propagate(src, tgt, loc)
            for st, sink_patterns in DANGEROUS_SINKS.items():
                for pat_tuple in sink_patterns:
                    pat = pat_tuple[0]
                    cwe = pat_tuple[1] if len(pat_tuple) > 1 else ""
                    if re.search(pat, line):
                        for var in self._tracker.tainted_vars:
                            if var in line:
                                f = self._tracker.check_sink(var, st, cwe)
                                if f:
                                    f.description += f" at {loc}"
                                    self._findings.append(f)
        return self._findings

    def analyze_tool_chain(self, tools: list[dict]) -> list[DataflowFinding]:
        out = []
        for t in tools:
            out.extend(self.analyze_code(
                t.get("code", ""), filename=f"tool:{t.get('name', '?')}",
            ))
        return out

    def analyze_mcp_server(self, server_code: str, name: str = "mcp_server") -> list[DataflowFinding]:
        findings = self.analyze_code(server_code, filename=name)
        tool_handler_pat = re.compile(r"@(?:tool|mcp\.tool|server\.tool)\s*(?:\(.*?\))?\s*\ndef\s+(\w+)")
        for m in tool_handler_pat.finditer(server_code):
            func_name = m.group(1)
            start = m.start()
            end = server_code.find("\ndef ", start + 1)
            if end == -1:
                end = len(server_code)
            func_code = server_code[start:end]
            sub_findings = self.analyze_code(func_code, filename=f"{name}:{func_name}")
            findings.extend(sub_findings)
        return findings


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROMPT DEFENSE ANALYZER (uses YAML-loaded prompt patterns)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PromptDefenseAnalyzer:

    # Build from YAML at class level
    INJECTION_PATTERNS: list[tuple[str, str, str]] = [
        (e["pattern"], e["type"], e["severity"])
        for e in _PROMPT_DEFENSE.get("injection_patterns", [])
    ]
    BOUNDARY_MARKERS: list[str] = _PROMPT_DEFENSE.get("boundary_markers", [])
    PROMPT_LEAK_INDICATORS: list[str] = _PROMPT_DEFENSE.get("prompt_leak_indicators", [])
    SPECIAL_TOKEN_PATTERNS: list[str] = _PROMPT_DEFENSE.get("special_token_patterns", [])
    UNICODE_SMUGGLING_PATTERNS: list[str] = _PROMPT_DEFENSE.get("unicode_smuggling_patterns", [])
    INDIRECT_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
        (e["pattern"], e["type"], e["severity"])
        for e in _PROMPT_DEFENSE.get("indirect_injection_patterns", [])
    ]

    @dataclass
    class PromptFinding:
        pattern_type: str
        severity: str
        location: str
        match: str
        description: str

    def analyze_prompt(self, prompt: str, name: str = "prompt") -> list[PromptFinding]:
        findings = []
        for lineno, line in enumerate(prompt.split("\n"), 1):
            loc = f"{name}:{lineno}"
            for pat, ptype, sev in self.INJECTION_PATTERNS:
                for m in re.finditer(pat, line):
                    findings.append(self.PromptFinding(
                        pattern_type=ptype, severity=sev,
                        location=loc, match=m.group(),
                        description=f"Potential injection via {ptype}",
                    ))
            for marker in self.BOUNDARY_MARKERS:
                if marker in line:
                    findings.append(self.PromptFinding(
                        pattern_type="boundary_marker", severity="HIGH",
                        location=loc, match=marker,
                        description=f"Prompt boundary marker found: {marker}",
                    ))
            for pat in self.SPECIAL_TOKEN_PATTERNS:
                for m in re.finditer(pat, line):
                    findings.append(self.PromptFinding(
                        pattern_type="special_token", severity="CRITICAL",
                        location=loc, match=m.group(),
                        description=f"LLM special token injection: {m.group()}",
                    ))
            for pat in self.UNICODE_SMUGGLING_PATTERNS:
                for m in re.finditer(pat, line):
                    findings.append(self.PromptFinding(
                        pattern_type="unicode_smuggling", severity="CRITICAL",
                        location=loc, match=repr(m.group()),
                        description="Unicode smuggling/invisible character detected",
                    ))
        return findings

    def check_system_prompt_exposure(self, response: str) -> list[str]:
        hits = []
        lower = response.lower()
        for indicator in self.PROMPT_LEAK_INDICATORS:
            if indicator in lower:
                hits.append(indicator)
        return hits

    def detect_indirect_injection(self, content: str) -> list[PromptFinding]:
        findings = []
        for pat, ptype, sev in self.INDIRECT_INJECTION_PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                findings.append(self.PromptFinding(
                    pattern_type=ptype, severity=sev,
                    location="content:indirect", match=m.group()[:100],
                    description=f"Indirect prompt injection: {ptype}",
                ))
        return findings
