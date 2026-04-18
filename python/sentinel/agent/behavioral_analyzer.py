"""Eresus Sentinel — MCP behavioral analyzer.

Runtime behavior analysis engine for MCP servers, agent tool calls,
and autonomous code execution. All detection patterns are loaded from
YAML configuration at startup — zero hardcoded patterns in this file.

YAML source (in order of precedence):
  1. SENTINEL_BEHAVIOR_PATTERNS_PATH env var
  2. Bundled sentinel/config/behavior_patterns.yaml
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

_MAX_PATTERN_LENGTH = 2048
_BUNDLED_YAML = Path(__file__).resolve().parent.parent / "config" / "behavior_patterns.yaml"


def _safe_compile(
    pattern: str, flags: int = 0, *, max_length: int = _MAX_PATTERN_LENGTH,
) -> re.Pattern | None:
    if len(pattern) > max_length:
        logger.warning(
            "Pattern too long (%d chars), skipping: %.60s…", len(pattern), pattern,
        )
        return None
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        logger.warning("Invalid regex %r: %s", pattern, exc)
        return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DATA CLASSES & ENUMS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BehaviorCategory(Enum):
    NORMAL = auto()
    EXCESSIVE_CALLS = auto()
    PARAMETER_INJECTION = auto()
    FUNCTION_DISCOVERY = auto()
    PRIVILEGE_ESCALATION = auto()
    OUTPUT_MANIPULATION = auto()
    TOOL_METADATA_INJECTION = auto()
    UNAUTHORIZED_INVOCATION = auto()
    RECURSIVE_CALL = auto()
    RATE_LIMIT_ABUSE = auto()
    PROMPT_LEAK = auto()
    DATA_EXFILTRATION = auto()
    SSRF_ATTEMPT = auto()
    CROSS_SESSION_LEAK = auto()
    SANDBOX_ESCAPE = auto()
    TOKEN_SMUGGLING = auto()
    ENCODING_EVASION = auto()
    TOOL_POISONING = auto()
    CHAIN_MANIPULATION = auto()
    RESOURCE_EXHAUSTION = auto()
    CREDENTIAL_ACCESS = auto()
    NOSQL_INJECTION = auto()
    LDAP_INJECTION = auto()
    XPATH_INJECTION = auto()
    DESERIALIZATION = auto()
    LOG_INJECTION = auto()
    HEADER_INJECTION = auto()
    PROTOTYPE_POLLUTION = auto()
    REGEX_DOS = auto()
    SUPPLY_CHAIN = auto()


@dataclass
class ToolCallEvent:
    tool_name: str
    parameters: dict[str, Any]
    timestamp: float = 0.0
    caller: str = ""
    result: Optional[str] = None
    duration_ms: float = 0.0
    session_id: str = ""


@dataclass
class BehaviorFinding:
    category: BehaviorCategory
    severity: str
    description: str
    evidence: list[str] = field(default_factory=list)
    tool_name: str = ""
    recommendation: str = ""
    cwe: str = ""
    aitech: str = ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# YAML PATTERN LOADER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CompiledPattern4 = tuple[re.Pattern, str, str, str]   # (regex, rule_id, severity, cwe)
CompiledPattern3 = tuple[re.Pattern, str, str]         # (regex, rule_id, severity) — no CWE


def _resolve_yaml_path() -> Path:
    env_path = os.getenv("SENTINEL_BEHAVIOR_PATTERNS_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p
        logger.warning("SENTINEL_BEHAVIOR_PATTERNS_PATH=%s not found, falling back to bundled", env_path)
    if _BUNDLED_YAML.is_file():
        return _BUNDLED_YAML
    raise FileNotFoundError(
        f"No behavior patterns YAML found. Set SENTINEL_BEHAVIOR_PATTERNS_PATH or ensure {_BUNDLED_YAML} exists."
    )


def _load_yaml() -> dict[str, Any]:
    path = _resolve_yaml_path()
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    logger.info("Loaded behavior patterns from %s", path)
    return data


def _parse_category(
    raw: Any, default_flags: int = re.IGNORECASE,
) -> list[CompiledPattern4]:
    if isinstance(raw, dict):
        case_sensitive = raw.get("case_sensitive", False)
        entries = raw.get("patterns", [])
        flags = 0 if case_sensitive else re.IGNORECASE
    elif isinstance(raw, list):
        entries = raw
        flags = default_flags
    else:
        return []

    compiled: list[CompiledPattern4] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pat_str = entry.get("pattern", "")
        rule_id = entry.get("rule_id", "unknown")
        severity = entry.get("severity", "MEDIUM")
        cwe = entry.get("cwe", "")
        pat = _safe_compile(pat_str, flags)
        if pat is not None:
            compiled.append((pat, rule_id, severity, cwe))
    return compiled


def _parse_output_category(raw: Any) -> list[CompiledPattern3]:
    entries = raw if isinstance(raw, list) else []
    compiled: list[CompiledPattern3] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pat_str = entry.get("pattern", "")
        rule_id = entry.get("rule_id", "unknown")
        severity = entry.get("severity", "MEDIUM")
        pat = _safe_compile(pat_str, re.IGNORECASE)
        if pat is not None:
            compiled.append((pat, rule_id, severity))
    return compiled


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LOAD ALL PATTERNS FROM YAML AT MODULE INIT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_data = _load_yaml()

_COMPILED_COMMAND_INJECTION = _parse_category(_data.get("command_injection"))
_COMPILED_SQL_INJECTION = _parse_category(_data.get("sql_injection"))
_COMPILED_NOSQL_INJECTION = _parse_category(_data.get("nosql_injection"))
_COMPILED_LDAP_INJECTION = _parse_category(_data.get("ldap_injection"))
_COMPILED_XPATH_INJECTION = _parse_category(_data.get("xpath_injection"))
_COMPILED_XSS_INJECTION = _parse_category(_data.get("xss_injection"))
_COMPILED_PATH_TRAVERSAL = _parse_category(_data.get("path_traversal"))
_COMPILED_SSRF = _parse_category(_data.get("ssrf"))
_COMPILED_SSTI = _parse_category(_data.get("ssti"))
_COMPILED_ENCODING_EVASION = _parse_category(_data.get("encoding_evasion"))
_COMPILED_DATA_EXFIL = _parse_category(_data.get("data_exfil"))
_COMPILED_CREDENTIAL = _parse_category(_data.get("credential"))
_COMPILED_PRIVILEGE = _parse_category(_data.get("privilege_escalation"))
_COMPILED_TOKEN_SMUGGLING = _parse_category(_data.get("token_smuggling"))
_COMPILED_DESERIALIZATION = _parse_category(_data.get("deserialization"))
_COMPILED_LOG_INJECTION = _parse_category(_data.get("log_injection"))
_COMPILED_HEADER_INJECTION = _parse_category(_data.get("header_injection"))
_COMPILED_SANDBOX_ESCAPE = _parse_category(_data.get("sandbox_escape"))
_COMPILED_SUPPLY_CHAIN = _parse_category(_data.get("supply_chain"))

_COMPILED_OUTPUT_MANIPULATION = _parse_output_category(_data.get("output_manipulation"))
_COMPILED_CHAIN_MANIPULATION = _parse_output_category(_data.get("chain_manipulation"))

ALL_INJECTION_PATTERNS: list[CompiledPattern4] = (
    _COMPILED_COMMAND_INJECTION
    + _COMPILED_SQL_INJECTION
    + _COMPILED_NOSQL_INJECTION
    + _COMPILED_LDAP_INJECTION
    + _COMPILED_XPATH_INJECTION
    + _COMPILED_XSS_INJECTION
    + _COMPILED_PATH_TRAVERSAL
    + _COMPILED_SSTI
    + _COMPILED_SSRF
    + _COMPILED_DESERIALIZATION
    + _COMPILED_LOG_INJECTION
    + _COMPILED_HEADER_INJECTION
    + _COMPILED_SANDBOX_ESCAPE
    + _COMPILED_SUPPLY_CHAIN
)

_DISCOVERY_INDICATORS: frozenset[str] = frozenset(
    _data.get("discovery_indicators", [])
)

_PATTERNS_YAML_PATH = str(_resolve_yaml_path())

_total_loaded = (
    len(ALL_INJECTION_PATTERNS)
    + len(_COMPILED_OUTPUT_MANIPULATION)
    + len(_COMPILED_CHAIN_MANIPULATION)
    + len(_COMPILED_DATA_EXFIL)
    + len(_COMPILED_CREDENTIAL)
    + len(_COMPILED_PRIVILEGE)
    + len(_COMPILED_ENCODING_EVASION)
    + len(_COMPILED_TOKEN_SMUGGLING)
)
logger.info("Behavioral analyzer: %d patterns compiled from YAML", _total_loaded)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ANALYZER CLASS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BehavioralAnalyzer:

    def __init__(
        self,
        max_calls_per_minute: int = 60,
        max_recursion_depth: int = 5,
        max_param_length: int = 10000,
    ):
        self._max_calls_per_minute = max_calls_per_minute
        self._max_recursion_depth = max_recursion_depth
        self._max_param_length = max_param_length
        self._call_history: list[ToolCallEvent] = []
        self._call_stack: list[str] = []
        self._session_data: dict[str, list[str]] = {}

    @staticmethod
    def patterns_source() -> str:
        return _PATTERNS_YAML_PATH

    @staticmethod
    def total_patterns() -> int:
        return _total_loaded

    def record_call(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        if event.timestamp == 0.0:
            event.timestamp = time.time()
        self._call_history.append(event)
        findings: list[BehaviorFinding] = []
        findings.extend(self._check_rate_limit(event))
        findings.extend(self._check_recursion(event))
        findings.extend(self._check_parameter_injection(event))
        findings.extend(self._check_function_discovery(event))
        findings.extend(self._check_privilege_escalation(event))
        findings.extend(self._check_output_manipulation(event))
        findings.extend(self._check_data_exfiltration(event))
        findings.extend(self._check_ssrf(event))
        findings.extend(self._check_credential_exposure(event))
        findings.extend(self._check_encoding_evasion(event))
        findings.extend(self._check_token_smuggling(event))
        findings.extend(self._check_cross_session_leak(event))
        findings.extend(self._check_resource_exhaustion(event))
        findings.extend(self._check_chain_manipulation(event))
        findings.extend(self._check_deserialization(event))
        findings.extend(self._check_sandbox_escape(event))
        return findings

    # ── Rate limit / burst detection ─────────────────────────────────

    def _check_rate_limit(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        now = event.timestamp
        recent = [e for e in self._call_history if now - e.timestamp < 60]
        if len(recent) > self._max_calls_per_minute:
            return [BehaviorFinding(
                category=BehaviorCategory.RATE_LIMIT_ABUSE,
                severity="HIGH",
                description=f"{len(recent)} calls in last minute (limit: {self._max_calls_per_minute})",
                tool_name=event.tool_name,
                recommendation="Implement rate limiting on tool calls",
                cwe="CWE-770",
            )]
        burst_window = [e for e in self._call_history if now - e.timestamp < 5]
        if len(burst_window) > 20:
            return [BehaviorFinding(
                category=BehaviorCategory.RATE_LIMIT_ABUSE,
                severity="MEDIUM",
                description=f"Burst detected: {len(burst_window)} calls in 5 seconds",
                tool_name=event.tool_name,
                recommendation="Implement burst rate limiting",
                cwe="CWE-770",
            )]
        return []

    # ── Recursion / loop detection ───────────────────────────────────

    def _check_recursion(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        self._call_stack.append(event.tool_name)
        depth = 0
        for name in reversed(self._call_stack):
            if name == event.tool_name:
                depth += 1
            else:
                break
        if depth > self._max_recursion_depth:
            return [BehaviorFinding(
                category=BehaviorCategory.RECURSIVE_CALL,
                severity="HIGH",
                description=f"Recursive call depth {depth} for {event.tool_name}",
                tool_name=event.tool_name,
                recommendation="Set maximum recursion depth for tool calls",
                cwe="CWE-674",
            )]
        recent_tools = [e.tool_name for e in self._call_history[-20:]]
        if len(recent_tools) >= 4:
            for i in range(len(recent_tools) - 3):
                pair = (recent_tools[i], recent_tools[i + 1])
                if (recent_tools[i + 2], recent_tools[i + 3]) == pair:
                    return [BehaviorFinding(
                        category=BehaviorCategory.RECURSIVE_CALL,
                        severity="MEDIUM",
                        description=f"Mutual recursion detected: {pair[0]} <-> {pair[1]}",
                        tool_name=event.tool_name,
                        recommendation="Monitor for infinite mutual recursion patterns",
                        cwe="CWE-674",
                    )]
        return []

    # ── Parameter injection (all categories) ─────────────────────────

    def _check_parameter_injection(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        for key, val in event.parameters.items():
            sval = str(val)
            if len(sval) > self._max_param_length:
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.PARAMETER_INJECTION,
                    severity="MEDIUM",
                    description=f"Oversized parameter '{key}': {len(sval)} chars",
                    tool_name=event.tool_name,
                    evidence=[sval[:200]],
                    cwe="CWE-400",
                ))
            for pat, rule_id, severity, cwe in ALL_INJECTION_PATTERNS:
                if pat.search(sval):
                    findings.append(BehaviorFinding(
                        category=BehaviorCategory.PARAMETER_INJECTION,
                        severity=severity,
                        description=f"{rule_id} in parameter '{key}'",
                        tool_name=event.tool_name,
                        evidence=[sval[:200]],
                        cwe=cwe,
                    ))
        return findings

    # ── Function / tool discovery ────────────────────────────────────

    def _check_function_discovery(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        lower_name = event.tool_name.lower()
        for indicator in _DISCOVERY_INDICATORS:
            if indicator in lower_name:
                return [BehaviorFinding(
                    category=BehaviorCategory.FUNCTION_DISCOVERY,
                    severity="MEDIUM",
                    description=f"Tool discovery attempt via {event.tool_name}",
                    tool_name=event.tool_name,
                    recommendation="Restrict tool enumeration APIs",
                    cwe="CWE-200",
                )]
        param_vals = " ".join(str(v) for v in event.parameters.values()).lower()
        if any(ind in param_vals for ind in _DISCOVERY_INDICATORS):
            return [BehaviorFinding(
                category=BehaviorCategory.FUNCTION_DISCOVERY,
                severity="MEDIUM",
                description="Tool discovery attempt via parameters",
                tool_name=event.tool_name,
                evidence=[param_vals[:200]],
                cwe="CWE-200",
            )]
        return []

    # ── Privilege escalation ─────────────────────────────────────────

    def _check_privilege_escalation(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        param_str = str(event.parameters)
        findings: list[BehaviorFinding] = []
        for pat, rule_id, severity, cwe in _COMPILED_PRIVILEGE:
            if pat.search(param_str):
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.PRIVILEGE_ESCALATION,
                    severity=severity,
                    description=rule_id,
                    tool_name=event.tool_name,
                    evidence=[param_str[:200]],
                    cwe=cwe,
                ))
        return findings

    # ── Output manipulation ──────────────────────────────────────────

    def _check_output_manipulation(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        if not event.result:
            return []
        findings: list[BehaviorFinding] = []
        for pat, rule_id, sev in _COMPILED_OUTPUT_MANIPULATION:
            if pat.search(event.result):
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.OUTPUT_MANIPULATION,
                    severity=sev,
                    description=rule_id,
                    tool_name=event.tool_name,
                    evidence=[event.result[:200]],
                    cwe="CWE-74",
                ))
        return findings

    # ── Data exfiltration ────────────────────────────────────────────

    def _check_data_exfiltration(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        param_str = str(event.parameters)
        for pat, rule_id, severity, cwe in _COMPILED_DATA_EXFIL:
            if pat.search(param_str):
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.DATA_EXFILTRATION,
                    severity=severity,
                    description=rule_id,
                    tool_name=event.tool_name,
                    evidence=[param_str[:200]],
                    cwe=cwe,
                ))
        return findings

    # ── SSRF ─────────────────────────────────────────────────────────

    def _check_ssrf(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        param_str = str(event.parameters)
        for pat, rule_id, severity, cwe in _COMPILED_SSRF:
            if pat.search(param_str):
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.SSRF_ATTEMPT,
                    severity=severity,
                    description=rule_id,
                    tool_name=event.tool_name,
                    evidence=[param_str[:200]],
                    cwe=cwe,
                ))
        return findings

    # ── Credential exposure ──────────────────────────────────────────

    def _check_credential_exposure(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        combined = str(event.parameters) + (event.result or "")
        for pat, rule_id, severity, cwe in _COMPILED_CREDENTIAL:
            if pat.search(combined):
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.CREDENTIAL_ACCESS,
                    severity=severity,
                    description=rule_id,
                    tool_name=event.tool_name,
                    evidence=[combined[:200]],
                    cwe=cwe,
                ))
        return findings

    # ── Encoding evasion ─────────────────────────────────────────────

    def _check_encoding_evasion(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        param_str = str(event.parameters)
        for pat, rule_id, severity, cwe in _COMPILED_ENCODING_EVASION:
            if pat.search(param_str):
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.ENCODING_EVASION,
                    severity=severity,
                    description=rule_id,
                    tool_name=event.tool_name,
                    evidence=[param_str[:200]],
                    cwe=cwe,
                ))
        return findings

    # ── Token smuggling ──────────────────────────────────────────────

    def _check_token_smuggling(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        param_str = str(event.parameters)
        for pat, rule_id, severity, cwe in _COMPILED_TOKEN_SMUGGLING:
            if pat.search(param_str):
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.TOKEN_SMUGGLING,
                    severity=severity,
                    description=rule_id,
                    tool_name=event.tool_name,
                    evidence=[repr(param_str[:100])],
                    cwe=cwe,
                ))
        return findings

    # ── Cross-session data leak ──────────────────────────────────────

    def _check_cross_session_leak(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        if event.session_id:
            for key, val in event.parameters.items():
                sval = str(val)
                for other_session, data_items in self._session_data.items():
                    if other_session != event.session_id:
                        for d in data_items:
                            if d in sval and len(d) > 8:
                                findings.append(BehaviorFinding(
                                    category=BehaviorCategory.CROSS_SESSION_LEAK,
                                    severity="HIGH",
                                    description=f"Cross-session data from '{other_session}' in parameter '{key}'",
                                    tool_name=event.tool_name,
                                    evidence=[sval[:200]],
                                    cwe="CWE-200",
                                ))
            if event.result and event.session_id not in self._session_data:
                self._session_data[event.session_id] = []
            if event.result and event.session_id:
                self._session_data[event.session_id].append(event.result[:500])
        return findings

    # ── Resource exhaustion ──────────────────────────────────────────

    def _check_resource_exhaustion(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        _size_re = re.compile(
            r"(?:limit|count|size|length|max|num|page_size|batch_size|chunk_size|timeout|wait|sleep|delay)\s*[:=]\s*(\d+)",
            re.IGNORECASE,
        )
        for key, val in event.parameters.items():
            sval = str(val)
            m = _size_re.search(sval)
            if m:
                val_int = int(m.group(1))
                if val_int > 1_000_000:
                    findings.append(BehaviorFinding(
                        category=BehaviorCategory.RESOURCE_EXHAUSTION,
                        severity="HIGH",
                        description=f"Excessive value {val_int} in parameter '{key}'",
                        tool_name=event.tool_name,
                        evidence=[sval[:200]],
                        cwe="CWE-400",
                    ))
            if len(sval) > 100_000:
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.RESOURCE_EXHAUSTION,
                    severity="HIGH",
                    description=f"Extremely large parameter '{key}': {len(sval)} chars",
                    tool_name=event.tool_name,
                    cwe="CWE-400",
                ))
        return findings

    # ── Chain manipulation ───────────────────────────────────────────

    def _check_chain_manipulation(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        if not event.result:
            return []
        findings: list[BehaviorFinding] = []
        for pat, desc, sev in _COMPILED_CHAIN_MANIPULATION:
            if pat.search(event.result):
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.CHAIN_MANIPULATION,
                    severity=sev,
                    description=desc,
                    tool_name=event.tool_name,
                    evidence=[event.result[:200]],
                    cwe="CWE-74",
                ))
        return findings

    # ── Deserialization attacks ───────────────────────────────────────

    def _check_deserialization(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        param_str = str(event.parameters)
        for pat, rule_id, severity, cwe in _COMPILED_DESERIALIZATION:
            if pat.search(param_str):
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.DESERIALIZATION,
                    severity=severity,
                    description=rule_id,
                    tool_name=event.tool_name,
                    evidence=[param_str[:200]],
                    cwe=cwe,
                ))
        return findings

    # ── Sandbox escape ───────────────────────────────────────────────

    def _check_sandbox_escape(self, event: ToolCallEvent) -> list[BehaviorFinding]:
        findings: list[BehaviorFinding] = []
        param_str = str(event.parameters)
        for pat, rule_id, severity, cwe in _COMPILED_SANDBOX_ESCAPE:
            if pat.search(param_str):
                findings.append(BehaviorFinding(
                    category=BehaviorCategory.SANDBOX_ESCAPE,
                    severity=severity,
                    description=rule_id,
                    tool_name=event.tool_name,
                    evidence=[param_str[:200]],
                    cwe=cwe,
                ))
        return findings

    # ── Summary ──────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        cats: dict[str, int] = {}
        for e in self._call_history:
            cats[e.tool_name] = cats.get(e.tool_name, 0) + 1
        return {
            "total_calls": len(self._call_history),
            "unique_tools": len(cats),
            "tool_distribution": cats,
            "max_depth": len(self._call_stack),
            "sessions_tracked": len(self._session_data),
            "total_patterns_loaded": _total_loaded,
            "patterns_source": _PATTERNS_YAML_PATH,
        }

    def reset(self) -> None:
        self._call_history.clear()
        self._call_stack.clear()
        self._session_data.clear()
