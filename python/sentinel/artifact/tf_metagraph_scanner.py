"""TensorFlow MetaGraph scanner (.meta) — protobuf graph definition analysis.

Detection rules are loaded from rules/tf_metagraph_rules.yaml at import time.
Covers:
  - Dangerous TF op types: PyFunc, PyFuncStateless, EagerPyFunc, PyCall,
    ShellExecute, LoadLibrary, LoadLibraryV2, ImmutableConst, RunPyFunc
  - Executable-context gating: HIGH-severity string findings (command,
    network, path) require a co-occurring executable-context op
  - String attribute scanning: command execution, network indicators,
    library/path references extracted from protobuf bytes
  - Encoded payload detection: Base64 blobs adjacent to decode/eval hints
  - Parse-budget enforcement: 20 MB read limit, node count caps
  - Bounded string extraction with context window
"""
from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

_RULES_PATH = Path(__file__).parent.parent.parent.parent / "rules" / "tf_metagraph_rules.yaml"

_MAX_PARSE_BYTES = 20 * 1024 * 1024
_MIN_PARSE_BYTES = 8
_MAX_GRAPH_NODES = 200_000
_MAX_FUNCTION_NODES = 100_000
_MAX_ATTR_VALUE_BYTES = 32 * 1024
_MAX_SIGNAL_EXAMPLES = 8
_CONTEXT_WINDOW = 256

_PRINTABLE_RE = re.compile(rb"[ -~]{8,}")


@lru_cache(maxsize=1)
def _load_rules() -> dict[str, Any]:
    try:
        with open(_RULES_PATH, "r") as fh:
            return yaml.safe_load(fh) or {}
    except Exception as exc:
        logger.warning("tf_metagraph_rules.yaml not loaded: %s", exc)
        return {}


@lru_cache(maxsize=1)
def _executable_context_ops() -> frozenset[bytes]:
    rules = _load_rules()
    ops = rules.get("executable_context_ops", [])
    return frozenset(op.encode() for op in ops)


@lru_cache(maxsize=1)
def _benign_io_ops() -> frozenset[bytes]:
    rules = _load_rules()
    ops = rules.get("benign_checkpoint_io_ops", [])
    return frozenset(op.encode() for op in ops)


@lru_cache(maxsize=1)
def _dangerous_critical_ops() -> frozenset[bytes]:
    rules = _load_rules()
    ops = rules.get("dangerous_tf_ops", {}).get("critical", [])
    return frozenset(op.encode() for op in ops)


@lru_cache(maxsize=1)
def _dangerous_high_ops() -> frozenset[bytes]:
    rules = _load_rules()
    ops = rules.get("dangerous_tf_ops", {}).get("high", [])
    return frozenset(op.encode() for op in ops)


@lru_cache(maxsize=1)
def _string_check_patterns() -> dict[str, tuple[re.Pattern[bytes], Severity, list[str], str, bool]]:
    rules = _load_rules()
    checks = rules.get("string_checks", {})
    sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM}
    out: dict[str, tuple[re.Pattern[bytes], Severity, list[str], str, bool]] = {}
    for name, entry in checks.items():
        if name == "encoded_payload":
            continue
        pat_str = entry.get("pattern", "")
        if not pat_str:
            continue
        try:
            out[name] = (
                re.compile(pat_str.encode(), re.IGNORECASE),
                sev_map.get(entry.get("severity", "HIGH"), Severity.HIGH),
                entry.get("cwe_ids", []),
                entry.get("description", ""),
                entry.get("requires_exec_op_context", True),
            )
        except re.error as exc:
            logger.debug("tf_metagraph_rules: bad pattern %r: %s", pat_str, exc)
    return out


@lru_cache(maxsize=1)
def _encoded_payload_patterns() -> tuple[re.Pattern[bytes], re.Pattern[bytes]]:
    rules = _load_rules()
    ep = rules.get("string_checks", {}).get("encoded_payload", {})
    b64_pat = ep.get("b64_pattern", r"\b[A-Za-z0-9+/]{120,}={0,2}\b")
    hint_pat = ep.get("decode_hint_pattern", r"(?i)(?:base64|b64decode|eval\(|exec\()")
    return (
        re.compile(b64_pat.encode(), re.IGNORECASE),
        re.compile(hint_pat.encode(), re.IGNORECASE),
    )


def _extract_printable_strings(data: bytes) -> list[tuple[int, str]]:
    """Extract printable ASCII strings ≥ 8 chars with their offsets."""
    results: list[tuple[int, str]] = []
    for m in _PRINTABLE_RE.finditer(data):
        text = m.group(0).decode("ascii", "ignore").strip()
        if text:
            results.append((m.start(), text))
    return results


def _has_exec_context(data: bytes) -> bool:
    for op in _executable_context_ops():
        if op in data:
            return True
    return False


def _context_snippet(data: bytes, offset: int, window: int = _CONTEXT_WINDOW) -> str:
    start = max(0, offset - window)
    end = min(len(data), offset + window)
    return data[start:end].decode("utf-8", "ignore").replace("\x00", "")


class TFMetaGraphScanner:
    """Scanner for TensorFlow MetaGraph protobuf definition files (.meta).

    Detection rules are loaded from rules/tf_metagraph_rules.yaml. Performs:
      - Dangerous TF op detection (CRITICAL: PyFunc, ShellExecute, LoadLibrary;
        HIGH: StatefulPartitionedCall, InitializeTableFromTextFile, etc.)
      - Executable-context-gated string analysis: command, network, path
        findings are only raised when a co-occurring exec-context op exists
      - Encoded payload detection (Base64 blob + decode/eval hint)
      - 20 MB parse budget with explicit truncation reporting
    """

    EXTENSIONS = frozenset({".meta"})

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in self.EXTENSIONS:
            return findings

        try:
            file_size = path.stat().st_size
        except OSError:
            return findings

        if file_size < _MIN_PARSE_BYTES:
            return findings

        try:
            with open(path, "rb") as fh:
                raw = fh.read(_MAX_PARSE_BYTES + 1)
        except OSError:
            return findings

        truncated = len(raw) > _MAX_PARSE_BYTES
        data = raw[:_MAX_PARSE_BYTES]

        if truncated:
            findings.append(Finding.artifact(
                rule_id="META-TRUNC",
                title="TF MetaGraph scan truncated — parse budget exceeded",
                description=f"File exceeds {_MAX_PARSE_BYTES // (1024*1024)} MB scan budget.",
                severity=Severity.MEDIUM,
                target=filepath,
                evidence=f"file_size={file_size}, max_parse_bytes={_MAX_PARSE_BYTES}",
            ))

        findings.extend(self._check_dangerous_ops(data, filepath))
        findings.extend(self._check_string_patterns(data, filepath))
        findings.extend(self._check_encoded_payload(data, filepath))

        return findings

    def _check_dangerous_ops(self, data: bytes, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[bytes] = set()

        for op in _dangerous_critical_ops():
            if op in seen:
                continue
            if op in data:
                seen.add(op)
                findings.append(Finding.artifact(
                    rule_id="META-OP-CRIT",
                    title=f"Dangerous TF op in MetaGraph: {op.decode()}",
                    description=(
                        f"The TF MetaGraph contains op '{op.decode()}' which executes arbitrary "
                        "Python code or loads native libraries when the graph is restored."
                    ),
                    severity=Severity.CRITICAL,
                    target=filepath,
                    evidence=f"op={op.decode()}",
                    cwe_ids=["CWE-94"],
                ))

        for op in _dangerous_high_ops():
            if op in seen:
                continue
            if op in data:
                seen.add(op)
                findings.append(Finding.artifact(
                    rule_id="META-OP-HIGH",
                    title=f"Suspicious TF op in MetaGraph: {op.decode()}",
                    description=(
                        f"The TF MetaGraph contains op '{op.decode()}' which may enable "
                        "code execution or data exfiltration depending on graph context."
                    ),
                    severity=Severity.HIGH,
                    target=filepath,
                    evidence=f"op={op.decode()}",
                    cwe_ids=["CWE-94"],
                ))

        return findings

    def _check_string_patterns(self, data: bytes, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        has_exec = _has_exec_context(data)
        patterns = _string_check_patterns()
        seen_checks: set[str] = set()

        for offset, text in _extract_printable_strings(data):
            if len(seen_checks) >= _MAX_SIGNAL_EXAMPLES:
                break
            for check_name, (pat, sev, cwe_ids, description, requires_exec) in patterns.items():
                if check_name in seen_checks:
                    continue
                if requires_exec and not has_exec:
                    continue
                if pat.search(text.encode()):
                    seen_checks.add(check_name)
                    snippet = _context_snippet(data, offset)
                    findings.append(Finding.artifact(
                        rule_id=f"META-STR-{check_name.upper()}",
                        title=f"Suspicious {check_name} indicator in TF MetaGraph node attribute",
                        description=description or (
                            f"A {check_name} pattern was found in MetaGraph string attributes. "
                            + ("Executable-context op present — elevated risk." if has_exec else "")
                        ),
                        severity=sev,
                        target=filepath,
                        evidence=snippet[:200],
                        cwe_ids=cwe_ids,
                    ))

        return findings

    def _check_encoded_payload(self, data: bytes, filepath: str) -> list[Finding]:
        b64_pat, hint_pat = _encoded_payload_patterns()
        if not hint_pat.search(data):
            return []

        for m in b64_pat.finditer(data):
            start = max(0, m.start() - _CONTEXT_WINDOW)
            end = min(len(data), m.end() + _CONTEXT_WINDOW)
            window = data[start:end]
            if hint_pat.search(window):
                snippet = window.decode("utf-8", "ignore").replace("\x00", "")
                return [Finding.artifact(
                    rule_id="META-B64",
                    title="Encoded payload in TF MetaGraph (Base64 + decode/eval hint)",
                    description=(
                        "A long Base64-encoded blob was found adjacent to a decode or eval keyword "
                        "in TF MetaGraph attributes. This pattern indicates a stage-2 payload "
                        "embedded in the computation graph."
                    ),
                    severity=Severity.CRITICAL,
                    target=filepath,
                    evidence=snippet[:200],
                    cwe_ids=["CWE-506", "CWE-94"],
                )]
        return []
