"""
SAST Taint Tracker.

Simplified taint analysis for tracking untrusted data flow
from sources (user input, network) to sinks (exec, eval, SQL).

All sources and sinks loaded from rules/taint_rules.yaml.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity, Location

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules"
_DEFAULT_YAML = _RULES_DIR / "taint_rules.yaml"

# Cache
_source_cache: Optional[list] = None
_sink_cache: Optional[list] = None
_cache_mtime: float = 0.0


@dataclass
class TaintSource:
    """A source of untrusted data."""
    name: str
    pattern: re.Pattern
    description: str


@dataclass
class TaintSink:
    """A dangerous function that consumes data."""
    name: str
    pattern: re.Pattern
    severity: Severity
    cwe: str
    description: str


@dataclass
class TaintFlow:
    """A detected taint flow from source to sink."""
    source: str
    source_line: int
    sink: str
    sink_line: int
    file: str
    severity: Severity
    cwe: str


def _load_rules(path: Optional[Path] = None) -> tuple[list[TaintSource], list[TaintSink]]:
    """Load taint sources and sinks from YAML."""
    global _source_cache, _sink_cache, _cache_mtime

    yaml_path = path or _DEFAULT_YAML
    if not yaml_path.exists():
        logger.warning("Taint rules YAML not found: %s", yaml_path)
        return [], []

    mtime = yaml_path.stat().st_mtime
    if _source_cache is not None and _sink_cache is not None and mtime == _cache_mtime:
        return _source_cache, _sink_cache

    try:
        import yaml
    except ImportError:
        logger.error("PyYAML required for loading taint rules")
        return [], []

    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    sources: list[TaintSource] = []
    for _category, entries in data.get("sources", {}).items():
        for entry in entries:
            try:
                sources.append(TaintSource(
                    name=entry["name"],
                    pattern=re.compile(entry["pattern"]),
                    description=entry.get("description", ""),
                ))
            except Exception as exc:
                logger.warning("Skipping invalid taint source %s: %s", entry.get("name"), exc)

    sinks: list[TaintSink] = []
    for _category, entries in data.get("sinks", {}).items():
        for entry in entries:
            try:
                sinks.append(TaintSink(
                    name=entry["name"],
                    pattern=re.compile(entry["pattern"]),
                    severity=_SEVERITY_MAP.get(entry.get("severity", "MEDIUM"), Severity.MEDIUM),
                    cwe=entry.get("cwe", "CWE-20"),
                    description=entry.get("description", ""),
                ))
            except Exception as exc:
                logger.warning("Skipping invalid taint sink %s: %s", entry.get("name"), exc)

    _source_cache = sources
    _sink_cache = sinks
    _cache_mtime = mtime
    logger.info("Loaded %d sources + %d sinks from %s", len(sources), len(sinks), yaml_path.name)
    return sources, sinks


def reload_rules(path: Optional[Path] = None) -> tuple[int, int]:
    """Force reload rules from YAML. Returns (source_count, sink_count)."""
    global _source_cache, _sink_cache, _cache_mtime
    _source_cache = None
    _sink_cache = None
    _cache_mtime = 0.0
    sources, sinks = _load_rules(path)
    return len(sources), len(sinks)


class TaintTracker:
    """
    Simplified intra-file taint analysis.
    All sources and sinks loaded from rules/taint_rules.yaml.

    Detects cases where untrusted data sources appear near
    dangerous sinks within the same function/block scope.
    This is a heuristic approach — not a full dataflow analysis.

    Usage:
        tracker = TaintTracker()
        findings = tracker.scan_file("app.py")
        flows = tracker.get_flows("app.py")
    """

    PROXIMITY_WINDOW = 15  # Lines within which source→sink is flagged

    def __init__(self, yaml_path: Optional[str] = None):
        path = Path(yaml_path) if yaml_path else None
        self._sources, self._sinks = _load_rules(path)

    @property
    def source_count(self) -> int:
        return len(self._sources)

    @property
    def sink_count(self) -> int:
        return len(self._sinks)

    def scan_file(self, path: str) -> list[Finding]:
        """Scan a file for taint flows."""
        flows = self.get_flows(path)
        findings = []

        for flow in flows:
            findings.append(Finding(
                rule_id="SAST-TAINT-001",
                module="sast.taint",
                title=f"Taint flow: {flow.source} → {flow.sink}",
                description=(
                    f"Untrusted data from '{flow.source}' (line {flow.source_line}) "
                    f"flows to '{flow.sink}' (line {flow.sink_line}) without sanitization."
                ),
                severity=flow.severity,
                confidence=0.7,
                target=flow.file,
                location=Location(file=flow.file, line_start=flow.sink_line),
                evidence=f"Source: {flow.source} (L{flow.source_line}) → Sink: {flow.sink} (L{flow.sink_line})",
                cwe_ids=[flow.cwe],
                tags=["category:taint-analysis"],
                remediation="Sanitize or validate input before passing to dangerous operations.",
            ))

        return findings

    def get_flows(self, path: str) -> list[TaintFlow]:
        """Detect taint flows in a single file."""
        fp = Path(path)
        if not fp.exists():
            return []

        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        # Find all source and sink locations
        source_locations: list[tuple[int, str]] = []
        sink_locations: list[tuple[int, TaintSink]] = []

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for source in self._sources:
                if source.pattern.search(stripped):
                    source_locations.append((line_num, source.name))

            for sink in self._sinks:
                if sink.pattern.search(stripped):
                    sink_locations.append((line_num, sink))

        # Find proximity flows
        flows = []
        for src_line, src_name in source_locations:
            for sink_line, sink in sink_locations:
                if sink_line > src_line and (sink_line - src_line) <= self.PROXIMITY_WINDOW:
                    flows.append(TaintFlow(
                        source=src_name,
                        source_line=src_line,
                        sink=sink.name,
                        sink_line=sink_line,
                        file=str(fp),
                        severity=sink.severity,
                        cwe=sink.cwe,
                    ))

        return flows

    def scan_directory(self, path: str) -> list[Finding]:
        """Scan a directory for taint flows."""
        root = Path(path)
        findings = []
        skip_dirs = {"__pycache__", ".git", "node_modules", ".venv", "venv"}

        for fp in sorted(root.rglob("*.py")):
            if not any(skip in fp.parts for skip in skip_dirs):
                findings.extend(self.scan_file(str(fp)))

        return findings
