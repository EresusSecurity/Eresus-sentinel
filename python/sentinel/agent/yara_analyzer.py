"""Eresus Sentinel — YARA rule analyzer.

Scans MCP tool implementations and skill files for malicious patterns
using real YARA rules loaded from .yar files via yara-python.

Rule source (in order of precedence):
  1. SENTINEL_YARA_RULES_PATH env var  (directory or single .yar file)
  2. Bundled sentinel/config/yara_rules/ directory

If yara-python is not installed, falls back to a regex-based engine
that parses the .yar file metadata and string literals for matching.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_BUNDLED_RULES_DIR = Path(__file__).resolve().parent.parent / "config" / "yara_rules"
_YARA_RULES_ENV_VAR = "SENTINEL_YARA_RULES_PATH"

# Try to import yara-python; if unavailable we use fallback
try:
    import yara as _yara  # type: ignore[import-untyped]
    _HAS_YARA = True
except ImportError:
    _yara = None  # type: ignore[assignment]
    _HAS_YARA = False
    logger.info("yara-python not installed — using regex fallback engine")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DATA CLASSES & ENUMS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class YaraMatchSeverity(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass
class YaraMatch:
    rule_name: str
    severity: YaraMatchSeverity
    matched_patterns: list[str]
    location: str
    description: str
    cwe: str = ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RULE SOURCE RESOLUTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _resolve_yar_files() -> list[Path]:
    env_path = os.getenv(_YARA_RULES_ENV_VAR)
    if env_path:
        p = Path(env_path)
        if p.is_file() and p.suffix in (".yar", ".yara"):
            return [p]
        if p.is_dir():
            files = sorted(p.glob("*.yar")) + sorted(p.glob("*.yara"))
            if files:
                return files
        logger.warning(
            "SENTINEL_YARA_RULES_PATH=%s invalid, falling back to bundled", env_path,
        )

    if _BUNDLED_RULES_DIR.is_dir():
        files = sorted(_BUNDLED_RULES_DIR.glob("*.yar")) + sorted(
            _BUNDLED_RULES_DIR.glob("*.yara")
        )
        if files:
            return files

    raise FileNotFoundError(
        f"No YARA rule files found. Set {_YARA_RULES_ENV_VAR} or place "
        f".yar files in {_BUNDLED_RULES_DIR}"
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NATIVE YARA ENGINE (uses yara-python)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_SEV_MAP = {
    "critical": YaraMatchSeverity.CRITICAL,
    "high": YaraMatchSeverity.HIGH,
    "medium": YaraMatchSeverity.MEDIUM,
    "low": YaraMatchSeverity.LOW,
}


def _compile_native(yar_files: list[Path]) -> Any:
    filepaths = {f"ns{i}": str(fp) for i, fp in enumerate(yar_files)}
    return _yara.compile(filepaths=filepaths)


def _native_scan(compiled_rules: Any, data: str, filename: str) -> list[YaraMatch]:
    raw_matches = compiled_rules.match(data=data)
    results: list[YaraMatch] = []
    for m in raw_matches:
        meta = m.meta or {}
        severity_str = str(meta.get("severity", "MEDIUM")).lower()
        severity = _SEV_MAP.get(severity_str, YaraMatchSeverity.MEDIUM)
        matched_strs = [
            s.identifier for s in (m.strings if hasattr(m, "strings") else [])
        ]
        results.append(YaraMatch(
            rule_name=m.rule,
            severity=severity,
            matched_patterns=matched_strs or [m.rule],
            location=filename,
            description=str(meta.get("description", m.rule)),
            cwe=str(meta.get("cwe", "")),
        ))
    return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FALLBACK REGEX ENGINE (parses .yar files without yara lib)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class _FallbackRule:
    name: str
    description: str
    severity: YaraMatchSeverity
    cwe: str
    string_patterns: list[re.Pattern]
    condition: str  # "any" or "all" or "N of them"


def _parse_yar_file_fallback(path: Path) -> list[_FallbackRule]:
    content = path.read_text(encoding="utf-8", errors="replace")
    rules: list[_FallbackRule] = []

    rule_re = re.compile(
        r"rule\s+(\w+)\s*\{(.*?)\}\s*(?=rule\s+\w+\s*\{|\Z)",
        re.DOTALL,
    )
    meta_re = re.compile(
        r'(\w+)\s*=\s*"([^"]*)"',
    )
    string_literal_re = re.compile(
        r'\$\w+\s*=\s*"([^"]*)"(?:\s+nocase)?',
    )
    string_regex_re = re.compile(
        r'\$\w+\s*=\s*/(.+?)/(?:\s+nocase)?',
    )
    condition_re = re.compile(
        r"condition\s*:\s*(.+?)(?:\}|\Z)",
        re.DOTALL,
    )

    for m in rule_re.finditer(content):
        rule_name = m.group(1)
        body = m.group(2)

        meta: dict[str, str] = {}
        meta_block = re.search(r"meta\s*:(.*?)(?:strings\s*:|condition\s*:)", body, re.DOTALL)
        if meta_block:
            for mm in meta_re.finditer(meta_block.group(1)):
                meta[mm.group(1)] = mm.group(2)

        description = meta.get("description", rule_name)
        severity_str = meta.get("severity", "MEDIUM").lower()
        severity = _SEV_MAP.get(severity_str, YaraMatchSeverity.MEDIUM)
        cwe = meta.get("cwe", "")

        patterns: list[re.Pattern] = []
        strings_block = re.search(r"strings\s*:(.*?)condition\s*:", body, re.DOTALL)
        if strings_block:
            for sm in string_literal_re.finditer(strings_block.group(1)):
                try:
                    patterns.append(re.compile(re.escape(sm.group(1)), re.IGNORECASE))
                except re.error:
                    pass
            for sm in string_regex_re.finditer(strings_block.group(1)):
                try:
                    patterns.append(re.compile(sm.group(1), re.IGNORECASE | re.DOTALL))
                except re.error:
                    pass

        cond_match = condition_re.search(body)
        cond_text = cond_match.group(1).strip() if cond_match else "any of them"

        if "all of them" in cond_text:
            condition = "all"
        elif re.search(r"(\d+)\s+of\s+them", cond_text):
            condition = re.search(r"(\d+)\s+of\s+them", cond_text).group(1)  # type: ignore[union-attr]
        else:
            condition = "any"

        rules.append(_FallbackRule(
            name=rule_name,
            description=description,
            severity=severity,
            cwe=cwe,
            string_patterns=patterns,
            condition=condition,
        ))

    return rules


def _fallback_scan(
    rules: list[_FallbackRule], data: str, filename: str,
) -> list[YaraMatch]:
    results: list[YaraMatch] = []
    for rule in rules:
        matched = [p.pattern for p in rule.string_patterns if p.search(data)]
        should_match = False
        if rule.condition == "any":
            should_match = len(matched) > 0
        elif rule.condition == "all":
            should_match = len(matched) == len(rule.string_patterns)
        else:
            try:
                threshold = int(rule.condition)
                should_match = len(matched) >= threshold
            except ValueError:
                should_match = len(matched) > 0

        if should_match:
            results.append(YaraMatch(
                rule_name=rule.name,
                severity=rule.severity,
                matched_patterns=matched,
                location=filename,
                description=rule.description,
                cwe=rule.cwe,
            ))
    return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ANALYZER CLASS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class YaraAnalyzer:

    def __init__(self, rules_path: str | Path | None = None):
        self._yar_files: list[Path] = []
        self._native_compiled: Any = None
        self._fallback_rules: list[_FallbackRule] = []
        self._using_native = _HAS_YARA
        self._rules_source = ""
        self._rule_count = 0

        if rules_path:
            p = Path(rules_path)
            if p.is_file():
                self._yar_files = [p]
            elif p.is_dir():
                self._yar_files = sorted(p.glob("*.yar")) + sorted(p.glob("*.yara"))
        else:
            self._yar_files = _resolve_yar_files()

        self._rules_source = str(self._yar_files[0].parent) if self._yar_files else ""
        self._compile()

    def _compile(self) -> None:
        if not self._yar_files:
            logger.warning("No YARA rule files to compile")
            return

        if self._using_native:
            try:
                self._native_compiled = _compile_native(self._yar_files)
                # Count rules from all files
                for fp in self._yar_files:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    self._rule_count += len(re.findall(r"^rule\s+\w+", content, re.MULTILINE))
                logger.info(
                    "YARA native engine: %d rules compiled from %d files",
                    self._rule_count, len(self._yar_files),
                )
            except Exception as exc:
                logger.warning("yara-python compilation failed, using fallback: %s", exc)
                self._using_native = False
                self._compile_fallback()
        else:
            self._compile_fallback()

    def _compile_fallback(self) -> None:
        for fp in self._yar_files:
            try:
                rules = _parse_yar_file_fallback(fp)
                self._fallback_rules.extend(rules)
            except Exception as exc:
                logger.warning("Failed to parse %s for fallback: %s", fp, exc)
        self._rule_count = len(self._fallback_rules)
        logger.info(
            "YARA fallback engine: %d rules parsed from %d files",
            self._rule_count, len(self._yar_files),
        )

    @property
    def rule_count(self) -> int:
        return self._rule_count

    @property
    def using_native(self) -> bool:
        return self._using_native and self._native_compiled is not None

    @property
    def rules_source(self) -> str:
        return self._rules_source

    @property
    def rule_names(self) -> list[str]:
        if self._using_native and self._native_compiled is not None:
            names: list[str] = []
            for fp in self._yar_files:
                content = fp.read_text(encoding="utf-8", errors="replace")
                names.extend(re.findall(r"^rule\s+(\w+)", content, re.MULTILINE))
            return names
        return [r.name for r in self._fallback_rules]

    def scan(self, code: str, filename: str = "unknown") -> list[YaraMatch]:
        if self._using_native and self._native_compiled is not None:
            return _native_scan(self._native_compiled, code, filename)
        return _fallback_scan(self._fallback_rules, code, filename)

    def scan_file(self, filepath: str | Path) -> list[YaraMatch]:
        p = Path(filepath)
        if not p.is_file():
            return []
        data = p.read_text(encoding="utf-8", errors="replace")
        return self.scan(data, filename=str(p))

    def scan_files(self, files: dict[str, str]) -> dict[str, list[YaraMatch]]:
        results: dict[str, list[YaraMatch]] = {}
        for fname, code in files.items():
            m = self.scan(code, filename=fname)
            if m:
                results[fname] = m
        return results

    def scan_directory(self, dirpath: str | Path, extensions: set[str] | None = None) -> dict[str, list[YaraMatch]]:
        exts = extensions or {".py", ".js", ".ts", ".rb", ".php", ".sh", ".yaml", ".yml", ".json", ".md"}
        results: dict[str, list[YaraMatch]] = {}
        d = Path(dirpath)
        if not d.is_dir():
            return results
        for fp in d.rglob("*"):
            if fp.is_file() and fp.suffix in exts:
                m = self.scan_file(fp)
                if m:
                    results[str(fp)] = m
        return results

    def scan_with_severity_filter(
        self, code: str, min_severity: YaraMatchSeverity = YaraMatchSeverity.LOW,
        filename: str = "unknown",
    ) -> list[YaraMatch]:
        all_matches = self.scan(code, filename)
        return [m for m in all_matches if m.severity.value >= min_severity.value]

    def get_scan_summary(self, matches: list[YaraMatch]) -> dict:
        severity_counts = {s.name: 0 for s in YaraMatchSeverity}
        rule_hits: dict[str, int] = {}
        cwe_map: dict[str, int] = {}
        for m in matches:
            severity_counts[m.severity.name] += 1
            rule_hits[m.rule_name] = rule_hits.get(m.rule_name, 0) + 1
            if m.cwe:
                cwe_map[m.cwe] = cwe_map.get(m.cwe, 0) + 1
        return {
            "total_matches": len(matches),
            "severity_distribution": severity_counts,
            "rules_triggered": rule_hits,
            "cwe_distribution": cwe_map,
            "unique_rules": len(rule_hits),
            "critical_count": severity_counts.get("CRITICAL", 0),
            "high_count": severity_counts.get("HIGH", 0),
            "total_rules_loaded": self.rule_count,
            "engine": "yara-python" if self.using_native else "regex-fallback",
            "rules_source": self.rules_source,
        }
