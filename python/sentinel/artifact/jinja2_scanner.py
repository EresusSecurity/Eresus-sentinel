"""Jinja2 template injection (SSTI) scanner (.jinja, .j2, .template, tokenizer configs).

Detection rules are loaded from rules/jinja2_rules.yaml at import time.
Covers CVE-2024-34359 and 6 SSTI risk categories.
"""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

_RULES_PATH = Path(__file__).parent.parent.parent.parent / "rules" / "jinja2_rules.yaml"
_MAX_FILE_SIZE = 10 * 1024 * 1024
_MAX_TEMPLATE_SIZE = 50 * 1024


@lru_cache(maxsize=1)
def _load_rules() -> dict[str, Any]:
    try:
        with open(_RULES_PATH, "r") as fh:
            return yaml.safe_load(fh) or {}
    except Exception as exc:
        logger.warning("jinja2_rules.yaml not loaded: %s", exc)
        return {}


@lru_cache(maxsize=1)
def _compiled_ssti_patterns() -> dict[str, tuple[Severity, list[str], list[tuple[str, re.Pattern[str]]]]]:
    """Return {category: (severity, cwe_ids, [(raw_pat, compiled_pat)])}."""
    rules = _load_rules()
    ssti = rules.get("ssti_patterns", {})
    out: dict[str, tuple[Severity, list[str], list[tuple[str, re.Pattern[str]]]]] = {}
    sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM}
    for category, entry in ssti.items():
        sev = sev_map.get(entry.get("severity", "HIGH"), Severity.HIGH)
        cwe_ids = entry.get("cwe_ids", ["CWE-94"])
        compiled_pats: list[tuple[str, re.Pattern[str]]] = []
        for raw in entry.get("patterns", []):
            try:
                compiled_pats.append((raw, re.compile(raw, re.IGNORECASE | re.MULTILINE)))
            except re.error as exc:
                logger.debug("jinja2_rules: bad pattern %r: %s", raw, exc)
        out[category] = (sev, cwe_ids, compiled_pats)
    return out


@lru_cache(maxsize=1)
def _safe_ml_patterns() -> frozenset[str]:
    rules = _load_rules()
    return frozenset(rules.get("safe_ml_patterns", []))


@lru_cache(maxsize=1)
def _template_indicators() -> tuple[str, ...]:
    rules = _load_rules()
    return tuple(rules.get("template_indicators", ["{{", "{%", "{#"]))


@lru_cache(maxsize=1)
def _ml_context_filenames() -> frozenset[str]:
    rules = _load_rules()
    return frozenset(rules.get("ml_context_filenames", []))


@lru_cache(maxsize=1)
def _ml_context_path_terms() -> tuple[str, ...]:
    rules = _load_rules()
    return tuple(rules.get("ml_context_path_terms", []))


@lru_cache(maxsize=1)
def _suspicious_template_keys() -> frozenset[str]:
    rules = _load_rules()
    return frozenset(rules.get("suspicious_template_keys", []))


def _has_jinja_indicators(text: str) -> bool:
    return any(ind in text for ind in _template_indicators())


def _is_safe_ml_token(text: str) -> bool:
    """Return True if the text contains only known-safe ML loop/variable tokens."""
    stripped = text.strip().lower()
    return stripped in _safe_ml_patterns()


def _snippet(text: str, max_len: int = 200) -> str:
    normalized = re.sub(r"\s+", " ", text).strip()
    return normalized if len(normalized) <= max_len else normalized[: max_len - 3] + "..."


def _scan_template(
    template_text: str,
    source_path: str,
    location_hint: str = "",
    max_findings_per_cat: int = 10,
) -> list[Finding]:
    """Scan a single template string for SSTI patterns."""
    if not _has_jinja_indicators(template_text):
        return []
    if len(template_text) > _MAX_TEMPLATE_SIZE:
        return [Finding.artifact(
            rule_id="JINJA2-TRUNC",
            title="Jinja2 template skipped — exceeds size limit",
            description=f"Template at {location_hint or source_path} is {len(template_text)} bytes, "
                        f"exceeding the {_MAX_TEMPLATE_SIZE} byte scan budget.",
            severity=Severity.LOW,
            target=source_path,
        )]

    findings: list[Finding] = []
    patterns = _compiled_ssti_patterns()
    category_meta = {
        "critical_rce": "Direct RCE via Jinja2 SSTI (CVE-2024-34359 class)",
        "code_execution": "Code execution via Python object introspection in Jinja2",
        "attribute_access": "Suspicious attribute access — SSTI stepping stone",
        "filter_bypass": "Jinja2 filter-based SSTI bypass technique",
        "obfuscation": "Encoded/obfuscated SSTI payload in Jinja2 template",
        "waf_bypass": "WAF bypass technique in Jinja2 template",
    }
    seen_categories: set[str] = set()

    for category, (sev, cwe_ids, compiled_pats) in patterns.items():
        if len([f for f in findings if f.rule_id.startswith("JINJA2-SSTI")]) >= max_findings_per_cat:
            break
        for raw_pat, pat in compiled_pats:
            m = pat.search(template_text)
            if not m:
                continue
            matched_text = m.group(0)
            if _is_safe_ml_token(matched_text):
                continue
            if category in seen_categories:
                continue
            seen_categories.add(category)
            loc = location_hint or source_path
            findings.append(Finding.artifact(
                rule_id="JINJA2-SSTI",
                title=category_meta.get(category, f"SSTI pattern: {category}"),
                description=(
                    f"Jinja2 SSTI pattern category '{category}' matched in template. "
                    f"Pattern: {raw_pat[:80]}. "
                    f"Match: {_snippet(matched_text, 120)}"
                ),
                severity=sev,
                target=source_path,
                evidence=f"location={loc}; match={_snippet(matched_text, 120)}",
                cwe_ids=cwe_ids,
            ))
            break

    return findings


def _extract_json_templates(data: Any, keys: frozenset[str], depth: int = 0) -> list[tuple[str, str]]:
    """Recursively extract template strings from JSON by key name."""
    results: list[tuple[str, str]] = []
    if depth > 8:
        return results
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() in keys and isinstance(v, str):
                results.append((k, v))
            else:
                results.extend(_extract_json_templates(v, keys, depth + 1))
    elif isinstance(data, list):
        for item in data:
            results.extend(_extract_json_templates(item, keys, depth + 1))
    return results


def _is_ml_context_path(filepath: str) -> bool:
    lowered = filepath.lower()
    name = Path(filepath).name.lower()
    if name in _ml_context_filenames():
        return True
    return any(term in lowered for term in _ml_context_path_terms())


class Jinja2InjectionScanner:
    """Scanner for Jinja2 Server-Side Template Injection (SSTI) in ML artifacts.

    Detection rules are loaded from rules/jinja2_rules.yaml. Performs:
      - 6-category SSTI pattern scanning (critical_rce, code_execution,
        attribute_access, filter_bypass, obfuscation, waf_bypass)
      - ML-context-aware file routing (tokenizer_config.json, chat_template,
        YAML configs, .jinja/.j2/.template files)
      - JSON template field extraction (chat_template, prompt_template, etc.)
      - YAML template extraction for model config files
      - Safe ML pattern suppression (loop variables, role names, token names)
      - CVE-2024-34359 targeted detection patterns
    """

    EXTENSIONS = frozenset({".jinja", ".jinja2", ".j2", ".template", ".json", ".yaml", ".yml"})

    _STANDALONE_EXTS = frozenset({".jinja", ".jinja2", ".j2", ".template"})

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.is_dir():
            return findings

        try:
            file_size = path.stat().st_size
        except OSError:
            return findings

        if file_size > _MAX_FILE_SIZE:
            return [Finding.artifact(
                rule_id="JINJA2-SIZE",
                title="File too large for Jinja2 template scan",
                description=f"File is {file_size} bytes; scan budget is {_MAX_FILE_SIZE} bytes.",
                severity=Severity.LOW,
                target=filepath,
            )]

        ext = path.suffix.lower()
        name = path.name.lower()

        if ext in self._STANDALONE_EXTS:
            findings.extend(self._scan_standalone_template(path, filepath))
        elif ext == ".json":
            if name in _ml_context_filenames() or _is_ml_context_path(filepath):
                findings.extend(self._scan_json_config(path, filepath))
        elif ext in (".yaml", ".yml"):
            if _is_ml_context_path(filepath):
                findings.extend(self._scan_yaml_config(path, filepath))

        return findings

    def _scan_standalone_template(self, path: Path, filepath: str) -> list[Finding]:
        try:
            text = path.read_text("utf-8", "ignore")
        except OSError:
            return []
        return _scan_template(text, filepath, location_hint="template_body")

    def _scan_json_config(self, path: Path, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            findings.append(Finding.artifact(
                rule_id="JINJA2-PARSE",
                title="JSON parse error in model config",
                description=f"Cannot parse {path.name}: {exc}",
                severity=Severity.MEDIUM,
                target=filepath,
                evidence=str(exc),
            ))
            return findings
        except OSError:
            return findings

        template_keys = _suspicious_template_keys()
        extracted = _extract_json_templates(data, template_keys)

        if not extracted:
            raw_text = json.dumps(data)
            if _has_jinja_indicators(raw_text):
                findings.extend(_scan_template(raw_text, filepath, location_hint="raw_json_body"))
            return findings

        for key, template_value in extracted:
            if not _has_jinja_indicators(template_value):
                continue
            findings.extend(_scan_template(
                template_value,
                filepath,
                location_hint=f"json_key={key}",
            ))

        return findings

    def _scan_yaml_config(self, path: Path, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            with open(path, encoding="utf-8") as fh:
                raw_text = fh.read()
        except OSError:
            return findings

        if not _has_jinja_indicators(raw_text):
            return findings

        try:
            data = yaml.safe_load(raw_text)
        except yaml.YAMLError:
            findings.extend(_scan_template(raw_text, filepath, location_hint="raw_yaml_body"))
            return findings

        if data and isinstance(data, dict):
            template_keys = _suspicious_template_keys()
            extracted = _extract_json_templates(data, template_keys)
            for key, template_value in extracted:
                if _has_jinja_indicators(template_value):
                    findings.extend(_scan_template(
                        template_value,
                        filepath,
                        location_hint=f"yaml_key={key}",
                    ))
        else:
            findings.extend(_scan_template(raw_text, filepath, location_hint="yaml_body"))

        return findings
