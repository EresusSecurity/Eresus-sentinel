"""
Eresus Sentinel — YAML Rule Loader

Central rule loading utility. All scanners load their patterns/rules
from YAML files in the rules/ directory. No hardcoded patterns in code.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# Default rules directory
_RULES_DIR = Path(__file__).parent.parent.parent / "rules"


def get_rules_dir() -> Path:
    """Return the rules directory, allowing override via env var."""
    env_dir = os.environ.get("ERESUS_RULES_DIR") or os.environ.get("LLMSECOPS_RULES_DIR")
    if env_dir:
        return Path(env_dir)
    return _RULES_DIR


def load_yaml(filename: str) -> Any:
    """Load a YAML file from the rules directory."""
    path = get_rules_dir() / filename
    if not path.exists():
        raise FileNotFoundError(f"Rule file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_secret_patterns() -> List[Dict[str, Any]]:
    """Load secret detection patterns from YAML and compile regexes.
    
    Supports both formats:
      - List format: top-level YAML list of pattern entries
      - Dict format: {"patterns": [...]}
    """
    data = load_yaml("secret_patterns.yaml")
    
    # Normalize: support both list-at-root and dict-with-patterns-key
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("patterns", [])
    else:
        entries = []

    patterns = []
    for entry in entries:
        try:
            compiled = re.compile(entry["pattern"])
            patterns.append({
                "id": entry.get("id", entry.get("name", "unknown")),
                "pattern": compiled,
                "description": entry.get("description", ""),
                "severity": entry.get("severity", "MEDIUM"),
                "category": entry.get("category", "generic"),
                "tags": entry.get("tags", []),
                "fp_note": entry.get("fp_note", ""),
            })
        except re.error:
            continue  # Skip invalid regex
    return patterns


def load_injection_patterns() -> Dict[str, List[Dict[str, Any]]]:
    """Load prompt injection patterns from YAML, organized by category.
    
    Supports entries with either 'id' or 'name' as identifier.
    Handles all categories present in the YAML file.
    """
    data = load_yaml("injection_patterns.yaml")
    if not isinstance(data, dict):
        return {}
    
    result = {}
    for category, entries in data.items():
        if not isinstance(entries, list):
            continue
        compiled = []
        for entry in entries:
            try:
                pattern_str = entry.get("pattern", "")
                if not pattern_str:
                    continue
                compiled.append({
                    "id": entry.get("id", entry.get("name", "unknown")),
                    "name": entry.get("name", entry.get("id", "unknown")),
                    "pattern": re.compile(pattern_str),
                    "description": entry.get("description", ""),
                    "severity": entry.get("severity", "MEDIUM"),
                    "weight": entry.get("weight", 0.5),
                })
            except re.error:
                continue
        result[category] = compiled
    return result


def load_sast_rules() -> List[Dict[str, Any]]:
    """Load SAST rules from YAML and compile regexes."""
    data = load_yaml("sast_rules.yaml")

    # Normalize: support both list-at-root and dict-with-rules-key
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("rules", [])
    else:
        entries = []

    rules = []
    for entry in entries:
        try:
            compiled = re.compile(entry["pattern"])
            rules.append({
                "id": entry.get("id", entry.get("name", "unknown")),
                "name": entry.get("name", entry.get("id", "unknown")),
                "description": entry.get("description", ""),
                "pattern": compiled,
                "severity": entry.get("severity", "MEDIUM"),
                "cwe_ids": entry.get("cwe_ids", []),
                "fix_hint": entry.get("fix_hint", ""),
                "fp_risk": entry.get("fp_risk", "MEDIUM"),
                "references": entry.get("references", []),
            })
        except re.error:
            continue
    return rules


def load_artifact_blocklist() -> Dict[str, List[str]]:
    """Load dangerous globals blocklist for pickle scanning."""
    data = load_yaml("artifact_blocklist.yaml")
    if isinstance(data, dict):
        return data.get("dangerous_globals", {})
    return {}


def load_artifact_allowlist() -> Dict[str, List[str]]:
    """Load allowlisted globals for pickle scanning."""
    data = load_yaml("artifact_blocklist.yaml")
    if isinstance(data, dict):
        return data.get("allowlist", {})
    return {}


def load_mcp_rules() -> Dict[str, Any]:
    """Load MCP/Agent security rules from YAML.

    Returns a dict with keys:
      - dangerous_capabilities: dict[str, {keywords, severity, description, cwe}]
      - description_injection_patterns: list[{pattern, name, description, severity}]
      - schema_permissiveness: list[{check, description, severity, rule_id}]
      - path_parameter_keywords: list[str]
      - auth_field_names: list[str]
    """
    data = load_yaml("mcp_rules.yaml")
    if not isinstance(data, dict):
        return {}

    # Compile regex patterns for description injection
    desc_patterns = []
    for entry in data.get("description_injection_patterns", []):
        try:
            desc_patterns.append({
                "pattern": re.compile(entry["pattern"]),
                "name": entry.get("name", "unknown"),
                "description": entry.get("description", ""),
                "severity": entry.get("severity", "HIGH"),
            })
        except re.error:
            continue

    return {
        "dangerous_capabilities": data.get("dangerous_capabilities", {}),
        "description_injection_patterns": desc_patterns,
        "schema_permissiveness": data.get("schema_permissiveness", []),
        "path_parameter_keywords": data.get("path_parameter_keywords", []),
        "auth_field_names": data.get("auth_field_names", []),
    }


def load_supply_chain_rules() -> Dict[str, Any]:
    """Load supply chain security rules from YAML.

    Returns a dict with keys:
      - dangerous_extensions: dict[ext, {description, severity}]
      - safe_extensions: list[str]
      - model_card_fields: list[str]
      - config_flags: list[{key, description, severity, rule_id}]
    """
    try:
        data = load_yaml("supply_chain_rules.yaml")
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def load_scanner_rules() -> Dict[str, Any]:
    """Load artifact scanner patterns from scanner_rules.yaml.

    Returns the full YAML dict with keys: common, torchscript, tensorflow,
    tflite, llamafile. Each scanner loads its section at init.
    Falls back to empty dict if file not found.
    """
    try:
        data = load_yaml("scanner_rules.yaml")
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def load_sast_secret_patterns() -> List[Dict[str, Any]]:
    """Load SAST secret detection patterns from YAML and compile regexes.

    Loads from: rules/sast_secret_patterns.yaml
    Returns a flat list of compiled pattern dicts:
      [{id, name, pattern (compiled), severity, description}, ...]
    """
    try:
        data = load_yaml("sast_secret_patterns.yaml")
    except FileNotFoundError:
        return []

    if not isinstance(data, dict):
        return []

    patterns = []
    for _category, entries in data.get("patterns", {}).items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            try:
                compiled = re.compile(entry["pattern"])
                patterns.append({
                    "id": entry.get("id", "unknown"),
                    "name": entry.get("name", "unknown"),
                    "pattern": compiled,
                    "severity": entry.get("severity", "HIGH"),
                    "description": entry.get("description", ""),
                })
            except re.error:
                continue
    return patterns


def load_taint_rules() -> Dict[str, List[Dict[str, Any]]]:
    """Load taint analysis rules (sources + sinks) from YAML.

    Loads from: rules/taint_rules.yaml
    Returns dict with:
      - sources: [{name, pattern (compiled), description}, ...]
      - sinks: [{name, pattern (compiled), severity, cwe, description}, ...]
    """
    try:
        data = load_yaml("taint_rules.yaml")
    except FileNotFoundError:
        return {"sources": [], "sinks": []}

    if not isinstance(data, dict):
        return {"sources": [], "sinks": []}

    sources = []
    for _category, entries in data.get("sources", {}).items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            try:
                sources.append({
                    "name": entry["name"],
                    "pattern": re.compile(entry["pattern"]),
                    "description": entry.get("description", ""),
                })
            except re.error:
                continue

    sinks = []
    for _category, entries in data.get("sinks", {}).items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            try:
                sinks.append({
                    "name": entry["name"],
                    "pattern": re.compile(entry["pattern"]),
                    "severity": entry.get("severity", "MEDIUM"),
                    "cwe": entry.get("cwe", "CWE-20"),
                    "description": entry.get("description", ""),
                })
            except re.error:
                continue

    return {"sources": sources, "sinks": sinks}


