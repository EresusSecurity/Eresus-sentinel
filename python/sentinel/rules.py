"""
Eresus Sentinel — YAML Rule Loader

Central rule loading utility. All scanners load their patterns/rules
from YAML files in the rules/ directory. No hardcoded patterns in code.
"""

import functools
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List

import yaml

_log = logging.getLogger(__name__)


# ── Module-level rule cache ──────────────────────────────────────────
# All load_* functions are wrapped with lru_cache to avoid recompiling
# regexes on every scan invocation. Call _clear_rule_cache() to reset.
_cache_enabled = True


def _clear_rule_cache():
    """Clear all cached rule data. Useful for testing or hot-reload."""
    load_secret_patterns.cache_clear()
    load_injection_patterns.cache_clear()
    load_input_data_exfiltration_rules.cache_clear()
    load_sast_rules.cache_clear()
    load_artifact_blocklist.cache_clear()
    load_artifact_allowlist.cache_clear()
    load_mcp_rules.cache_clear()
    load_supply_chain_rules.cache_clear()
    load_scanner_rules.cache_clear()
    load_sast_secret_patterns.cache_clear()
    load_taint_rules.cache_clear()
    load_aibom_patterns.cache_clear()
    load_cntk_rules.cache_clear()
    load_backdoor_patterns.cache_clear()
    load_fp_patterns.cache_clear()


def get_rules_dir() -> Path:
    """Return the rules directory, allowing override via env var."""
    env_dir = os.environ.get("ERESUS_RULES_DIR") or os.environ.get("LLMSECOPS_RULES_DIR")
    if env_dir:
        return Path(env_dir)
    # wheel install: rules/ next to package
    pkg_rules = Path(__file__).parent / "rules"
    if pkg_rules.exists():
        return pkg_rules
    # development: repo root (three levels up from python/sentinel/rules.py)
    dev_rules = Path(__file__).parent.parent.parent / "rules"
    if dev_rules.exists():
        return dev_rules
    return pkg_rules  # fallback


def load_yaml(filename: str) -> Any:
    """Load a YAML file from the rules directory."""
    path = get_rules_dir() / filename
    if not path.exists():
        raise FileNotFoundError(f"Rule file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@functools.lru_cache(maxsize=1)
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
        except re.error as exc:
            _log.warning(
                "rules.py: skipping invalid regex in secret_patterns.yaml "
                "(id=%r): %s",
                entry.get("id", entry.get("name", "?")),
                exc,
            )
            continue  # Skip invalid regex
    return patterns


@functools.lru_cache(maxsize=1)
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
            except re.error as exc:
                _log.warning(
                    "rules.py: skipping invalid regex in injection_patterns.yaml "
                    "(category=%r, id=%r): %s",
                    category,
                    entry.get("id", entry.get("name", "?")),
                    exc,
                )
                continue
        result[category] = compiled
    return result


@functools.lru_cache(maxsize=1)
def load_input_data_exfiltration_rules() -> Dict[str, Any]:
    """Load input data-exfiltration intent rules and compile regexes."""
    data = load_yaml("input_data_exfiltration.yaml")
    if not isinstance(data, dict):
        return {"rules": [], "benign_context_patterns": []}

    compiled_rules = []
    for entry in data.get("rules", []):
        try:
            compiled = dict(entry)
            compiled["pattern"] = re.compile(entry["pattern"])
            compiled_rules.append(compiled)
        except (AttributeError, KeyError, TypeError, ValueError, re.error) as exc:
            _log.warning(
                "rules.py: skipping invalid regex in input_data_exfiltration.yaml "
                "(id=%r): %s",
                entry.get("id", entry.get("name", "?")) if isinstance(entry, dict) else "?",
                exc,
            )

    benign_contexts = []
    for pattern in data.get("benign_context_patterns", []):
        try:
            benign_contexts.append(re.compile(pattern))
        except re.error as exc:
            _log.warning(
                "rules.py: skipping invalid benign context regex in "
                "input_data_exfiltration.yaml: %s",
                exc,
            )

    return {
        "rules": compiled_rules,
        "benign_context_patterns": benign_contexts,
    }


@functools.lru_cache(maxsize=1)
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
            raw_excl = entry.get("exclude_value_patterns", [])
            excl_compiled = []
            for ep in raw_excl:
                ep_str = str(ep).split('#')[0].strip()
                if ep_str:
                    try:
                        excl_compiled.append(re.compile(ep_str))
                    except re.error:
                        pass
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
                "exclude_value_patterns": excl_compiled,
            })
        except re.error as exc:
            _log.warning(
                "rules.py: skipping invalid regex in sast_rules.yaml (id=%r): %s",
                entry.get("id", entry.get("name", "?")),
                exc,
            )
            continue
    return rules


@functools.lru_cache(maxsize=1)
def load_artifact_blocklist() -> Dict[str, List[str]]:
    """Load dangerous globals blocklist for pickle scanning."""
    data = load_yaml("artifact_blocklist.yaml")
    if isinstance(data, dict):
        return data.get("dangerous_globals", {})
    return {}


@functools.lru_cache(maxsize=1)
def load_artifact_allowlist() -> Dict[str, List[str]]:
    """Load allowlisted globals for pickle scanning."""
    data = load_yaml("artifact_blocklist.yaml")
    if isinstance(data, dict):
        return data.get("allowlist", {})
    return {}


@functools.lru_cache(maxsize=1)
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
                "rule_id": entry.get("rule_id", "MCP-040"),
                "title": entry.get("title", "Suspicious language in tool description"),
            })
        except re.error as exc:
            _log.warning(
                "Skipping invalid regex in mcp_rules.yaml (name=%r): %s",
                entry.get("name", "unknown"),
                exc,
            )
            continue

    return {
        "dangerous_capabilities": data.get("dangerous_capabilities", {}),
        "description_injection_patterns": desc_patterns,
        "schema_permissiveness": data.get("schema_permissiveness", []),
        "path_parameter_keywords": data.get("path_parameter_keywords", []),
        "auth_field_names": data.get("auth_field_names", []),
    }


@functools.lru_cache(maxsize=1)
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


@functools.lru_cache(maxsize=1)
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


@functools.lru_cache(maxsize=1)
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


@functools.lru_cache(maxsize=1)
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


_RE_FLAG_MAP = {"MULTILINE": re.MULTILINE, "IGNORECASE": re.IGNORECASE, "DOTALL": re.DOTALL}


def _compile_pattern_list(entries: list) -> list[tuple[re.Pattern, str, bool, tuple[str, ...]]]:
    """Compile a list of {pattern, label, flags?, capture?, requires_co_occurrence?} dicts.

    Returns list of (compiled_regex, label, capture_flag, co_occurrence_strings).
    The co_occurrence tuple is empty when no context requirement is specified.
    """
    out = []
    for e in entries:
        if not isinstance(e, dict) or "pattern" not in e:
            continue
        flags = 0
        for f in str(e.get("flags", "")).split("|"):
            flags |= _RE_FLAG_MAP.get(f.strip(), 0)
        try:
            rx = re.compile(e["pattern"], flags)
            co_occ = tuple(e.get("requires_co_occurrence", ()))
            out.append((rx, e.get("label", "unknown"), bool(e.get("capture")), co_occ))
        except re.error as exc:
            _log.warning("aibom pattern skip: %s — %s", e.get("label"), exc)
    return out


@functools.lru_cache(maxsize=1)
def load_aibom_patterns() -> Dict[str, Any]:
    """Load AIBOM scanner patterns from YAML and compile all regexes."""
    raw = load_yaml("aibom_scanner_patterns.yaml")
    result: Dict[str, Any] = {}

    # ml_lifecycle — phase groups
    ml = raw.get("ml_lifecycle", {})
    result["ml_lifecycle"] = {}
    for phase, entries in ml.items():
        if isinstance(entries, list):
            result["ml_lifecycle"][phase] = _compile_pattern_list(entries)

    # structural_agent — category groups
    sa = raw.get("structural_agent", {})
    result["structural_agent"] = {}
    for cat, entries in sa.items():
        if isinstance(entries, list):
            result["structural_agent"][cat] = _compile_pattern_list(entries)

    # agent_evidence
    ae = raw.get("agent_evidence", {})
    result["agent_evidence"] = {
        "frameworks": ae.get("frameworks", {}),
        "signals": {},
    }
    for sig_name, pat in ae.get("signals", {}).items():
        if isinstance(pat, str):
            try:
                result["agent_evidence"]["signals"][sig_name] = re.compile(pat)
            except re.error:
                pass

    # import_context — category groups
    ic = raw.get("import_context", {})
    result["import_context"] = {}
    for cat, entries in ic.items():
        if isinstance(entries, list):
            result["import_context"][cat] = _compile_pattern_list(entries)

    # multi_language — language groups
    mls = raw.get("multi_language", {})
    result["multi_language"] = {}
    for lang, entries in mls.items():
        if isinstance(entries, list):
            result["multi_language"][lang] = _compile_pattern_list(entries)

    # env_var
    ev = raw.get("env_var", {})
    ai_key_pat = ev.get("ai_key_pattern", "")
    code_pats = ev.get("code_patterns", {})
    result["env_var"] = {
        "ai_key_re": re.compile(ai_key_pat, re.IGNORECASE) if ai_key_pat else None,
        "model_env_names": frozenset(ev.get("model_env_names", [])),
        "endpoint_env_names": frozenset(ev.get("endpoint_env_names", [])),
        "code_patterns": {},
    }
    for lang, pat in code_pats.items():
        flags = re.MULTILINE if lang == "dotenv" else 0
        try:
            result["env_var"]["code_patterns"][lang] = re.compile(pat, flags)
        except re.error:
            pass

    # deployment
    dep = raw.get("deployment", {})
    gpu_pat = dep.get("gpu_pattern", "")
    result["deployment"] = {
        "ai_container_images": tuple(dep.get("ai_container_images", [])),
        "terraform_ai_resources": frozenset(dep.get("terraform_ai_resources", [])),
        "gpu_re": re.compile(gpu_pat, re.IGNORECASE) if gpu_pat else None,
    }

    return result


@functools.lru_cache(maxsize=1)
def load_cntk_rules() -> Dict[str, Any]:
    """Load CNTK model security rules from cntk_rules.yaml.

    Returns the raw YAML dict. Patterns are compiled by the CNTK scanner
    (which has cntk-specific compilation logic). This function provides
    caching and centralised path resolution via rules.get_rules_dir().
    """
    try:
        return load_yaml("cntk_rules.yaml") or {}
    except FileNotFoundError:
        _log.warning("rules.py: cntk_rules.yaml not found in %s", get_rules_dir())
        return {}
    except Exception as exc:
        _log.warning("rules.py: failed to load cntk_rules.yaml: %s", exc)
        return {}


@functools.lru_cache(maxsize=1)
def load_backdoor_patterns() -> Dict[str, Any]:
    """Load backdoor & reverse-shell detection patterns from backdoor_patterns.yaml.

    Returns a dict keyed by category section. Each list entry includes a
    'compiled' key with the pre-compiled regex for fast matching.
    """
    try:
        data = load_yaml("backdoor_patterns.yaml") or {}
    except FileNotFoundError:
        _log.warning("rules.py: backdoor_patterns.yaml not found in %s", get_rules_dir())
        return {}
    except Exception as exc:
        _log.warning("rules.py: failed to load backdoor_patterns.yaml: %s", exc)
        return {}

    compiled: Dict[str, Any] = {}
    for section, entries in data.items():
        if section == "version":
            compiled[section] = entries
            continue
        if not isinstance(entries, list):
            compiled[section] = entries
            continue
        compiled_entries = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            pat_str = entry.get("pattern", "")
            if not pat_str:
                compiled_entries.append(entry)
                continue
            try:
                compiled_entry = dict(entry)
                compiled_entry["compiled"] = re.compile(pat_str, re.IGNORECASE)
                compiled_entries.append(compiled_entry)
            except re.error as exc:
                _log.warning(
                    "rules.py: bad pattern in backdoor_patterns.yaml "
                    "section=%r id=%r: %s",
                    section,
                    entry.get("id", "?"),
                    exc,
                )
        compiled[section] = compiled_entries
    return compiled


@functools.lru_cache(maxsize=1)
def load_fp_patterns() -> List[Dict[str, Any]]:
    """Load false-positive suppression patterns from fp_patterns.yaml.

    Returns a list of compiled FP entries with 'compiled', 'id', 'description',
    and 'category' fields.
    """
    try:
        data = load_yaml("fp_patterns.yaml") or {}
    except FileNotFoundError:
        _log.warning("rules.py: fp_patterns.yaml not found in %s", get_rules_dir())
        return []
    except Exception as exc:
        _log.warning("rules.py: failed to load fp_patterns.yaml: %s", exc)
        return []

    entries = data if isinstance(data, list) else data.get("patterns", [])
    compiled_list = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pat_str = entry.get("pattern", "")
        if not pat_str:
            continue
        try:
            compiled_list.append({
                "id": entry.get("id", entry.get("name", "unknown")),
                "description": entry.get("description", ""),
                "category": entry.get("category", "generic"),
                "compiled": re.compile(pat_str, re.IGNORECASE),
            })
        except re.error as exc:
            _log.warning(
                "rules.py: bad FP pattern id=%r: %s",
                entry.get("id", entry.get("name", "?")),
                exc,
            )
    return compiled_list


def validate_all_rule_files() -> Dict[str, Any]:
    """Health-check: attempt to load every known YAML rule file and compile patterns.

    Returns a report dict:
      - 'ok': list of filenames that loaded successfully
      - 'failed': list of (filename, error_message) tuples
      - 'bad_patterns': list of (filename, rule_id, error_message) tuples
    """
    _RULE_FILES = [
        "secret_patterns.yaml",
        "injection_patterns.yaml",
        "sast_rules.yaml",
        "artifact_blocklist.yaml",
        "mcp_rules.yaml",
        "supply_chain_rules.yaml",
        "scanner_rules.yaml",
        "sast_secret_patterns.yaml",
        "taint_rules.yaml",
        "backdoor_patterns.yaml",
        "fp_patterns.yaml",
        "cntk_rules.yaml",
        "dangerous_code_patterns.yaml",
        "deception_patterns.yaml",
        "rknn_rules.yaml",
        "jax_rules.yaml",
        "tf_metagraph_rules.yaml",
        "manifest_rules.yaml",
        "model_format_rules.yaml",
    ]

    report: Dict[str, Any] = {"ok": [], "failed": [], "bad_patterns": []}
    rules_dir = get_rules_dir()

    def _check_patterns(section: Any, fname: str) -> None:
        if isinstance(section, list):
            for entry in section:
                if not isinstance(entry, dict):
                    continue
                pat = entry.get("pattern", "")
                if not pat:
                    continue
                try:
                    re.compile(pat, re.IGNORECASE)
                except re.error as exc:
                    report["bad_patterns"].append(
                        (fname, entry.get("id", entry.get("name", "?")), str(exc))
                    )
        elif isinstance(section, dict):
            for v in section.values():
                _check_patterns(v, fname)

    for filename in _RULE_FILES:
        path = rules_dir / filename
        if not path.exists():
            report["failed"].append((filename, "file not found"))
            continue
        try:
            import yaml as _yaml
            with open(path, "r", encoding="utf-8") as fh:
                data = _yaml.safe_load(fh) or {}
        except Exception as exc:
            report["failed"].append((filename, str(exc)))
            continue

        if isinstance(data, list):
            _check_patterns(data, filename)
        elif isinstance(data, dict):
            for v in data.values():
                _check_patterns(v, filename)

        report["ok"].append(filename)

    return report
