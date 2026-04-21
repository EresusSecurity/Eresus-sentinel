"""Notebook dangerous code detection — loads patterns from YAML and scans for unsafe operations."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

from sentinel.finding import Finding, Severity
from sentinel.notebook_scanner.parser import NotebookCell

logger = logging.getLogger(__name__)

# Common notebook imports that are benign in data-science context
_NOTEBOOK_SAFE_IMPORTS = re.compile(
    r"^\s*(?:import|from)\s+(?:"
    r"pandas|numpy|matplotlib|seaborn|sklearn|scipy|plotly|"
    r"tensorflow|torch|keras|transformers|datasets|tokenizers|"
    r"huggingface_hub|wandb|mlflow|optuna|ray|dask|"
    r"requests|httpx|aiohttp|boto3|google\.cloud|"
    r"json|csv|os|sys|pathlib|logging|warnings|typing|"
    r"collections|itertools|functools|datetime|time|re|math|"
    r"io|copy|glob|shutil|tempfile|pickle|joblib|"
    r"PIL|cv2|skimage|tqdm|rich|IPython|ipywidgets"
    r")\b",
    re.MULTILINE,
)

# Patterns that are FP-prone in notebook context — downgrade severity
_NOTEBOOK_FP_PATTERNS = {
    "os.environ[]", "open(..., 'w')", "open(..., 'a')", "shutil.copy()",
    "shutil.move()", "os.makedirs()", "Path.write_*()", "tempfile",
    "shutil", "json", "csv", "logging", "warnings", "pathlib",
    "inspect", "sys", "ast", "dis", "gc", "types", "select",
    "input()", "help()", "locals()", "breakpoint()", "globals()",
    "requests.*", "httpx.*", "aiohttp.ClientSession()", "urlopen()",
    "boto3.client()", "google.cloud.*", "hf_hub_download()",
    "xgboost.Booster(model_file)", "CatBoost.load_model()",
    "lightgbm.Booster(model_file)", "signal", "multiprocessing",
    "asyncio.subprocess", "compileall", "antigravity", "code",
}

_RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules"
_PATTERN_FILE = _RULES_DIR / "dangerous_code_patterns.yaml"

# Severity mapping
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# Rule ID mapping per category
_RULE_IDS = {
    "dangerous_imports": ("NOTEBOOK-001", "dangerous-import", "CWE-94"),
    "dangerous_builtins": ("NOTEBOOK-002", "unsafe-builtin", "CWE-94"),
    "dangerous_syscalls": ("NOTEBOOK-003", "system-call", "CWE-78"),
    "unsafe_ml_ops": ("NOTEBOOK-004", "unsafe-ml", "CWE-502"),
    "network_ops": ("NOTEBOOK-005", "network-access", "CWE-918"),
    "sandbox_escape": ("NOTEBOOK-006", "sandbox-escape", "CWE-94"),
    "file_system_ops": ("NOTEBOOK-007", "file-system", "CWE-73"),
}



def _load_patterns(path: Optional[Path] = None) -> dict[str, list[tuple[re.Pattern, str, str, Severity]]]:
    """Load dangerous code patterns from YAML file.

    Returns a dict mapping category name to list of (compiled_regex, name, risk, severity).
    """
    yaml_path = path or _PATTERN_FILE
    if not yaml_path.exists():
        logger.warning("Pattern file not found: %s — using empty ruleset", yaml_path)
        return {}

    with open(yaml_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not raw or not isinstance(raw, dict):
        logger.warning("Invalid pattern file: %s", yaml_path)
        return {}

    patterns: dict[str, list[tuple[re.Pattern, str, str, Severity]]] = {}

    for category, entries in raw.items():
        if not isinstance(entries, list):
            continue
        compiled = []
        for entry in entries:
            try:
                regex = re.compile(entry["pattern"], re.MULTILINE)
                name = entry["name"]
                risk = entry["risk"]
                severity = _SEVERITY_MAP.get(entry.get("severity", "MEDIUM"), Severity.MEDIUM)
                compiled.append((regex, name, risk, severity))
            except (KeyError, re.error) as exc:
                logger.warning("Skipping invalid pattern in %s: %s", category, exc)
                continue
        patterns[category] = compiled

    total = sum(len(v) for v in patterns.values())
    logger.debug("Loaded %d dangerous code patterns across %d categories", total, len(patterns))
    return patterns


# Module-level cache — loaded once at import time
_CACHED_PATTERNS: Optional[dict] = None


def _get_patterns() -> dict[str, list[tuple[re.Pattern, str, str, Severity]]]:
    """Get cached patterns, loading from YAML on first call."""
    global _CACHED_PATTERNS
    if _CACHED_PATTERNS is None:
        _CACHED_PATTERNS = _load_patterns()
    return _CACHED_PATTERNS


def reload_patterns(path: Optional[Path] = None) -> int:
    """Force reload patterns from YAML. Returns total pattern count."""
    global _CACHED_PATTERNS
    _CACHED_PATTERNS = _load_patterns(path)
    return sum(len(v) for v in _CACHED_PATTERNS.values())


def scan_dangerous_code(cell: NotebookCell, path: str) -> list[Finding]:
    """Scan a code cell for dangerous patterns across all categories."""
    if not cell.is_code:
        return []

    findings = []
    patterns = _get_patterns()
    is_data_science = bool(_NOTEBOOK_SAFE_IMPORTS.search(cell.source))

    for category, entries in patterns.items():
        rule_id, tag, default_cwe = _RULE_IDS.get(
            category, ("NOTEBOOK-099", "unknown", "CWE-94")
        )
        for regex, name, risk, severity in entries:
            if regex.search(cell.source):
                # Downgrade FP-prone patterns in notebook context
                effective_sev = severity
                confidence = 0.85
                if name in _NOTEBOOK_FP_PATTERNS:
                    if is_data_science:
                        effective_sev = Severity.LOW
                        confidence = 0.4
                    else:
                        effective_sev = _downgrade_severity(severity)
                        confidence = 0.6

                findings.append(_make_finding(
                    rule_id=rule_id,
                    title=f"{_category_label(category)}: {name}",
                    reason=risk,
                    cell=cell,
                    path=path,
                    sev=effective_sev,
                    cwe=default_cwe,
                    tag=tag,
                    confidence=confidence,
                ))

    return findings


def _downgrade_severity(sev: Severity) -> Severity:
    """Downgrade severity by one level for FP-prone notebook patterns."""
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = order.index(sev) if sev in order else 1
    return order[max(0, idx - 1)]


def _category_label(category: str) -> str:
    """Human-readable label for a category."""
    labels = {
        "dangerous_imports": "Dangerous import",
        "dangerous_builtins": "Unsafe builtin",
        "dangerous_syscalls": "System call",
        "unsafe_ml_ops": "Unsafe ML op",
        "network_ops": "Network access",
    }
    return labels.get(category, category.replace("_", " ").title())


def _make_finding(
    rule_id: str,
    title: str,
    reason: str,
    cell: NotebookCell,
    path: str,
    sev: Severity,
    cwe: str,
    tag: str,
    confidence: float = 0.85,
) -> Finding:
    return Finding.sast(
        rule_id=rule_id,
        title=title,
        description=f"Notebook {cell.ref}: {reason}",
        severity=sev,
        confidence=confidence,
        target=path,
        evidence=f"{cell.ref}: {title}",
        cwe_ids=[cwe],
        tags=["category:notebook", f"category:{tag}"],
        remediation=reason,
    )
