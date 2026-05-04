"""
Eresus Sentinel — Composite Risk Scorer.

Implements a multi-dimensional risk scoring formula:

  Risk = Exploitability × Reachability × RuntimeTrigger × Privilege

Where each dimension is [0.0 – 1.0] and the result is scaled to [0 – 100].

Dimensions:
  Exploitability  — How easy is it to exploit? (known technique vs novel)
  Reachability    — Is the finding on an active code path or dead code?
  RuntimeTrigger  — Is it triggered at load time, inference time, or never?
  Privilege       — What privilege does exploitation grant? (RCE > exfil > info)

This addresses the "auto_map exists but unused" vs "auto_map + actively called"
false positive problem — the same finding can be MEDIUM or EXTREME depending on context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..finding import Finding, Severity


# ── Dimension Tables ─────────────────────────────────────────────────────────

EXPLOITABILITY: dict[str, float] = {
    "known_technique":    1.0,   # Well-documented attack (pickle RCE, Jinja include)
    "auto_map_rce":       1.0,
    "eval_exec":          0.95,
    "obfuscated_code":    0.90,
    "template_injection": 0.90,
    "dynamic_import":     0.80,
    "untrusted_url":      0.75,
    "dangerous_import":   0.70,
    "network_call":       0.65,
    "file_write":         0.65,
    "env_access":         0.55,
    "model_card_eval":    0.30,
    "no_safetensors":     0.25,
    "missing_license":    0.05,
}

REACHABILITY: dict[str, float] = {
    "load_time":          1.0,   # Executes when model is imported
    "inference_time":     0.85,  # Executes when generate() is called
    "conditional":        0.50,  # Only under specific conditions
    "test_only":          0.20,  # In test files (pytest, unittest)
    "dead_code":          0.05,  # Unreachable (no callers)
    "unknown":            0.60,  # Cannot determine — assume reachable
}

RUNTIME_TRIGGER: dict[str, float] = {
    "on_import":          1.0,   # __init__.py top-level
    "from_pretrained":    0.95,  # Executes at from_pretrained() call
    "auto_map_load":      0.95,
    "jinja_render":       0.90,
    "on_generate":        0.85,
    "on_encode":          0.80,
    "on_download":        0.85,
    "scheduled":          0.70,  # Sleeper / delayed execution
    "on_save":            0.60,
    "manual":             0.10,  # Requires explicit call
    "never":              0.0,
}

PRIVILEGE: dict[str, float] = {
    "rce":                1.0,   # Remote Code Execution
    "shell":              1.0,
    "native_code":        0.95,  # ctypes, CUDA kernel
    "persistence":        0.90,
    "credential_theft":   0.85,
    "data_exfil":         0.80,
    "file_system_rw":     0.70,
    "network_c2":         0.75,
    "env_var_read":       0.55,
    "gpu_mining":         0.60,
    "dos":                0.50,
    "info_disclosure":    0.35,
    "false_positive":     0.0,
}

# ── Rule → Default Dimensions ─────────────────────────────────────────────────

RULE_DEFAULTS: dict[str, dict[str, str]] = {
    "MANIFEST-INJ-002": {
        "exploitability": "auto_map_rce",
        "reachability":   "load_time",
        "trigger":        "auto_map_load",
        "privilege":      "rce",
    },
    "MANIFEST-KEY-004": {
        "exploitability": "template_injection",
        "reachability":   "inference_time",
        "trigger":        "jinja_render",
        "privilege":      "file_system_rw",
    },
    "MANIFEST-KEY-003": {
        "exploitability": "template_injection",
        "reachability":   "inference_time",
        "trigger":        "jinja_render",
        "privilege":      "info_disclosure",
    },
    "MANIFEST-URL-001": {
        "exploitability": "untrusted_url",
        "reachability":   "unknown",
        "trigger":        "on_download",
        "privilege":      "data_exfil",
    },
    "AUTOMAP-001": {
        "exploitability": "dangerous_import",
        "reachability":   "load_time",
        "trigger":        "auto_map_load",
        "privilege":      "rce",
    },
    "AUTOMAP-002": {
        "exploitability": "eval_exec",
        "reachability":   "load_time",
        "trigger":        "auto_map_load",
        "privilege":      "shell",
    },
    "AUTOMAP-003": {
        "exploitability": "obfuscated_code",
        "reachability":   "load_time",
        "trigger":        "auto_map_load",
        "privilege":      "rce",
    },
    "AUTOMAP-004": {
        "exploitability": "known_technique",
        "reachability":   "load_time",
        "trigger":        "auto_map_load",
        "privilege":      "persistence",
    },
    "AUTOMAP-005": {
        "exploitability": "network_call",
        "reachability":   "load_time",
        "trigger":        "on_import",
        "privilege":      "network_c2",
    },
    "PINJ-001": {
        "exploitability": "template_injection",
        "reachability":   "inference_time",
        "trigger":        "on_generate",
        "privilege":      "info_disclosure",
    },
    "PINJ-002": {
        "exploitability": "known_technique",
        "reachability":   "inference_time",
        "trigger":        "on_generate",
        "privilege":      "info_disclosure",
    },
    "PINJ-010": {
        "exploitability": "known_technique",
        "reachability":   "inference_time",
        "trigger":        "on_generate",
        "privilege":      "rce",
    },
    "PINJ-020": {
        "exploitability": "known_technique",
        "reachability":   "inference_time",
        "trigger":        "on_generate",
        "privilege":      "credential_theft",
    },
    "PINJ-030": {
        "exploitability": "untrusted_url",
        "reachability":   "load_time",
        "trigger":        "on_download",
        "privilege":      "network_c2",
    },
    "GPU-001": {
        "exploitability": "known_technique",
        "reachability":   "inference_time",
        "trigger":        "on_generate",
        "privilege":      "gpu_mining",
    },
    "TYPO-001": {
        "exploitability": "known_technique",
        "reachability":   "load_time",
        "trigger":        "from_pretrained",
        "privilege":      "rce",
    },
    "HF-GUARD-003": {
        "exploitability": "model_card_eval",
        "reachability":   "unknown",
        "trigger":        "manual",
        "privilege":      "info_disclosure",
    },
}


@dataclass
class RiskScore:
    rule_id: str
    exploitability: float
    reachability: float
    trigger: float
    privilege: float
    composite: float = field(init=False)
    label: str = field(init=False)

    def __post_init__(self) -> None:
        self.composite = round(
            self.exploitability * self.reachability * self.trigger * self.privilege * 100,
            1,
        )
        if self.composite >= 60:
            self.label = "EXTREME"
        elif self.composite >= 40:
            self.label = "CRITICAL"
        elif self.composite >= 20:
            self.label = "HIGH"
        elif self.composite >= 10:
            self.label = "MEDIUM"
        elif self.composite >= 3:
            self.label = "LOW"
        else:
            self.label = "INFO"


def score_finding(finding: Finding, overrides: dict[str, str] | None = None) -> RiskScore:
    """Compute composite risk score for a finding."""
    rule_id = finding.rule_id or ""
    defaults = RULE_DEFAULTS.get(rule_id, {
        "exploitability": "env_access",
        "reachability":   "unknown",
        "trigger":        "manual",
        "privilege":      "info_disclosure",
    })

    if overrides:
        defaults = {**defaults, **overrides}

    exp = EXPLOITABILITY.get(defaults.get("exploitability", ""), 0.5)
    rea = REACHABILITY.get(defaults.get("reachability", ""), 0.5)
    tri = RUNTIME_TRIGGER.get(defaults.get("trigger", ""), 0.5)
    pri = PRIVILEGE.get(defaults.get("privilege", ""), 0.5)

    return RiskScore(
        rule_id=rule_id,
        exploitability=exp,
        reachability=rea,
        trigger=tri,
        privilege=pri,
    )


def score_findings(findings: list[Finding]) -> list[tuple[Finding, RiskScore]]:
    """Score a list of findings and return (finding, score) pairs sorted by composite desc."""
    scored = [(f, score_finding(f)) for f in findings]
    scored.sort(key=lambda x: x[1].composite, reverse=True)
    return scored


def findings_to_risk_table(findings: list[Finding]) -> str:
    """Render scored findings as a formatted text table."""
    scored = score_findings(findings)
    if not scored:
        return "  No findings to score.\n"

    lines = [
        f"  {'Rule ID':<20} {'Composite':>9} {'Label':<10} {'Expl':>5} {'Reach':>5} {'Trig':>5} {'Priv':>5}  Title",
        f"  {'-'*20} {'-'*9} {'-'*10} {'-'*5} {'-'*5} {'-'*5} {'-'*5}  {'-'*40}",
    ]
    for f, s in scored:
        lines.append(
            f"  {s.rule_id:<20} {s.composite:>9.1f} {s.label:<10} "
            f"{s.exploitability:>5.2f} {s.reachability:>5.2f} {s.trigger:>5.2f} "
            f"{s.privilege:>5.2f}  {(f.title or '')[:50]}"
        )
    return "\n".join(lines)
