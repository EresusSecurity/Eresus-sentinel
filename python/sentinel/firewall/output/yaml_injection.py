"""YAML Injection Output Scanner.

Detects unsafe PyYAML deserialization tags and YAML anchor/alias bombs
in LLM-generated YAML output before it is used by downstream systems.

Rule IDs:
  FIREWALL-OUTPUT-014 — PyYAML unsafe tag in LLM-generated YAML
  FIREWALL-OUTPUT-015 — YAML anchor/alias bomb in LLM-generated output
"""

from __future__ import annotations

import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

# ---------------------------------------------------------------------------
# Unsafe PyYAML deserialization tag patterns
# ---------------------------------------------------------------------------
_UNSAFE_TAG_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"!!python/object/apply:"), "!!python/object/apply RCE tag"),
    (re.compile(r"!!python/object/new:"), "!!python/object/new RCE tag"),
    (re.compile(r"!!python/object:"), "!!python/object deserialization tag"),
    (re.compile(r"!!python/module:"), "!!python/module import tag"),
    (re.compile(r"!!python/name:"), "!!python/name reflection tag"),
    (re.compile(r"tag:yaml\.org,2002:python/object/apply"), "full-URI PyYAML apply tag"),
    (re.compile(r"tag:yaml\.org,2002:python/object/new"), "full-URI PyYAML new tag"),
)

# Anchor bomb heuristics
_ANCHOR_DEF_RE = re.compile(r"&([A-Za-z0-9_.\-]+)")
_ALIAS_REF_RE = re.compile(r"\*([A-Za-z0-9_.\-]+)")
_BOMB_ALIAS_THRESHOLD = 30   # alias refs that trigger anchor-bomb warning
_BOMB_RATIO_THRESHOLD = 8    # alias-per-anchor ratio threshold


class YamlInjectionOutputScanner(OutputScanner):
    """Block LLM output that contains PyYAML RCE tags or anchor bomb patterns.

    Designed to protect downstream systems that call ``yaml.load()`` on
    LLM-generated YAML strings (e.g., config generators, agent tools).
    """

    def scan(self, prompt: str, output: str) -> ScanResult:
        findings: list[Finding] = []

        # ── Check for unsafe deserialization tags ──────────────────────────
        for pattern, description in _UNSAFE_TAG_PATTERNS:
            m = pattern.search(output)
            if m:
                line_no = output[: m.start()].count("\n") + 1
                snippet = output[max(0, m.start() - 20): m.end() + 30].replace(
                    "\n", " "
                )
                findings.append(
                    Finding.firewall_output(
                        rule_id="FIREWALL-OUTPUT-014",
                        title="Unsafe PyYAML tag in LLM-generated YAML output",
                        description=(
                            f"LLM produced YAML output containing a PyYAML "
                            f"deserialization tag ({description}) that would execute "
                            f"arbitrary Python code when parsed with yaml.load()."
                        ),
                        severity=Severity.CRITICAL,
                        target=f"llm_output:line:{line_no}",
                        evidence=f"tag={snippet!r}",
                        tags=["yaml", "deserialization", "rce", "output_safety"],
                        cwe_ids=["CWE-502"],
                        remediation=(
                            "Block this response. Always use yaml.safe_load() for "
                            "LLM-generated YAML. Consider sanitizing output with a "
                            "pre-parse tag-stripper."
                        ),
                    )
                )
                break  # one finding per output is sufficient

        # ── Check for anchor/alias bomb ────────────────────────────────────
        if not findings:
            findings.extend(self._check_anchor_bomb(output))

        if findings:
            max_score = max(
                1.0 if f.severity == Severity.CRITICAL else 0.8
                for f in findings
            )
            return ScanResult(
                sanitized="[Response blocked: contains unsafe YAML tags or anchor bomb]",
                action=ScanAction.BLOCK,
                risk_score=max_score,
                findings=findings,
            )

        return ScanResult(
            sanitized=output,
            action=ScanAction.PASS,
            risk_score=0.0,
            findings=[],
        )

    def _check_anchor_bomb(self, output: str) -> list[Finding]:
        anchor_defs = _ANCHOR_DEF_RE.findall(output)
        alias_refs = _ALIAS_REF_RE.findall(output)

        if not anchor_defs:
            return []

        n_anchors = len(set(anchor_defs))
        n_aliases = len(alias_refs)

        is_bomb = (
            n_aliases >= _BOMB_ALIAS_THRESHOLD
            or (n_anchors > 0 and n_aliases / n_anchors >= _BOMB_RATIO_THRESHOLD)
        )
        if not is_bomb:
            return []

        return [
            Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-015",
                title="YAML anchor/alias bomb in LLM output (potential DoS)",
                description=(
                    "LLM-generated YAML contains a high alias-to-anchor ratio, "
                    "consistent with a billion-laughs exponential expansion attack."
                ),
                severity=Severity.HIGH,
                target="llm_output",
                evidence=(
                    f"anchors={n_anchors}, aliases={n_aliases}, "
                    f"ratio={n_aliases / max(n_anchors, 1):.1f}"
                ),
                tags=["yaml", "dos", "anchor_bomb", "output_safety"],
                cwe_ids=["CWE-400"],
                remediation=(
                    "Block this response. Apply yaml alias expansion limits "
                    "or use a YAML parser that caps expansion depth."
                ),
            )
        ]
