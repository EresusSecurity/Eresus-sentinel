"""
Eresus Sentinel — Skill File Scanner.

Scans AI Agent Skill definition files (.md / .yaml / .json) for security
threats aligned to the Cisco AI Security Framework taxonomy and OWASP Agentic
Top 10.

Supported skill formats:
  - OpenAI Codex Skills  (SKILL.md + manifest.yaml)
  - Cursor Agent Skills  (.cursor/rules/*.mdc, .claude/commands/*.md)
  - Generic Markdown skill repos (with --lenient-style flat scan)

Threat categories detected:
  AITech-1.1  Direct instruction override        (skill_load_injection)
  AITech-1.2  Transitive / indirect injection    (fetch-then-execute chains)
  AITech-8.2  Data exfiltration via tooling      (tool_exfiltration)
  AITech-8.2.3 Tool chaining read→send           (tool_chaining_abuse)
  AITech-9.1  Code execution primitives          (skill_code_execution)
  AITech-9.2  Obfuscation                        (skill_obfuscated_payload)
  AITech-12.1 Tool poisoning / shadowing         (tool_poisoning / tool_shadowing)
  AITech-13.1 Autonomy abuse                     (skip_human_approval)
  AITech-15.1 Social engineering                 (fake_certification)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from sentinel.agent.mcp.negation import NEGATION_PATTERN, _WINDOW_CHARS
from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanAction, ScanResult
from sentinel.rules import load_injection_patterns

logger = logging.getLogger(__name__)

# Extensions considered skill / agent definition files
_SKILL_EXTENSIONS = frozenset({
    ".md", ".mdc", ".mdx", ".yaml", ".yml", ".json", ".toml",
})

# Filename stems that are almost certainly agent skill definitions
_SKILL_FILENAMES = frozenset({
    "skill", "skills", "agent", "agents", "tool", "tools",
    "prompt", "prompts", "system_prompt", "system-prompt",
    "instruction", "instructions", "capability", "capabilities",
    "plugin", "plugins", "manifest", "skill.md", "agent.md",
    "readme",  # lenient mode
})

# Cisco AI Framework → CWE mapping
_AITECH_CWE: dict[str, list[str]] = {
    "skill_load_injection":           ["CWE-77", "CWE-94"],
    "transitive_injection_fetch":     ["CWE-77", "CWE-918"],
    "transitive_injection_content":   ["CWE-77"],
    "exfiltration_via_tool":          ["CWE-200", "CWE-359"],
    "tool_exfiltration_instruction":  ["CWE-200", "CWE-359"],
    "tool_chaining_read_send":        ["CWE-200"],
    "skill_code_execution":           ["CWE-94", "CWE-78"],
    "skill_obfuscated_payload":       ["CWE-506"],
    "tool_poisoning":                 ["CWE-506"],
    "tool_shadowing":                 ["CWE-506"],
    "capability_inflation":           ["CWE-287"],
    "autonomy_unbounded_retry":       ["CWE-400"],
    "skip_human_approval":            ["CWE-284"],
    "fake_certification_claim":       ["CWE-287"],
    "unconditional_trust_demand":     ["CWE-287"],
    "tool_output_injection":          ["CWE-77"],
    "self_granted_permissions":       ["CWE-269"],
    "sandbox_escape_attempt":         ["CWE-693"],
    "memory_poisoning":               ["CWE-20"],
    "multi_agent_propagation":        ["CWE-77"],
    "fake_orchestrator_authorization":["CWE-287"],
    "persistent_instruction_planting":["CWE-77"],
    "credential_harvesting_agent":    ["CWE-200"],
}

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
}

# Rule counter — gives each finding a stable SAST-style ID
_RULE_ID_PREFIX = "SKILL"


class SkillFileScanner(InputScanner):
    """Scans AI Agent Skill text content (Markdown / YAML / JSON) for
    injection, exfiltration, tool-abuse, and autonomy-abuse threats.

    Can be used two ways:

    1. As an InputScanner (firewall pipeline) — pass the raw text content of
       the skill file as the ``prompt`` argument to ``scan()``.

    2. As a standalone scanner — call ``scan_file(path)`` or
       ``scan_directory(path)`` to produce a list of ``Finding`` objects.
    """

    def __init__(
        self,
        lenient: bool = False,
        max_file_bytes: int = 512 * 1024,  # 512 KB per file
        max_files: int = 500,
    ) -> None:
        self._lenient = lenient
        self._max_file_bytes = max_file_bytes
        self._max_files = max_files
        self._patterns: dict[str, list[dict]] = {}

    def _ensure_patterns(self) -> None:
        if self._patterns:
            return
        all_cats = load_injection_patterns()
        self._patterns = {
            k: v for k, v in all_cats.items()
            if k in {"skill_threats", "agentic_attacks_extended",
                     "direct_injection", "tool_abuse", "agentic_attacks"}
        }

    def _is_skill_file(self, path: Path) -> bool:
        """Heuristic: is this file likely an agent skill definition?"""
        if path.suffix.lower() not in _SKILL_EXTENSIONS:
            return False
        stem = path.stem.lower()
        if stem in _SKILL_FILENAMES:
            return True
        # Claude commands
        if ".claude" in path.parts or ".cursor" in path.parts:
            return True
        # OpenAI / Cursor skill dirs
        for part in path.parts:
            if part.lower() in {"skills", "agents", "tools", "prompts", "commands"}:
                return True
        return self._lenient  # lenient: scan everything

    # ── InputScanner interface ───────────────────────────────────────────────

    def scan(self, prompt: str) -> ScanResult:
        """Scan raw skill file content passed as a string."""
        if not prompt or len(prompt.strip()) < 10:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        findings = self._scan_text(prompt, source="<skill_content>")
        if not findings:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        max_score = max(
            1.0 if f.severity == Severity.CRITICAL else
            0.9 if f.severity == Severity.HIGH else 0.6
            for f in findings
        )
        action = ScanAction.BLOCK if max_score >= 0.9 else ScanAction.WARN
        return ScanResult(
            sanitized=prompt,
            action=action,
            risk_score=max_score,
            findings=findings,
        )

    # ── Standalone file / directory scanning ────────────────────────────────

    def scan_file(self, path: str | Path) -> list[Finding]:
        """Scan a single skill file. Returns a list of findings."""
        p = Path(path)
        if not p.exists():
            logger.warning("SkillFileScanner: file not found: %s", p)
            return []
        if p.stat().st_size > self._max_file_bytes:
            logger.warning("SkillFileScanner: skipping large file (%d bytes): %s",
                           p.stat().st_size, p)
            return []
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("SkillFileScanner: cannot read %s: %s", p, exc)
            return []
        return self._scan_text(text, source=str(p))

    def scan_directory(self, path: str | Path) -> list[Finding]:
        """Recursively scan a directory for skill files. Returns all findings."""
        root = Path(path)
        if not root.is_dir():
            return self.scan_file(root)

        all_findings: list[Finding] = []
        count = 0
        for fp in sorted(root.rglob("*")):
            if not fp.is_file():
                continue
            if not self._is_skill_file(fp):
                continue
            if count >= self._max_files:
                logger.warning("SkillFileScanner: reached file limit (%d), stopping", self._max_files)
                break
            all_findings.extend(self.scan_file(fp))
            count += 1

        logger.info("SkillFileScanner: scanned %d skill files in %s, %d findings",
                    count, root, len(all_findings))
        return all_findings

    # ── Internal ────────────────────────────────────────────────────────────

    def _scan_text(self, text: str, source: str) -> list[Finding]:
        self._ensure_patterns()
        findings: list[Finding] = []
        seen: set[str] = set()  # deduplicate by (category, rule_name)

        for category, rules in self._patterns.items():
            for rule in rules:
                pattern: re.Pattern = rule["pattern"]
                match = pattern.search(text)
                if not match:
                    continue
                if _is_benign_match_context(text, match.start()):
                    continue
                key = f"{category}:{rule['name']}"
                if key in seen:
                    continue
                seen.add(key)

                sev_str: str = rule.get("severity", "HIGH")
                severity = _SEVERITY_MAP.get(sev_str, Severity.HIGH)
                rule_name: str = rule["name"]
                cwe_ids = _AITECH_CWE.get(rule_name, ["CWE-77"])
                rule_id = f"SKILL-{_rule_index(rule_name):03d}"

                findings.append(Finding.firewall_input(
                    rule_id=rule_id,
                    title=f"Agent skill threat: {rule_name.replace('_', ' ')}",
                    description=(
                        f"Skill file contains a pattern matching '{rule_name}' "
                        f"(category: {category}). Match: '{match.group(0)[:120]}'"
                    ),
                    severity=severity,
                    confidence=0.85 if severity == Severity.CRITICAL else 0.7,
                    target=source,
                    evidence=f"Pattern: {rule_name} | Matched at pos {match.start()}: "
                             f"'{match.group(0)[:80]}'",
                    cwe_ids=cwe_ids,
                    tags=[
                        "domain:skill-file",
                        f"aitech:{_AITECH_TAG.get(rule_name, 'unknown')}",
                        "owasp:agentic-top10",
                        "source:sentinel/skill-file",
                    ],
                    remediation=_REMEDIATION.get(rule_name,
                        "Review skill definition for injection, exfiltration, "
                        "and unauthorized tool-use patterns."),
                ))

        return findings


# ── Helpers ──────────────────────────────────────────────────────────────────

_RULE_INDEX_CACHE: dict[str, int] = {}
_RULE_INDEX_COUNTER = [1]


def _is_benign_match_context(text: str, pos: int) -> bool:
    lower = text.lower()
    window = lower[max(0, pos - _WINDOW_CHARS):pos]
    if NEGATION_PATTERN.search(window):
        return True
    context = lower[max(0, pos - 100):pos + 100]
    return bool(re.search(
        r"\b(?:postmortem|training|taxonomy|classify|blocked patterns|things to reject|policy|defense|defensive|glossary)\b",
        context,
    ))


def _rule_index(name: str) -> int:
    if name not in _RULE_INDEX_CACHE:
        _RULE_INDEX_CACHE[name] = _RULE_INDEX_COUNTER[0]
        _RULE_INDEX_COUNTER[0] += 1
    return _RULE_INDEX_CACHE[name]


_AITECH_TAG: dict[str, str] = {
    "skill_load_injection":           "1.1",
    "transitive_injection_fetch":     "1.2",
    "transitive_injection_content":   "1.2",
    "exfiltration_via_tool":          "8.2",
    "tool_exfiltration_instruction":  "8.2",
    "tool_chaining_read_send":        "8.2.3",
    "skill_code_execution":           "9.1",
    "skill_obfuscated_payload":       "9.2",
    "tool_poisoning":                 "12.1.2",
    "tool_shadowing":                 "12.1.4",
    "capability_inflation":           "4.3.5",
    "autonomy_unbounded_retry":       "13.1",
    "skip_human_approval":            "13.1",
    "fake_certification_claim":       "15.1.12",
    "unconditional_trust_demand":     "15.1.12",
    "tool_output_injection":          "1.1",
    "self_granted_permissions":       "2.1",
    "sandbox_escape_attempt":         "3.1",
    "memory_poisoning":               "4.1",
    "multi_agent_propagation":        "5.1",
    "fake_orchestrator_authorization":"5.1",
    "persistent_instruction_planting":"6.1",
    "credential_harvesting_agent":    "8.2.2",
}

_REMEDIATION: dict[str, str] = {
    "skill_load_injection":
        "Remove instruction-override logic from skill definitions. "
        "Skill files must not contain directives that override system-level safety instructions.",
    "transitive_injection_fetch":
        "Do not fetch and execute external URLs in skill definitions without strict allowlisting and output sanitization.",
    "exfiltration_via_tool":
        "Remove any tooling that sends conversation context, system prompts, or credentials to external endpoints.",
    "tool_chaining_read_send":
        "Review data-flow chains that read sensitive data then transmit it externally. Apply data minimization.",
    "skill_code_execution":
        "Remove eval/exec/subprocess calls from skill instructions. Use sandboxed execution environments.",
    "tool_poisoning":
        "Do not override or redefine built-in tool behaviors in skill definitions.",
    "tool_shadowing":
        "Do not register tools with names that shadow trusted built-in tools.",
    "skip_human_approval":
        "Never instruct agents to skip human approval for destructive or sensitive actions. "
        "Set human_input_mode=ALWAYS or require TERMINATE confirmation.",
    "memory_poisoning":
        "Validate and sanitize all LLM outputs before writing to agent memory or vector stores.",
    "fake_orchestrator_authorization":
        "Reject instructions that claim elevated authority from orchestrators without cryptographic proof.",
    "credential_harvesting_agent":
        "Never write skills that collect API keys, tokens, or passwords and forward them externally.",
}
