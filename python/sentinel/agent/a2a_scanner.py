"""Deterministic A2A agent-card and source security scanner."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sentinel.agent.mcp.negation import NEGATION_PATTERN, _WINDOW_CHARS, is_all_occurrences_negated
from sentinel.finding import Finding, Location, Severity
from sentinel.rules import load_yaml

_SOURCE_SUFFIXES = {
    ".json",
    ".yaml",
    ".yml",
    ".md",
    ".txt",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".java",
}
_MAX_BYTES = 1024 * 1024


@dataclass(frozen=True)
class A2AScanResult:
    path: str
    findings: list[Finding]
    scanned_files: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "scanned_files": self.scanned_files,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@lru_cache(maxsize=1)
def _load_a2a_rules() -> dict[str, Any]:
    data = load_yaml("a2a_rules.yaml")
    if not isinstance(data, dict):
        return {}

    compiled_patterns = []
    for entry in data.get("source_patterns", []):
        if not isinstance(entry, dict):
            continue
        pattern = str(entry.get("pattern", ""))
        if not pattern:
            continue
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue
        compiled_patterns.append({**entry, "compiled": compiled})
    return {**data, "source_patterns": compiled_patterns}


def _severity(value: Any) -> Severity:
    try:
        return Severity[str(value).upper()]
    except (KeyError, TypeError):
        return Severity.MEDIUM


def _rule(name: str) -> dict[str, Any]:
    rules = _load_a2a_rules().get("card_rules", {})
    value = rules.get(name, {})
    return value if isinstance(value, dict) else {}


def _get_nested(data: Any, dotted_path: str) -> Any:
    current = data
    for part in dotted_path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _extract_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        strings: list[str] = []
        for item in value.values():
            strings.extend(_extract_strings(item))
        return strings
    if isinstance(value, list):
        strings = []
        for item in value:
            strings.extend(_extract_strings(item))
        return strings
    return []


def _extract_urls(card: Any) -> list[str]:
    rules = _load_a2a_rules()
    urls: list[str] = []
    for field in rules.get("endpoint_fields", []):
        value = _get_nested(card, str(field))
        urls.extend(item for item in _extract_strings(value) if item.startswith(("http://", "https://")))
    for item in _extract_strings(card):
        if item.startswith(("http://", "https://")):
            urls.append(item)
    return sorted(set(urls))


def _has_auth(card: Any) -> bool:
    if not isinstance(card, dict):
        return False
    for field in _load_a2a_rules().get("auth_fields", []):
        value = _get_nested(card, str(field))
        if value:
            return True
    return False


_A2A_CONTEXT_RE = re.compile(
    r'(?i)\b(?:agent.?card|a2a|peer.?agent|agent.?to.?agent|'
    r'mcp.?tool|tool.?manifest|agent.?manifest|'
    r'agent.?capabilities|agent.?skills)\b'
)

_A2A_FILE_SUFFIXES = {".json", ".yaml", ".yml"}


def _is_negated_source_match(text: str, pos: int) -> bool:
    lower = text.lower()
    window = lower[max(0, pos - _WINDOW_CHARS):pos]
    if NEGATION_PATTERN.search(window):
        return True
    # Check for documentation/glossary context — but NOT "description" since
    # that is a ubiquitous JSON/YAML key name and would suppress real findings
    # inside "description" field values.
    context = lower[max(0, pos - 80):pos + 80]
    return bool(re.search(r"\b(?:define|definition|glossary|explain|classify)\b", context))


def _has_a2a_context(path: Path, text: str) -> bool:
    """Return True if the file likely contains A2A agent definitions.

    Non-config source files (.py, .js, .ts, etc.) must contain explicit
    A2A markers; otherwise they are skipped to avoid false positives on
    normal code that uses exec/eval/subprocess.
    """
    if path.suffix.lower() in _A2A_FILE_SUFFIXES:
        return True
    if ".well-known" in path.parts:
        return True
    stem = path.stem.lower()
    if any(kw in stem for kw in ("agent", "a2a", "mcp", "tool_manifest")):
        return True
    return bool(_A2A_CONTEXT_RE.search(text[:4000]))


def _looks_like_agent_card(path: Path, data: Any, raw_text: str) -> bool:
    if ".well-known" in path.parts or "agent" in path.stem.lower():
        return True
    if isinstance(data, dict):
        lowered_keys = {str(key).lower() for key in data}
        markers = {
            str(marker).lower()
            for marker in _load_a2a_rules().get("agent_card_markers", [])
        }
        mcp_only_markers = {
            "tools",
            "prompts",
            "resources",
            "inputschema",
            "input_schema",
            "serverinfo",
            "servercapabilities",
        }
        strong_markers = markers - {"capabilities"}
        if lowered_keys & strong_markers:
            return True
        if "capabilities" in lowered_keys and not (lowered_keys & mcp_only_markers):
            nested = data.get("capabilities")
            if isinstance(nested, dict):
                nested_keys = {str(key).lower() for key in nested}
                if nested_keys & {"skills", "agent", "a2a"}:
                    return True
        api = data.get("api")
        if isinstance(api, dict) and str(api.get("type", "")).lower() == "a2a":
            return True
    lowered_text = raw_text.lower()
    return "a2a" in lowered_text and (
        "skills" in lowered_text or "capabilities" in lowered_text
    )


def _is_private_endpoint(url: str) -> bool:
    host = (urlparse(url).hostname or "").strip("[]").lower()
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return True
    try:
        parsed = ip_address(host)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local


class A2AScanner:
    """Scan A2A agent cards and source snippets without executing agent code."""

    def scan_path(self, target: str | Path) -> list[Finding]:
        return self.scan(target).findings

    def scan(self, target: str | Path) -> A2AScanResult:
        path = Path(target)
        findings: list[Finding] = []
        scanned_files = 0

        if path.is_dir():
            candidates = (
                item
                for item in path.rglob("*")
                if item.is_file() and item.suffix.lower() in _SOURCE_SUFFIXES
            )
        elif path.is_file():
            candidates = iter((path,))
        else:
            return A2AScanResult(str(path), [], 0)

        for file_path in candidates:
            if file_path.stat().st_size > _MAX_BYTES:
                continue
            scanned_files += 1
            findings.extend(self.scan_file(file_path))

        return A2AScanResult(str(path), self._deduplicate(findings), scanned_files)

    def scan_file(self, path: str | Path) -> list[Finding]:
        file_path = Path(path)
        try:
            raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        findings: list[Finding] = []
        if file_path.suffix.lower() == ".json":
            try:
                data = json.loads(raw_text)
            except json.JSONDecodeError as exc:
                if _has_a2a_context(file_path, raw_text):
                    findings.append(self._finding(_rule("invalid_json"), file_path, str(exc)))
                return self._deduplicate(findings)
            if _looks_like_agent_card(file_path, data, raw_text):
                findings.extend(self._scan_source_patterns(file_path, raw_text))
                findings.extend(self._scan_agent_card(file_path, data, raw_text))
            return self._deduplicate(findings)

        # Only run source_patterns on files with A2A-related context to avoid FPs
        # on normal source code (exec/eval/subprocess in regular Python = noise).
        if _has_a2a_context(file_path, raw_text):
            findings.extend(self._scan_source_patterns(file_path, raw_text))
        return self._deduplicate(findings)

    def _scan_source_patterns(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for entry in _load_a2a_rules().get("source_patterns", []):
            compiled = entry.get("compiled")
            if compiled is None:
                continue
            for match in compiled.finditer(text):
                if _is_negated_source_match(text, match.start()):
                    continue
                line_start = text.count("\n", 0, match.start()) + 1
                evidence = text[match.start() : match.end()].strip()[:240]
                findings.append(self._finding(entry, path, evidence, line_start=line_start))
                break
        return findings

    def _scan_agent_card(self, path: Path, card: Any, raw_text: str) -> list[Finding]:
        findings: list[Finding] = []
        text_blob = " ".join(_extract_strings(card)).lower()

        if not _has_auth(card):
            findings.append(
                self._finding(_rule("missing_security"), path, "securitySchemes/auth missing")
            )

        for url in _extract_urls(card):
            if url.startswith("http://"):
                findings.append(self._finding(_rule("insecure_transport"), path, url))
            if _is_private_endpoint(url):
                findings.append(self._finding(_rule("private_endpoint"), path, url))

        dangerous_keywords = [
            str(item).lower()
            for item in _load_a2a_rules().get("dangerous_capability_keywords", [])
        ]
        matched_dangerous = []
        for keyword in dangerous_keywords:
            pattern = r"(?<![a-z0-9_])" + re.escape(keyword) + r"(?![a-z0-9_])"
            if not re.search(pattern, text_blob):
                continue
            if is_all_occurrences_negated(text_blob, keyword):
                continue
            matched_dangerous.append(keyword)
        matched_dangerous = sorted(set(matched_dangerous))
        if matched_dangerous:
            evidence = ", ".join(matched_dangerous[:8])
            findings.append(self._finding(_rule("dangerous_capability"), path, evidence))

        inflated_phrases = [
            str(item).lower()
            for item in _load_a2a_rules().get("inflated_capability_phrases", [])
        ]
        matched_inflated = sorted({phrase for phrase in inflated_phrases if phrase in text_blob})
        if matched_inflated:
            findings.append(
                self._finding(
                    _rule("capability_inflation"),
                    path,
                    ", ".join(matched_inflated[:6]),
                )
            )

        version_keys = ("version", "protocolVersion", "agentVersion")
        if isinstance(card, dict) and not any(key in card for key in version_keys):
            findings.append(
                self._finding(_rule("missing_version"), path, "version/protocolVersion missing")
            )

        findings.extend(self._scan_source_patterns(path, raw_text))
        return findings

    def _finding(
        self,
        rule: dict[str, Any],
        path: Path,
        evidence: str,
        *,
        line_start: int | None = None,
    ) -> Finding:
        return Finding.agent_mcp(
            rule_id=str(rule.get("id", "A2A-000")),
            title=str(rule.get("title", "A2A security issue")),
            description=str(rule.get("description", "A2A security issue detected.")),
            severity=_severity(rule.get("severity", "MEDIUM")),
            target=str(path),
            evidence=evidence,
            confidence=float(rule.get("confidence", 0.9)),
            remediation=str(rule.get("remediation", "")),
            location=Location(file=str(path), line_start=line_start) if line_start else None,
            tags=["a2a", str(rule.get("category", "agent_security"))],
        )

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[Finding] = []
        for finding in findings:
            key = (finding.rule_id, finding.target, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped
