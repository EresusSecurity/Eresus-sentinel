"""
Eresus Sentinel — Diff Security Scanner Engine.

Main scanning engine that combines the diff parser with ML-specific
anti-pattern rules to detect security regressions in code changes.

Supports:
- Scanning raw diff text (from git diff, patches, stdin)
- Scanning git working tree (staged, unstaged)
- Scanning specific commits
- File-type-aware pattern matching
- Finding generation with exact line locations

Usage:
    from sentinel.diff_scanner import DiffScanner

    scanner = DiffScanner()
    findings = scanner.scan_diff(diff_text)
    findings = scanner.scan_git_staged()
    findings = scanner.scan_commit("abc123")
"""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Optional

from sentinel.diff_scanner.diff_parser import (
    DiffLine,
    FileDiff,
    parse_unified_diff,
)
from sentinel.diff_scanner.ml_patterns import (
    ALL_PATTERNS,
    MLPattern,
)
from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _load_yaml_patterns() -> list[MLPattern]:
    """Load supplementary patterns from rules/diff_patterns.yaml."""
    try:
        import yaml

        from sentinel.rules import get_rules_dir
    except ImportError:
        return []

    yaml_path = get_rules_dir() / "diff_patterns.yaml"
    if not yaml_path.exists():
        return []

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        logger.warning("Failed to load diff_patterns.yaml: %s", exc)
        return []

    if not isinstance(data, dict):
        return []

    existing_ids = {p.id for p in ALL_PATTERNS}
    extra: list[MLPattern] = []

    for _category, entries in data.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            pid = entry.get("id", "")
            if pid in existing_ids:
                continue
            try:
                extra.append(MLPattern(
                    id=pid,
                    name=entry.get("name", "unknown"),
                    pattern=re.compile(entry["pattern"]),
                    severity=entry.get("severity", "MEDIUM"),
                    description=entry.get("description", ""),
                    cwe_ids=[entry.get("cwe", "CWE-20")],
                    owasp_llm=entry.get("owasp", "LLM05"),
                    remediation=entry.get("remediation", ""),
                    file_filter=entry.get("file_filter"),
                    added_only=entry.get("added_only", True),
                ))
            except (KeyError, re.error) as exc:
                logger.warning("Skipping invalid diff pattern %s: %s", pid, exc)

    if extra:
        logger.debug("Loaded %d supplementary diff patterns from YAML", len(extra))
    return extra


class DiffScanner:
    """
    ML security diff scanner.

    Scans code diffs for ML-specific security anti-patterns
    and generates structured findings.

    Config via sentinel.toml:
        [scanners.diff]
        enabled = true
        scan_removed = false  # Also flag patterns in removed lines
    """

    def __init__(
        self,
        patterns: Optional[list[MLPattern]] = None,
        scan_removed: bool = False,
        git_dir: Optional[str] = None,
    ):
        """
        Args:
            patterns: Custom patterns to use. Defaults to ALL_PATTERNS.
            scan_removed: Also scan removed lines (default: added only).
            git_dir: Git repository path for git operations.
        """
        self._patterns = patterns or (ALL_PATTERNS + _load_yaml_patterns())
        self._scan_removed = scan_removed
        self._git_dir = git_dir

    def scan_diff(self, diff_text: str) -> list[Finding]:
        """
        Scan raw diff text for ML security anti-patterns.

        Args:
            diff_text: Unified diff format string.

        Returns:
            List of security findings.
        """
        if not diff_text.strip():
            return []

        file_diffs = parse_unified_diff(diff_text)
        return self._scan_file_diffs(file_diffs)

    def scan_pr_patch(
        self,
        diff_text: str,
        base_ref: str = "",
        head_ref: str = "",
        pr_number: str = "",
    ) -> list[Finding]:
        """Scan a pull-request patch and tag findings with PR context."""
        findings = self.scan_diff(diff_text)
        context_tags = ["mode:pr"]
        if base_ref:
            context_tags.append(f"base:{base_ref}")
        if head_ref:
            context_tags.append(f"head:{head_ref}")
        if pr_number:
            context_tags.append(f"pr:{pr_number}")

        for finding in findings:
            for tag in context_tags:
                if tag not in finding.tags:
                    finding.tags.append(tag)
        return findings

    def scan_git_staged(self) -> list[Finding]:
        """Scan git staged changes (git diff --cached)."""
        diff_text = self._run_git("diff", "--cached")
        if not diff_text:
            logger.info("No staged changes to scan.")
            return []
        return self.scan_diff(diff_text)

    def scan_git_unstaged(self) -> list[Finding]:
        """Scan git unstaged changes (git diff)."""
        diff_text = self._run_git("diff")
        if not diff_text:
            logger.info("No unstaged changes to scan.")
            return []
        return self.scan_diff(diff_text)

    def scan_git_all(self) -> list[Finding]:
        """Scan all changes (staged + unstaged)."""
        diff_text = self._run_git("diff", "HEAD")
        if not diff_text:
            return []
        return self.scan_diff(diff_text)

    def scan_commit(self, commit_sha: str) -> list[Finding]:
        """Scan a specific commit."""
        diff_text = self._run_git("diff", f"{commit_sha}^", commit_sha)
        if not diff_text:
            logger.info("No changes in commit %s.", commit_sha)
            return []
        return self.scan_diff(diff_text)

    def scan_commit_range(self, from_sha: str, to_sha: str) -> list[Finding]:
        """Scan a range of commits."""
        diff_text = self._run_git("diff", from_sha, to_sha)
        if not diff_text:
            return []
        return self.scan_diff(diff_text)

    def scan_file(self, diff_file: str) -> list[Finding]:
        """Scan a .patch or .diff file."""
        with open(diff_file, "r", encoding="utf-8", errors="replace") as f:
            diff_text = f.read()
        return self.scan_diff(diff_text)

    # ─── Internal ─────────────────────────────────────────────

    def _scan_file_diffs(self, file_diffs: list[FileDiff]) -> list[Finding]:
        """Scan parsed file diffs against patterns."""
        findings: list[Finding] = []

        for file_diff in file_diffs:
            if file_diff.is_binary:
                continue

            for pattern in self._patterns:
                # Check file filter
                if pattern.file_filter:
                    if not re.search(pattern.file_filter, file_diff.path):
                        continue

                # Scan added lines
                for line in file_diff.all_added_lines:
                    match = pattern.pattern.search(line.content)
                    if match:
                        finding = self._create_finding(
                            pattern, file_diff, line, match, is_added=True
                        )
                        findings.append(finding)

                # Optionally scan removed lines
                if self._scan_removed and not pattern.added_only:
                    for line in file_diff.all_removed_lines:
                        match = pattern.pattern.search(line.content)
                        if match:
                            finding = self._create_finding(
                                pattern, file_diff, line, match, is_added=False
                            )
                            findings.append(finding)

        return findings

    def _create_finding(
        self,
        pattern: MLPattern,
        file_diff: FileDiff,
        line: DiffLine,
        match: re.Match,
        is_added: bool,
    ) -> Finding:
        """Create a Finding from a pattern match."""
        severity = SEVERITY_MAP.get(pattern.severity, Severity.MEDIUM)
        change_type = "added" if is_added else "removed"

        return Finding.sast(
            rule_id=pattern.id,
            title=f"ML anti-pattern: {pattern.name} ({change_type})",
            description=pattern.description,
            severity=severity,
            target=f"{file_diff.path}:{line.line_number}",
            evidence=(
                f"Line {line.line_number}: {line.content.strip()[:200]}\n"
                f"Match: {match.group(0)}"
            ),
            cwe_ids=pattern.cwe_ids,
            tags=[
                f"owasp:{pattern.owasp_llm.lower()}",
                "scanner:diff",
                f"change:{change_type}",
            ],
            remediation=pattern.remediation,
        )

    def _run_git(self, *args: str) -> str:
        """Run a git command and return its stdout."""
        cmd = ["git"]
        if self._git_dir:
            cmd.extend(["-C", self._git_dir])
        cmd.extend(args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.warning(
                    "git command failed: %s\nstderr: %s",
                    " ".join(cmd), result.stderr.strip()
                )
                return ""
            return result.stdout
        except FileNotFoundError:
            logger.error("git not found in PATH.")
            return ""
        except subprocess.TimeoutExpired:
            logger.error("git command timed out after 30s.")
            return ""
        except Exception as exc:
            logger.error("git command error: %s", exc)
            return ""

    def generate_report(self, findings: list[Finding]) -> dict:
        """Generate a structured report from scan findings."""
        by_severity = {}
        by_pattern = {}
        affected_files = set()

        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_pattern[f.rule_id] = by_pattern.get(f.rule_id, 0) + 1
            if f.target:
                affected_files.add(f.target.split(":")[0])

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_pattern": by_pattern,
            "affected_files": sorted(affected_files),
            "has_critical": by_severity.get("CRITICAL", 0) > 0,
            "has_high": by_severity.get("HIGH", 0) > 0,
            "gate_pass": by_severity.get("CRITICAL", 0) == 0,
        }
