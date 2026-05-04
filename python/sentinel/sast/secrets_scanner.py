"""
Eresus Sentinel — Enterprise Secrets Scanner.

Dedicated scanner for detecting hardcoded secrets, API keys, tokens,
and credentials in source code. All patterns loaded from YAML.

Features:
  - 120+ provider-specific regex patterns (YAML-driven)
  - Shannon entropy detection for unknown secret formats
  - Git history scanning (committed & deleted secrets)
  - YAML/env/config file deep scan
  - Incremental scanning with file hash cache
  - False positive reduction via ignore patterns
  - Evidence redaction for safe reporting
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Location, Severity
from sentinel.rules import get_rules_dir

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_RULES_DIR = get_rules_dir()
_DEFAULT_YAML = _RULES_DIR / "sast_secret_patterns.yaml"

# Cache
_pattern_cache: Optional[list] = None
_entropy_config: Optional[dict] = None
_cache_mtime: float = 0.0


@dataclass
class SecretPattern:
    """A secret detection pattern."""
    id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    description: str


@dataclass
class EntropyConfig:
    """Entropy detection configuration."""
    enabled: bool = True
    min_length: int = 16
    hex_threshold: float = 3.5
    base64_threshold: float = 4.2
    generic_threshold: float = 4.5
    ignore_patterns: list[re.Pattern] = field(default_factory=list)


def _load_yaml_data(path: Optional[Path] = None) -> dict:
    """Load raw YAML data."""
    yaml_path = path or _DEFAULT_YAML
    if not yaml_path.exists():
        logger.warning("Secret patterns YAML not found: %s", yaml_path)
        return {}
    try:
        import yaml
    except ImportError:
        logger.error("PyYAML required for loading secret patterns")
        return {}
    with open(yaml_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _load_patterns(path: Optional[Path] = None) -> list[SecretPattern]:
    """Load secret patterns from YAML."""
    global _pattern_cache, _cache_mtime

    yaml_path = path or _DEFAULT_YAML
    if not yaml_path.exists():
        return []

    mtime = yaml_path.stat().st_mtime
    if _pattern_cache is not None and mtime == _cache_mtime:
        return _pattern_cache

    data = _load_yaml_data(yaml_path)

    patterns = []
    for _category, entries in data.get("patterns", {}).items():
        for entry in entries:
            try:
                patterns.append(SecretPattern(
                    id=entry["id"],
                    name=entry["name"],
                    pattern=re.compile(entry["pattern"]),
                    severity=_SEVERITY_MAP.get(entry.get("severity", "HIGH"), Severity.HIGH),
                    description=entry.get("description", ""),
                ))
            except Exception as exc:
                logger.warning("Skipping invalid secret pattern %s: %s", entry.get("id"), exc)

    _pattern_cache = patterns
    _cache_mtime = mtime
    if patterns:
        logger.info("Loaded %d secret patterns from %s", len(patterns), yaml_path.name)
    else:
        logger.warning("0 secret patterns loaded from %s — check YAML structure (expected 'patterns:' key with category groups)", yaml_path.name)
    return patterns


def _load_entropy_config(path: Optional[Path] = None) -> EntropyConfig:
    """Load entropy detection config from YAML."""
    global _entropy_config

    if _entropy_config is not None:
        return _entropy_config

    data = _load_yaml_data(path)
    ec = data.get("entropy", {})

    ignore_compiled = []
    for pat in ec.get("ignore_patterns", []):
        try:
            ignore_compiled.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            pass

    _entropy_config = EntropyConfig(
        enabled=ec.get("enabled", True),
        min_length=ec.get("min_length", 16),
        hex_threshold=ec.get("hex_threshold", 3.5),
        base64_threshold=ec.get("base64_threshold", 4.2),
        generic_threshold=ec.get("generic_threshold", 4.5),
        ignore_patterns=ignore_compiled,
    )
    return _entropy_config


def reload_patterns(path: Optional[Path] = None) -> int:
    """Force reload patterns from YAML. Returns pattern count."""
    global _pattern_cache, _cache_mtime, _entropy_config
    _pattern_cache = None
    _cache_mtime = 0.0
    _entropy_config = None
    return len(_load_patterns(path))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ENTROPY ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_HEX_RE = re.compile(r'\b[a-fA-F0-9]{16,}\b')
_B64_RE = re.compile(r'\b[A-Za-z0-9+/]{16,}={0,2}\b')
_GENERIC_RE = re.compile(r'\b[A-Za-z0-9_\-]{20,}\b')


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class EntropyDetector:
    """Detect high-entropy strings that may be undocumented secrets."""

    def __init__(self, config: Optional[EntropyConfig] = None):
        self._config = config or _load_entropy_config()

    def scan_line(self, line: str, line_num: int, filepath: str) -> list[Finding]:
        """Scan a single line for high-entropy strings."""
        if not self._config.enabled:
            return []

        findings = []

        # Skip lines that are comments or known false positives
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            return []

        for ignore_pat in self._config.ignore_patterns:
            if ignore_pat.search(line):
                return []

        # Hex strings
        for m in _HEX_RE.finditer(line):
            token = m.group()
            if len(token) < self._config.min_length:
                continue
            entropy = _shannon_entropy(token)
            if entropy > self._config.hex_threshold:
                findings.append(Finding(
                    rule_id="SEC-ENTROPY-HEX",
                    module="sast.secrets.entropy",
                    title="High-entropy hex string",
                    description=f"Hex string with entropy {entropy:.2f} (threshold: {self._config.hex_threshold})",
                    severity=Severity.MEDIUM,
                    confidence=min(0.5 + (entropy - self._config.hex_threshold) * 0.2, 0.95),
                    target=filepath,
                    location=Location(file=filepath, line_start=line_num),
                    evidence=self._redact(token),
                    cwe_ids=["CWE-798"],
                    tags=["category:secrets", "method:entropy"],
                ))

        # Base64 strings
        for m in _B64_RE.finditer(line):
            token = m.group()
            if len(token) < self._config.min_length:
                continue
            # Skip if already caught by hex
            if _HEX_RE.fullmatch(token):
                continue
            entropy = _shannon_entropy(token)
            if entropy > self._config.base64_threshold:
                findings.append(Finding(
                    rule_id="SEC-ENTROPY-B64",
                    module="sast.secrets.entropy",
                    title="High-entropy base64 string",
                    description=f"Base64 string with entropy {entropy:.2f} (threshold: {self._config.base64_threshold})",
                    severity=Severity.MEDIUM,
                    confidence=min(0.4 + (entropy - self._config.base64_threshold) * 0.2, 0.90),
                    target=filepath,
                    location=Location(file=filepath, line_start=line_num),
                    evidence=self._redact(token),
                    cwe_ids=["CWE-798"],
                    tags=["category:secrets", "method:entropy"],
                ))

        # Generic high-entropy tokens near assignment operators
        if re.search(r'[=:]\s*["\x27]', line):
            for m in _GENERIC_RE.finditer(line):
                token = m.group()
                if len(token) < self._config.min_length:
                    continue
                entropy = _shannon_entropy(token)
                if entropy > self._config.generic_threshold:
                    findings.append(Finding(
                        rule_id="SEC-ENTROPY-GEN",
                        module="sast.secrets.entropy",
                        title="High-entropy token near assignment",
                        description=f"Token with entropy {entropy:.2f} near assignment (threshold: {self._config.generic_threshold})",
                        severity=Severity.LOW,
                        confidence=min(0.3 + (entropy - self._config.generic_threshold) * 0.15, 0.80),
                        target=filepath,
                        location=Location(file=filepath, line_start=line_num),
                        evidence=self._redact(token),
                        cwe_ids=["CWE-798"],
                        tags=["category:secrets", "method:entropy"],
                    ))

        return findings

    @staticmethod
    def _redact(text: str, visible: int = 6) -> str:
        if len(text) <= visible:
            return "***REDACTED***"
        return text[:visible] + "***REDACTED***"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GIT HISTORY SCANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class GitHistoryScanner:
    """Scan git history for committed secrets (including deleted ones)."""

    def __init__(self, patterns: Optional[list[SecretPattern]] = None):
        self._patterns = patterns or _load_patterns()

    def scan_repo(self, repo_path: str, max_commits: int = 500) -> list[Finding]:
        """Scan git log for secrets in diffs."""
        findings = []
        repo = Path(repo_path)

        if not (repo / ".git").is_dir():
            logger.debug("Not a git repo: %s", repo_path)
            return []

        try:
            result = subprocess.run(
                ["git", "log", "--all", "--diff-filter=ACMR",
                 f"-{max_commits}", "--pretty=format:%H|%an|%ae|%aI|%s",
                 "-p", "--no-color"],
                capture_output=True, text=True, cwd=repo_path,
                timeout=120,
            )
            if result.returncode != 0:
                logger.warning("git log failed: %s", result.stderr[:200])
                return []

            output = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning("Git history scan failed: %s", e)
            return []

        current_commit = ""
        current_file = ""
        current_author = ""
        current_date = ""

        for line in output.split("\n"):
            # Commit header
            if "|" in line and len(line.split("|")) >= 5 and len(line.split("|")[0]) == 40:
                parts = line.split("|", 4)
                current_commit = parts[0]
                current_author = parts[1]
                current_date = parts[3]
                continue

            # File header
            if line.startswith("diff --git"):
                parts = line.split(" b/")
                current_file = parts[-1] if len(parts) > 1 else ""
                continue

            # Added lines only
            if not line.startswith("+") or line.startswith("+++"):
                continue

            added_line = line[1:]  # Strip leading +
            for sp in self._patterns:
                if sp.pattern.search(added_line):
                    findings.append(Finding(
                        rule_id=f"GIT-{sp.id}",
                        module="sast.secrets.git",
                        title=f"Secret in git history: {sp.name}",
                        description=f"{sp.description}. Found in commit {current_commit[:8]} "
                                    f"by {current_author} on {current_date}",
                        severity=sp.severity,
                        confidence=0.85,
                        target=current_file,
                        location=Location(file=current_file),
                        evidence=SecretsScanner._redact(added_line.strip()[:80]),
                        cwe_ids=["CWE-798", "CWE-540"],
                        tags=["category:secrets", "source:git-history",
                              f"commit:{current_commit[:8]}"],
                        remediation="Rotate the exposed credential immediately. "
                                    "Use `git filter-branch` or BFG Repo-Cleaner to remove from history.",
                    ))
                    break  # One per line

        logger.info("Git history scan: %d findings in %s", len(findings), repo_path)
        return findings


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONFIG FILE DEEP SCANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ConfigFileScanner:
    """Deep scan configuration files for embedded secrets."""

    CONFIG_EXTENSIONS = {
        ".env", ".env.local", ".env.production", ".env.development",
        ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
        ".json", ".xml", ".properties", ".tfvars", ".auto.tfvars",
    }

    CONFIG_FILENAMES = {
        ".env", ".env.local", ".env.production", ".env.staging",
        ".env.development", ".env.test",
        "docker-compose.yml", "docker-compose.yaml",
        "config.yaml", "config.yml", "config.json", "config.toml",
        "secrets.yaml", "secrets.yml", "credentials.json",
        "terraform.tfvars", "variables.tf",
        ".npmrc", ".pypirc", ".netrc", ".gitconfig",
        "kubeconfig", "kube.config",
    }

    SENSITIVE_KEYS = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "api-key", "access_key", "secret_key", "private_key", "auth_token",
        "client_secret", "database_url", "connection_string", "dsn",
        "smtp_password", "aws_secret", "encryption_key", "signing_key",
        "master_key", "deploy_key", "webhook_secret", "db_password",
    }

    def __init__(self, patterns: Optional[list[SecretPattern]] = None):
        self._patterns = patterns or _load_patterns()
        self._entropy = EntropyDetector()

    def scan_file(self, filepath: str) -> list[Finding]:
        """Deep scan a config file."""
        fp = Path(filepath)
        findings = []

        if not fp.exists() or fp.stat().st_size > 5_000_000:
            return []

        suffix = fp.suffix.lower()
        name = fp.name.lower()

        # Detect if it's a config file
        is_config = suffix in self.CONFIG_EXTENSIONS or name in self.CONFIG_FILENAMES

        if not is_config:
            return []

        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        lines = content.split("\n")

        # .env format: KEY=VALUE
        if name.startswith(".env") or suffix == ".env":
            for lineno, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip().lower()
                    value = value.strip().strip("'\"")
                    if any(sk in key for sk in self.SENSITIVE_KEYS) and value:
                        findings.append(Finding(
                            rule_id="SEC-CONFIG-ENV",
                            module="sast.secrets.config",
                            title=f"Sensitive value in .env: {key.upper()}",
                            description=f"Environment variable '{key}' contains a sensitive value",
                            severity=Severity.HIGH,
                            confidence=0.9,
                            target=filepath,
                            location=Location(file=filepath, line_start=lineno),
                            evidence=f"{key}={SecretsScanner._redact(value)}",
                            cwe_ids=["CWE-798"],
                            tags=["category:secrets", "source:env-file"],
                        ))

        # YAML/JSON: scan values at any depth
        if suffix in (".yaml", ".yml", ".json"):
            for lineno, line in enumerate(lines, 1):
                for sp in self._patterns:
                    if sp.pattern.search(line):
                        findings.append(Finding(
                            rule_id=f"CONFIG-{sp.id}",
                            module="sast.secrets.config",
                            title=f"Secret in config: {sp.name}",
                            description=sp.description,
                            severity=sp.severity,
                            confidence=0.85,
                            target=filepath,
                            location=Location(file=filepath, line_start=lineno),
                            evidence=SecretsScanner._redact(line.strip()[:80]),
                            cwe_ids=["CWE-798"],
                            tags=["category:secrets", "source:config-file"],
                        ))
                        break

                # Entropy check on config values
                findings.extend(self._entropy.scan_line(line, lineno, filepath))

        return findings

    def scan_directory(self, path: str) -> list[Finding]:
        """Recursively scan for config files."""
        findings = []
        root = Path(path)
        skip_dirs = {"__pycache__", ".git", "node_modules", ".venv", "venv", "dist", "build", ".tox"}

        for fp in root.rglob("*"):
            if fp.is_file() and not any(skip in fp.parts for skip in skip_dirs):
                findings.extend(self.scan_file(str(fp)))

        return findings


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN SCANNER (ORCHESTRATOR)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SecretsScanner:
    """
    Enterprise secrets scanner — orchestrates regex, entropy, git, and config scanning.

    Usage:
        scanner = SecretsScanner()

        # Single file
        findings = scanner.scan_file("app.py")

        # Directory (recursive)
        findings = scanner.scan_directory("/path/to/project")

        # Full audit (includes git history + config files)
        findings = scanner.full_audit("/path/to/project")
    """

    SKIP_EXTENSIONS = {
        ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".whl", ".egg",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
        ".woff", ".woff2", ".ttf", ".eot",
        ".db", ".sqlite", ".sqlite3",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    }
    SKIP_DIRS = {
        "__pycache__", ".git", "node_modules", ".venv", "venv",
        "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
        "coverage", ".coverage", "htmlcov", "eggs", ".eggs",
    }
    MAX_FILE_SIZE = 2_000_000  # 2MB

    def __init__(self, yaml_path: Optional[str] = None, enable_entropy: bool = True):
        path = Path(yaml_path) if yaml_path else None
        self._patterns = _load_patterns(path)
        self._entropy = EntropyDetector() if enable_entropy else None
        self._git_scanner = GitHistoryScanner(self._patterns)
        self._config_scanner = ConfigFileScanner(self._patterns)
        self._file_cache: dict[str, str] = {}  # filepath -> hash

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)

    def scan_file(self, path: str) -> list[Finding]:
        """Scan a single file for secrets (regex + entropy)."""
        fp = Path(path)
        if not fp.exists() or fp.suffix.lower() in self.SKIP_EXTENSIONS:
            return []
        if fp.stat().st_size > self.MAX_FILE_SIZE:
            logger.debug("Skipping large file: %s", path)
            return []

        # Incremental: skip unchanged files
        try:
            with open(fp, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            if self._file_cache.get(path) == file_hash:
                return []
            self._file_cache[path] = file_hash
        except Exception:
            pass

        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        findings = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue

            is_comment = stripped.startswith("#") or stripped.startswith("//")

            # Regex patterns — run on ALL lines including comments
            # (credentials left in comments are still leaked credentials)
            for sp in self._patterns:
                match = sp.pattern.search(line)
                if match:
                    findings.append(Finding(
                        rule_id=sp.id,
                        module="sast.secrets",
                        title=sp.name,
                        description=sp.description,
                        severity=sp.severity,
                        confidence=0.85 if is_comment else 0.9,
                        target=str(fp),
                        location=Location(file=str(fp), line_start=line_num),
                        evidence=self._redact(match.group(0)),
                        cwe_ids=["CWE-798"],
                        tags=["category:secrets"] + (["source:comment"] if is_comment else []),
                        remediation="Remove the credential from the comment and rotate it immediately.",
                    ))
                    break  # One finding per line

            # Entropy detection — skip comment lines to avoid FPs on normal text
            if self._entropy and not is_comment:
                findings.extend(self._entropy.scan_line(line, line_num, str(fp)))

        return findings

    def scan_directory(self, path: str, recursive: bool = True) -> list[Finding]:
        """Scan a directory for secrets."""
        root = Path(path)
        if not root.is_dir():
            return []

        findings = []
        pattern = "**/*" if recursive else "*"
        for fp in sorted(root.glob(pattern)):
            if fp.is_file() and fp.suffix.lower() not in self.SKIP_EXTENSIONS:
                if not any(skip in fp.parts for skip in self.SKIP_DIRS):
                    findings.extend(self.scan_file(str(fp)))

        return findings

    def scan_git_history(self, repo_path: str, max_commits: int = 500) -> list[Finding]:
        """Scan git history for leaked secrets."""
        return self._git_scanner.scan_repo(repo_path, max_commits)

    def scan_config_files(self, path: str) -> list[Finding]:
        """Deep scan configuration files."""
        return self._config_scanner.scan_directory(path)

    def full_audit(self, project_path: str, include_git: bool = True, max_git_commits: int = 500) -> list[Finding]:
        """
        Complete secrets audit: files + config + git history.

        Returns deduplicated findings sorted by severity.
        """
        findings = []

        # 1. Source code scan
        findings.extend(self.scan_directory(project_path))

        # 2. Config file deep scan
        findings.extend(self.scan_config_files(project_path))

        # 3. Git history scan
        if include_git:
            findings.extend(self.scan_git_history(project_path, max_git_commits))

        # Deduplicate by (rule_id, target, line)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.rule_id, f.target, getattr(f.location, 'line_start', 0))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Sort by severity (CRITICAL first)
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        deduped.sort(key=lambda f: severity_order.get(f.severity, 5))

        return deduped

    @staticmethod
    def _redact(text: str, visible_chars: int = 6) -> str:
        """Redact a secret, showing only the first N characters."""
        if len(text) <= visible_chars:
            return "***REDACTED***"
        return text[:visible_chars] + "***REDACTED***"
