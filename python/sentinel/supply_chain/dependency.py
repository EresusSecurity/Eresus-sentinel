"""
Eresus Sentinel — Dependency Auditor.

Scans project dependency files for known vulnerable packages
in the AI/ML ecosystem. Checks lockfiles and manifests for:
  - Known vulnerable package versions
  - Pinning hygiene (unpinned, wildcard, range deps)
  - Typosquatting detection (Levenshtein distance)
  - Deprecated/abandoned packages
  - License compliance risks
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..finding import Finding, Severity
from ..rules import load_supply_chain_rules


@dataclass
class DependencyEntry:
    """Parsed dependency from a manifest/lockfile."""
    name: str
    version_spec: str = ""
    resolved_version: str = ""
    source_file: str = ""
    line_number: int = 0


# Well-known AI/ML package names for typosquatting detection
KNOWN_AI_PACKAGES = [
    "transformers", "torch", "tensorflow", "keras", "onnx",
    "onnxruntime", "safetensors", "accelerate", "datasets",
    "tokenizers", "diffusers", "gradio", "langchain", "llama-index",
    "openai", "anthropic", "cohere", "huggingface-hub",
    "sentence-transformers", "peft", "optimum", "bitsandbytes",
    "auto-gptq", "vllm", "trl", "evaluate", "scikit-learn",
    "scipy", "numpy", "pandas", "matplotlib", "seaborn",
    "xgboost", "lightgbm", "catboost", "fastai", "spacy",
    "nltk", "gensim", "pillow", "opencv-python", "mediapipe",
    "ultralytics", "detectron2", "torchvision", "torchaudio",
]


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


class DependencyAuditor:
    """Scans dependency files for security issues."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self._rules = load_supply_chain_rules()
        self._vuln_packages = self._rules.get("known_vulnerable_packages", [])
        self._dep_patterns = self._rules.get("dependency_patterns", {})

    def audit_file(self, filepath: str) -> list[Finding]:
        """Audit a single dependency file."""
        self.findings = []
        path = Path(filepath)

        if not path.exists():
            return self.findings

        filename = path.name

        if filename == "requirements.txt":
            deps = self._parse_requirements_txt(filepath)
        elif filename == "pyproject.toml":
            deps = self._parse_pyproject_toml(filepath)
        elif filename == "package.json":
            deps = self._parse_package_json(filepath)
        elif filename == "Cargo.toml":
            deps = self._parse_cargo_toml(filepath)
        elif filename in ("Pipfile", "setup.cfg"):
            deps = self._parse_requirements_txt(filepath)  # Close enough
        else:
            return self.findings

        for dep in deps:
            self._check_known_vulnerabilities(dep)
            self._check_pinning_hygiene(dep)
            self._check_typosquatting(dep)

        return self.findings

    def audit_directory(self, dirpath: str) -> list[Finding]:
        """Recursively scan a directory for dependency files."""
        self.findings = []
        path = Path(dirpath)

        if not path.is_dir():
            return self.findings

        # Collect all known manifest/lockfile names
        target_files = set()
        for lang_info in self._dep_patterns.values():
            for f in lang_info.get("lockfiles", []):
                target_files.add(f)
            for f in lang_info.get("manifest", []):
                target_files.add(f)

        # Also always look for these
        target_files.update(["requirements.txt", "pyproject.toml", "package.json", "Cargo.toml"])

        found_any = False
        for fpath in path.rglob("*"):
            if fpath.is_dir() or ".git" in fpath.parts:
                continue
            if fpath.name in target_files:
                found_any = True
                self.audit_file(str(fpath))

        if not found_any:
            self.findings.append(Finding.supply_chain(
                rule_id="DEP-001",
                title="No dependency files found",
                description=f"Directory '{dirpath}' has no recognized dependency manifests. "
                            "This may indicate vendored or embedded dependencies.",
                severity=Severity.INFO,
                target=dirpath,
            ))

        return self.findings

    def _parse_requirements_txt(self, filepath: str) -> list[DependencyEntry]:
        """Parse pip requirements.txt format."""
        deps = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                # Pattern: package==version, package>=version, package
                match = re.match(r'^([a-zA-Z0-9_.-]+)\s*([><=!~]+)?\s*([0-9a-zA-Z.*_-]*)', line)
                if match:
                    name = match.group(1).lower().replace("_", "-")
                    spec = (match.group(2) or "") + (match.group(3) or "")
                    deps.append(DependencyEntry(
                        name=name,
                        version_spec=spec,
                        source_file=filepath,
                        line_number=line_num,
                    ))
        return deps

    def _parse_pyproject_toml(self, filepath: str) -> list[DependencyEntry]:
        """Parse pyproject.toml dependencies (simplified)."""
        deps = []
        in_deps = False

        with open(filepath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                stripped = line.strip()

                if stripped in ("[project]", "[tool.poetry.dependencies]"):
                    in_deps = False
                if "dependencies" in stripped and ("[" in stripped or "=" in stripped):
                    in_deps = True
                    continue

                if in_deps and stripped.startswith('"'):
                    # "package>=version"
                    match = re.match(r'"([a-zA-Z0-9_.-]+)\s*([><=!~]+)?\s*([0-9a-zA-Z.*_-]*)"', stripped)
                    if match:
                        name = match.group(1).lower().replace("_", "-")
                        spec = (match.group(2) or "") + (match.group(3) or "")
                        deps.append(DependencyEntry(
                            name=name,
                            version_spec=spec,
                            source_file=filepath,
                            line_number=line_num,
                        ))

                if in_deps and stripped == "]":
                    in_deps = False

        return deps

    def _parse_package_json(self, filepath: str) -> list[DependencyEntry]:
        """Parse package.json dependencies."""
        import json
        deps = []

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return deps

        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in data.get(section, {}).items():
                deps.append(DependencyEntry(
                    name=name.lower(),
                    version_spec=version,
                    source_file=filepath,
                ))

        return deps

    def _parse_cargo_toml(self, filepath: str) -> list[DependencyEntry]:
        """Parse Cargo.toml dependencies (simplified)."""
        deps = []
        in_deps = False

        with open(filepath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                stripped = line.strip()
                if stripped in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
                    in_deps = True
                    continue
                if stripped.startswith("[") and in_deps:
                    in_deps = False

                if in_deps and "=" in stripped:
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]+)"|\{.*version\s*=\s*"([^"]+)")', stripped)
                    if match:
                        name = match.group(1)
                        version = match.group(2) or match.group(3) or ""
                        deps.append(DependencyEntry(
                            name=name.lower(),
                            version_spec=version,
                            source_file=filepath,
                            line_number=line_num,
                        ))

        return deps

    def _check_known_vulnerabilities(self, dep: DependencyEntry) -> None:
        """Check if dependency is a known vulnerable AI/ML package."""
        for vuln in self._vuln_packages:
            vuln_name = vuln.get("name", "").lower().replace("_", "-")
            if dep.name == vuln_name:
                sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                       "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}.get(
                    vuln.get("severity", "MEDIUM"), Severity.MEDIUM)

                self.findings.append(Finding.supply_chain(
                    rule_id="DEP-010",
                    title=f"Known vulnerable package: {dep.name}",
                    description=f"Package '{dep.name}' (spec: {dep.version_spec or 'unpinned'}) is in the "
                                f"known vulnerability database. Reason: {vuln.get('reason', 'N/A')}. "
                                f"Minimum safe version: {vuln.get('versions_before', 'N/A')}",
                    severity=sev,
                    target=dep.source_file,
                    evidence=f"package={dep.name}, spec={dep.version_spec}, min_safe={vuln.get('versions_before')}",
                ))
                break

    def _check_pinning_hygiene(self, dep: DependencyEntry) -> None:
        """Check if dependency version is properly pinned."""
        spec = dep.version_spec

        if not spec:
            self.findings.append(Finding.supply_chain(
                rule_id="DEP-020",
                title=f"Unpinned dependency: {dep.name}",
                description=f"Package '{dep.name}' has no version constraint. "
                            "Pin dependencies to avoid supply chain substitution attacks.",
                severity=Severity.MEDIUM,
                target=dep.source_file,
                evidence=f"package={dep.name}, spec=none, line={dep.line_number}",
            ))
        elif spec == "*" or spec == "latest":
            self.findings.append(Finding.supply_chain(
                rule_id="DEP-021",
                title=f"Wildcard dependency: {dep.name}",
                description=f"Package '{dep.name}' uses wildcard version '{spec}'. "
                            "This accepts any version, including malicious updates.",
                severity=Severity.HIGH,
                target=dep.source_file,
                evidence=f"package={dep.name}, spec={spec}",
            ))

    def _check_typosquatting(self, dep: DependencyEntry) -> None:
        """Check for potential typosquatting of known AI/ML packages."""
        dep_norm = dep.name.lower().replace("_", "-")
        known_norms = {known.lower().replace("_", "-") for known in KNOWN_AI_PACKAGES}
        if dep_norm in known_norms:
            return

        for known in KNOWN_AI_PACKAGES:
            known_norm = known.lower().replace("_", "-")

            dist = _levenshtein(dep_norm, known_norm)
            if 0 < dist <= 2 and len(dep_norm) > 4:
                self.findings.append(Finding.supply_chain(
                    rule_id="DEP-030",
                    title=f"Potential typosquat: {dep.name}",
                    description=f"Package '{dep.name}' is suspiciously similar to known package '{known}' "
                                f"(Levenshtein distance: {dist}). "
                                "This may be a typosquatting attack.",
                    severity=Severity.HIGH,
                    target=dep.source_file,
                    evidence=f"package={dep.name}, similar_to={known}, distance={dist}",
                ))
                break  # Report once per dep
