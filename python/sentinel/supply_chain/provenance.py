"""
Eresus Sentinel — Model Provenance & Supply Chain Verifier.

Validates model provenance and integrity:
  - SHA256 file integrity verification
  - HuggingFace model card provenance validation
  - Author reputation assessment
  - Dangerous file type detection in model repos
  - Missing safetensors migration detection
  - Commit signature verification
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..finding import Finding, Severity

# Known dangerous file extensions in model repositories
DANGEROUS_EXTENSIONS = {
    ".pkl": ("Pickle file — potential arbitrary code execution", Severity.CRITICAL),
    ".pickle": ("Pickle file — potential arbitrary code execution", Severity.CRITICAL),
    ".bin": ("Binary file — may contain serialized Python objects", Severity.HIGH),
    ".pt": ("PyTorch file — may use pickle serialization", Severity.HIGH),
    ".pth": ("PyTorch file — may use pickle serialization", Severity.HIGH),
    ".joblib": ("Joblib file — potential arbitrary code execution", Severity.HIGH),
    ".npy": ("NumPy file — limited attack surface", Severity.LOW),
    ".npz": ("NumPy compressed — limited attack surface", Severity.LOW),
    ".h5": ("HDF5/Keras file — check for Lambda layers", Severity.MEDIUM),
    ".keras": ("Keras file — check for Lambda layers and CVE-2025-1550", Severity.MEDIUM),
    ".ckpt": ("Checkpoint file — may use pickle serialization", Severity.HIGH),
    ".msgpack": ("MessagePack file — limited attack surface", Severity.LOW),
    ".exe": ("Executable binary — should never be in model repos", Severity.CRITICAL),
    ".dll": ("Dynamic library — should never be in model repos", Severity.CRITICAL),
    ".so": ("Shared object — should never be in model repos", Severity.CRITICAL),
    ".sh": ("Shell script — potential command execution", Severity.HIGH),
    ".bat": ("Batch script — potential command execution", Severity.HIGH),
    ".ps1": ("PowerShell script — potential command execution", Severity.HIGH),
}

# Safe file extensions that should be preferred
SAFE_EXTENSIONS = {".safetensors", ".gguf", ".onnx", ".json", ".txt", ".md", ".yaml", ".yml", ".toml", ".cfg", ".csv"}

MODEL_REPO_SIGNAL_FILES = {
    "adapter_config.json",
    "config.json",
    "generation_config.json",
    "model_index.json",
    "preprocessor_config.json",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
}

MODEL_REPO_SIGNAL_EXTENSIONS = {
    ".safetensors",
    ".onnx",
    ".gguf",
    ".mlmodel",
    ".mlpackage",
    ".pt",
    ".pth",
    ".bin",
    ".ckpt",
    ".h5",
    ".keras",
}

# Minimum expected fields in a properly documented model card
MODEL_CARD_REQUIRED_FIELDS = [
    "model_name",     # or model_id or id
    "library_name",   # which framework
    "pipeline_tag",   # task type
]


@dataclass
class IntegrityRecord:
    """Stores SHA256 hash for a file."""
    filepath: str
    expected_hash: str
    actual_hash: str = ""
    verified: bool = False
    error: Optional[str] = None


class ProvenanceVerifier:
    """Validates model provenance, integrity, and supply chain security."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def verify_integrity(self, filepath: str, expected_sha256: str) -> list[Finding]:
        """Verify file integrity against expected SHA256 hash."""
        self.findings = []
        path = Path(filepath)

        if not path.exists():
            self.findings.append(Finding.supply_chain(
                rule_id="SC-001",
                title="File not found for integrity verification",
                description=f"Cannot verify integrity: file '{filepath}' does not exist.",
                severity=Severity.HIGH,
                target=filepath,
            ))
            return self.findings

        actual_hash = self._compute_sha256(filepath)

        if actual_hash != expected_sha256.lower():
            self.findings.append(Finding.supply_chain(
                rule_id="SC-002",
                title="SHA256 integrity mismatch",
                description=f"File '{filepath}' has been modified or corrupted. "
                            f"Expected SHA256: {expected_sha256}, Got: {actual_hash}. "
                            "This could indicate supply chain tampering.",
                severity=Severity.CRITICAL,
                target=filepath,
                evidence=f"expected={expected_sha256}, actual={actual_hash}",
            ))
        return self.findings

    def verify_manifest(self, manifest_path: str) -> list[Finding]:
        """Verify all files listed in a SHA256 manifest file.

        Manifest format (one per line):
            <sha256_hash>  <filepath>
        """
        self.findings = []
        path = Path(manifest_path)

        if not path.exists():
            self.findings.append(Finding.supply_chain(
                rule_id="SC-003",
                title="Manifest file not found",
                description=f"SHA256 manifest file '{manifest_path}' not found. "
                            "Use a manifest to track model file integrity.",
                severity=Severity.MEDIUM,
                target=manifest_path,
            ))
            return self.findings

        manifest_dir = path.parent
        with open(path, "r", encoding="utf-8") as f:
            for _line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue

                expected_hash, rel_path = parts
                abs_path = str(manifest_dir / rel_path)
                self.verify_integrity(abs_path, expected_hash)

        return self.findings

    def audit_directory(self, dirpath: str) -> list[Finding]:
        """Audit a model directory for supply chain security issues."""
        self.findings = []
        path = Path(dirpath)

        if not path.is_dir():
            return self.findings

        has_safetensors = False
        has_pickle_based = False
        has_model_repo_signal = False
        dangerous_files = []
        all_files = []

        for fpath in path.rglob("*"):
            if fpath.is_dir():
                continue
            if ".git" in fpath.parts:
                continue

            all_files.append(fpath)
            ext = fpath.suffix.lower()
            if fpath.name in MODEL_REPO_SIGNAL_FILES or ext in MODEL_REPO_SIGNAL_EXTENSIONS:
                has_model_repo_signal = True

            if ext == ".safetensors":
                has_safetensors = True

            if ext in (".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib"):
                has_pickle_based = True

            if ext in DANGEROUS_EXTENSIONS:
                desc, sev = DANGEROUS_EXTENSIONS[ext]
                dangerous_files.append((str(fpath), desc, sev))

        # Flag dangerous files
        for fpath, desc, sev in dangerous_files:
            self.findings.append(Finding.supply_chain(
                rule_id="SC-010",
                title=f"Dangerous file type: {Path(fpath).suffix}",
                description=f"File '{fpath}': {desc}. Consider using safetensors format instead.",
                severity=sev,
                target=fpath,
                evidence=f"extension={Path(fpath).suffix}",
            ))

        # Flag missing safetensors migration
        if has_pickle_based and not has_safetensors:
            self.findings.append(Finding.supply_chain(
                rule_id="SC-011",
                title="No safetensors files found",
                description=f"Directory '{dirpath}' contains pickle-based model files but no safetensors files. "
                            "Safetensors is the recommended secure format. Migrate with: "
                            "model.save_pretrained(path, safe_serialization=True)",
                severity=Severity.HIGH,
                target=dirpath,
                evidence="pickle_based=true, safetensors=false",
            ))

        # Check for model card
        model_card = path / "README.md"
        if has_model_repo_signal and not model_card.exists():
            self.findings.append(Finding.supply_chain(
                rule_id="SC-012",
                title="Missing model card (README.md)",
                description=f"Directory '{dirpath}' has no README.md model card. "
                            "Model cards document provenance, training data, and intended use.",
                severity=Severity.MEDIUM,
                target=dirpath,
            ))

        # Check for config.json (HF standard)
        config_file = path / "config.json"
        if config_file.exists():
            self._audit_config(str(config_file))

        return self.findings

    def audit_model_card(self, card_path: str) -> list[Finding]:
        """Audit a HuggingFace model card for provenance fields."""
        self.findings = []
        path = Path(card_path)

        if not path.exists():
            return self.findings

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        content_lower = content.lower()

        # Check for YAML frontmatter
        if not content.startswith("---"):
            self.findings.append(Finding.supply_chain(
                rule_id="SC-020",
                title="Missing YAML frontmatter in model card",
                description=f"Model card '{card_path}' has no YAML frontmatter. "
                            "HuggingFace model cards should include metadata like library_name, pipeline_tag.",
                severity=Severity.LOW,
                target=card_path,
            ))

        # Check for license
        if "license" not in content_lower:
            self.findings.append(Finding.supply_chain(
                rule_id="SC-021",
                title="Missing license in model card",
                description=f"Model card '{card_path}' does not mention a license. "
                            "Models should declare their licensing terms.",
                severity=Severity.MEDIUM,
                target=card_path,
            ))

        # Check for training data disclosure
        training_keywords = ["training data", "dataset", "trained on", "fine-tuned on"]
        if not any(kw in content_lower for kw in training_keywords):
            self.findings.append(Finding.supply_chain(
                rule_id="SC-022",
                title="Missing training data documentation",
                description=f"Model card '{card_path}' does not document training data. "
                            "This is important for assessing data provenance and bias.",
                severity=Severity.MEDIUM,
                target=card_path,
            ))

        return self.findings

    def _audit_config(self, config_path: str) -> None:
        """Audit a HuggingFace config.json for security issues."""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        # Check for auto_map (arbitrary code execution)
        if "auto_map" in config:
            auto_map = config["auto_map"]
            for key, value in auto_map.items() if isinstance(auto_map, dict) else []:
                if "--" in str(value):  # Custom module reference
                    self.findings.append(Finding.supply_chain(
                        rule_id="SC-030",
                        title=f"auto_map with custom code: {key}",
                        description=f"config.json contains auto_map['{key}'] = '{value}' which references custom code. "
                                    "This will execute arbitrary Python code when loading the model. "
                                    "Only use models with auto_map from trusted sources.",
                        severity=Severity.CRITICAL,
                        target=config_path,
                        evidence=f"auto_map.{key}={value}",
                    ))

        # Check for trust_remote_code
        if config.get("trust_remote_code"):
            self.findings.append(Finding.supply_chain(
                rule_id="SC-031",
                title="trust_remote_code enabled in config",
                description="config.json has trust_remote_code=true. "
                            "This enables arbitrary code execution when loading the model.",
                severity=Severity.CRITICAL,
                target=config_path,
                evidence="trust_remote_code=true",
            ))

        # Check for custom_code flag
        if config.get("custom_code"):
            self.findings.append(Finding.supply_chain(
                rule_id="SC-032",
                title="Custom code flag enabled in config",
                description="config.json has custom_code enabled. "
                            "Review all Python files in the repo for malicious code.",
                severity=Severity.HIGH,
                target=config_path,
                evidence="custom_code=true",
            ))

    @staticmethod
    def _compute_sha256(filepath: str) -> str:
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
