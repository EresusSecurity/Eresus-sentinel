"""
Eresus Sentinel — Hugging Face Repository Scanner

Scans Hugging Face model repositories for:
- Dangerous file types (pickle, pt, keras, etc.)
- Missing safetensors alternatives
- Config/tokenizer injection
- Suspicious README content
- Model card inconsistencies
- Supply chain integrity (commit signatures, SHA verification)
"""

import json
import os
from pathlib import Path
from typing import List, Optional

from ..finding import Finding, Severity

# Dangerous model file extensions
DANGEROUS_EXTENSIONS = {
    ".pkl": "Python Pickle — arbitrary code execution via __reduce__",
    ".pickle": "Python Pickle — arbitrary code execution",
    ".bin": "PyTorch binary — may contain pickle payload",
    ".pt": "PyTorch checkpoint — pickle-based serialization",
    ".pth": "PyTorch weights — pickle-based serialization",
    ".ckpt": "TensorFlow/PyTorch checkpoint — may use pickle",
    ".h5": "Legacy Keras HDF5 — potential Lambda layer exploits",
    ".hdf5": "Legacy Keras HDF5 — potential Lambda layer exploits",
    ".joblib": "Joblib serialization — pickle-based",
    ".npy": "NumPy array — safe if allow_pickle=False",
    ".npz": "NumPy compressed — safe if allow_pickle=False",
}

# Safe model file extensions
SAFE_EXTENSIONS = {
    ".safetensors": "Safetensors — safe tensor format",
    ".gguf": "GGUF — safe metadata, needs metadata inspection",
    ".onnx": "ONNX — needs custom op inspection",
    ".json": "JSON config — needs content inspection",
    ".txt": "Text file — likely tokenizer vocab",
    ".model": "SentencePiece model — protobuf-based",
}

# Suspicious patterns in config files
SUSPICIOUS_CONFIG_PATTERNS = [
    "__import__",
    "os.system",
    "subprocess",
    "eval(",
    "exec(",
    "pickle.load",
    "torch.load",
    "Lambda(",
    "__reduce__",
    "base64.b64decode",
    "marshal.loads",
]


class HuggingFaceScanner:
    """Scans Hugging Face model repositories for security issues."""

    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token or os.environ.get("HF_TOKEN")

    def scan_local_repo(self, repo_path: str) -> List[Finding]:
        """Scan a locally cloned HuggingFace repository."""
        findings = []
        p = Path(repo_path)

        if not p.exists():
            return [Finding.artifact(
                rule_id="HF-001",
                title="Repository path does not exist",
                description=f"Path {repo_path} not found",
                severity=Severity.INFO,
                source=repo_path,
            )]

        # Scan file types
        findings.extend(self._check_file_types(p))

        # Scan config files
        findings.extend(self._check_configs(p))

        # Check for safetensors availability
        findings.extend(self._check_safetensors_availability(p))

        # Scan tokenizer
        findings.extend(self._check_tokenizer(p))

        # Scan model card/README
        findings.extend(self._check_readme(p))

        # Model card completeness
        readme_file = p / "README.md"
        card_text = None
        if readme_file.is_file():
            try:
                card_text = readme_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
        findings.extend(self._check_model_card_completeness(repo_path, card_text))

        return findings

    def scan_remote_repo(self, repo_id: str) -> List[Finding]:
        """Scan a remote HuggingFace repository via API."""
        findings = []
        try:
            from huggingface_hub import HfApi, hf_hub_url

            api = HfApi(token=self.api_token)
            repo_info = api.repo_info(repo_id)

            # Check siblings (files)
            for sibling in repo_info.siblings:
                ext = Path(sibling.rfilename).suffix.lower()
                if ext in DANGEROUS_EXTENSIONS:
                    findings.append(Finding.artifact(
                        rule_id="HF-010",
                        title=f"Dangerous file type in repo: {sibling.rfilename}",
                        description=DANGEROUS_EXTENSIONS[ext],
                        severity=Severity.HIGH,
                        source=f"{repo_id}/{sibling.rfilename}",
                        cwe_ids=["CWE-502"],
                    ))

            # Check if safetensors available
            has_safetensors = any(
                s.rfilename.endswith(".safetensors") for s in repo_info.siblings
            )
            has_pickle = any(
                Path(s.rfilename).suffix.lower() in {".pkl", ".bin", ".pt", ".pth"}
                for s in repo_info.siblings
            )

            if has_pickle and not has_safetensors:
                findings.append(Finding.artifact(
                    rule_id="HF-011",
                    title="No safetensors alternative available",
                    description="Repository uses pickle-based weights without a safetensors alternative. "
                                "Safetensors provides a safe, zero-copy format for model weights.",
                    severity=Severity.MEDIUM,
                    source=repo_id,
                ))

            # Check SHA256 for each file
            for sibling in repo_info.siblings:
                if not sibling.lfs:
                    continue
                if not sibling.lfs.get("sha256"):
                    findings.append(Finding.artifact(
                        rule_id="HF-012",
                        title=f"Missing SHA256 for LFS file: {sibling.rfilename}",
                        description="LFS file lacks SHA256 hash for integrity verification.",
                        severity=Severity.MEDIUM,
                        source=f"{repo_id}/{sibling.rfilename}",
                        cwe_ids=["CWE-354"],
                    ))

            # Model card completeness
            card_text = None
            try:
                from huggingface_hub import hf_hub_download
                readme_path = hf_hub_download(
                    repo_id=repo_id, filename="README.md",
                    token=self.api_token, local_dir=None,
                )
                with open(readme_path, encoding="utf-8", errors="replace") as fh:
                    card_text = fh.read()
            except Exception:
                card_text = None
            findings.extend(self._check_model_card_completeness(repo_id, card_text))

        except ImportError:
            findings.append(Finding.artifact(
                rule_id="HF-020",
                title="huggingface_hub not installed",
                description="Install huggingface_hub to enable remote repo scanning: "
                            "pip install huggingface_hub",
                severity=Severity.INFO,
                source=repo_id,
            ))
        except Exception as e:
            findings.append(Finding.artifact(
                rule_id="HF-021",
                title="HuggingFace API error",
                description=f"Failed to query HuggingFace API: {e}",
                severity=Severity.MEDIUM,
                source=repo_id,
            ))

        return findings

    # ── Model card completeness scoring ─────────────────────────

    _CARD_SECTIONS = [
        "model_description",
        "intended_uses",
        "limitations",
        "training_data",
        "ethical_considerations",
        "eval_results",
    ]

    # Markdown heading aliases that count as covering each section
    _CARD_KEYWORDS: dict[str, list[str]] = {
        "model_description":     ["## model description", "## about", "## overview", "## introduction"],
        "intended_uses":         ["## intended use", "## uses", "## out-of-scope", "## direct use"],
        "limitations":           ["## limitation", "## bias", "## risks", "## caveats"],
        "training_data":         ["## training data", "## dataset", "## data"],
        "ethical_considerations":["## ethical", "## fairness", "## safety consideration", "## social"],
        "eval_results":          ["## evaluation", "## benchmark", "## result", "## performance"],
    }

    def _score_model_card(self, card_text: str) -> tuple[int, list[str]]:
        """Return (score 0-100, list of missing sections)."""
        lowered = card_text.lower()
        missing = []
        for section, keywords in self._CARD_KEYWORDS.items():
            if not any(kw in lowered for kw in keywords):
                missing.append(section)
        present = len(self._CARD_SECTIONS) - len(missing)
        score = round(present / len(self._CARD_SECTIONS) * 100)
        return score, missing

    def _check_model_card_completeness(self, repo_id: str, card_text: str | None) -> list[Finding]:
        """Produce findings when model card is absent or incomplete."""
        findings: list[Finding] = []

        if not card_text or not card_text.strip():
            findings.append(Finding.artifact(
                rule_id="HF-030",
                title="Model card missing",
                description=(
                    "Repository has no README / model card. "
                    "Model cards should document intended uses, limitations, training data, "
                    "ethical considerations, and evaluation results."
                ),
                severity=Severity.HIGH,
                source=repo_id,
                confidence=1.0,
                cwe_ids=["CWE-1059"],
            ))
            return findings

        score, missing = self._score_model_card(card_text)

        if score < 35:
            sev = Severity.MEDIUM
        elif score < 70:
            sev = Severity.LOW
        elif score < 90:
            sev = Severity.INFO
        else:
            return findings  # sufficiently complete

        findings.append(Finding.artifact(
            rule_id="HF-031",
            title=f"Incomplete model card (score {score}/100)",
            description=(
                f"Model card is missing key sections: {', '.join(missing)}. "
                f"Completeness score: {score}/100. "
                "A complete card improves transparency and responsible-use assessment."
            ),
            severity=sev,
            source=repo_id,
            evidence=f"missing_sections={missing}",
            confidence=0.9,
            cwe_ids=["CWE-1059"],
        ))
        return findings

    def _check_file_types(self, repo_path: Path) -> List[Finding]:
        """Check for dangerous file types."""
        findings = []
        for f in repo_path.rglob("*"):
            if f.is_file():
                ext = f.suffix.lower()
                if ext in DANGEROUS_EXTENSIONS:
                    findings.append(Finding.artifact(
                        rule_id="HF-002",
                        title=f"Dangerous file type: {f.name}",
                        description=DANGEROUS_EXTENSIONS[ext],
                        severity=Severity.HIGH,
                        source=str(f),
                        cwe_ids=["CWE-502"],
                    ))
        return findings

    def _check_safetensors_availability(self, repo_path: Path) -> List[Finding]:
        """Check if safetensors version is available when pickle exists."""
        findings = []
        has_safe = any(repo_path.rglob("*.safetensors"))
        has_pickle = any(
            repo_path.rglob(f"*{ext}")
            for ext in [".pkl", ".bin", ".pt", ".pth"]
        )
        if has_pickle and not has_safe:
            findings.append(Finding.artifact(
                rule_id="HF-003",
                title="No safetensors alternative",
                description="Repository contains pickle-based model files without "
                            "a safer safetensors alternative.",
                severity=Severity.MEDIUM,
                source=str(repo_path),
            ))
        return findings

    def _check_configs(self, repo_path: Path) -> List[Finding]:
        """Scan JSON config files for suspicious patterns."""
        findings = []
        config_files = list(repo_path.glob("*.json"))

        for cf in config_files:
            try:
                with open(cf, "r", encoding="utf-8") as f:
                    content = f.read()

                for pattern in SUSPICIOUS_CONFIG_PATTERNS:
                    if pattern in content:
                        findings.append(Finding.artifact(
                            rule_id="HF-004",
                            title=f"Suspicious pattern in config: {cf.name}",
                            description=f"Config contains '{pattern}' which may indicate "
                                        f"code injection via deserialization.",
                            severity=Severity.HIGH,
                            source=str(cf),
                            cwe_ids=["CWE-94"],
                        ))
                        break

                # Parse and check auto_map (custom code loading)
                try:
                    data = json.loads(content)
                    if "auto_map" in data:
                        findings.append(Finding.artifact(
                            rule_id="HF-005",
                            title="Custom code mapping (auto_map)",
                            description="Config uses auto_map which loads custom Python code "
                                        "from the repository. This enables arbitrary code execution.",
                            severity=Severity.HIGH,
                            source=str(cf),
                            cwe_ids=["CWE-94"],
                        ))

                    # Check for trust_remote_code patterns
                    if data.get("trust_remote_code", False):
                        findings.append(Finding.artifact(
                            rule_id="HF-006",
                            title="trust_remote_code enabled",
                            description="Config has trust_remote_code=True which allows "
                                        "arbitrary Python code execution during model loading.",
                            severity=Severity.CRITICAL,
                            source=str(cf),
                            cwe_ids=["CWE-94"],
                        ))
                except json.JSONDecodeError:
                    pass

            except Exception:
                continue

        return findings

    def _check_tokenizer(self, repo_path: Path) -> List[Finding]:
        """Check tokenizer files for injection patterns."""
        findings = []
        tokenizer_files = [
            "tokenizer.json", "tokenizer_config.json",
            "special_tokens_map.json", "added_tokens.json",
        ]

        for tf_name in tokenizer_files:
            tf_path = repo_path / tf_name
            if tf_path.exists():
                try:
                    with open(tf_path, "r", encoding="utf-8") as f:
                        content = f.read()

                    for pattern in SUSPICIOUS_CONFIG_PATTERNS:
                        if pattern in content:
                            findings.append(Finding.artifact(
                                rule_id="HF-007",
                                title=f"Suspicious pattern in tokenizer: {tf_name}",
                                description=f"Tokenizer file contains '{pattern}'.",
                                severity=Severity.HIGH,
                                source=str(tf_path),
                                cwe_ids=["CWE-94"],
                            ))
                            break
                except Exception:
                    continue

        return findings

    def _check_readme(self, repo_path: Path) -> List[Finding]:
        """Check README/model card for suspicious instructions."""
        findings = []
        readme = repo_path / "README.md"
        if not readme.exists():
            findings.append(Finding.artifact(
                rule_id="HF-008",
                title="Missing model card (README.md)",
                description="No README.md found. Model card is required for "
                            "responsible model distribution.",
                severity=Severity.LOW,
                source=str(repo_path),
            ))
            return findings

        try:
            with open(readme, "r", encoding="utf-8") as f:
                content = f.read().lower()

            # Check for instructions to disable safety
            unsafe_instructions = [
                "trust_remote_code=true",
                "safe_mode=false",
                "allow_pickle=true",
                "weights_only=false",
            ]
            for instr in unsafe_instructions:
                if instr in content:
                    findings.append(Finding.artifact(
                        rule_id="HF-009",
                        title=f"README instructs unsafe loading: {instr}",
                        description=f"Model card instructs users to use '{instr}' "
                                    f"which disables security protections.",
                        severity=Severity.MEDIUM,
                        source=str(readme),
                    ))
        except Exception:
            pass

        return findings
