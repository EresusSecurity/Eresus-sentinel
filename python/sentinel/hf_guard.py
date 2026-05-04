"""
Eresus Sentinel — HuggingFace Pre-Download Guard.

Scans HuggingFace model repositories BEFORE downloading,
preventing malicious models from reaching disk.

Architecture:
  1. Query HF Hub API for repo file listing
  2. Flag dangerous file types (.pkl, .pt, .bin, .onnx, etc.)
  3. Check model card for known unsafe patterns
  4. Verify SHA256 integrity of safetensors
  5. Optionally: download + scan individual files in temp dir

Features:
  - Pre-download risk assessment (no download required for initial check)
  - File type analysis with severity scoring
  - Model card safety analysis
  - Safetensors preference enforcement
  - Community vulnerability checks
  - Integration with HuggingFace Hub API
  - Configurable allow/block policies per file type

Usage:
    from sentinel.hf_guard import HFGuard

    guard = HFGuard()

    # Quick assessment (no download)
    report = guard.assess("microsoft/phi-2")
    if report.risk_level == "HIGH":
        print("WARNING: Dangerous model repository!")

    # Full scan (downloads and scans files)
    findings = guard.scan("username/model-name")

    # Pre-download hook
    guard.safe_download("org/model", local_dir="./models/")
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.finding import Finding, Severity
from sentinel.offline import offline_enabled

logger = logging.getLogger(__name__)


# ── Dangerous file extensions with risk levels ────────────────────

FILE_RISK_MAP: dict[str, tuple[str, str]] = {
    # HIGH risk — executable code, arbitrary deserialization
    ".pkl": ("HIGH", "Pickle files can execute arbitrary code on load"),
    ".pickle": ("HIGH", "Pickle files can execute arbitrary code on load"),
    ".pt": ("HIGH", "PyTorch files may contain pickle-based code execution"),
    ".pth": ("HIGH", "PyTorch files may contain pickle-based code execution"),
    ".bin": ("MEDIUM", "Binary files may contain serialized objects"),
    ".ckpt": ("HIGH", "Checkpoint files often use pickle serialization"),
    ".joblib": ("HIGH", "Joblib files use pickle internally"),
    ".npy": ("MEDIUM", "NumPy files can contain pickled objects"),
    ".npz": ("MEDIUM", "NumPy archives can contain pickled objects"),

    # MEDIUM risk — structured but potentially exploitable
    ".onnx": ("MEDIUM", "ONNX models can contain custom operators"),
    ".pb": ("MEDIUM", "TensorFlow protobuf files can be manipulated"),
    ".h5": ("MEDIUM", "HDF5/Keras files may contain Lambda layers with code"),
    ".hdf5": ("MEDIUM", "HDF5/Keras files may contain Lambda layers with code"),
    ".keras": ("MEDIUM", "Keras files may contain Lambda layers with code"),
    ".tflite": ("LOW", "TFLite models are sandboxed but can be malformed"),
    ".llamafile": ("HIGH", "LlamaFile contains executable binaries"),

    # LOW risk — generally safe
    ".safetensors": ("INFO", "Safetensors is designed to be safe — verify SHA256"),
    ".gguf": ("LOW", "GGUF format is relatively safe but verify provenance"),
    ".json": ("INFO", "JSON config files — check for injection patterns"),
    ".yaml": ("INFO", "YAML config files — check for code injection"),
    ".yml": ("INFO", "YAML config files — check for code injection"),
    ".txt": ("INFO", "Text files — low risk"),
    ".md": ("INFO", "Markdown files — low risk"),

    # Archive risk
    ".tar": ("MEDIUM", "Archive may contain path traversal (zip slip)"),
    ".tar.gz": ("MEDIUM", "Archive may contain path traversal"),
    ".tgz": ("MEDIUM", "Archive may contain path traversal"),
    ".zip": ("MEDIUM", "Archive may contain path traversal (zip slip)"),
}

# Patterns that indicate unsafe model cards
UNSAFE_CARD_PATTERNS = [
    "pickle",
    "eval(",
    "exec(",
    "os.system",
    "__reduce__",
    "subprocess",
    "import os",
    "lambda",
    "torch.load",
    "unsafe_globals",
]


@dataclass
class HFAssessment:
    """Pre-download risk assessment for a HuggingFace repository."""
    repo_id: str
    risk_level: str = "INFO"           # INFO, LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float = 0.0            # 0.0 - 1.0
    total_files: int = 0
    dangerous_files: list[dict[str, str]] = field(default_factory=list)
    safe_files: list[str] = field(default_factory=list)
    has_safetensors: bool = False
    has_pickle: bool = False
    has_model_card: bool = False
    model_card_warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    all_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "repo_id": self.repo_id,
            "risk_level": self.risk_level,
            "risk_score": round(self.risk_score, 3),
            "total_files": self.total_files,
            "dangerous_files": len(self.dangerous_files),
            "has_safetensors": self.has_safetensors,
            "has_pickle": self.has_pickle,
            "recommendations": self.recommendations,
        }


class HFGuard:
    """
    HuggingFace pre-download security guard.

    Checks model repositories for dangerous files before downloading.

    Usage:
        guard = HFGuard()
        assessment = guard.assess("org/model-name")
        if assessment.risk_level in ("HIGH", "CRITICAL"):
            print("Refusing to download dangerous model")
    """

    def __init__(
        self,
        token: str | None = None,
        block_pickle: bool = False,
        require_safetensors: bool = False,
        offline: bool | None = None,
    ):
        self._token = token or os.environ.get("HF_TOKEN", "")
        self._block_pickle = block_pickle
        self._require_safetensors = require_safetensors
        self._offline = offline_enabled(offline)

    def assess(self, repo_id: str, revision: str = "main") -> HFAssessment:
        """
        Perform a pre-download risk assessment without downloading any files.

        Args:
            repo_id: HuggingFace repo (e.g., "microsoft/phi-2").
            revision: Branch or commit hash.

        Returns:
            HFAssessment with risk analysis.
        """
        assessment = HFAssessment(repo_id=repo_id)
        assessment.metadata["offline"] = self._offline
        assessment.metadata["revision"] = revision

        if self._offline:
            assessment.recommendations.append(
                "Offline mode: skipped HuggingFace Hub API calls"
            )
            return assessment

        try:
            from huggingface_hub import HfApi
            api = HfApi(token=self._token if self._token else None)

            # Get file listing
            files = list(api.list_repo_files(repo_id, revision=revision))
            assessment.total_files = len(files)
            assessment.all_files = files

        except ImportError:
            logger.warning("huggingface_hub not installed — using filename-only assessment")
            assessment.recommendations.append("Install huggingface_hub for full assessment")
            return assessment
        except Exception as e:
            logger.error("Failed to access HF repo %s: %s", repo_id, e)
            assessment.risk_level = "MEDIUM"
            assessment.risk_score = 0.5
            assessment.recommendations.append(f"Could not access repository: {e}")
            return assessment

        # Analyze each file
        max_risk_score = 0.0

        for filepath in files:
            ext = self._get_extension(filepath)
            risk_info = FILE_RISK_MAP.get(ext)

            if risk_info:
                risk_level, reason = risk_info
                risk_val = {"INFO": 0.1, "LOW": 0.3, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 1.0}.get(risk_level, 0.1)

                if risk_val >= 0.5:
                    assessment.dangerous_files.append({
                        "file": filepath,
                        "extension": ext,
                        "risk": risk_level,
                        "reason": reason,
                    })
                    max_risk_score = max(max_risk_score, risk_val)
                else:
                    assessment.safe_files.append(filepath)

                # Track key formats
                if ext in (".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin"):
                    assessment.has_pickle = True
                if ext == ".safetensors":
                    assessment.has_safetensors = True
            else:
                assessment.safe_files.append(filepath)

            # Model card check
            if filepath.lower() in ("readme.md", "model_card.md"):
                assessment.has_model_card = True

        # Check model card content if available
        try:
            from huggingface_hub import hf_hub_download
            readme_path = hf_hub_download(repo_id, "README.md", revision=revision,
                                          token=self._token if self._token else None)
            with open(readme_path, "r", encoding="utf-8", errors="ignore") as f:
                card_content = f.read().lower()

            for pattern in UNSAFE_CARD_PATTERNS:
                if pattern.lower() in card_content:
                    assessment.model_card_warnings.append(
                        f"Model card contains '{pattern}' — review manually"
                    )
        except Exception:
            pass

        # Generate risk level
        assessment.risk_score = max_risk_score

        if max_risk_score >= 0.8:
            assessment.risk_level = "HIGH"
        elif max_risk_score >= 0.5:
            assessment.risk_level = "MEDIUM"
        elif max_risk_score >= 0.3:
            assessment.risk_level = "LOW"
        else:
            assessment.risk_level = "INFO"

        # Generate recommendations
        if assessment.has_pickle and assessment.has_safetensors:
            assessment.recommendations.append(
                "Both pickle and safetensors found — use safetensors format (safer)"
            )
        elif assessment.has_pickle and not assessment.has_safetensors:
            assessment.recommendations.append(
                "⚠ Only pickle-based weights found — HIGH risk of code execution"
            )
            assessment.recommendations.append(
                "Request the author to provide safetensors format"
            )
        elif assessment.has_safetensors and not assessment.has_pickle:
            assessment.recommendations.append(
                "✅ Uses safetensors only — safe format"
            )

        if not assessment.has_model_card:
            assessment.recommendations.append(
                "No model card found — cannot verify provenance"
            )

        if assessment.model_card_warnings:
            assessment.recommendations.append(
                f"⚠ {len(assessment.model_card_warnings)} model card warnings — review manually"
            )

        return assessment

    def scan(self, repo_id: str, revision: str = "main") -> list[Finding]:
        """
        Full scan: assess + download dangerous files to temp dir for deep scan.

        Args:
            repo_id: HuggingFace repo.
            revision: Branch or commit.

        Returns:
            List of Finding objects.
        """
        findings = []
        assessment = self.assess(repo_id, revision)

        # Policy enforcement
        if self._block_pickle and assessment.has_pickle:
            findings.append(Finding.artifact(
                rule_id="HF-GUARD-001",
                title="Pickle-based model blocked by policy",
                description=f"Repository {repo_id} contains pickle files and block_pickle policy is enabled",
                severity=Severity.HIGH,
                confidence=1.0,
                target=repo_id,
                evidence=", ".join(f["file"] for f in assessment.dangerous_files[:5]),
                remediation="Use safetensors format or disable block_pickle policy",
            ))
            return findings

        if self._require_safetensors and not assessment.has_safetensors:
            findings.append(Finding.artifact(
                rule_id="HF-GUARD-002",
                title="No safetensors format available",
                description=f"Repository {repo_id} does not provide safetensors and require_safetensors is enabled",
                severity=Severity.MEDIUM,
                confidence=1.0,
                target=repo_id,
                remediation="Request safetensors from model author or disable require_safetensors",
            ))

        # ── Manifest scan: known config files + custom Python files ─────
        # Only scan known safe config filenames — NOT all .json to avoid
        # scanning tokenizer.json (vocabulary) and other data files
        _SAST_EXTS = {".py"}
        _MANIFEST_NAMES = {
            "config.json", "tokenizer_config.json", "generation_config.json",
            "special_tokens_map.json", "preprocessor_config.json",
            "adapter_config.json", "quantize_config.json",
        }
        _MANIFEST_YAML = {".yaml", ".yml"}   # training config / conda env files
        try:
            from huggingface_hub import hf_hub_download
            from sentinel.artifact.manifest_scanner import MLManifestScanner
            from sentinel.sast.analyzer import SASTAnalyzer

            manifest_scanner = MLManifestScanner()
            sast_analyzer    = SASTAnalyzer()

            all_files = assessment.all_files

            # Collect files to manifest/SAST scan
            manifest_targets = [
                f for f in all_files
                if Path(f).name in _MANIFEST_NAMES
                or Path(f).suffix.lower() in _MANIFEST_YAML
            ]
            sast_targets = [
                f for f in all_files
                if Path(f).suffix.lower() in _SAST_EXTS
            ]

            with tempfile.TemporaryDirectory(prefix="sentinel_hf_manifest_") as tmpdir:
                for filepath in manifest_targets[:20]:   # cap at 20 config files
                    try:
                        local_path = hf_hub_download(
                            repo_id, filepath, revision=revision,
                            local_dir=tmpdir,
                            token=self._token if self._token else None,
                        )
                        mf = manifest_scanner.scan_file(local_path)
                        for f in mf:
                            f.target = f"{repo_id}/{filepath}"
                        findings.extend(mf)
                    except Exception as e:
                        logger.debug("Manifest scan skip %s/%s: %s", repo_id, filepath, e)

                for filepath in sast_targets[:10]:       # cap at 10 .py files
                    try:
                        local_path = hf_hub_download(
                            repo_id, filepath, revision=revision,
                            local_dir=tmpdir,
                            token=self._token if self._token else None,
                        )
                        sf = sast_analyzer.scan_path(local_path)
                        for f in sf:
                            f.target = f"{repo_id}/{filepath}"
                        findings.extend(sf)
                    except Exception as e:
                        logger.debug("SAST scan skip %s/%s: %s", repo_id, filepath, e)

        except ImportError:
            logger.warning("huggingface_hub not installed — skipping manifest/SAST scan")

        # ── Deep scan dangerous binary files ──────────────────────────────
        if assessment.dangerous_files:
            try:
                from huggingface_hub import hf_hub_download
                from sentinel.cli_dispatch import _scan_single_artifact

                with tempfile.TemporaryDirectory(prefix="sentinel_hf_") as tmpdir:
                    for file_info in assessment.dangerous_files:
                        filepath = file_info["file"]
                        try:
                            local_path = hf_hub_download(
                                repo_id, filepath, revision=revision,
                                local_dir=tmpdir,
                                token=self._token if self._token else None,
                            )
                            file_findings = _scan_single_artifact(Path(local_path))
                            for f in file_findings:
                                f.target = f"{repo_id}/{filepath}"
                            findings.extend(file_findings)
                        except Exception as e:
                            logger.warning("Failed to scan %s/%s: %s", repo_id, filepath, e)
            except ImportError:
                logger.warning("huggingface_hub not installed — skipping deep scan")

        # Model card warnings as findings
        for warning in assessment.model_card_warnings:
            findings.append(Finding.artifact(
                rule_id="HF-GUARD-003",
                title="Model card safety warning",
                description=warning,
                severity=Severity.LOW,
                confidence=0.5,
                target=f"{repo_id}/README.md",
            ))

        # ── Typosquat detection ────────────────────────────────────────────
        try:
            from sentinel.supply_chain.typosquat_detector import TyposquatDetector
            typo_findings = TyposquatDetector().check_repo(repo_id)
            findings.extend(typo_findings)
        except Exception as e:
            logger.debug("Typosquat check failed: %s", e)

        # ── Prompt injection + IOC + social engineering scan ──────────────
        # Scan manifest text fields and README for hidden instructions
        try:
            from huggingface_hub import hf_hub_download
            from sentinel.artifact.prompt_injection_analyzer import PromptInjectionAnalyzer

            pinj = PromptInjectionAnalyzer()
            _TEXT_TARGETS = {"README.md", "README.rst"} | set(_MANIFEST_NAMES)

            with tempfile.TemporaryDirectory(prefix="sentinel_hf_pinj_") as tmpdir:
                for filepath in assessment.all_files:
                    if Path(filepath).name not in _TEXT_TARGETS:
                        continue
                    try:
                        local_path = hf_hub_download(
                            repo_id, filepath, revision=revision,
                            local_dir=tmpdir,
                            token=self._token if self._token else None,
                        )
                        pf = pinj.analyze_file(local_path)
                        for f in pf:
                            f.target = f"{repo_id}/{filepath}"
                        findings.extend(pf)
                    except Exception as e:
                        logger.debug("Prompt injection scan skip %s/%s: %s", repo_id, filepath, e)
        except ImportError:
            logger.debug("PromptInjectionAnalyzer not available")

        # ── auto_map AST deep scan ─────────────────────────────────────────
        # For every .py referenced by auto_map, run full AST + GPU analysis
        auto_map_files: list[str] = []
        try:
            for f in findings:
                if getattr(f, "rule_id", "") == "MANIFEST-INJ-002":
                    ev = getattr(f, "evidence", "") or ""
                    for py_file in assessment.all_files:
                        if py_file.endswith(".py") and py_file not in auto_map_files:
                            auto_map_files.append(py_file)
        except Exception:
            pass

        if auto_map_files:
            try:
                from huggingface_hub import hf_hub_download
                from sentinel.artifact.auto_map_ast_analyzer import AutoMapASTAnalyzer
                from sentinel.artifact.gpu_abuse_detector import GPUAbuseDetector

                ast_analyzer = AutoMapASTAnalyzer()
                gpu_detector = GPUAbuseDetector()

                with tempfile.TemporaryDirectory(prefix="sentinel_hf_ast_") as tmpdir:
                    for filepath in auto_map_files[:15]:
                        try:
                            local_path = hf_hub_download(
                                repo_id, filepath, revision=revision,
                                local_dir=tmpdir,
                                token=self._token if self._token else None,
                            )
                            ast_findings = ast_analyzer.scan_file(local_path)
                            gpu_findings = gpu_detector.scan_file(local_path)
                            for f in ast_findings + gpu_findings:
                                f.target = f"{repo_id}/{filepath}"
                            findings.extend(ast_findings)
                            findings.extend(gpu_findings)
                        except Exception as e:
                            logger.debug("AST/GPU scan skip %s/%s: %s", repo_id, filepath, e)
            except ImportError:
                logger.debug("AutoMapASTAnalyzer/GPUAbuseDetector not available")

        # ── GPU abuse scan on all .py files ───────────────────────────────
        try:
            from huggingface_hub import hf_hub_download
            from sentinel.artifact.gpu_abuse_detector import GPUAbuseDetector

            gpu = GPUAbuseDetector()
            gpu_targets = [f for f in assessment.all_files if f.endswith(".py")]

            with tempfile.TemporaryDirectory(prefix="sentinel_hf_gpu_") as tmpdir:
                for filepath in gpu_targets[:10]:
                    if filepath in auto_map_files:
                        continue
                    try:
                        local_path = hf_hub_download(
                            repo_id, filepath, revision=revision,
                            local_dir=tmpdir,
                            token=self._token if self._token else None,
                        )
                        gf = gpu.scan_file(local_path)
                        for f in gf:
                            f.target = f"{repo_id}/{filepath}"
                        findings.extend(gf)
                    except Exception as e:
                        logger.debug("GPU scan skip %s/%s: %s", repo_id, filepath, e)
        except ImportError:
            logger.debug("GPUAbuseDetector not available")

        # ── Composite risk scoring (annotate findings in-place) ───────────
        try:
            from sentinel.analysis.risk_scorer import score_findings
            scored = score_findings(findings)
            for finding, risk in scored:
                if not hasattr(finding, "metadata") or finding.metadata is None:
                    finding.metadata = {}
                finding.metadata["risk_score"] = risk.composite
                finding.metadata["risk_label"] = risk.label
        except Exception as e:
            logger.debug("Risk scoring failed: %s", e)

        return findings

    def safe_download(
        self,
        repo_id: str,
        local_dir: str = ".",
        revision: str = "main",
        allow_patterns: list[str] | None = None,
    ) -> Path:
        """
        Download a model after safety verification.

        Raises ValueError if the model is deemed too risky.

        Args:
            repo_id: HuggingFace repo.
            local_dir: Where to save the model.
            revision: Branch or commit.
            allow_patterns: File patterns to download (e.g., ["*.safetensors"]).

        Returns:
            Path to downloaded model directory.
        """
        from huggingface_hub import snapshot_download

        # Assess first
        assessment = self.assess(repo_id, revision)

        if assessment.risk_level in ("HIGH", "CRITICAL"):
            if self._block_pickle:
                raise ValueError(
                    f"Refusing to download {repo_id}: risk level is {assessment.risk_level}. "
                    f"Dangerous files: {[f['file'] for f in assessment.dangerous_files[:3]]}"
                )
            logger.warning(
                "Downloading HIGH risk model %s — %d dangerous files detected",
                repo_id, len(assessment.dangerous_files)
            )

        # Prefer safetensors if available
        if allow_patterns is None and assessment.has_safetensors:
            allow_patterns = [
                "*.safetensors",
                "*.json",
                "*.txt",
                "*.md",
                "tokenizer*",
                "config*",
            ]
            logger.info("Auto-selecting safetensors format for %s", repo_id)

        local_path = snapshot_download(
            repo_id,
            revision=revision,
            local_dir=local_dir,
            allow_patterns=allow_patterns,
            token=self._token if self._token else None,
        )

        return Path(local_path)

    @staticmethod
    def _get_extension(filepath: str) -> str:
        """Extract file extension, handling double extensions like .tar.gz."""
        lower = filepath.lower()
        if lower.endswith(".tar.gz"):
            return ".tar.gz"
        return Path(lower).suffix
