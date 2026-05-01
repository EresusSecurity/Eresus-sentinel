"""
Eresus Sentinel — CLI Dispatch Module.

Internal dispatch layer used by the CLI and SDK to route scan commands
to the appropriate security module. Each dispatcher returns a list of
Finding objects.

Usage:
    # Called internally by sentinel.cli
    findings = dispatch_artifact("/path/to/model.pt")
    findings = dispatch_firewall_input("user prompt")

    # Or standalone
    python3 -m sentinel.cli_dispatch --module artifact --target /path/to/model.pt

Available modules:
    artifact         — Scan model files for backdoors
    firewall_input   — Scan prompts through input guardrails
    firewall_output  — Scan responses through output guardrails
    sast             — Run SAST analysis on source code
    agent            — Validate MCP/agent configurations
    supply_chain     — Audit model supply chain
    diff             — Scan git diffs for ML anti-patterns
    notebook         — Scan Jupyter notebooks
    redteam          — Run red team probes (requires target LLM)
    validate_rules   — Validate YAML rule files
    serve            — Start REST API server

Output:
    JSON array of Finding objects on stdout.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from sentinel.finding import Finding, Location, Severity

logger = logging.getLogger(__name__)


def _existing_file_target(target: str) -> Path | None:
    """Return a path only when a firewall target is plausibly a file path."""
    if not target or len(target) > 4096 or any(ch in target for ch in "\x00\r\n"):
        return None
    try:
        path = Path(target)
        return path if path.is_file() else None
    except OSError:
        return None


# ── Post-Processing Pipeline ──────────────────────────────────────────

def _load_config() -> dict:
    """Load sentinel.toml config if available."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return {}
    config_path = Path(__file__).resolve().parent.parent.parent / "sentinel.toml"
    if not config_path.exists():
        return {}
    with open(config_path, "rb") as f:
        return tomllib.load(f)


def _post_process(findings: list[Finding], project_root: str | None = None) -> list[Finding]:
    """Apply suppression, severity filter, shadow mode, and AI FP reduction."""
    if not findings:
        return findings

    config = _load_config()
    engine_cfg = config.get("engine", {})
    suppression_cfg = config.get("suppression", {})

    # 1. Suppression engine
    from sentinel.suppression import SuppressionEngine
    suppression = SuppressionEngine(
        ignore_file=suppression_cfg.get("ignore_file", ".sentinelignore"),
        allowed_rules=suppression_cfg.get("allowed_rules", []),
        ignore_paths=suppression_cfg.get("ignore_paths", []),
        hash_file=suppression_cfg.get("hash_file", ".sentinel-suppressions.yaml"),
        shadow_mode=engine_cfg.get("shadow_mode", False),
        project_root=project_root,
    )
    findings = suppression.filter(findings)

    # 2. Minimum severity filter
    min_sev = engine_cfg.get("min_severity", "MEDIUM")
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = sev_order.get(min_sev.lower(), 2)
    findings = [
        f for f in findings
        if sev_order.get(
            (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower(), 0
        ) >= threshold
    ]

    # 3. Shadow mode: downgrade BLOCK -> WARN (set action on findings)
    if suppression.shadow_mode:
        for f in findings:
            if hasattr(f, "action") and getattr(f, "action", None) == "BLOCK":
                f.action = "WARN"
        logger.info("Shadow mode: all BLOCK actions downgraded to WARN")

    # 4. Action policy enforcement
    action_policy = engine_cfg.get("action_policy", "balanced")
    if action_policy == "advisory":
        for f in findings:
            if hasattr(f, "action"):
                f.action = "WARN"

    # 5. AI-assisted FP reduction (only when AI is enabled)
    ai_cfg = config.get("ai", {})
    if ai_cfg.get("enabled", False) and ai_cfg.get("features", {}).get("false_positive_reduction", False):
        try:
            from sentinel.ai.reasoning import AIReasoningLayer
            layer = AIReasoningLayer()
            if layer.is_enabled():
                findings = layer.reduce_false_positives(findings)
                logger.info("AI FP reduction applied")
        except Exception as e:
            logger.debug("AI FP reduction skipped: %s", e)

    return findings


# ── Module Dispatchers ────────────────────────────────────────────────

def dispatch_artifact(target: str) -> list[Finding]:
    """Run artifact scanner on target."""
    findings = []
    path = Path(target)

    if path.is_file():
        findings.extend(_scan_single_artifact(path))
    elif path.is_dir():
        for file_path in path.rglob("*"):
            if file_path.is_file():
                findings.extend(_scan_single_artifact(file_path))
    else:
        logger.warning("Target not found: %s", target)

    return findings


def _findings_from_artifact_result(result) -> list[Finding]:
    if result is None:
        return []
    if isinstance(result, list):
        return result
    findings = getattr(result, "findings", None)
    if findings is not None:
        return list(findings)
    return list(result)


def _scan_single_artifact(path: Path) -> list[Finding]:
    """Scan a single model artifact file with safety limits."""
    from sentinel.artifact import (
        GGUFAnalyzer,
        LlamaFileScanner,
        PickleScanner,
        SafetensorsValidator,
        TensorFlowScanner,
        TFLiteScanner,
        TorchScanner,
        TorchScriptScanner,
    )
    from sentinel.artifact.archive_slip import ArchiveSlipDetector
    from sentinel.artifact.catboost_scanner import CatBoostScanner
    from sentinel.artifact.coreml_scanner import CoreMLScanner
    from sentinel.artifact.flax_scanner import FlaxScanner
    from sentinel.artifact.keras_scanner import KerasScanner
    from sentinel.artifact.lightgbm_scanner import LightGBMScanner
    from sentinel.artifact.mxnet_scanner import MXNetScanner
    from sentinel.artifact.nemo_scanner import NeMoScanner
    from sentinel.artifact.numpy_scanner import NumpyScanner
    from sentinel.artifact.onnx_scanner import ONNXScanner
    from sentinel.artifact.openvino_scanner import OpenVINOScanner
    from sentinel.artifact.paddle_scanner import PaddleScanner
    from sentinel.artifact.pmml_scanner import PMMLScanner
    from sentinel.artifact.r_serialized_scanner import RSerializedScanner
    from sentinel.artifact.sevenz_scanner import SevenZipScanner
    from sentinel.artifact.skops_scanner import SkopsScanner
    from sentinel.artifact.torchserve_scanner import (
        ExecuTorchScanner,
        TensorRTScanner,
        Torch7Scanner,
        TorchServeScanner,
    )
    from sentinel.artifact.xgboost_scanner import XGBoostScanner
    from sentinel.artifact.yaml_scanner import YamlScanner
    from sentinel.finding import Severity
    from sentinel.scan_safety import FileTooLargeError, check_file_size

    # Pre-check file size before scanning
    try:
        check_file_size(path)
    except FileTooLargeError as e:
        return [Finding.artifact(
            rule_id="SCAN-SIZE",
            title="File too large to scan safely",
            description=str(e),
            severity=Severity.HIGH,
            target=str(path),
            cwe_ids=["CWE-400"],
        )]

    findings = []
    suffix = path.suffix.lower()
    name_lower = path.name.lower()

    if suffix == ".zip":
        import zipfile
        archive_findings = ArchiveSlipDetector().scan_file(str(path))
        findings.extend(archive_findings)
        if zipfile.is_zipfile(str(path)):
            try:
                with zipfile.ZipFile(str(path), "r") as zf:
                    if any(n.startswith("code/") for n in zf.namelist()):
                        findings.extend(TorchScriptScanner().scan_file(str(path)))
            except zipfile.BadZipFile:
                pass
        return findings

    scanner_map = {
        (".pkl", ".pickle", ".p", ".dill", ".dat", ".data"): PickleScanner,
        (".safetensors",): SafetensorsValidator,
        (".gguf",): GGUFAnalyzer,
        (".pb",): TensorFlowScanner,
        (".torchscript", ".ptc"): TorchScriptScanner,
        (".tflite",): TFLiteScanner,
        (".llamafile",): LlamaFileScanner,
        (".onnx",): ONNXScanner,
        (".keras",): KerasScanner,
        (".h5", ".hdf5"): KerasScanner,
        (".xgb", ".ubj", ".model"): XGBoostScanner,
        (".joblib",): XGBoostScanner,
        (".npy",): NumpyScanner,
        (".npz",): NumpyScanner,
        (".yaml", ".yml"): YamlScanner,
        (".nemo",): NeMoScanner,
        (".mar",): TorchServeScanner,
        (".tar", ".tar.gz", ".tgz", ".zip"): ArchiveSlipDetector,
        (".7z",): SevenZipScanner,
        # New format scanners
        (".cbm",): CatBoostScanner,
        (".mlmodel", ".mlpackage"): CoreMLScanner,
        (".msgpack", ".orbax", ".flax"): FlaxScanner,
        (".lgb", ".lightgbm"): LightGBMScanner,
        (".params",): MXNetScanner,
        (".pdmodel", ".pdiparams", ".pdparams"): PaddleScanner,
        (".pmml",): PMMLScanner,
        (".rds", ".rda", ".rdata"): RSerializedScanner,
        (".skops",): SkopsScanner,
        (".t7", ".th"): Torch7Scanner,
        (".pte", ".ptl"): ExecuTorchScanner,
        (".engine", ".plan", ".trt"): TensorRTScanner,
        (".xml",): OpenVINOScanner,
    }

    for extensions, scanner_cls in scanner_map.items():
        if any(name_lower.endswith(ext) for ext in extensions):
            scanner = scanner_cls()
            findings.extend(_findings_from_artifact_result(scanner.scan_file(str(path))))
            return findings

    # PyTorch: check if TorchScript archive (ZIP with code/ dir)
    if suffix in (".pt", ".pth", ".bin", ".ckpt"):
        import zipfile
        if zipfile.is_zipfile(str(path)):
            try:
                with zipfile.ZipFile(str(path), "r") as zf:
                    if any(n.startswith("code/") for n in zf.namelist()):
                        findings.extend(TorchScriptScanner().scan_file(str(path)))
                        return findings
            except zipfile.BadZipFile:
                pass
        findings.extend(TorchScanner().scan_file(path))

    # Watermark and distribution shift checks (all supported formats)
    _WATERMARK_EXTS = frozenset({".gguf", ".safetensors", ".pt", ".pth", ".bin", ".ckpt"})
    _DIST_SHIFT_EXTS = frozenset({".safetensors", ".pt", ".pth", ".bin", ".ckpt"})
    if suffix in _WATERMARK_EXTS:
        try:
            from sentinel.artifact.watermark_detector import WatermarkDetector
            findings.extend(WatermarkDetector().scan_file(path))
        except Exception as exc:
            logger.debug("WatermarkDetector: %s", exc)
    if suffix in _DIST_SHIFT_EXTS:
        try:
            from sentinel.artifact.distribution_shift_detector import DistributionShiftDetector
            findings.extend(DistributionShiftDetector().scan_file(path))
        except Exception as exc:
            logger.debug("DistributionShiftDetector: %s", exc)

    return findings


def dispatch_firewall_input(target: str) -> list[Finding]:
    """Run ALL input firewall scanners on target."""
    from sentinel.policy import PolicyEngine
    engine = PolicyEngine.default()
    pipeline = engine.build_input_pipeline()

    findings = []
    path = _existing_file_target(target)

    if path is not None:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                result = pipeline.scan(line)
                for finding in result.findings:
                    finding.target = f"{target}:{line_num}"
                findings.extend(result.findings)
    else:
        result = pipeline.scan(target)
        findings.extend(result.findings)

    return findings


def dispatch_firewall_output(target: str) -> list[Finding]:
    """Run ALL output firewall scanners on target."""
    from sentinel.policy import PolicyEngine
    engine = PolicyEngine.default()
    pipeline = engine.build_output_pipeline()

    findings = []
    path = _existing_file_target(target)

    if path is not None:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        result = pipeline.scan(content, prompt="")
        findings.extend(result.findings)
    else:
        result = pipeline.scan(target, prompt="")
        findings.extend(result.findings)

    return findings


def dispatch_sast(target: str) -> list[Finding]:
    """Run SAST analysis on source code."""
    from sentinel.sast.analyzer import SASTAnalyzer
    analyzer = SASTAnalyzer()
    return analyzer.scan_path(target)


def dispatch_agent(target: str) -> list[Finding]:
    """Run agent/MCP security validation."""
    from sentinel.agent.a2a_scanner import A2AScanner
    from sentinel.agent.mcp_validator import MCPValidator
    from sentinel.agent.skill_scanner import SkillScanner

    a2a_scanner = A2AScanner()
    skill_scanner = SkillScanner()
    validator = MCPValidator()
    path = Path(target)
    findings: list[Finding] = []

    def _is_probable_mcp_manifest(file_path: Path) -> bool:
        if file_path.suffix.lower() not in {".json", ".yaml", ".yml"}:
            return False
        name = file_path.name.lower()
        if any(token in name for token in ("mcp", "tool", "manifest")):
            return True
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            if file_path.suffix.lower() == ".json":
                data = json.loads(text)
            else:
                import yaml
                data = yaml.safe_load(text)
        except Exception:
            return False
        if isinstance(data, dict):
            keys = {str(key) for key in data}
            return bool(keys & {"tools", "prompts", "resources", "inputSchema", "input_schema"})
        if isinstance(data, list):
            return any(isinstance(item, dict) and ("inputSchema" in item or "input_schema" in item) for item in data)
        return False

    def _is_probable_skill_file(file_path: Path) -> bool:
        if file_path.suffix.lower() not in {".md", ".mdc", ".yaml", ".yml", ".json"}:
            return False
        lowered_parts = {part.lower() for part in file_path.parts}
        name = file_path.name.lower()
        stem = file_path.stem.lower()
        if name == "skill.md" or "skills" in lowered_parts:
            return True
        return any(token in stem for token in ("skill", "plugin", "agent", "command"))

    def _skill_findings(file_path: Path) -> list[Finding]:
        if not _is_probable_skill_file(file_path):
            return []
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        converted: list[Finding] = []
        for item in skill_scanner.scan_skill(text, file_path.name):
            try:
                severity = Severity[str(item.severity).upper()]
            except KeyError:
                severity = Severity.MEDIUM
            line_start = None
            if item.location and ":" in item.location:
                maybe_line = item.location.rsplit(":", 1)[-1]
                if maybe_line.isdigit():
                    line_start = int(maybe_line)
            rule_id = item.rule_id or f"SKILL-{item.finding_type.upper().replace('_', '-')}"
            tags = ["skill", item.finding_type]
            if item.category:
                tags.append(item.category)
            tags.extend(item.taxonomy or [])
            converted.append(Finding.agent_mcp(
                rule_id=rule_id,
                title=f"Agent skill issue: {item.finding_type.replace('_', ' ')}",
                description=item.description,
                severity=severity,
                target=str(file_path),
                evidence=item.evidence,
                confidence=0.9,
                remediation=item.recommendation,
                cwe_ids=[item.cwe] if item.cwe else [],
                location=Location(file=str(file_path), line_start=line_start) if line_start else None,
                tags=tags,
            ))
        return converted

    if path.is_dir():
        for file_path in path.rglob("*"):
            if not file_path.is_file():
                continue
            if _is_probable_mcp_manifest(file_path):
                findings.extend(validator.validate_file(str(file_path)))
            findings.extend(_skill_findings(file_path))
        findings.extend(a2a_scanner.scan_path(path))
    elif path.is_file():
        if _is_probable_mcp_manifest(path):
            findings.extend(validator.validate_file(str(path)))
        findings.extend(_skill_findings(path))
        findings.extend(a2a_scanner.scan_path(path))
    else:
        logger.warning("Target not found: %s", target)

    return findings


def dispatch_supply_chain(target: str) -> list[Finding]:
    """Run supply chain audit."""
    from sentinel.supply_chain.dependency import DependencyAuditor
    from sentinel.supply_chain.provenance import ProvenanceVerifier

    findings = []
    verifier = ProvenanceVerifier()
    findings.extend(verifier.audit_directory(target))
    auditor = DependencyAuditor()
    findings.extend(auditor.audit_directory(target))
    return findings


def dispatch_diff(target: str) -> list[Finding]:
    """Run diff scanner on git diff, commit, or patch file."""
    import subprocess as _sp
    import sys

    from sentinel.diff_scanner import DiffScanner
    scanner = DiffScanner()

    if target == "-":
        # Read unified diff from stdin
        diff_text = sys.stdin.read()
        return scanner.scan_diff(diff_text)
    elif target == "--staged":
        return scanner.scan_git_staged()
    elif target == "--unstaged":
        return scanner.scan_git_unstaged()
    elif target == "--all":
        return scanner.scan_git_all()
    elif ".." in target:
        parts = target.split("..", 1)
        return scanner.scan_commit_range(parts[0], parts[1])
    elif target.endswith((".patch", ".diff")):
        return scanner.scan_file(target)
    elif len(target) >= 7 and all(c in '0123456789abcdef' for c in target[:7]):
        return scanner.scan_commit(target)
    else:
        # Try as a file path first
        path = Path(target)
        if path.is_file():
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                diff_text = f.read()
            return scanner.scan_diff(diff_text)
        # Try as a git ref (HEAD~1, branch name, tag, etc.)
        try:
            result = _sp.run(
                ["git", "diff", target],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                return scanner.scan_diff(result.stdout)
        except Exception:
            pass
        # Last resort: try as a single commit
        try:
            result = _sp.run(
                ["git", "diff", f"{target}^", target],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                return scanner.scan_diff(result.stdout)
        except Exception:
            pass
        return []


def dispatch_notebook(target: str) -> list[Finding]:
    """Run notebook security scanner on .ipynb files or directories."""
    from sentinel.notebook_scanner import NotebookScanner

    scanner = NotebookScanner()
    path = Path(target)

    if path.is_dir():
        results = scanner.scan_directory(str(path))
    elif path.is_file() and path.suffix == ".ipynb":
        results = [scanner.scan_file(str(path))]
    else:
        logger.error("Target must be a .ipynb file or directory: %s", target)
        return []

    all_findings = []
    for result in results:
        if result.error:
            logger.warning("Notebook scan error for %s: %s", result.path, result.error)
            all_findings.append(Finding.sast(
                rule_id="NOTEBOOK-000",
                title="Notebook parse error",
                description=(
                    "The notebook could not be parsed, so Sentinel could not "
                    "inspect its cells or outputs."
                ),
                severity=Severity.MEDIUM,
                confidence=1.0,
                target=result.path,
                evidence=result.error,
                cwe_ids=["CWE-20"],
                tags=["category:notebook", "category:parse-error"],
                remediation="Fix the .ipynb JSON structure and re-run the scan.",
            ))
        all_findings.extend(result.findings)
    return all_findings


def dispatch_redteam(target: str) -> list[Finding]:
    """Run red team probes against a target LLM."""
    from sentinel.redteam.orchestrator import RedTeamOrchestrator

    orchestrator = RedTeamOrchestrator()
    report = orchestrator.run_quick_scan(target)
    return report.findings if hasattr(report, 'findings') else []


def dispatch_validate_rules(target: str) -> list[Finding]:
    """Validate all YAML pattern databases load correctly."""
    from sentinel.data_loader import load_data

    yaml_files = [
        "toxicity.yaml", "sentiment.yaml", "bias.yaml",
        "ban_topics.yaml", "ban_code.yaml", "competitors.yaml",
        "refusal.yaml", "emotion.yaml",
    ]

    results = {}
    errors = []
    for filename in yaml_files:
        try:
            data = load_data(filename)
            results[filename] = len(data) if isinstance(data, dict) else 0
        except Exception as e:
            errors.append(f"{filename}: {e}")
            results[filename] = -1

    summary = {"yaml_files": results, "errors": errors, "total": len(yaml_files)}
    import logging
    logging.getLogger("sentinel.validate").debug(json.dumps(summary, default=str))
    return []


def dispatch_serve(target: str, **kwargs) -> list[Finding]:
    """Start the REST API server."""
    import os
    policy = kwargs.get("policy", "")
    host, port = "0.0.0.0", 8080

    if ":" in target:
        parts = target.rsplit(":", 1)
        host = parts[0]
        port = int(parts[1])

    if policy:
        os.environ["SENTINEL_POLICY"] = policy

    try:
        import uvicorn

        from sentinel.server import create_app
        app = create_app(policy_path=policy or None)
        uvicorn.run(app, host=host, port=port, server_header=False)
    except ImportError:
        print(json.dumps({"error": "uvicorn not installed. Run: pip install uvicorn fastapi"}))

    return []


def dispatch_huggingface(target: str) -> list[Finding]:
    """Scan a HuggingFace model repository."""
    import os
    from urllib.parse import urlparse

    from sentinel.artifact.huggingface_scanner import HuggingFaceScanner

    scanner = HuggingFaceScanner()
    # Use scan_remote_repo for repo IDs, scan_local_repo for local paths
    if os.path.exists(target):
        return scanner.scan_local_repo(target)

    parsed = urlparse(target)
    if parsed.netloc in {"huggingface.co", "www.huggingface.co"}:
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2:
            target = "/".join(parts[:2])

    return scanner.scan_remote_repo(target)


def dispatch_hf_bulk(
    *,
    owner: str | None = None,
    task: str | None = None,
    tags: list[str] | None = None,
    limit: int = 1000,
    min_downloads: int = 0,
    mode: str = "guard",
    concurrency: int = 4,
    output_path: str | None = None,
    resume: bool = False,
) -> list[Finding]:
    """Bulk-scan HuggingFace Hub repositories and return aggregate findings."""
    from sentinel.hf_bulk_scanner import HFBulkScanner

    scanner = HFBulkScanner(concurrency=concurrency)
    results = scanner.scan_bulk(
        owner=owner,
        task=task,
        tags=tags,
        limit=limit,
        min_downloads=min_downloads,
        mode=mode,
        output_path=output_path,
        resume=resume,
    )

    # Synthesise findings from aggregate results for pipeline integration
    from sentinel.finding import Finding, Severity

    findings: list[Finding] = []
    for result in results:
        if result.risk_level in ("CRITICAL", "HIGH"):
            sev = Severity.CRITICAL if result.risk_level == "CRITICAL" else Severity.HIGH
            findings.append(Finding.artifact(
                rule_id="HF-BULK-001",
                title=f"High-risk HuggingFace repository: {result.repo_id}",
                description=(
                    f"Bulk scan identified {result.finding_count} finding(s) in "
                    f"{result.repo_id} (risk={result.risk_level})."
                ),
                severity=sev,
                target=result.repo_id,
                evidence=f"finding_count={result.finding_count} mode={result.mode}",
                confidence=0.9,
            ))
    return findings


def dispatch_multi_agent(
    agents: list[dict],
    scenarios: list[str] | None = None,
) -> list[Finding]:
    """Run multi-agent security tests from manifest configs.

    Args:
        agents:    List of agent manifest dicts with at minimum a ``name`` key.
        scenarios: List of scenario names to run; defaults to all.
    """
    from sentinel.agent.multi_agent import (
        CascadingHallucinationDetector,
        CrossContaminationTester,
    )

    findings: list[Finding] = []
    enabled = set(scenarios) if scenarios else {"hallucination", "contamination", "memory_poisoning"}

    # Run static manifest analysis for each pair of agents
    agent_pairs = [
        (agents[i], agents[j])
        for i in range(len(agents))
        for j in range(i + 1, len(agents))
    ]

    if "hallucination" in enabled:
        detector = CascadingHallucinationDetector()
        for ma, mb in agent_pairs:
            findings.extend(detector.run_from_manifests(ma, mb))

    if "contamination" in enabled:
        tester = CrossContaminationTester()
        for ma, mb in agent_pairs:
            findings.extend(tester.run_from_manifests(ma, mb))

    return findings


def dispatch_sbom(target: str) -> list[Finding]:
    """Generate SBOM for scanned model artifacts."""
    from sentinel.integrations import LicenseChecker, SBOMGenerator
    findings: list[Finding] = []
    sbom_gen = SBOMGenerator()
    license_checker = LicenseChecker()
    path = Path(target)
    if path.is_file():
        sbom = sbom_gen.generate_from_file(str(path))
        for comp in sbom.get("components", []):
            lic = comp.get("license")
            if lic:
                cat = license_checker.categorize(lic)
                if cat.name in ("BLOCKED", "COPYLEFT"):
                    findings.append(Finding.artifact(
                        rule_id="LICENSE-001", title=f"License issue: {lic}",
                        description=f"Component {comp.get('name', '?')} uses {cat.name} license",
                        severity=Severity.HIGH if cat.name == "BLOCKED" else Severity.MEDIUM,
                        target=str(path),
                    ))
        import json
        print(json.dumps(sbom, default=str, indent=2))
    elif path.is_dir():
        sbom = sbom_gen.generate_from_directory(str(path))
        import json
        print(json.dumps(sbom, default=str, indent=2))
    return findings


def dispatch_doctor(target: str) -> list[Finding]:
    """Run health check diagnostics."""
    import json

    from sentinel.scanner_selection import DoctorCheck
    doctor = DoctorCheck()
    results = doctor.run()
    print(json.dumps(results, default=str, indent=2))
    return []


def dispatch_metadata(target: str) -> list[Finding]:
    """Extract metadata from model file without deserialization."""
    import json

    from sentinel.scanner_selection import MetadataExtractor
    extractor = MetadataExtractor()
    meta = extractor.extract(target)
    print(json.dumps(meta, default=str, indent=2))
    return []


# ── Module dispatcher map ─────────────────────────────────────────

DISPATCHERS = {
    "artifact": dispatch_artifact,
    "firewall_input": dispatch_firewall_input,
    "firewall_output": dispatch_firewall_output,
    "sast": dispatch_sast,
    "agent": dispatch_agent,
    "supply_chain": dispatch_supply_chain,
    "diff": dispatch_diff,
    "notebook": dispatch_notebook,
    "redteam": dispatch_redteam,
    "huggingface": dispatch_huggingface,
    "validate_rules": dispatch_validate_rules,
    "serve": dispatch_serve,
    "sbom": dispatch_sbom,
    "doctor": dispatch_doctor,
    "metadata": dispatch_metadata,
}


def main():
    parser = argparse.ArgumentParser(
        description="Eresus Sentinel Module Dispatcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available modules:
  artifact         Scan model files for backdoors
  firewall_input   Scan prompts through input guardrails (24 scanners)
  firewall_output  Scan responses through output guardrails (24 scanners)
  sast             Run SAST analysis on source code
  agent            Validate MCP/agent configurations
  supply_chain     Audit model supply chain
  diff             Scan git diffs for ML anti-patterns
  notebook         Scan Jupyter notebooks
  redteam          Run red team probes
  validate_rules   Validate YAML pattern databases
  serve            Start REST API server
  sbom             Generate SBOM for model artifacts
  doctor           Run health check diagnostics
  metadata         Extract model metadata without deserialization
        """,
    )
    parser.add_argument("--module", required=True, choices=DISPATCHERS.keys(),
                        help="Security module to run")
    parser.add_argument("--target", required=True,
                        help="Target path, text, or URL to scan")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--policy", default="",
                        help="Path to YAML policy file (for serve module)")
    parser.add_argument("--output-sarif", default="",
                        help="Write SARIF output to file")
    parser.add_argument("--scanners", default="",
                        help="Comma-separated scanner IDs to enable (include filter)")
    parser.add_argument("--exclude-scanner", default="",
                        help="Comma-separated scanner IDs to exclude")
    parser.add_argument("--list-scanners", action="store_true",
                        help="List all available scanners and exit")
    parser.add_argument("--stream", action="store_true",
                        help="Stream mode: scan files one at a time")
    parser.add_argument("--max-size", type=int, default=0,
                        help="Max file size in bytes for streaming mode")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be scanned without scanning")
    parser.add_argument("--no-cache", action="store_true",
                        help="Disable scan result caching")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    # List scanners mode
    if args.list_scanners:
        from sentinel.scanner_selection import ScannerSelection
        scanners = ScannerSelection.list_all()
        print(json.dumps(scanners, default=str, indent=2))
        return

    dispatcher = DISPATCHERS[args.module]

    try:
        if args.module == "serve":
            findings = dispatcher(args.target, policy=args.policy)
        else:
            findings = dispatcher(args.target)
    except Exception as e:
        logger.error("Module %s failed: %s", args.module, e)
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    # Post-process: suppression, severity filter, shadow mode, AI FP reduction
    if args.module not in ("serve", "validate_rules", "doctor", "metadata"):
        findings = _post_process(findings)

    # Scanner selection filter
    if args.scanners or args.exclude_scanner:
        from sentinel.scanner_selection import ScannerSelection
        include = args.scanners.split(",") if args.scanners else None
        exclude = args.exclude_scanner.split(",") if args.exclude_scanner else None
        selection = ScannerSelection(include=include, exclude=exclude)
        findings = [f for f in findings if selection.is_enabled(f.rule_id or "")]

    # SARIF output
    if args.output_sarif and findings:
        from sentinel.sarif_output import write_sarif
        write_sarif(findings, args.output_sarif)
        logger.info("SARIF written to %s", args.output_sarif)

    # Output as JSON to stdout for Rust CLI consumption
    if findings:
        output = [f.to_dict() for f in findings]
        print(json.dumps(output, default=str))


if __name__ == "__main__":
    main()
