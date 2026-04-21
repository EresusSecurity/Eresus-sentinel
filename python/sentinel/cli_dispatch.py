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

from sentinel.finding import Finding

logger = logging.getLogger(__name__)


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


def _scan_single_artifact(path: Path) -> list[Finding]:
    """Scan a single model artifact file with safety limits."""
    from sentinel.artifact import (
        PickleScanner, TorchScanner, SafetensorsValidator, GGUFAnalyzer,
        TensorFlowScanner, TorchScriptScanner, TFLiteScanner, LlamaFileScanner,
    )
    from sentinel.artifact.onnx_scanner import ONNXScanner
    from sentinel.artifact.keras_scanner import KerasScanner
    from sentinel.artifact.archive_slip import ArchiveSlipDetector
    from sentinel.artifact.xgboost_scanner import XGBoostScanner
    from sentinel.artifact.numpy_scanner import NumPyScanner
    from sentinel.scan_safety import check_file_size, FileTooLargeError
    from sentinel.finding import Severity

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
        (".lgb",): XGBoostScanner,
        (".joblib",): XGBoostScanner,
        (".npy",): NumPyScanner,
        (".npz",): NumPyScanner,
        (".nemo", ".mar"): ArchiveSlipDetector,
        (".tar", ".tar.gz", ".tgz", ".zip", ".7z"): ArchiveSlipDetector,
    }

    for extensions, scanner_cls in scanner_map.items():
        if suffix in extensions:
            scanner = scanner_cls()
            findings.extend(scanner.scan_file(str(path)))
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

    return findings


def dispatch_firewall_input(target: str) -> list[Finding]:
    """Run ALL input firewall scanners on target."""
    from sentinel.policy import PolicyEngine
    engine = PolicyEngine.default()
    pipeline = engine.build_input_pipeline()

    findings = []
    path = Path(target)

    if path.is_file():
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
    path = Path(target)

    if path.is_file():
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
    from sentinel.agent.mcp_validator import MCPValidator
    validator = MCPValidator()
    return validator.validate_file(target)


def dispatch_supply_chain(target: str) -> list[Finding]:
    """Run supply chain audit."""
    from sentinel.supply_chain.provenance import ProvenanceVerifier
    from sentinel.supply_chain.dependency import DependencyAuditor

    findings = []
    verifier = ProvenanceVerifier()
    findings.extend(verifier.audit_directory(target))
    auditor = DependencyAuditor()
    findings.extend(auditor.audit_directory(target))
    return findings


def dispatch_diff(target: str) -> list[Finding]:
    """Run diff scanner on git diff, commit, or patch file."""
    from sentinel.diff_scanner import DiffScanner
    scanner = DiffScanner()

    if target in ("--staged", "-"):
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
        diff_text = target
        path = Path(target)
        if path.is_file():
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                diff_text = f.read()
        return scanner.scan_diff(diff_text)


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
    print(json.dumps(summary, default=str))
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
        uvicorn.run(app, host=host, port=port)
    except ImportError:
        print(json.dumps({"error": "uvicorn not installed. Run: pip install uvicorn fastapi"}))

    return []


def dispatch_huggingface(target: str) -> list[Finding]:
    """Scan a HuggingFace model repository."""
    import os
    from sentinel.artifact.huggingface_scanner import HuggingFaceScanner

    scanner = HuggingFaceScanner()
    # Use scan_remote_repo for repo IDs, scan_local_repo for local paths
    if os.path.exists(target):
        return scanner.scan_local_repo(target)
    return scanner.scan_remote_repo(target)


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
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

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
    if args.module not in ("serve", "validate_rules"):
        findings = _post_process(findings)

    # Output as JSON to stdout for Rust CLI consumption
    if findings:
        output = [f.to_dict() for f in findings]
        print(json.dumps(output, default=str))


if __name__ == "__main__":
    main()
