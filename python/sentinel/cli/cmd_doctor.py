"""sentinel doctor — environment health check command."""

from __future__ import annotations

import importlib
import os
import shutil
import sys
from dataclasses import dataclass
from typing import Optional


@dataclass
class _Check:
    name: str
    status: str  # "PASS" | "WARN" | "FAIL"
    detail: str
    fix: Optional[str] = None


def _check_python() -> _Check:
    v = sys.version_info
    if v >= (3, 10):
        return _Check("Python version", "PASS", f"{v.major}.{v.minor}.{v.micro}")
    return _Check("Python version", "WARN", f"{v.major}.{v.minor}.{v.micro} — 3.10+ recommended", "Upgrade Python")


def _check_sentinel_version() -> _Check:
    try:
        import importlib.metadata
        ver = importlib.metadata.version("eresus-sentinel")
        return _Check("Sentinel package", "PASS", f"v{ver}")
    except Exception:
        return _Check("Sentinel package", "WARN", "version metadata not found (editable install?)")


def _check_pickle_bridge() -> _Check:
    try:
        import sentinel_pickle  # type: ignore[import-untyped]
        return _Check("Rust pickle bridge (sentinel_pickle)", "PASS", "importable")
    except ImportError:
        return _Check("Rust pickle bridge (sentinel_pickle)", "WARN",
                      "not installed — pickle fuzzing disabled",
                      "pip install sentinel-pickle  OR  cd rust/pickle_bridge && maturin develop")


def _check_treesitter() -> list[_Check]:
    checks: list[_Check] = []
    try:
        import tree_sitter  # type: ignore[import-untyped]
        checks.append(_Check("tree-sitter core", "PASS", f"v{tree_sitter.__version__ if hasattr(tree_sitter, '__version__') else 'installed'}"))
    except ImportError:
        checks.append(_Check("tree-sitter core", "WARN", "not installed — tree-sitter parsing disabled",
                             "pip install tree-sitter"))
        return checks

    ts_langs = ["python", "javascript", "typescript", "java", "go", "rust", "ruby", "c_sharp"]
    for lang in ts_langs:
        pkg = f"tree_sitter_{lang}"
        try:
            importlib.import_module(pkg)
            checks.append(_Check(f"tree-sitter:{lang}", "PASS", "installed"))
        except ImportError:
            checks.append(_Check(f"tree-sitter:{lang}", "WARN", "not installed",
                                 f"pip install {pkg.replace('_', '-')}"))
    return checks


def _check_api_keys() -> list[_Check]:
    """All API keys are optional (INFO) — none are required for core scanning."""
    checks: list[_Check] = []
    keys = [
        ("OPENAI_API_KEY", "OpenAI", "llm-judge, eval-compare"),
        ("ANTHROPIC_API_KEY", "Anthropic", "llm-judge, eval-compare"),
        ("GOOGLE_API_KEY", "Google AI / Gemini", "llm-judge, eval-compare"),
        ("HUGGING_FACE_HUB_TOKEN", "HuggingFace", "remote model download"),
        ("GROQ_API_KEY", "Groq", "eval-compare"),
        ("MISTRAL_API_KEY", "Mistral", "eval-compare"),
        ("COHERE_API_KEY", "Cohere", "eval-compare"),
        ("VIRUSTOTAL_API_KEY", "VirusTotal", "malware scanning"),
        ("MLFLOW_TRACKING_URI", "MLflow", "MLflow registry scanning"),
        ("JFROG_API_KEY", "JFrog Artifactory", "JFrog artifact scanning"),
    ]
    for env_var, label, feature in keys:
        val = os.environ.get(env_var)
        if val and len(val) > 4:
            checks.append(_Check(f"API key: {label}", "PASS", f"{env_var} set ({len(val)} chars) — enables: {feature}"))
        else:
            checks.append(_Check(f"API key: {label}", "INFO",
                                 f"{env_var} not set — optional, enables: {feature}"))
    return checks


def _check_model_file_formats() -> list[_Check]:
    """Check live format coverage from artifact scanner catalog."""
    checks: list[_Check] = []

    try:
        from sentinel.artifact import _scanner_catalog
        catalog = _scanner_catalog()
        all_exts: list[str] = []
        for spec in catalog:
            all_exts.extend(spec.extensions)
        ext_set = set(all_exts)

        checks.append(_Check(
            "Artifact scanner catalog",
            "PASS",
            f"{len(catalog)} scanners, {len(ext_set)} unique extensions registered",
        ))

        key_formats = [
            (".pkl",    "Pickle (unsafe serialization)"),
            (".safetensors", "SafeTensors (recommended)"),
            (".gguf",   "GGUF (llama.cpp)"),
            (".ggml",   "GGML variants"),
            (".pt",     "PyTorch checkpoint"),
            (".onnx",   "ONNX"),
            (".tflite", "TFLite/LiteRT"),
            (".h5",     "Keras HDF5"),
            (".npy",    "NumPy arrays"),
            (".skops",  "Scikit-learn Skops"),
            (".nemo",   "NVIDIA NeMo"),
            (".mar",    "TorchServe MAR"),
            (".msgpack", "Flax/JAX msgpack"),
            (".jax",    "JAX checkpoint"),
            (".rds",    "R serialized"),
            (".cbm",    "CatBoost"),
            (".pmml",   "PMML"),
            (".pdmodel", "PaddlePaddle"),
            (".meta",   "TF MetaGraph"),
            (".tar.bz2", "TAR variants (bz2/xz)"),
            (".jinja",  "Jinja2 template injection"),
            (".json",   "ML manifest (config.json, tokenizer.json, etc.)"),
            (".mlmodel", "CoreML"),
            (".rknn",   "RKNN (Rockchip)"),
            (".dnn",    "CNTK"),
            (".pte",    "ExecuTorch"),
            (".engine", "TensorRT"),
            (".llamafile", "LlamaFile"),
        ]
        for ext, desc in key_formats:
            if ext in ext_set:
                checks.append(_Check(f"Format: {ext}", "PASS", desc))
            else:
                checks.append(_Check(f"Format: {ext}", "WARN", f"NOT in catalog — {desc}"))
    except Exception as exc:
        checks.append(_Check("Artifact scanner catalog", "WARN", f"could not load: {exc}"))

    optional_deps = [
        ("onnx",         ".onnx full validation"),
        ("h5py",         ".h5/.hdf5/.keras full inspection"),
        ("safetensors",  ".safetensors fast path"),
        ("flatbuffers",  ".tflite FlatBuffer parse"),
        ("numpy",        ".npy/.npz array scanning"),
    ]
    for mod, desc in optional_deps:
        try:
            importlib.import_module(mod)
            checks.append(_Check(f"Format dep: {mod}", "PASS", desc))
        except ImportError:
            checks.append(_Check(f"Format dep: {mod}", "INFO",
                                 f"not installed — {desc} falls back to header scan",
                                 f"pip install {mod}"))

    return checks


def _check_fp_engine() -> list[_Check]:
    """Check FP suppression engine components."""
    checks: list[_Check] = []

    # Check YAML rules are loadable
    try:
        from sentinel.sast.multilang_scanner import _rules_for_lang, _RULES_DIR
        if _RULES_DIR.exists():
            yaml_files = list(_RULES_DIR.glob("*.yaml"))
            total_rules = sum(len(_rules_for_lang(yf.stem)) for yf in yaml_files if yf.stem in [
                "javascript", "typescript", "java", "go", "ruby", "csharp", "rust", "kotlin", "php"
            ])
            checks.append(_Check("FP engine: YAML rules", "PASS",
                                 f"{len(yaml_files)} language rule files, ~{total_rules} total compiled rules"))
        else:
            checks.append(_Check("FP engine: YAML rules", "WARN",
                                 f"rules/sast/ directory not found at {_RULES_DIR}"))
    except Exception as exc:
        checks.append(_Check("FP engine: YAML rules", "WARN", f"could not load rules: {exc}"))

    # Check re2 for faster/safer regex
    try:
        importlib.import_module("re2")
        checks.append(_Check("FP engine: re2 (Google RE2)", "PASS", "fast, safe regex engine available"))
    except ImportError:
        checks.append(_Check("FP engine: re2 (Google RE2)", "INFO",
                             "not installed — using stdlib re (slower, no ReDoS protection)",
                             "pip install google-re2"))

    # Check semgrep
    if shutil.which("semgrep"):
        checks.append(_Check("FP engine: semgrep", "PASS", "AST-level analysis available"))
    else:
        checks.append(_Check("FP engine: semgrep", "INFO",
                             "not installed — YAML rules use regex fallback only",
                             "pip install semgrep"))

    return checks


def _check_external_tools() -> list[_Check]:
    checks: list[_Check] = []
    tools = [
        ("docker", "Container image extraction (preferred)"),
        ("podman", "Container image extraction (alternative)"),
        ("skopeo", "Container image extraction (OCI registry)"),
        ("crane", "Container image inspection (gcrane)"),
        ("dvc", "DVC remote scanning"),
        ("opa", "OPA policy evaluation (sentinel policy check)"),
        ("git", "Git-based incremental scanning"),
        ("rg", "ripgrep — fast content search (optional speedup)"),
    ]
    for binary, purpose in tools:
        if shutil.which(binary):
            checks.append(_Check(f"CLI tool: {binary}", "PASS", purpose))
        else:
            checks.append(_Check(f"CLI tool: {binary}", "INFO", f"not found — {purpose} may be limited"))
    return checks


def _check_python_extras() -> list[_Check]:
    checks: list[_Check] = []
    pkgs = [
        ("boto3", "S3 remote scanning"),
        ("google.cloud.storage", "GCS remote scanning"),
        ("mlflow", "MLflow scanning"),
        ("yaml", "YAML rule loading (PyYAML — required)"),
        ("rich", "Rich terminal output (required)"),
        ("safetensors", "SafeTensors artifact scanning"),
        ("onnx", "ONNX model scanning"),
        ("h5py", "HDF5/Keras model scanning"),
        ("flatbuffers", "TFLite FlatBuffer scanning"),
        ("requests", "HTTP client for remote scanning"),
        ("jinja2", "HTML report templating"),
        ("aiohttp", "Async HTTP for eval-compare"),
    ]
    for mod, purpose in pkgs:
        required = mod in ("yaml", "rich")
        try:
            importlib.import_module(mod)
            checks.append(_Check(f"Python: {mod}", "PASS", purpose))
        except ImportError:
            status = "FAIL" if required else "INFO"
            fix = f"pip install {mod.replace('.', '-')}" if required else None
            checks.append(_Check(f"Python: {mod}", status,
                                 f"not installed — {purpose}{'  (REQUIRED)' if required else ''}",
                                 fix))
    return checks


def _print_section(console, title: str, checks: list[_Check], *, failures: list, warnings: list) -> None:
    status_icon = {"PASS": "[green]✔[/green]", "WARN": "[yellow]⚠[/yellow]", "FAIL": "[red]✖[/red]", "INFO": "[dim]·[/dim]"}
    status_color = {"PASS": "green", "WARN": "yellow", "FAIL": "red", "INFO": "dim"}
    console.print(f"\n[bold cyan]{title}[/bold cyan]")
    for c in checks:
        icon = status_icon.get(c.status, "?")
        color = status_color.get(c.status, "white")
        console.print(f"  {icon} [{color}]{c.status:<4}[/{color}]  {c.name}: [dim]{c.detail}[/dim]")
        if c.fix:
            console.print(f"         [yellow]→ fix:[/yellow] {c.fix}")
        if c.status == "FAIL":
            failures.append(c.name)
        elif c.status == "WARN":
            warnings.append(c.name)


def run_doctor_checks() -> tuple[list[_Check], dict[str, list[_Check]]]:
    """Run all checks. Returns (flat_list, sections_dict) for programmatic use."""
    sections: dict[str, list[_Check]] = {
        "Core": [_check_python(), _check_sentinel_version(), _check_pickle_bridge()],
        "Tree-sitter": _check_treesitter(),
        "FP Engine": _check_fp_engine(),
        "Model File Formats": _check_model_file_formats(),
        "Python Packages": _check_python_extras(),
        "API Keys (optional)": _check_api_keys(),
        "External Tools": _check_external_tools(),
    }
    flat = [c for checks in sections.values() for c in checks]
    return flat, sections


def cmd_doctor(args) -> int:
    """Run environment health checks and report results."""
    import json as _json
    from sentinel.cli._helpers import console

    flat, sections = run_doctor_checks()

    if getattr(args, "json_output", False):
        out = {
            sec: [{"name": c.name, "status": c.status, "detail": c.detail, "fix": c.fix} for c in checks]
            for sec, checks in sections.items()
        }
        print(_json.dumps(out, indent=2))
        failures = [c for c in flat if c.status == "FAIL"]
        return 1 if failures else 0

    console.print("\n[bold]Sentinel Doctor[/bold] — Environment Health Check")

    failures: list[str] = []
    warnings: list[str] = []
    for title, checks in sections.items():
        _print_section(console, title, checks, failures=failures, warnings=warnings)

    console.print()
    total = len(flat)
    passed = sum(1 for c in flat if c.status == "PASS")
    console.print(f"  [dim]{passed}/{total} checks passed[/dim]")
    console.print()

    if failures:
        console.print(f"[red bold]✖ {len(failures)} FAIL[/red bold]  {', '.join(failures[:3])}")
        if warnings:
            console.print(f"[yellow]⚠ {len(warnings)} WARN[/yellow]")
        return 1
    if warnings:
        console.print(f"[yellow]⚠ {len(warnings)} WARN — optional components missing[/yellow]")
        return 0
    console.print("[green bold]✔ All critical checks passed[/green bold]")
    return 0
