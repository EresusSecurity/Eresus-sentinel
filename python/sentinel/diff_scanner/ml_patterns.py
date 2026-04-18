"""
Eresus Sentinel — ML-Specific Anti-Pattern Rules for Diff Scanning.

Detects ML security anti-patterns in code diffs:
- Unsafe deserialization (pickle.load, torch.load without safeguards)
- trust_remote_code=True additions
- safe_globals / allowlist weakening
- eval()/exec() in model loading paths
- Unsafe package additions in requirements
- auto_map additions in model configs
- Hardcoded credentials in pipeline configs
- Disabled serialization safety flags

Each pattern is defined as a compiled regex with metadata
for severity, CWE mapping, and remediation guidance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class MLPattern:
    """A single ML security anti-pattern."""
    id: str
    name: str
    pattern: re.Pattern
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    cwe_ids: list[str]
    owasp_llm: str
    remediation: str
    file_filter: Optional[str] = None  # Regex for applicable file paths
    added_only: bool = True  # Only flag if pattern is in added lines


# ─── Pattern Definitions ──────────────────────────────────────────────

UNSAFE_DESERIALIZATION = [
    MLPattern(
        id="DIFF-DESER-001",
        name="pickle_load_unsafe",
        pattern=re.compile(
            r"pickle\.loads?\s*\(", re.IGNORECASE
        ),
        severity="CRITICAL",
        description=(
            "pickle.load() executes arbitrary code during deserialization. "
            "A malicious pickle file can achieve full RCE on the host."
        ),
        cwe_ids=["CWE-502"],
        owasp_llm="LLM05",
        remediation=(
            "Replace pickle.load() with safetensors or a validated JSON loader. "
            "If pickle is required, use fickling to audit the file first."
        ),
        file_filter=r"\.py$",
    ),
    MLPattern(
        id="DIFF-DESER-002",
        name="torch_load_no_weights_only",
        pattern=re.compile(
            r"torch\.load\s*\([^)]*(?<!\bweights_only\s*=\s*True)\)"
        ),
        severity="CRITICAL",
        description=(
            "torch.load() without weights_only=True uses pickle internally, "
            "enabling arbitrary code execution."
        ),
        cwe_ids=["CWE-502"],
        owasp_llm="LLM05",
        remediation=(
            "Use torch.load(path, weights_only=True) or migrate to safetensors. "
            "See: https://pytorch.org/docs/stable/generated/torch.load.html"
        ),
        file_filter=r"\.py$",
    ),
    MLPattern(
        id="DIFF-DESER-003",
        name="joblib_load_unsafe",
        pattern=re.compile(r"joblib\.load\s*\("),
        severity="HIGH",
        description=(
            "joblib.load() uses pickle internally and is vulnerable "
            "to the same arbitrary code execution risks."
        ),
        cwe_ids=["CWE-502"],
        owasp_llm="LLM05",
        remediation="Replace with safetensors or ONNX format.",
        file_filter=r"\.py$",
    ),
    MLPattern(
        id="DIFF-DESER-004",
        name="numpy_load_allow_pickle",
        pattern=re.compile(r"np\.load\s*\([^)]*allow_pickle\s*=\s*True"),
        severity="HIGH",
        description=(
            "numpy.load() with allow_pickle=True deserializes pickle objects "
            "embedded in .npy/.npz files."
        ),
        cwe_ids=["CWE-502"],
        owasp_llm="LLM05",
        remediation="Use np.load(path, allow_pickle=False) or validate files first.",
        file_filter=r"\.py$",
    ),
]

TRUST_REMOTE_CODE = [
    MLPattern(
        id="DIFF-TRUST-001",
        name="trust_remote_code_true",
        pattern=re.compile(
            r"trust_remote_code\s*=\s*True"
        ),
        severity="CRITICAL",
        description=(
            "trust_remote_code=True downloads and executes arbitrary Python "
            "from the model repository. This is equivalent to running "
            "untrusted code on your infrastructure."
        ),
        cwe_ids=["CWE-94", "CWE-829"],
        owasp_llm="LLM05",
        remediation=(
            "Remove trust_remote_code=True. Only use models that don't require it, "
            "or audit the remote code thoroughly before enabling."
        ),
    ),
    MLPattern(
        id="DIFF-TRUST-002",
        name="auto_map_config",
        pattern=re.compile(r'"auto_map"\s*:\s*\{'),
        severity="HIGH",
        description=(
            "auto_map in model config.json specifies custom Python classes "
            "to be loaded at import time. This is a known supply chain vector."
        ),
        cwe_ids=["CWE-94"],
        owasp_llm="LLM05",
        remediation="Remove auto_map entries or audit the referenced classes.",
        file_filter=r"config\.json$",
    ),
]

SAFETY_FLAG_WEAKENING = [
    MLPattern(
        id="DIFF-SAFETY-001",
        name="weights_only_false",
        pattern=re.compile(r"weights_only\s*=\s*False"),
        severity="CRITICAL",
        description=(
            "Explicitly setting weights_only=False disables PyTorch's "
            "deserialization safety check, re-enabling pickle execution."
        ),
        cwe_ids=["CWE-502"],
        owasp_llm="LLM05",
        remediation="Set weights_only=True or use safetensors.",
    ),
    MLPattern(
        id="DIFF-SAFETY-002",
        name="safe_globals_addition",
        pattern=re.compile(
            r"(?:add_safe_globals|safe_globals|SAFE_GLOBALS)\s*[\.\(=]"
        ),
        severity="HIGH",
        description=(
            "Expanding safe_globals weakens PyTorch's allowlist for "
            "deserialization, potentially allowing dangerous classes."
        ),
        cwe_ids=["CWE-502"],
        owasp_llm="LLM05",
        remediation="Minimize safe_globals entries. Audit each added class carefully.",
        file_filter=r"\.py$",
    ),
    MLPattern(
        id="DIFF-SAFETY-003",
        name="verify_false",
        pattern=re.compile(r"verify\s*=\s*False"),
        severity="MEDIUM",
        description="Disabling SSL/TLS verification for model downloads.",
        cwe_ids=["CWE-295"],
        owasp_llm="LLM05",
        remediation="Always use verify=True for HTTPS connections.",
    ),
]

CODE_EXECUTION = [
    MLPattern(
        id="DIFF-EXEC-001",
        name="eval_in_ml_path",
        pattern=re.compile(r"\beval\s*\("),
        severity="HIGH",
        description=(
            "eval() in ML pipeline code can execute arbitrary expressions. "
            "Attackers may inject malicious strings via model configs."
        ),
        cwe_ids=["CWE-95"],
        owasp_llm="LLM05",
        remediation="Replace eval() with ast.literal_eval() or explicit parsing.",
        file_filter=r"\.py$",
    ),
    MLPattern(
        id="DIFF-EXEC-002",
        name="exec_in_ml_path",
        pattern=re.compile(r"\bexec\s*\("),
        severity="CRITICAL",
        description=(
            "exec() executes arbitrary Python code. Must never appear "
            "in model loading or inference paths."
        ),
        cwe_ids=["CWE-95"],
        owasp_llm="LLM05",
        remediation="Remove exec() entirely. Use safe alternatives.",
        file_filter=r"\.py$",
    ),
    MLPattern(
        id="DIFF-EXEC-003",
        name="subprocess_in_ml",
        pattern=re.compile(r"subprocess\.\w+\s*\("),
        severity="HIGH",
        description="subprocess calls in ML code can be exploited via injection.",
        cwe_ids=["CWE-78"],
        owasp_llm="LLM05",
        remediation="Avoid subprocess in ML paths. Use safe Python APIs instead.",
        file_filter=r"\.py$",
    ),
    MLPattern(
        id="DIFF-EXEC-004",
        name="os_system_call",
        pattern=re.compile(r"os\.(?:system|popen|exec\w*)\s*\("),
        severity="CRITICAL",
        description="Direct OS command execution in ML pipeline code.",
        cwe_ids=["CWE-78"],
        owasp_llm="LLM05",
        remediation="Remove os.system/popen calls. Use safe alternatives.",
        file_filter=r"\.py$",
    ),
]

SUPPLY_CHAIN = [
    MLPattern(
        id="DIFF-SUPPLY-001",
        name="unsafe_pip_package",
        pattern=re.compile(
            r"(?:pickle|dill|cloudpickle|shelve|marshal|rpyc|pyro)\b"
        ),
        severity="MEDIUM",
        description=(
            "Addition of a package known for unsafe deserialization. "
            "These packages enable arbitrary code execution by design."
        ),
        cwe_ids=["CWE-502"],
        owasp_llm="LLM05",
        remediation="Evaluate whether the package is strictly necessary.",
        file_filter=r"requirements.*\.txt$|Pipfile$|pyproject\.toml$|setup\.(py|cfg)$",
    ),
    MLPattern(
        id="DIFF-SUPPLY-002",
        name="unpinned_ml_dependency",
        pattern=re.compile(
            r"(?:transformers|torch|tensorflow|keras|onnx|safetensors|huggingface.hub)\s*$",
            re.MULTILINE,
        ),
        severity="LOW",
        description="ML dependency added without version pinning.",
        cwe_ids=["CWE-829"],
        owasp_llm="LLM05",
        remediation="Pin dependency versions with exact hashes.",
        file_filter=r"requirements.*\.txt$",
    ),
]

CREDENTIAL_EXPOSURE = [
    MLPattern(
        id="DIFF-CRED-001",
        name="hardcoded_api_key",
        pattern=re.compile(
            r"(?:api_key|apikey|api_token|secret_key|auth_token|access_token)"
            r"\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
            re.IGNORECASE,
        ),
        severity="CRITICAL",
        description="Hardcoded API key or secret in ML pipeline configuration.",
        cwe_ids=["CWE-798"],
        owasp_llm="LLM05",
        remediation="Use environment variables or a secrets manager.",
    ),
    MLPattern(
        id="DIFF-CRED-002",
        name="hardcoded_hf_token",
        pattern=re.compile(r"hf_[A-Za-z0-9]{34,}"),
        severity="CRITICAL",
        description="Hardcoded HuggingFace API token.",
        cwe_ids=["CWE-798"],
        owasp_llm="LLM05",
        remediation="Use HF_TOKEN environment variable instead.",
    ),
    MLPattern(
        id="DIFF-CRED-003",
        name="hardcoded_aws_key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        severity="CRITICAL",
        description="Hardcoded AWS access key.",
        cwe_ids=["CWE-798"],
        owasp_llm="LLM05",
        remediation="Use AWS IAM roles or environment variables.",
    ),
]

# ─── Combined Registry ────────────────────────────────────────────────

ALL_PATTERNS: list[MLPattern] = (
    UNSAFE_DESERIALIZATION
    + TRUST_REMOTE_CODE
    + SAFETY_FLAG_WEAKENING
    + CODE_EXECUTION
    + SUPPLY_CHAIN
    + CREDENTIAL_EXPOSURE
)

PATTERN_BY_ID: dict[str, MLPattern] = {p.id: p for p in ALL_PATTERNS}
