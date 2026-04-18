"""Keras model scanner — Lambda layers, gadget chains, archive integrity."""

from __future__ import annotations

import base64
import json
import logging
import struct
import zipfile
from pathlib import Path
from typing import List, Optional, Any

from ..finding import Finding, Severity, Location

logger = logging.getLogger(__name__)


# ── Allowed Keras ecosystem modules (post-3.9 fix) ───────────────

KERAS_ALLOWED_MODULES = {
    "keras", "keras_hub", "keras_cv", "keras_nlp",
    "tensorflow", "tf",
}

# ── Dangerous callable gadgets reachable via deserialization ──────

# These functions are callable through config.json deserialization
# even with safe_mode=True (the Lambda check only blocks Lambda layers)
DANGEROUS_GADGETS: dict[str, dict] = {
    # CRITICAL: Remote file download (bypasses safe_mode!)
    "get_file": {
        "module": "keras.utils",
        "severity": "CRITICAL",
        "description": "Downloads arbitrary files from remote URLs to local filesystem",
        "bypass": "safe_mode",
        "cve": None,
    },
    # CRITICAL: Bytecode execution
    "func_load": {
        "module": "keras.src.utils.python_utils",
        "severity": "CRITICAL",
        "description": "Loads Python function from base64-encoded bytecode via marshal.loads()",
        "cve": "CVE-2024-3660",
    },
    # HIGH: Can construct custom layer behavior
    "deserialize": {
        "module": "keras.src.saving.serialization_lib",
        "severity": "HIGH",
        "description": "Recursive deserialization that resolves arbitrary module references",
        "cve": "CVE-2025-1550",
    },
}

# ── Suspicious patterns in any config.json string value ──────────

SUSPICIOUS_CONFIG_PATTERNS = [
    # Code execution
    "__import__", "os.system", "subprocess", "eval(", "exec(",
    "compile(", "marshal.loads", "marshal.load",
    # Bytecode / encoding
    "base64.b64decode", "base64.decodebytes", "codecs.decode",
    # Lambda exploitation
    "lambda x:", "lambda x,",
    # Shell commands
    "touch /tmp", "/bin/sh", "/bin/bash", "echo ", "curl ", "wget ",
    "nc ", "ncat ", "bash -i", "python -c", "python3 -c",
    # Reverse shells
    "socket.socket", "connect(", ".send(", ".recv(",
    "/dev/tcp/", "mkfifo",
    # File operations
    "open(", "write(", "read(",
    # CVE-2025-9906: safe_mode disable via config manipulation
    "safe_mode",
    # Object attribute traversal (Oligo Security findings)
    "__class__", "__bases__", "__subclasses__", "__globals__",
    "__builtins__", "__code__", "__func__",
    # Importlib gadget (CVE-2025-1550 path)
    "importlib", "import_module", "__loader__", "spec_from_loader",
]

# ── Dangerous class_name values that indicate gadget usage ───────

DANGEROUS_CLASS_NAMES = {
    "get_file", "func_load", "load_model", "model_from_config",
    "deserialize_keras_object", "import_module",
    # Python builtins that shouldn't appear in layer configs
    "exec", "eval", "compile", "system", "popen",
    "__import__", "getattr", "setattr",
}

# ── Keras modules with known dangerous callables ─────────────────

DANGEROUS_KERAS_CALLABLES: dict[str, set[str]] = {
    "keras.utils": {"get_file", "custom_object_scope", "get_source_inputs"},
    "keras.src.utils": {"get_file"},
    "keras.src.utils.python_utils": {"func_load", "func_dump"},
    "keras.saving": {"deserialize_keras_object"},
    "keras.src.saving.serialization_lib": {
        "deserialize_keras_object", "_retrieve_class_or_fn",
    },
}


class KerasScanner:
    """Scans .keras and .h5 files for deserialization vulnerabilities."""

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a Keras model file (.keras, .h5, .hdf5)."""
        p = Path(path)
        if p.suffix == ".keras":
            return self._scan_keras_format(p)
        elif p.suffix in (".h5", ".hdf5"):
            return self._scan_hdf5_format(p)
        return []

    # ─── .keras ZIP format scanning ───────────────────────────

    def _scan_keras_format(self, path: Path) -> List[Finding]:
        """Scan .keras ZIP format with deep config analysis."""
        findings: list[Finding] = []
        source = str(path)

        if not zipfile.is_zipfile(path):
            findings.append(Finding.artifact(
                rule_id="KERAS-001",
                title="Invalid .keras file structure",
                description=(
                    f"File '{source}' has .keras extension but is not a valid ZIP archive. "
                    f"This could indicate corruption or a disguised file."
                ),
                severity=Severity.MEDIUM,
                target=source,
            ))
            return findings

        with zipfile.ZipFile(path, "r") as zf:
            # ── Archive slip detection ──
            findings.extend(self._check_archive_slip(zf, source))

            # ── CVE-2025-9906: safe_mode bypass via metadata.json ──
            if "metadata.json" in zf.namelist():
                try:
                    meta_raw = zf.read("metadata.json")
                    meta_data = json.loads(meta_raw)
                    findings.extend(self._check_safe_mode_bypass(meta_data, source))
                except (json.JSONDecodeError, Exception):
                    pass

            # ── Analyze config.json ──
            if "config.json" in zf.namelist():
                try:
                    config_raw = zf.read("config.json")
                    config_data = json.loads(config_raw)
                    findings.extend(self._analyze_config(config_data, source))
                    findings.extend(self._detect_gadget_chains(config_data, source))
                    findings.extend(self._detect_structural_anomalies(config_data, source))
                except json.JSONDecodeError as e:
                    findings.append(Finding.artifact(
                        rule_id="KERAS-003",
                        title="Malformed config.json",
                        description=(
                            f"config.json is not valid JSON: {e}. "
                            f"This could indicate a file manipulation attempt."
                        ),
                        severity=Severity.MEDIUM,
                        target=source,
                        cwe_ids=["CWE-502"],
                    ))
            else:
                findings.append(Finding.artifact(
                    rule_id="KERAS-020",
                    title="Missing config.json in .keras file",
                    description=(
                        "A valid .keras archive should contain config.json. "
                        "Missing config suggests corruption or non-standard creation."
                    ),
                    severity=Severity.LOW,
                    target=source,
                ))

            # ── Check for unexpected files in archive ──
            expected = {"config.json", "metadata.json", "model.weights.h5"}
            actual = set(zf.namelist())
            unexpected = actual - expected
            # Ignore known sub-paths
            unexpected = {f for f in unexpected if not f.startswith("assets/")}
            if unexpected:
                findings.append(Finding.artifact(
                    rule_id="KERAS-021",
                    title="Unexpected files in .keras archive",
                    description=(
                        f"Archive contains unexpected files: {sorted(unexpected)[:10]}. "
                        f"Legitimate .keras files typically contain only config.json, "
                        f"metadata.json, and model.weights.h5."
                    ),
                    severity=Severity.LOW,
                    target=source,
                    evidence=f"Unexpected entries: {sorted(unexpected)[:10]}",
                ))

        return findings

    def _check_archive_slip(self, zf: zipfile.ZipFile, source: str) -> List[Finding]:
        """Check for path traversal, symlinks, and ZIP bombs in .keras archive."""
        findings = []
        total_size = 0

        for info in zf.infolist():
            # Path traversal
            if info.filename.startswith("/") or ".." in info.filename:
                findings.append(Finding.artifact(
                    rule_id="KERAS-002",
                    title="Archive slip in .keras file",
                    description=(
                        f"Archive member '{info.filename}' contains path traversal. "
                        f"Extracting this file would write outside the target directory, "
                        f"potentially overwriting system files or planting backdoors."
                    ),
                    severity=Severity.CRITICAL,
                    target=source,
                    evidence=f"Member path: {info.filename}",
                    cwe_ids=["CWE-22"],
                ))

            # Symlink detection (ZIP external attributes)
            if (info.external_attr >> 28) == 0xA:
                findings.append(Finding.artifact(
                    rule_id="KERAS-022",
                    title="Symlink in .keras archive",
                    description=(
                        f"Archive member '{info.filename}' is a symlink. "
                        f"Symlinks can be used to escape the extraction sandbox."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"Symlink member: {info.filename}",
                    cwe_ids=["CWE-59"],
                ))

            # Decompression bomb
            total_size += info.file_size
            if total_size > 500 * 1024 * 1024:  # 500MB for a model config is suspicious
                findings.append(Finding.artifact(
                    rule_id="KERAS-023",
                    title="Decompression bomb in .keras archive",
                    description=(
                        f"Total decompressed size exceeds 500MB. "
                        f"This is unusual for a .keras config archive."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    cwe_ids=["CWE-409"],
                ))
                break

        return findings

    # ─── config.json recursive analysis ───────────────────────

    def _analyze_config(
        self, config: Any, source: str, depth: int = 0, path: str = "$"
    ) -> List[Finding]:
        """
        Recursively analyze config.json for all known attack vectors:
        - Lambda layers with base64 bytecode
        - Non-Keras module imports (CVE-2025-1550)
        - Dangerous function references (get_file, func_load)
        - Suspicious string patterns in values
        """
        findings: list[Finding] = []
        if depth > 30:
            return findings

        if isinstance(config, dict):
            class_name = config.get("class_name", "")
            module = config.get("module", "")

            # ── Lambda layer detection ──
            if class_name == "Lambda":
                findings.append(Finding.artifact(
                    rule_id="KERAS-004",
                    title="Lambda layer detected in model",
                    description=(
                        "Lambda layers can execute arbitrary Python code during model "
                        "loading. This is the primary attack vector for Keras model "
                        "backdoors (CVE-2024-3660). Even with safe_mode=True, the "
                        "Lambda layer's from_config() method may execute code if "
                        "the function definition uses non-lambda callables."
                    ),
                    severity=Severity.CRITICAL,
                    target=source,
                    evidence=f"Lambda layer at config path: {path}",
                    cwe_ids=["CWE-502", "CWE-94"],
                ))

                # Check for base64-encoded bytecode in Lambda config
                findings.extend(
                    self._check_lambda_bytecode(config, source, path)
                )

            # ── Non-Keras module import (CVE-2025-1550) ──
            if module:
                package = module.split(".", maxsplit=1)[0]
                if package and package not in KERAS_ALLOWED_MODULES:
                    findings.append(Finding.artifact(
                        rule_id="KERAS-006",
                        title=f"Non-Keras module reference: {module}",
                        description=(
                            f"Config references module '{module}' which is outside the "
                            f"Keras ecosystem allowlist ({KERAS_ALLOWED_MODULES}). "
                            f"In Keras <= 3.8, this enables arbitrary module loading via "
                            f"importlib.import_module() (CVE-2025-1550). Even in "
                            f"patched versions, non-standard modules indicate tampering."
                        ),
                        severity=Severity.CRITICAL,
                        target=source,
                        evidence=f"Module: {module} at path: {path}",
                        cwe_ids=["CWE-94"],
                    ))

            # ── Dangerous callable detection ──
            if class_name in DANGEROUS_CLASS_NAMES:
                findings.append(Finding.artifact(
                    rule_id="KERAS-007",
                    title=f"Dangerous callable reference: {class_name}",
                    description=(
                        f"Config references '{class_name}' which can be exploited "
                        f"for code execution or unauthorized file operations during "
                        f"model deserialization."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"class_name: {class_name}, module: {module}, path: {path}",
                    cwe_ids=["CWE-94"],
                ))

            # ── Gadget-specific detection ──
            if module and class_name:
                for gadget_name, gadget_info in DANGEROUS_KERAS_CALLABLES.items():
                    if module.startswith(gadget_name) and class_name in gadget_info:
                        findings.append(Finding.artifact(
                            rule_id="KERAS-030",
                            title=f"Keras deserialization gadget: {module}.{class_name}",
                            description=(
                                f"Config references '{module}.{class_name}' which is a "
                                f"known deserialization gadget. This callable can be "
                                f"invoked through config.json deserialization even with "
                                f"safe_mode=True."
                            ),
                            severity=Severity.CRITICAL,
                            target=source,
                            evidence=f"Gadget: {module}.{class_name} at path: {path}",
                            cwe_ids=["CWE-502"],
                        ))

            # ── Scan all string values for suspicious patterns ──
            for key, value in config.items():
                if isinstance(value, str):
                    for pattern in SUSPICIOUS_CONFIG_PATTERNS:
                        if pattern in value:
                            findings.append(Finding.artifact(
                                rule_id="KERAS-008",
                                title=f"Suspicious content in config: {pattern}",
                                description=(
                                    f"Key '{key}' at path '{path}.{key}' contains "
                                    f"suspicious pattern '{pattern}' which may indicate "
                                    f"code injection or payload embedding."
                                ),
                                severity=Severity.HIGH,
                                target=source,
                                evidence=f"Pattern: {pattern}, Value: {value[:200]}",
                                cwe_ids=["CWE-94"],
                            ))
                            break
                elif isinstance(value, (dict, list)):
                    findings.extend(
                        self._analyze_config(value, source, depth + 1, f"{path}.{key}")
                    )

        elif isinstance(config, list):
            for i, item in enumerate(config):
                findings.extend(
                    self._analyze_config(item, source, depth + 1, f"{path}[{i}]")
                )

        return findings

    def _check_lambda_bytecode(
        self, config: dict, source: str, path: str
    ) -> List[Finding]:
        """Detect base64-encoded Python bytecode in Lambda layer configs."""
        findings = []
        fn_config = config.get("config", {}).get("function", {})

        if isinstance(fn_config, dict):
            inner = fn_config.get("config", {})

            # Check for __lambda__ class with bytecode
            if fn_config.get("class_name") == "__lambda__":
                findings.append(Finding.artifact(
                    rule_id="KERAS-005",
                    title="Lambda __lambda__ bytecode detected",
                    description=(
                        "Lambda layer contains a __lambda__ class_name with serialized "
                        "Python bytecode. This is the exact mechanism used in CVE-2024-3660. "
                        "The base64-encoded bytecode will be executed via python_utils.func_load() "
                        "→ marshal.loads() during model loading."
                    ),
                    severity=Severity.CRITICAL,
                    target=source,
                    evidence=f"__lambda__ at path: {path}",
                    cwe_ids=["CWE-502"],
                ))

            if isinstance(inner, dict) and "code" in inner:
                code_value = inner["code"]
                findings.append(Finding.artifact(
                    rule_id="KERAS-005",
                    title="Base64 bytecode in Lambda layer",
                    description=(
                        "Lambda layer contains base64-encoded Python bytecode in the "
                        "'code' field. This bytecode will be decoded and executed via "
                        "marshal.loads() during model loading, enabling arbitrary "
                        "code execution."
                    ),
                    severity=Severity.CRITICAL,
                    target=source,
                    evidence=f"Bytecode (first 100 chars): {str(code_value)[:100]}",
                    cwe_ids=["CWE-502"],
                ))

                # Try to detect payload content from bytecode
                try:
                    decoded = base64.b64decode(code_value)
                    # Look for dangerous strings in raw bytecode
                    text = decoded.decode("utf-8", errors="replace")
                    danger_indicators = [
                        "os.system", "subprocess", "__import__",
                        "eval", "exec", "/tmp/", "/bin/",
                        "socket", "reverse", "shell",
                    ]
                    for indicator in danger_indicators:
                        if indicator in text:
                            findings.append(Finding.artifact(
                                rule_id="KERAS-031",
                                title=f"Malicious bytecode content: {indicator}",
                                description=(
                                    f"Decoded Lambda bytecode contains '{indicator}' "
                                    f"which strongly indicates malicious intent."
                                ),
                                severity=Severity.CRITICAL,
                                confidence=1.0,
                                target=source,
                                evidence=f"Found '{indicator}' in decoded bytecode",
                                cwe_ids=["CWE-94"],
                            ))
                            break
                except Exception:
                    pass

        return findings

    # ─── Gadget chain detection ───────────────────────────────

    def _detect_gadget_chains(self, config: dict, source: str) -> List[Finding]:
        """
        Detect deserialization gadget chains in config.json.

        A gadget chain is a sequence of config entries that, when
        deserialized together, achieve a dangerous effect even though
        each individual entry might look benign.

        Example: keras.utils.get_file() bypass:
        The attacker injects a Lambda layer whose function field
        references get_file instead of a lambda, bypassing safe_mode.
        """
        findings = []

        # Walk all layers looking for get_file gadget bypass
        layers = self._extract_layers(config)
        for i, layer in enumerate(layers):
            fn = layer.get("config", {}).get("function", {})
            if isinstance(fn, dict):
                fn_module = fn.get("module", "")
                fn_class = fn.get("class_name", "")

                # get_file bypass: Lambda.function points to keras.utils.get_file
                if "get_file" in fn_class:
                    args = layer.get("config", {}).get("arguments", {})
                    findings.append(Finding.artifact(
                        rule_id="KERAS-032",
                        title="get_file download gadget (safe_mode bypass)",
                        description=(
                            "Lambda layer's function field references keras.utils.get_file "
                            "instead of a Python lambda. Because get_file is a standard "
                            "Keras function (not a Lambda), this BYPASSES safe_mode=True. "
                            "The attacker can download arbitrary files from remote URLs "
                            "to the victim's filesystem."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        target=source,
                        evidence=(
                            f"Layer {i}: function.class_name={fn_class}, "
                            f"module={fn_module}, args={str(args)[:200]}"
                        ),
                        cwe_ids=["CWE-94", "CWE-918"],
                        remediation=(
                            "Reject any model where Lambda.function references a "
                            "non-lambda callable. Implement deserialization allowlisting."
                        ),
                    ))

                # Generic non-lambda function reference in Lambda.function
                if fn_module and fn_class and fn_class not in ("__lambda__",):
                    pkg = fn_module.split(".", maxsplit=1)[0]
                    if pkg in KERAS_ALLOWED_MODULES and fn_class not in ("__lambda__",):
                        findings.append(Finding.artifact(
                            rule_id="KERAS-033",
                            title=f"Non-lambda function in Lambda layer: {fn_class}",
                            description=(
                                f"Lambda layer references '{fn_module}.{fn_class}' as its "
                                f"function. This is not a serialized Python lambda — it's "
                                f"a direct callable reference that may bypass safe_mode."
                            ),
                            severity=Severity.HIGH,
                            target=source,
                            evidence=f"function: {fn_module}.{fn_class}",
                            cwe_ids=["CWE-94"],
                        ))

        return findings

    def _extract_layers(self, config: Any) -> list[dict]:
        """Extract all layer configs from a Keras model config."""
        layers = []
        if isinstance(config, dict):
            if "class_name" in config and "config" in config:
                layers.append(config)
            # Recurse into nested structures
            for key, value in config.items():
                if key == "layers" and isinstance(value, list):
                    for item in value:
                        layers.extend(self._extract_layers(item))
                elif isinstance(value, (dict, list)):
                    layers.extend(self._extract_layers(value))
        elif isinstance(config, list):
            for item in config:
                layers.extend(self._extract_layers(item))
        return layers

    # ─── Structural anomaly detection ─────────────────────────

    def _detect_structural_anomalies(self, config: dict, source: str) -> List[Finding]:
        """
        Detect structural anomalies in config.json that suggest tampering.

        Legitimate Keras models have predictable structure. Anomalies include:
        - Excessive nesting depth
        - Unusual key names not in Keras schema
        - Mixed model types (Sequential containing Functional)
        - config keys with non-standard types
        """
        findings = []

        # Check nesting depth
        max_depth = self._measure_depth(config)
        if max_depth > 50:
            findings.append(Finding.artifact(
                rule_id="KERAS-040",
                title="Excessive config.json nesting depth",
                description=(
                    f"Config has nesting depth of {max_depth} levels. "
                    f"Normal Keras models rarely exceed 20 levels. "
                    f"Deep nesting may indicate an attempt to hide malicious content."
                ),
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"Max nesting depth: {max_depth}",
            ))

        # Count total config nodes
        node_count = self._count_nodes(config)
        if node_count > 50000:
            findings.append(Finding.artifact(
                rule_id="KERAS-041",
                title="Abnormally large config.json",
                description=(
                    f"Config contains {node_count:,} nodes. "
                    f"Extremely large configs may cause DoS during deserialization "
                    f"or hide malicious entries in the noise."
                ),
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"Total config nodes: {node_count:,}",
            ))

        return findings

    def _measure_depth(self, obj: Any, current: int = 0) -> int:
        """Measure maximum nesting depth of a config structure."""
        if current > 100:
            return current
        if isinstance(obj, dict):
            if not obj:
                return current
            return max(
                self._measure_depth(v, current + 1) for v in obj.values()
            )
        elif isinstance(obj, list):
            if not obj:
                return current
            return max(
                self._measure_depth(item, current + 1) for item in obj
            )
        return current

    def _count_nodes(self, obj: Any) -> int:
        """Count total nodes in config structure."""
        if isinstance(obj, dict):
            return 1 + sum(self._count_nodes(v) for v in obj.values())
        elif isinstance(obj, list):
            return 1 + sum(self._count_nodes(item) for item in obj)
        return 1

    # ─── safe_mode bypass detection (CVE-2025-9906) ───────────

    def _check_safe_mode_bypass(
        self, metadata: dict, source: str
    ) -> List[Finding]:
        """
        Detect CVE-2025-9906: safe_mode bypass via metadata.json.

        An attacker can craft a .keras archive where metadata.json
        sets safe_mode to False before config.json deserialization.
        This disables the Lambda layer protection entirely.
        """
        findings = []

        # Check for explicit safe_mode=False in metadata
        safe_mode = metadata.get("safe_mode")
        if safe_mode is False or safe_mode == "false" or safe_mode == 0:
            findings.append(Finding.artifact(
                rule_id="KERAS-050",
                title="safe_mode bypass in metadata.json (CVE-2025-9906)",
                description=(
                    "metadata.json explicitly sets safe_mode=False. This disables "
                    "Lambda layer protection, allowing arbitrary code execution "
                    "during model loading. This is a known bypass technique "
                    "(CVE-2025-9906) where the attacker manipulates the archive "
                    "to disable security controls before deserialization."
                ),
                severity=Severity.CRITICAL,
                confidence=1.0,
                target=source,
                evidence=f"safe_mode: {safe_mode}",
                cwe_ids=["CWE-693", "CWE-94"],
                remediation=(
                    "Never trust safe_mode values from inside the model file. "
                    "Enforce safe_mode=True at the application level, not from "
                    "model metadata. Upgrade to Keras >= 3.11.0."
                ),
            ))

        # Check for custom_objects that could override security
        custom_objs = metadata.get("custom_objects", {})
        if custom_objs:
            for obj_name, obj_val in custom_objs.items():
                if isinstance(obj_val, str) and any(
                    p in obj_val for p in (
                        "__import__", "os.", "subprocess", "eval", "exec",
                        "marshal", "pickle", "importlib",
                    )
                ):
                    findings.append(Finding.artifact(
                        rule_id="KERAS-051",
                        title=f"Dangerous custom_object in metadata: {obj_name}",
                        description=(
                            f"metadata.json defines custom_object '{obj_name}' with "
                            f"value referencing dangerous functions. Custom objects "
                            f"in metadata can bypass deserialization allowlists."
                        ),
                        severity=Severity.CRITICAL,
                        target=source,
                        evidence=f"custom_object: {obj_name}={str(obj_val)[:200]}",
                        cwe_ids=["CWE-94"],
                    ))

        return findings

    # ─── Legacy HDF5 format scanning ──────────────────────────

    def _scan_hdf5_format(self, path: Path) -> List[Finding]:
        """
        Deep scan of legacy HDF5 (.h5) format.

        HDF5 models can contain Lambda layers with embedded Python code.
        Unlike the new .keras format, HDF5 has no safe_mode protection.
        """
        findings = []
        source = str(path)

        # Always flag HDF5 as legacy risk
        findings.append(Finding.artifact(
            rule_id="KERAS-010",
            title="Legacy HDF5 model format",
            description=(
                "HDF5 (.h5) models use the legacy Keras serialization format which "
                "has NO safe_mode protection. Lambda layers with arbitrary Python code "
                "WILL execute during model loading. Convert to .keras format and use "
                "safe_mode=True."
            ),
            severity=Severity.MEDIUM,
            target=source,
            cwe_ids=["CWE-502"],
            remediation=(
                "Convert to .keras format: model.save('model.keras'). "
                "Then load with safe_mode=True (default in Keras >= 3.9)."
            ),
        ))

        # Try to deep-scan with h5py if available
        try:
            import h5py  # type: ignore

            with h5py.File(path, "r") as hf:
                # Check for model_config attribute (contains architecture)
                if "model_config" in hf.attrs:
                    config_str = hf.attrs["model_config"]
                    if isinstance(config_str, bytes):
                        config_str = config_str.decode("utf-8", errors="replace")

                    try:
                        config_data = json.loads(config_str)
                        findings.extend(
                            self._analyze_config(config_data, source)
                        )
                    except json.JSONDecodeError:
                        pass

                    # Direct string scan for Lambda patterns
                    config_lower = config_str.lower()
                    if "lambda" in config_lower:
                        findings.append(Finding.artifact(
                            rule_id="KERAS-011",
                            title="Lambda layer in HDF5 model config",
                            description=(
                                "HDF5 model contains a Lambda layer reference in its "
                                "model_config attribute. Lambda layers in HDF5 format "
                                "have NO safe_mode protection and WILL execute arbitrary "
                                "Python code during model loading."
                            ),
                            severity=Severity.CRITICAL,
                            target=source,
                            cwe_ids=["CWE-502", "CWE-94"],
                        ))

                # Check for training_config (can contain custom objects)
                if "training_config" in hf.attrs:
                    training_str = hf.attrs["training_config"]
                    if isinstance(training_str, bytes):
                        training_str = training_str.decode("utf-8", errors="replace")
                    for pattern in SUSPICIOUS_CONFIG_PATTERNS:
                        if pattern in training_str:
                            findings.append(Finding.artifact(
                                rule_id="KERAS-012",
                                title=f"Suspicious content in HDF5 training config: {pattern}",
                                description=(
                                    f"Training config contains '{pattern}' which may "
                                    f"indicate code injection."
                                ),
                                severity=Severity.HIGH,
                                target=source,
                                cwe_ids=["CWE-94"],
                            ))
                            break

        except ImportError:
            logger.debug("h5py not available — HDF5 deep scan skipped")
        except Exception as e:
            logger.warning("HDF5 scan failed for %s: %s", source, e)

        return findings
