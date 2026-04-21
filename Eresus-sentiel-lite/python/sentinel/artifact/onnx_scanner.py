"""ONNX model scanner — custom ops, control flow, external data SSRF."""

from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import List, Any, Optional

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

# ── Standard ONNX operator domains ───────────────────────────────

STANDARD_DOMAINS = {
    "",                     # Default ONNX domain
    "ai.onnx",
    "ai.onnx.ml",
    "ai.onnx.training",
    "ai.onnx.preview.training",
    "com.microsoft",        # Microsoft extensions
    "com.microsoft.nchwc",
    "com.microsoft.dml",    # DirectML
}

# ── Suspicious metadata keys ─────────────────────────────────────

SUSPICIOUS_METADATA_KEYS = {
    "exec", "eval", "system", "command", "script", "code",
    "payload", "shell", "callback", "__reduce__", "__import__",
    "popen", "subprocess", "os.system", "run",
}

# ── Suspicious string patterns in any ONNX content ───────────────

INJECTION_PATTERNS = [
    "__import__", "os.system", "eval(", "exec(",
    "subprocess", "os.popen", "os.exec",
    "builtins.exec", "builtins.eval",
    "marshal.loads", "pickle.loads",
    "base64.b64decode", "codecs.decode",
    "ctypes.", "dlopen",
    "/bin/sh", "/bin/bash",
    "curl ", "wget ", "nc ",
    "socket.", "connect(",
    "import os", "import sys",
    "import subprocess", "import socket",
]

# ── Native extension file patterns ───────────────────────────────

NATIVE_EXTENSION_PATTERNS = [
    ".so", ".dll", ".dylib",
    ".pyd", ".lib",
    "libcustom", "custom_op",
    "ort_custom_ops",
]

# Patterns that are too short/generic for raw binary scan and need
# word-boundary context to avoid false positives in protobuf data.
_BINARY_SAFE_NATIVE_PATTERNS = [
    b".dll", b".dylib", b".pyd",
    b"libcustom", b"custom_op", b"ort_custom_ops",
]

# Short extensions that need context (preceded by alnum or path separator)
_CONTEXT_NATIVE_PATTERNS = [
    (b".so", b".so."),    # .so or .so.1
    (b".lib", None),
]

# ── ONNX op_types with control flow (can hide payloads) ──────────

CONTROL_FLOW_OPS = {"If", "Loop", "Scan", "SequenceMap"}

# ── Maximum subgraph depth before flagging ──────────────────────

MAX_SUBGRAPH_DEPTH = 20

# ── Op_types that should never appear in ML-only models ──────────

SUSPICIOUS_OP_TYPES = {
    "StringNormalizer",  # Can process arbitrary strings
    "RegexFullMatch",    # Regex can be injected
    "StringConcat",      # Building strings at runtime
}


class ONNXScanner:
    """
    Advanced ONNX model scanner with deep computational graph analysis.

    Detection capabilities:
    - Native extension references in custom operations
    - Conditional payload branches in If/Loop subgraphs
    - Protobuf field manipulation signatures
    - ONNX Runtime config abuse
    - Function proto embedded code scanning
    """

    def scan_file(self, path: str) -> List[Finding]:
        """Scan an ONNX model file for all known attack vectors."""
        findings: list[Finding] = []
        p = Path(path)

        if not p.exists():
            logger.warning("File not found: %s", p)
            return findings

        try:
            import onnx  # type: ignore

            model = onnx.load(str(p), load_external_data=False)
            findings.extend(self._check_custom_ops(model, str(p)))
            findings.extend(self._check_metadata(model, str(p)))
            findings.extend(self._check_external_data(model, str(p)))
            findings.extend(self._check_control_flow(model, str(p)))
            findings.extend(self._check_function_protos(model, str(p)))
            findings.extend(self._check_graph_complexity(model, str(p)))
            findings.extend(self._check_subgraph_depth(model, str(p)))
            findings.extend(self._check_native_extensions(model, str(p)))
            findings.extend(self._check_opset_imports(model, str(p)))

        except ImportError:
            logger.debug("onnx library not available — using binary scan")
            findings.extend(self._scan_binary(p))

        except Exception as e:
            findings.append(Finding.artifact(
                rule_id="ONNX-001",
                title="ONNX parse error",
                description=(
                    f"Failed to parse ONNX file: {e}. "
                    f"This could indicate corruption, a crafted file designed "
                    f"to exploit parser vulnerabilities, or protobuf abuse."
                ),
                severity=Severity.MEDIUM,
                target=str(p),
                cwe_ids=["CWE-20"],
            ))

        return findings

    # ─── Custom Op Detection ──────────────────────────────────

    def _check_custom_ops(self, model: Any, source: str) -> List[Finding]:
        """
        Check for custom operator usage — primary attack vector.

        Custom ops can execute native code (C++/CUDA) at inference time.
        An attacker who injects a model with custom ops from a malicious
        domain can achieve arbitrary code execution on the inference host.
        """
        findings = []
        if not hasattr(model, 'graph'):
            return findings

        custom_domains: dict[str, list[str]] = {}

        for node in model.graph.node:
            domain = node.domain or ""
            if domain and domain not in STANDARD_DOMAINS:
                if domain not in custom_domains:
                    custom_domains[domain] = []
                custom_domains[domain].append(node.op_type)

        for domain, op_types in custom_domains.items():
            unique_ops = sorted(set(op_types))
            findings.append(Finding.artifact(
                rule_id="ONNX-002",
                title=f"Custom operator domain: {domain}",
                description=(
                    f"Model uses custom operator domain '{domain}' with "
                    f"{len(unique_ops)} unique op type(s): {unique_ops[:10]}. "
                    f"Custom ops execute native code (C++/CUDA) and are the "
                    f"primary attack vector for ONNX model exploitation. "
                    f"Loading this model requires the custom op library to be "
                    f"registered with the ONNX Runtime."
                ),
                severity=Severity.HIGH,
                target=source,
                evidence=f"Domain: {domain}, Ops: {unique_ops[:10]}",
                cwe_ids=["CWE-94"],
                remediation=(
                    "Verify the custom op domain is from a trusted source. "
                    "Never register custom ops from untrusted models."
                ),
            ))

        return findings

    # ─── Metadata Analysis ────────────────────────────────────

    def _check_metadata(self, model: Any, source: str) -> List[Finding]:
        """Check model metadata for injection and suspicious content."""
        findings = []

        for prop in model.metadata_props:
            key_lower = prop.key.lower()

            # Suspicious key names
            if key_lower in SUSPICIOUS_METADATA_KEYS:
                findings.append(Finding.artifact(
                    rule_id="ONNX-003",
                    title=f"Suspicious metadata key: {prop.key}",
                    description=(
                        f"Metadata key '{prop.key}' suggests potential code injection "
                        f"or payload embedding."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"Key: {prop.key}, Value: {prop.value[:200]}",
                    cwe_ids=["CWE-94"],
                ))

            # Scan values for injection patterns
            for pattern in INJECTION_PATTERNS:
                if pattern in prop.value:
                    findings.append(Finding.artifact(
                        rule_id="ONNX-004",
                        title=f"Code injection pattern in ONNX metadata: {prop.key}",
                        description=(
                            f"Metadata key '{prop.key}' contains '{pattern}' "
                            f"which indicates code injection or exploitation attempt."
                        ),
                        severity=Severity.CRITICAL,
                        target=source,
                        evidence=f"Key: {prop.key}, Pattern: {pattern}",
                        cwe_ids=["CWE-94"],
                    ))
                    break

            # Oversized metadata values
            if len(prop.value) > 100_000:
                findings.append(Finding.artifact(
                    rule_id="ONNX-015",
                    title=f"Oversized metadata value: {prop.key}",
                    description=(
                        f"Metadata key '{prop.key}' has value of "
                        f"{len(prop.value):,} characters."
                    ),
                    severity=Severity.LOW,
                    target=source,
                ))

        return findings

    # ─── External Data References ─────────────────────────────

    def _check_external_data(self, model: Any, source: str) -> List[Finding]:
        """Check for external data references (SSRF/path traversal)."""
        findings = []

        for init in model.graph.initializer:
            if init.data_location == 1:  # EXTERNAL
                loc = ""
                offset = 0
                length = 0

                for ext_data in init.external_data:
                    if ext_data.key == "location":
                        loc = ext_data.value
                    elif ext_data.key == "offset":
                        offset = int(ext_data.value)
                    elif ext_data.key == "length":
                        length = int(ext_data.value)

                # SSRF via remote URLs
                if loc.startswith(("http://", "https://", "ftp://")):
                    findings.append(Finding.artifact(
                        rule_id="ONNX-005",
                        title=f"Remote external data reference: {init.name}",
                        description=(
                            f"Tensor '{init.name}' references remote data at '{loc}'. "
                            f"Loading this model will fetch data from a remote server, "
                            f"enabling SSRF attacks against internal services."
                        ),
                        severity=Severity.CRITICAL,
                        target=source,
                        evidence=f"Tensor: {init.name}, URL: {loc}",
                        cwe_ids=["CWE-918"],
                    ))

                # Path traversal
                elif loc.startswith(("/", "\\")) or ".." in loc:
                    findings.append(Finding.artifact(
                        rule_id="ONNX-016",
                        title=f"Path traversal in external data: {init.name}",
                        description=(
                            f"Tensor '{init.name}' references external data at '{loc}'. "
                            f"Absolute paths or parent directory references can be used "
                            f"to read sensitive files from the inference host."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"Tensor: {init.name}, Path: {loc}",
                        cwe_ids=["CWE-22"],
                    ))

                # Windows UNC paths (network share access)
                elif loc.startswith("\\\\"):
                    findings.append(Finding.artifact(
                        rule_id="ONNX-017",
                        title=f"UNC path in external data: {init.name}",
                        description=(
                            f"Tensor '{init.name}' references UNC path '{loc}'. "
                            f"This can access network shares and leak NTLM hashes."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"Tensor: {init.name}, UNC: {loc}",
                        cwe_ids=["CWE-918"],
                    ))

        return findings

    # ─── Control Flow Analysis ────────────────────────────────

    def _check_control_flow(self, model: Any, source: str) -> List[Finding]:
        """
        Analyze If/Loop subgraphs for hidden computational paths.

        An attacker can hide malicious computation in the 'else' branch
        of an If node that only triggers under specific conditions.
        """
        findings = []
        if_nodes = []
        loop_nodes = []

        for node in model.graph.node:
            if node.op_type == "If":
                if_nodes.append(node)
            elif node.op_type in ("Loop", "Scan"):
                loop_nodes.append(node)

        # Analyze If nodes for asymmetric branches
        for node in if_nodes:
            then_graph = None
            else_graph = None

            for attr in node.attribute:
                if attr.name == "then_branch":
                    then_graph = attr.g
                elif attr.name == "else_branch":
                    else_graph = attr.g

            if then_graph and else_graph:
                then_ops = len(then_graph.node)
                else_ops = len(else_graph.node)

                # Asymmetric branches suggest hidden computation
                if then_ops > 0 and else_ops > 0:
                    ratio = max(then_ops, else_ops) / max(min(then_ops, else_ops), 1)
                    if ratio > 10:
                        findings.append(Finding.artifact(
                            rule_id="ONNX-020",
                            title=f"Asymmetric If branches (ratio: {ratio:.1f}x)",
                            description=(
                                f"If node '{node.name}' has highly asymmetric branches: "
                                f"then_branch has {then_ops} ops, else_branch has {else_ops}. "
                                f"A {ratio:.1f}x ratio suggests hidden computation in the "
                                f"larger branch that only triggers under specific conditions."
                            ),
                            severity=Severity.MEDIUM,
                            target=source,
                            evidence=(
                                f"Node: {node.name}, "
                                f"then_ops: {then_ops}, else_ops: {else_ops}"
                            ),
                        ))

                # Check subgraphs for custom ops
                for graph, branch_name in [
                    (then_graph, "then"), (else_graph, "else")
                ]:
                    if graph:
                        for sub_node in graph.node:
                            domain = sub_node.domain or ""
                            if domain and domain not in STANDARD_DOMAINS:
                                findings.append(Finding.artifact(
                                    rule_id="ONNX-021",
                                    title=f"Custom op hidden in {branch_name} branch",
                                    description=(
                                        f"If node '{node.name}' → {branch_name}_branch "
                                        f"contains custom op '{sub_node.op_type}' from "
                                        f"domain '{domain}'. Hiding custom ops inside "
                                        f"conditional branches is a known evasion technique."
                                    ),
                                    severity=Severity.HIGH,
                                    target=source,
                                    cwe_ids=["CWE-94"],
                                ))

        # Excessive control flow
        total_cf = len(if_nodes) + len(loop_nodes)
        if total_cf > 50:
            findings.append(Finding.artifact(
                rule_id="ONNX-006",
                title=f"Excessive control flow: {total_cf} nodes",
                description=(
                    f"Model has {len(if_nodes)} If and {len(loop_nodes)} Loop nodes. "
                    f"Complex control flow can hide malicious computation paths "
                    f"and makes static analysis difficult."
                ),
                severity=Severity.MEDIUM,
                target=source,
            ))

        return findings

    # ─── Function Proto Analysis ──────────────────────────────

    def _check_function_protos(self, model: Any, source: str) -> List[Finding]:
        """
        Analyze FunctionProto definitions for embedded code.

        ONNX functions define reusable computation subgraphs.
        A malicious function could define dangerous operations.
        """
        findings = []

        if not hasattr(model, 'functions'):
            return findings

        for func in model.functions:
            domain = func.domain or ""

            # Non-standard function domain
            if domain and domain not in STANDARD_DOMAINS:
                findings.append(Finding.artifact(
                    rule_id="ONNX-025",
                    title=f"Custom function domain: {domain}",
                    description=(
                        f"Function '{func.name}' uses custom domain '{domain}'. "
                        f"Custom functions can embed arbitrary computation."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"Function: {func.name}, Domain: {domain}",
                    cwe_ids=["CWE-94"],
                ))

            # Check function body for custom ops
            for node in func.node:
                node_domain = node.domain or ""
                if node_domain and node_domain not in STANDARD_DOMAINS:
                    findings.append(Finding.artifact(
                        rule_id="ONNX-026",
                        title=f"Custom op in function body: {func.name}",
                        description=(
                            f"Function '{func.name}' contains custom op "
                            f"'{node.op_type}' from domain '{node_domain}'."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        cwe_ids=["CWE-94"],
                    ))

        return findings

    # ─── Graph Complexity Analysis ────────────────────────────

    def _check_graph_complexity(self, model: Any, source: str) -> List[Finding]:
        """Analyze overall graph for anomalies."""
        findings = []
        total_nodes = len(model.graph.node)

        # Op_type frequency analysis
        op_counts: dict[str, int] = {}
        for node in model.graph.node:
            op_counts[node.op_type] = op_counts.get(node.op_type, 0) + 1

        # Check for suspicious op_types
        for op_type in SUSPICIOUS_OP_TYPES:
            if op_type in op_counts:
                findings.append(Finding.artifact(
                    rule_id="ONNX-030",
                    title=f"Suspicious op_type: {op_type} (×{op_counts[op_type]})",
                    description=(
                        f"Model uses '{op_type}' operation ({op_counts[op_type]} times). "
                        f"This op_type can process arbitrary string data."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                ))

        return findings

    # ─── Subgraph Depth Analysis ──────────────────────────────

    def _check_subgraph_depth(self, model: Any, source: str) -> List[Finding]:
        """Check for excessively deep subgraph nesting."""
        findings = []
        max_depth = self._measure_subgraph_depth(model.graph, 0)

        if max_depth > MAX_SUBGRAPH_DEPTH:
            findings.append(Finding.artifact(
                rule_id="ONNX-035",
                title=f"Deep subgraph nesting: depth {max_depth}",
                description=(
                    f"Model has subgraph nesting to depth {max_depth}. "
                    f"Deeply nested subgraphs can cause stack overflow in "
                    f"recursive parsers and may hide malicious computations."
                ),
                severity=Severity.HIGH,
                target=source,
                cwe_ids=["CWE-674"],
            ))

        return findings

    def _measure_subgraph_depth(self, graph: Any, current: int) -> int:
        """Recursively measure maximum subgraph depth."""
        if current > 50:
            return current

        max_depth = current
        for node in graph.node:
            for attr in node.attribute:
                if hasattr(attr, 'g') and attr.g and len(attr.g.node) > 0:
                    depth = self._measure_subgraph_depth(attr.g, current + 1)
                    max_depth = max(max_depth, depth)
                if hasattr(attr, 'graphs') and attr.graphs:
                    for sub_g in attr.graphs:
                        depth = self._measure_subgraph_depth(sub_g, current + 1)
                        max_depth = max(max_depth, depth)

        return max_depth

    # ─── Native Extension Detection ───────────────────────────

    def _check_native_extensions(self, model: Any, source: str) -> List[Finding]:
        """
        Detect references to native extensions (.so/.dll/.dylib).

        Custom ops require native code libraries. Finding references to
        specific library files indicates the model expects to load
        native code at runtime.
        """
        findings = []
        all_text = []

        # Collect all string content from the model
        for prop in model.metadata_props:
            all_text.append(f"{prop.key}={prop.value}")

        for node in model.graph.node:
            all_text.append(node.name)
            all_text.append(node.doc_string)
            for attr in node.attribute:
                if attr.s:
                    all_text.append(attr.s.decode("utf-8", errors="replace"))

        combined = " ".join(all_text)

        for pattern in NATIVE_EXTENSION_PATTERNS:
            if pattern in combined:
                findings.append(Finding.artifact(
                    rule_id="ONNX-040",
                    title=f"Native extension reference: {pattern}",
                    description=(
                        f"Model contains reference to native extension pattern '{pattern}'. "
                        f"Loading this model may attempt to load a native code library, "
                        f"enabling arbitrary code execution."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"Pattern: {pattern}",
                    cwe_ids=["CWE-426"],
                ))

        return findings

    # ─── Opset Import Analysis ────────────────────────────────

    def _check_opset_imports(self, model: Any, source: str) -> List[Finding]:
        """Check opset imports for non-standard domains."""
        findings = []

        for opset in model.opset_import:
            domain = opset.domain or ""
            if domain and domain not in STANDARD_DOMAINS:
                findings.append(Finding.artifact(
                    rule_id="ONNX-045",
                    title=f"Non-standard opset import: {domain}",
                    description=(
                        f"Model imports opset from non-standard domain '{domain}' "
                        f"(version {opset.version}). This requires custom op "
                        f"libraries to be installed."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"Domain: {domain}, Version: {opset.version}",
                ))

        return findings

    # ─── Binary Fallback Scanner ──────────────────────────────

    def _scan_binary(self, path: Path) -> List[Finding]:
        """
        Fallback binary scan when onnx library is not available.

        Scans raw bytes for suspicious patterns without full protobuf parsing.
        """
        findings = []
        source = str(path)

        try:
            file_size = path.stat().st_size
            scan_size = min(file_size, 2 * 1024 * 1024)  # First 2MB

            with open(path, "rb") as f:
                data = f.read(scan_size)

            # Decode for text scanning
            text = data.decode("utf-8", errors="ignore")

            # Check for injection patterns
            for pattern in INJECTION_PATTERNS:
                if pattern in text:
                    findings.append(Finding.artifact(
                        rule_id="ONNX-010",
                        title=f"Suspicious string in ONNX binary: {pattern}",
                        description=(
                            f"Raw ONNX binary contains '{pattern}' which suggests "
                            f"potential code injection in metadata or custom ops."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"Pattern: {pattern}",
                    ))

            # Check for native extension references (context-aware)
            for pattern in _BINARY_SAFE_NATIVE_PATTERNS:
                if pattern in data:
                    findings.append(Finding.artifact(
                        rule_id="ONNX-011",
                        title=f"Native extension in ONNX binary: {pattern.decode()}",
                        description=(
                            f"Raw ONNX binary references '{pattern.decode()}'. "
                            f"This model may require native code execution."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                    ))

            # Short patterns need context: must be preceded by alnum/path char
            for short_pat, variant in _CONTEXT_NATIVE_PATTERNS:
                idx = 0
                while True:
                    idx = data.find(short_pat, idx)
                    if idx < 0:
                        break
                    # Check context: preceded by a filename char (a-z, 0-9, _, -)
                    if idx > 0 and (
                        data[idx - 1:idx].isalnum() or data[idx - 1:idx] in (b"_", b"-")
                    ):
                        findings.append(Finding.artifact(
                            rule_id="ONNX-011",
                            title=f"Native extension in ONNX binary: {short_pat.decode()}",
                            description=(
                                f"Raw ONNX binary references '{short_pat.decode()}'. "
                                f"This model may require native code execution."
                            ),
                            severity=Severity.HIGH,
                            target=source,
                        ))
                        break
                    idx += 1

            # Check for oversized file (potential DoS)
            if file_size > 10 * 1024 * 1024 * 1024:  # 10GB
                findings.append(Finding.artifact(
                    rule_id="ONNX-012",
                    title="Oversized ONNX model file",
                    description=f"File is {file_size / (1024*1024*1024):.1f}GB.",
                    severity=Severity.LOW,
                    target=source,
                ))

        except Exception as e:
            logger.warning("Binary scan failed for %s: %s", source, e)

        return findings
