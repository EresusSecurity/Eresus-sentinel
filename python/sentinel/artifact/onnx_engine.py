"""
Eresus Sentinel — ONNX Reverse Engine.

Deep-inspects ONNX model files using protobuf parsing at the byte level.
Detects graph manipulation, dangerous operators, external data references,
and metadata security issues.

ONNX format:
  - Protobuf-serialized ModelProto
  - Contains: ir_version, opset_imports, graph (nodes, initializers, inputs/outputs)
  - Optional: metadata_props, training_info, functions

No onnx pip dependency required — uses raw protobuf varint/field parsing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

from ..finding import Finding, Severity
from .format_common import FormatReport, TensorInfo
from .protobuf_parser import LENGTH_DELIMITED, VARINT, ProtobufParser

# ONNX ModelProto field numbers
FIELD_IR_VERSION = 1           # int64
FIELD_OPSET_IMPORT = 8         # repeated OperatorSetIdProto
FIELD_PRODUCER_NAME = 2        # string
FIELD_PRODUCER_VERSION = 3     # string
FIELD_DOMAIN = 4               # string
FIELD_MODEL_VERSION = 5        # int64
FIELD_DOC_STRING = 6           # string
FIELD_GRAPH = 7                # GraphProto
FIELD_METADATA_PROPS = 14      # repeated StringStringEntryProto
FIELD_TRAINING_INFO = 20       # repeated TrainingInfoProto
FIELD_FUNCTIONS = 25           # repeated FunctionProto

# GraphProto field numbers
GRAPH_NODE = 1                 # repeated NodeProto
GRAPH_NAME = 2                 # string
GRAPH_INITIALIZER = 5          # repeated TensorProto
GRAPH_DOC_STRING = 10          # string
GRAPH_INPUT = 11               # repeated ValueInfoProto
GRAPH_OUTPUT = 12              # repeated ValueInfoProto

# NodeProto field numbers
NODE_INPUT = 1                 # repeated string
NODE_OUTPUT = 2                # repeated string
NODE_NAME = 3                  # string
NODE_OP_TYPE = 4               # string
NODE_DOMAIN = 7                # string
NODE_ATTRIBUTE = 5             # repeated AttributeProto
NODE_DOC_STRING = 6            # string

# ONNX dangerous/suspicious operator types
DANGEROUS_OPS = {
    "Loop", "If", "Scan",           # Control flow — can hide logic
    "CastLike",                       # Type confusion
    "NonMaxSuppression",              # Complex post-processing
    "TfIdfVectorizer",                # Text processing — injection surface
    "RegexFullMatch",                 # Regex execution
    "StringNormalizer",               # String manipulation
}

# Operators that can execute external code or access filesystem
CRITICAL_OPS = {
    "custom_op", "CustomOp",         # Custom operators — arbitrary code
    "ATen", "aten",                  # PyTorch ATen ops — native execution
    "TorchScript",                   # TorchScript — code execution
    "CaffeOp",                       # Caffe ops — legacy unsafe
}

# Known ONNX opsets with security implications
SUSPICIOUS_DOMAINS = {
    "ai.onnx.ml",                    # ML-specific operators
    "com.microsoft",                 # Microsoft custom ops
    "ai.onnx.training",              # Training operators
}


class ONNXReverseEngine:
    """Deep-inspect ONNX model files using raw protobuf parsing.

    Does NOT require onnx or protobuf pip packages.
    Parses the binary protobuf format directly.
    """

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def analyze(self, filepath: str) -> FormatReport:
        """Full ONNX format analysis."""
        self.findings = []
        path = Path(filepath)
        report = FormatReport(
            format_name="ONNX",
            file_path=filepath,
            file_size=path.stat().st_size if path.exists() else 0,
        )

        if not path.exists():
            self.findings.append(Finding.artifact(
                rule_id="FMT-300", title="File not found",
                description=f"ONNX file not found: {filepath}",
                severity=Severity.HIGH, target=filepath,
            ))
            report.findings = self.findings
            return report

        try:
            with open(filepath, "rb") as f:
                data = f.read()

            if len(data) < 4:
                self.findings.append(Finding.artifact(
                    rule_id="FMT-301", title="File too small for ONNX",
                    description="File is too small to be a valid ONNX model.",
                    severity=Severity.HIGH, target=filepath,
                ))
                report.findings = self.findings
                return report

            # Parse top-level ModelProto fields
            model_fields = ProtobufParser.parse_fields(data)
            report.metadata = self._extract_model_metadata(model_fields)

            # Validate IR version
            ir_version = report.metadata.get("ir_version", 0)
            if ir_version < 1 or ir_version > 12:
                self.findings.append(Finding.artifact(
                    rule_id="FMT-310", title=f"Unusual ONNX IR version: {ir_version}",
                    description=f"IR version {ir_version} is outside expected range (1-10).",
                    severity=Severity.LOW, target=filepath,
                    evidence=f"ir_version={ir_version}",
                ))

            # Parse opset imports
            opset_imports = self._extract_opset_imports(model_fields)
            report.metadata["opset_imports"] = opset_imports
            self._analyze_opset_security(opset_imports, filepath)

            # Parse graph
            graph_data = ProtobufParser.get_field_bytes(model_fields, FIELD_GRAPH)
            if graph_data:
                graph_fields = ProtobufParser.parse_fields(graph_data)
                nodes = self._extract_nodes(graph_fields)
                report.metadata["node_count"] = len(nodes)
                report.metadata["op_types"] = list({n["op_type"] for n in nodes if "op_type" in n})
                self._analyze_node_security(nodes, filepath)

                # Extract initializers as tensor info
                initializers = self._extract_initializers(graph_fields)
                report.tensors = initializers
                report.metadata["initializer_count"] = len(initializers)
                self._analyze_tensor_security(initializers, filepath)

                # Check graph name for injection
                graph_name = ProtobufParser.get_field_string(graph_fields, GRAPH_NAME)
                if graph_name:
                    report.metadata["graph_name"] = graph_name
                    self._check_string_injection(graph_name, "graph_name", filepath)

            # Parse metadata properties
            metadata_props = self._extract_metadata_props(model_fields)
            report.metadata["metadata_props"] = metadata_props
            self._analyze_metadata_security(metadata_props, filepath)

            # Check doc strings for injection
            doc_string = report.metadata.get("doc_string", "")
            if doc_string:
                self._check_string_injection(doc_string, "model_doc_string", filepath)

            # Check for external data references
            self._check_external_data(data, filepath)

            # File size sanity
            if report.file_size > 2_000_000_000:  # 2GB
                self.findings.append(Finding.artifact(
                    rule_id="FMT-350", title="Oversized ONNX model",
                    description=f"ONNX file is {report.file_size / 1e9:.1f}GB — may contain embedded data or payloads.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"file_size={report.file_size}",
                ))

            # Training backdoor detection — training_info (field 20)
            training_infos = self._get_all_fields(model_fields, FIELD_TRAINING_INFO)
            if training_infos:
                report.metadata["training_info_count"] = len(training_infos)
                for i, ti_raw in enumerate(training_infos):
                    ti_fields = self._parse_protobuf_fields(ti_raw)
                    # Check for embedded training graphs with suspicious ops
                    # TrainingInfoProto has: initialization (field 1), algorithm (field 2)
                    for graph_field_num in (1, 2):
                        embedded_graph = self._get_field_bytes(ti_fields, graph_field_num)
                        if embedded_graph:
                            eg_fields = self._parse_protobuf_fields(embedded_graph)
                            embedded_nodes = self._extract_nodes(eg_fields)
                            bad_ops = [
                                n["op_type"] for n in embedded_nodes
                                if n.get("op_type", "") in CRITICAL_OPS
                                or n.get("op_type", "").lower() in {o.lower() for o in CRITICAL_OPS}
                            ]
                            if bad_ops:
                                self.findings.append(Finding.artifact(
                                    rule_id="FMT-344",
                                    title=f"Dangerous ops in training graph #{i}",
                                    description=(
                                        f"TrainingInfo #{i} contains embedded graph with "
                                        f"dangerous operators: {', '.join(bad_ops[:5])}. "
                                        f"Training graphs execute during fine-tuning and "
                                        f"can contain backdoor update rules."
                                    ),
                                    severity=Severity.CRITICAL, target=filepath,
                                    evidence=f"training_info={i}, ops={bad_ops[:5]}",
                                ))

                self.findings.append(Finding.artifact(
                    rule_id="FMT-344",
                    title=f"ONNX model contains {len(training_infos)} training info block(s)",
                    description=(
                        "Training info blocks define how a model should be fine-tuned. "
                        "These can contain backdoor gradient manipulation rules that "
                        "activate during transfer learning."
                    ),
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"training_info_count={len(training_infos)}",
                ))

            # Custom function definitions — functions (field 25)
            function_defs = self._get_all_fields(model_fields, FIELD_FUNCTIONS)
            if function_defs:
                report.metadata["function_count"] = len(function_defs)
                for i, func_raw in enumerate(function_defs):
                    func_fields = self._parse_protobuf_fields(func_raw)
                    # FunctionProto: name (field 1), node (field 4)
                    func_name = self._get_field_string(func_fields, 1)
                    func_nodes_raw = self._get_all_fields(func_fields, 4)
                    func_node_count = len(func_nodes_raw)

                    # Parse ops inside the function
                    func_ops = []
                    for node_raw in func_nodes_raw:
                        nf = self._parse_protobuf_fields(node_raw)
                        op = self._get_field_string(nf, NODE_OP_TYPE)
                        if op:
                            func_ops.append(op)

                    bad_func_ops = [
                        op for op in func_ops
                        if op in CRITICAL_OPS or op in DANGEROUS_OPS
                    ]
                    if bad_func_ops:
                        self.findings.append(Finding.artifact(
                            rule_id="FMT-345",
                            title=f"Dangerous ops in ONNX function: {func_name or f'func_{i}'}",
                            description=(
                                f"Custom function '{func_name or f'func_{i}'}' contains "
                                f"{func_node_count} nodes with dangerous operators: "
                                f"{', '.join(bad_func_ops[:5])}. Custom functions can "
                                f"hide arbitrary computation chains."
                            ),
                            severity=Severity.HIGH, target=filepath,
                            evidence=f"function={func_name}, ops={bad_func_ops[:5]}",
                        ))
                    elif func_node_count > 1000:
                        self.findings.append(Finding.artifact(
                            rule_id="FMT-346",
                            title=f"Large ONNX function: {func_name or f'func_{i}'} ({func_node_count} nodes)",
                            description=(
                                f"Custom function '{func_name or f'func_{i}'}' has "
                                f"{func_node_count} nodes — unusually large for a function "
                                f"definition. May obscure malicious logic."
                            ),
                            severity=Severity.LOW, target=filepath,
                            evidence=f"function={func_name}, node_count={func_node_count}",
                        ))

        except Exception as e:
            self.findings.append(Finding.artifact(
                rule_id="FMT-302", title="ONNX parse error",
                description=f"Failed to parse ONNX file: {e}",
                severity=Severity.MEDIUM, target=filepath, evidence=str(e),
            ))

        report.findings = self.findings
        return report

    # ── Protobuf helpers (delegating to shared ProtobufParser) ─────
    # Kept as thin wrappers for backwards compatibility within this module.

    def _get_field_bytes(self, fields, field_num):
        return ProtobufParser.get_field_bytes(fields, field_num)

    def _get_field_string(self, fields, field_num):
        return ProtobufParser.get_field_string(fields, field_num)

    def _get_field_varint(self, fields, field_num):
        return ProtobufParser.get_field_varint(fields, field_num)

    def _get_all_fields(self, fields, field_num):
        return ProtobufParser.get_all_fields(fields, field_num)

    def _parse_protobuf_fields(self, data):
        return ProtobufParser.parse_fields(data)

    # ── Model metadata extraction ─────────────────────────────

    def _extract_model_metadata(self, fields: List[Tuple[int, int, bytes]]) -> Dict[str, Any]:
        meta = {}
        meta["ir_version"] = self._get_field_varint(fields, FIELD_IR_VERSION)
        meta["producer_name"] = self._get_field_string(fields, FIELD_PRODUCER_NAME)
        meta["producer_version"] = self._get_field_string(fields, FIELD_PRODUCER_VERSION)
        meta["domain"] = self._get_field_string(fields, FIELD_DOMAIN)
        meta["model_version"] = self._get_field_varint(fields, FIELD_MODEL_VERSION)
        meta["doc_string"] = self._get_field_string(fields, FIELD_DOC_STRING)
        return meta

    def _extract_opset_imports(self, fields: List[Tuple[int, int, bytes]]) -> List[Dict[str, Any]]:
        """Parse OperatorSetIdProto entries."""
        opsets = []
        for raw in self._get_all_fields(fields, FIELD_OPSET_IMPORT):
            sub_fields = self._parse_protobuf_fields(raw)
            domain = self._get_field_string(sub_fields, 1)  # domain
            version = self._get_field_varint(sub_fields, 2)   # version
            opsets.append({"domain": domain or "ai.onnx", "version": version})
        return opsets

    def _extract_metadata_props(self, fields: List[Tuple[int, int, bytes]]) -> Dict[str, str]:
        """Parse StringStringEntryProto entries."""
        props = {}
        for raw in self._get_all_fields(fields, FIELD_METADATA_PROPS):
            sub_fields = self._parse_protobuf_fields(raw)
            key = self._get_field_string(sub_fields, 1)
            value = self._get_field_string(sub_fields, 2)
            if key:
                props[key] = value
        return props

    # ── Graph and node extraction ─────────────────────────────

    def _extract_nodes(self, graph_fields: List[Tuple[int, int, bytes]]) -> List[Dict[str, Any]]:
        """Parse NodeProto entries from graph."""
        nodes = []
        for raw in self._get_all_fields(graph_fields, GRAPH_NODE):
            node_fields = self._parse_protobuf_fields(raw)
            node = {
                "op_type": self._get_field_string(node_fields, NODE_OP_TYPE),
                "name": self._get_field_string(node_fields, NODE_NAME),
                "domain": self._get_field_string(node_fields, NODE_DOMAIN),
                "doc_string": self._get_field_string(node_fields, NODE_DOC_STRING),
                "inputs": [self._get_field_string([(1, LENGTH_DELIMITED, b)], 1)
                           for b in self._get_all_fields(node_fields, NODE_INPUT)],
                "outputs": [self._get_field_string([(1, LENGTH_DELIMITED, b)], 1)
                            for b in self._get_all_fields(node_fields, NODE_OUTPUT)],
            }
            nodes.append(node)
        return nodes

    def _extract_initializers(self, graph_fields: List[Tuple[int, int, bytes]]) -> List[TensorInfo]:
        """Parse TensorProto entries (initializers/weights)."""
        tensors = []
        for raw in self._get_all_fields(graph_fields, GRAPH_INITIALIZER):
            sub = self._parse_protobuf_fields(raw)
            name = self._get_field_string(sub, 2)   # TensorProto.name = field 2 (was 8 before, check)
            # dims are repeated int64 at field 1
            dims = []
            for fn, wt, val in sub:
                if fn == 1 and wt == VARINT:
                    dims.append(int.from_bytes(val[:8], "little"))

            data_type = self._get_field_varint(sub, 2) if not name else 0
            # Try field 8 for name (ONNX uses field 8 for external data name)
            if not name:
                name = self._get_field_string(sub, 8) or f"unnamed_tensor_{len(tensors)}"

            tensors.append(TensorInfo(
                name=name, n_dims=len(dims), shape=dims,
                dtype=f"onnx_type_{data_type}", offset=0,
                size_bytes=len(raw),
            ))
        return tensors

    # ── Security analysis ─────────────────────────────────────

    def _analyze_opset_security(self, opsets: List[Dict[str, Any]], filepath: str) -> None:
        """Check opset imports for security implications."""
        for opset in opsets:
            domain = opset.get("domain", "")
            version = opset.get("version", 0)

            if domain in SUSPICIOUS_DOMAINS:
                self.findings.append(Finding.artifact(
                    rule_id="FMT-320",
                    title=f"ONNX uses domain: {domain}",
                    description=f"Model imports opset from domain '{domain}' v{version}. "
                                "Non-standard domains may contain custom operators.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"domain={domain}, version={version}",
                ))

            if domain == "" or domain == "ai.onnx":
                if version < 7:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-321",
                        title=f"Old ONNX opset version: {version}",
                        description=f"Model uses opset v{version}. Versions <7 have known limitations.",
                        severity=Severity.LOW, target=filepath,
                        evidence=f"version={version}",
                    ))

    def _analyze_node_security(self, nodes: List[Dict[str, Any]], filepath: str) -> None:
        """Check graph nodes for dangerous operators."""
        op_counts: Dict[str, int] = {}
        for node in nodes:
            op = node.get("op_type", "")
            op_counts[op] = op_counts.get(op, 0) + 1

            # Critical operators — possible code execution
            if op in CRITICAL_OPS or op.lower() in {o.lower() for o in CRITICAL_OPS}:
                self.findings.append(Finding.artifact(
                    rule_id="FMT-330",
                    title=f"ONNX critical operator: {op}",
                    description=f"Node '{node.get('name', '?')}' uses operator '{op}' "
                                "which can execute arbitrary native code.",
                    severity=Severity.CRITICAL, target=filepath,
                    evidence=f"op={op}, node={node.get('name', '?')}",
                ))

            # Dangerous operators
            if op in DANGEROUS_OPS:
                self.findings.append(Finding.artifact(
                    rule_id="FMT-331",
                    title=f"ONNX dangerous operator: {op}",
                    description=f"Node '{node.get('name', '?')}' uses '{op}' which has "
                                "complex control flow that can obscure model behavior.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"op={op}, node={node.get('name', '?')}",
                ))

            # Check node doc strings for injection
            doc = node.get("doc_string", "")
            if doc:
                self._check_string_injection(doc, f"node_{node.get('name', '?')}_doc", filepath)

            # Detect custom domain operators
            domain = node.get("domain", "")
            if domain and domain not in ("", "ai.onnx", "ai.onnx.ml"):
                self.findings.append(Finding.artifact(
                    rule_id="FMT-332",
                    title=f"Custom domain operator: {domain}::{op}",
                    description=f"Node uses custom domain '{domain}' — may require external libraries.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"domain={domain}, op={op}",
                ))

        # Excessive node count
        if len(nodes) > 50000:
            self.findings.append(Finding.artifact(
                rule_id="FMT-333", title=f"Excessive ONNX graph size: {len(nodes)} nodes",
                description="Graph has an unusually large number of nodes — may impact performance.",
                severity=Severity.LOW, target=filepath,
                evidence=f"node_count={len(nodes)}",
            ))

        # Nested control flow analysis — If/Loop subgraphs can hide
        # computation paths. The deeper the nesting, the more suspicious.
        control_flow_ops = [n for n in nodes if n.get("op_type") in ("If", "Loop", "Scan")]
        if len(control_flow_ops) > 10:
            self.findings.append(Finding.artifact(
                rule_id="FMT-334",
                title=f"Excessive control flow operators: {len(control_flow_ops)} If/Loop/Scan nodes",
                description=(
                    f"Graph contains {len(control_flow_ops)} control flow operators. "
                    f"Dense control flow can hide malicious computation paths that "
                    f"only activate under specific input conditions (conditional backdoors)."
                ),
                severity=Severity.HIGH, target=filepath,
                evidence=f"control_flow_ops={[n.get('op_type') for n in control_flow_ops[:10]]}",
            ))

        # Custom operator with native runtime registration pattern
        custom_domain_ops = [
            n for n in nodes
            if n.get("domain") and n["domain"] not in ("", "ai.onnx", "ai.onnx.ml")
        ]
        if custom_domain_ops:
            unique_domains = {n["domain"] for n in custom_domain_ops}
            for domain in unique_domains:
                domain_ops = [n for n in custom_domain_ops if n["domain"] == domain]
                op_types = list({n.get("op_type", "?") for n in domain_ops})
                if any(kw in domain.lower() for kw in ("native", "cuda", "runtime", "custom")):
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-335",
                        title=f"Native runtime custom operator domain: {domain}",
                        description=(
                            f"Model uses custom domain '{domain}' with {len(domain_ops)} nodes "
                            f"({', '.join(op_types[:5])}). Domains with native/CUDA/runtime "
                            f"keywords indicate operators implemented in native code (C++/CUDA) "
                            f"which execute arbitrary code when loaded by ONNX Runtime."
                        ),
                        severity=Severity.CRITICAL, target=filepath,
                        evidence=f"domain={domain}, ops={op_types[:5]}",
                        cwe_ids=["CWE-94"],
                    ))

    def _analyze_tensor_security(self, tensors: List[TensorInfo], filepath: str) -> None:
        """Check initializer tensors for anomalies."""
        suspicious_names = ["backdoor", "trojan", "payload", "inject", "exploit", "hidden", "secret"]
        for t in tensors:
            name_lower = t.name.lower()
            for sus in suspicious_names:
                if sus in name_lower:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-340",
                        title=f"Suspicious ONNX tensor name: {t.name}",
                        description=f"Initializer tensor '{t.name}' has a suspicious name.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"tensor={t.name}, shape={t.shape}",
                    ))
                    break

    def _analyze_metadata_security(self, props: Dict[str, str], filepath: str) -> None:
        """Check metadata properties for code injection."""
        for key, value in props.items():
            val_lower = value.lower()
            if any(danger in val_lower for danger in [
                "eval(", "exec(", "import os", "subprocess",
                "__import__", "os.system", "<script",
                "javascript:", "data:text/html", "onerror=",
            ]):
                self.findings.append(Finding.artifact(
                    rule_id="FMT-341",
                    title=f"Suspicious ONNX metadata: {key}",
                    description=f"Metadata property '{key}' contains code execution patterns.",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"key={key}, value={value[:200]}",
                ))

    def _check_string_injection(self, text: str, field_name: str, filepath: str) -> None:
        """Check any string field for injection patterns."""
        text_lower = text.lower()
        if any(danger in text_lower for danger in [
            "eval(", "exec(", "__import__", "os.system",
            "subprocess", "<script", "javascript:",
        ]):
            self.findings.append(Finding.artifact(
                rule_id="FMT-342",
                title=f"Code injection in ONNX field: {field_name}",
                description=f"Field '{field_name}' contains executable code patterns.",
                severity=Severity.HIGH, target=filepath,
                evidence=f"field={field_name}, preview={text[:200]}",
            ))

    def _check_external_data(self, data: bytes, filepath: str) -> None:
        """Detect external data references in the protobuf."""
        # External data uses TensorProto.data_location = EXTERNAL (1)
        # which stores data in separate files — potential for path traversal
        indicators = [b"data_location", b"external_data", b"..", b"/etc/", b"\\\\"]
        for indicator in indicators:
            if indicator in data:
                self.findings.append(Finding.artifact(
                    rule_id="FMT-343",
                    title="ONNX external data reference detected",
                    description=f"Model contains external data references containing '{indicator.decode('utf-8', errors='replace')}'. "
                                "External data files may enable path traversal attacks.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"indicator={indicator}",
                ))
                break  # One finding is enough
