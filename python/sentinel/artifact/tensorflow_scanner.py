"""
Eresus Sentinel — TensorFlow SavedModel Scanner.

Deep-inspects TensorFlow SavedModel protobuf files for backdoor operations,
dangerous function definitions, malicious assets, and DoS-prone structures.

Covers PAIT threat IDs:
  - PAIT-TF-200: Backdoor detection via dangerous ops (PyFunc, ReadFile, etc.)
  - PAIT-TF-300: Code execution via tf.function definitions
  - PAIT-TF-301: Arbitrary file access via malicious assets
  - PAIT-TF-302: DoS via malformed/oversized protobuf

SavedModel directory structure:
  saved_model/
  ├── saved_model.pb          ← protobuf ModelProto
  ├── variables/
  │   ├── variables.data-00000-of-00001
  │   └── variables.index
  └── assets/                 ← arbitrary files (attack surface)

No tensorflow pip dependency required — uses raw protobuf varint/field parsing.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Set

from ..finding import Finding, Severity
from ..rules import load_scanner_rules
from .protobuf_parser import ProtobufParser

_rules = load_scanner_rules()
_tf_rules = _rules.get("tensorflow", {})
_common = _rules.get("common", {})

# SavedModel protobuf field numbers
SM_SCHEMA_VERSION = 1
SM_META_GRAPHS = 2

# MetaGraphDef field numbers
MG_META_INFO_DEF = 1
MG_GRAPH_DEF = 2
MG_SAVER_DEF = 3
MG_COLLECTION_DEF = 4
MG_SIGNATURE_DEF = 5
MG_ASSET_FILE_DEF = 6
MG_OBJECT_GRAPH_DEF = 7

# GraphDef field numbers
GD_NODE = 1
GD_VERSIONS = 4
GD_LIBRARY = 2

# NodeDef field numbers
ND_NAME = 1
ND_OP = 2
ND_INPUT = 3
ND_DEVICE = 4
ND_ATTR = 5

# FunctionDefLibrary field numbers
FDL_FUNCTION = 1

# FunctionDef field numbers
FD_SIGNATURE = 1
FD_NODE_DEF = 3

# OpDef field numbers
OD_NAME = 1

TF_CRITICAL_OPS: Set[str] = set(
    _tf_rules.get("critical_ops", [
        "PyFunc", "PyFuncStateless", "EagerPyFunc",
        "ShellOp", "ExternalProcess", "Abort",
    ])
)

TF_HIGH_OPS: Set[str] = set(
    _tf_rules.get("high_ops", [
        "ReadFile", "WriteFile", "MatchingFiles",
        "WholeFileReader", "WholeFileReaderV2",
        "FileSystemSetConfiguration", "TempFileResourceHandle",
        "InitializeTableFromTextFile", "InitializeTableFromTextFileV2",
        "LMDBReader",
        "DebugIdentity", "DebugNanCount", "DebugNumericSummary",
        "Print", "PrintV2",
        "DecodeRaw", "DecodeCSV",
    ])
)

TF_MEDIUM_OPS: Set[str] = set(
    _tf_rules.get("medium_ops", [
        "CollectiveGather", "CollectiveReduce", "CollectiveBcastSend",
        "CollectiveBcastRecv", "Assert",
        "PartitionedCall", "StatefulPartitionedCall",
    ])
)

ALL_DANGEROUS_OPS = TF_CRITICAL_OPS | TF_HIGH_OPS | TF_MEDIUM_OPS

EXECUTABLE_EXTENSIONS: Set[str] = set(
    _common.get("executable_extensions", [
        ".sh", ".bash", ".py", ".rb", ".pl", ".bat", ".cmd", ".ps1",
        ".exe", ".dll", ".so", ".dylib", ".com", ".msi",
    ])
)

SUSPICIOUS_ASSET_NAMES = _common.get("suspicious_names", [
    "backdoor", "payload", "exploit", "trojan", "malware",
    "reverse_shell", "c2", "exfil", "keylogger",
])


class TensorFlowScanner:
    """Deep-inspect TensorFlow SavedModel files for security threats.

    Supports both directory-based SavedModel scanning and single .pb file analysis.
    Does NOT require tensorflow pip package — parses protobuf directly.
    """

    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a TensorFlow SavedModel (directory or .pb file).

        Args:
            path: Path to a SavedModel directory or a single .pb file.

        Returns:
            List of security findings.
        """
        self.findings = []
        p = Path(path)

        if p.is_dir():
            self._scan_savedmodel_dir(p)
        elif p.is_file():
            self._scan_pb_file(p)
        else:
            self.findings.append(Finding.artifact(
                rule_id="TF-000", title="Path not found",
                description=f"TensorFlow path not found: {path}",
                severity=Severity.HIGH, target=path,
            ))

        return self.findings

    def scan_directory(self, dirpath: str) -> List[Finding]:
        """Scan a directory tree for SavedModel directories and .pb files."""
        all_findings: List[Finding] = []
        p = Path(dirpath)
        if not p.is_dir():
            return all_findings

        for pb in p.rglob("saved_model.pb"):
            scanner = TensorFlowScanner()
            all_findings.extend(scanner.scan_file(str(pb.parent)))

        for pb in p.rglob("*.pb"):
            if pb.name != "saved_model.pb":
                scanner = TensorFlowScanner()
                all_findings.extend(scanner.scan_file(str(pb)))

        return all_findings

    def _scan_savedmodel_dir(self, model_dir: Path) -> None:
        """Scan a complete SavedModel directory structure."""
        filepath = str(model_dir)

        pb_file = model_dir / "saved_model.pb"
        if pb_file.exists():
            self._scan_pb_file(pb_file)
        else:
            self.findings.append(Finding.artifact(
                rule_id="TF-000", title="Missing saved_model.pb",
                description=f"SavedModel directory has no saved_model.pb: {model_dir}",
                severity=Severity.HIGH, target=filepath,
            ))

        assets_dir = model_dir / "assets"
        if assets_dir.is_dir():
            self._check_assets(assets_dir, filepath)

        assets_extra = model_dir / "assets.extra"
        if assets_extra.is_dir():
            self._check_assets(assets_extra, filepath)

    def _scan_pb_file(self, pb_path: Path) -> None:
        """Parse and analyze a saved_model.pb protobuf file."""
        filepath = str(pb_path)

        self._check_protobuf_sanity(pb_path, filepath)

        try:
            data = pb_path.read_bytes()
            if len(data) < 4:
                self.findings.append(Finding.artifact(
                    rule_id="TF-031", title="Protobuf too small",
                    description="SavedModel .pb file is too small to be valid.",
                    severity=Severity.HIGH, target=filepath,
                ))
                return

            sm_fields = ProtobufParser.parse_fields(data)

            schema_ver = ProtobufParser.get_field_varint(sm_fields, SM_SCHEMA_VERSION)
            if schema_ver > 2:
                self.findings.append(Finding.artifact(
                    rule_id="TF-032", title=f"Unusual schema version: {schema_ver}",
                    description=f"SavedModel schema version {schema_ver} is unknown. "
                                "Expected 1 or 2.",
                    severity=Severity.LOW, target=filepath,
                    evidence=f"schema_version={schema_ver}",
                ))

            meta_graphs = ProtobufParser.get_all_fields(sm_fields, SM_META_GRAPHS)
            if not meta_graphs:
                self.findings.append(Finding.artifact(
                    rule_id="TF-033", title="No MetaGraphDef in SavedModel",
                    description="SavedModel contains no MetaGraphDef entries.",
                    severity=Severity.MEDIUM, target=filepath,
                ))
                return

            for i, mg_data in enumerate(meta_graphs):
                self._analyze_metagraph(mg_data, filepath, i)

        except Exception as e:
            self.findings.append(Finding.artifact(
                rule_id="TF-099", title="TF protobuf parse error",
                description=f"Failed to parse SavedModel protobuf: {e}",
                severity=Severity.MEDIUM, target=filepath,
                evidence=str(e),
            ))

    def _analyze_metagraph(self, mg_data: bytes, filepath: str, mg_index: int) -> None:
        """Analyze a MetaGraphDef for security threats."""
        mg_fields = ProtobufParser.parse_fields(mg_data)

        graph_data = ProtobufParser.get_field_bytes(mg_fields, MG_GRAPH_DEF)
        if graph_data:
            graph_fields = ProtobufParser.parse_fields(graph_data)

            self._check_backdoor_ops(graph_fields, filepath, mg_index)

            lib_data = ProtobufParser.get_field_bytes(graph_fields, GD_LIBRARY)
            if lib_data:
                self._check_function_defs(lib_data, filepath, mg_index)

            node_datas = ProtobufParser.get_all_fields(graph_fields, GD_NODE)
            if len(node_datas) > 100_000:
                self.findings.append(Finding.artifact(
                    rule_id="TF-030", title=f"Excessive node count: {len(node_datas)}",
                    description=f"MetaGraph {mg_index} has {len(node_datas)} nodes — "
                                "may cause performance issues or denial of service.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"metagraph={mg_index}, node_count={len(node_datas)}",
                    cwe_ids=["CWE-400"],
                ))

    def _check_backdoor_ops(
        self, graph_fields: list, filepath: str, mg_index: int
    ) -> None:
        """Scan GraphDef nodes for dangerous TensorFlow operations."""
        node_datas = ProtobufParser.get_all_fields(graph_fields, GD_NODE)

        for node_data in node_datas:
            node_fields = ProtobufParser.parse_fields(node_data)
            node_name = ProtobufParser.get_field_string(node_fields, ND_NAME)
            node_op = ProtobufParser.get_field_string(node_fields, ND_OP)

            if not node_op:
                continue

            if node_op in TF_CRITICAL_OPS:
                self.findings.append(Finding.artifact(
                    rule_id="TF-001",
                    title=f"TF critical op: {node_op}",
                    description=f"Node '{node_name}' uses operator '{node_op}' "
                                "which enables arbitrary code execution. "
                                "This is a strong indicator of a backdoored model.",
                    severity=Severity.CRITICAL, target=filepath,
                    evidence=f"op={node_op}, node={node_name}, metagraph={mg_index}",
                    cwe_ids=["CWE-94"],
                ))
            elif node_op in TF_HIGH_OPS:
                self.findings.append(Finding.artifact(
                    rule_id="TF-002",
                    title=f"TF high-risk op: {node_op}",
                    description=f"Node '{node_name}' uses operator '{node_op}' "
                                "which provides filesystem or debug access.",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"op={node_op}, node={node_name}, metagraph={mg_index}",
                    cwe_ids=["CWE-94"],
                ))
            elif node_op in TF_MEDIUM_OPS:
                self.findings.append(Finding.artifact(
                    rule_id="TF-003",
                    title=f"TF suspicious op: {node_op}",
                    description=f"Node '{node_name}' uses operator '{node_op}' "
                                "which has elevated risk in adversarial contexts.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"op={node_op}, node={node_name}, metagraph={mg_index}",
                ))

            name_lower = node_name.lower()
            for pattern in SUSPICIOUS_ASSET_NAMES:
                if pattern in name_lower:
                    self.findings.append(Finding.artifact(
                        rule_id="TF-004",
                        title=f"Suspicious node name: {node_name}",
                        description=f"Node '{node_name}' has a name containing "
                                    f"suspicious pattern '{pattern}'.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"node={node_name}, pattern={pattern}",
                    ))
                    break

    def _check_function_defs(
        self, lib_data: bytes, filepath: str, mg_index: int
    ) -> None:
        """Analyze FunctionDefLibrary for dangerous function definitions."""
        lib_fields = ProtobufParser.parse_fields(lib_data)
        func_datas = ProtobufParser.get_all_fields(lib_fields, FDL_FUNCTION)

        for func_data in func_datas:
            func_fields = ProtobufParser.parse_fields(func_data)

            sig_data = ProtobufParser.get_field_bytes(func_fields, FD_SIGNATURE)
            func_name = ""
            if sig_data:
                sig_fields = ProtobufParser.parse_fields(sig_data)
                func_name = ProtobufParser.get_field_string(sig_fields, OD_NAME)

            body_nodes = ProtobufParser.get_all_fields(func_fields, FD_NODE_DEF)
            for node_data in body_nodes:
                node_fields = ProtobufParser.parse_fields(node_data)
                node_op = ProtobufParser.get_field_string(node_fields, ND_OP)

                if node_op in TF_CRITICAL_OPS:
                    self.findings.append(Finding.artifact(
                        rule_id="TF-010",
                        title=f"Dangerous op in tf.function: {node_op}",
                        description=f"Function '{func_name}' contains dangerous "
                                    f"operator '{node_op}'. Code execution is possible "
                                    "when this function is called during inference.",
                        severity=Severity.CRITICAL, target=filepath,
                        evidence=f"function={func_name}, op={node_op}, "
                                 f"metagraph={mg_index}",
                        cwe_ids=["CWE-94"],
                    ))
                elif node_op in TF_HIGH_OPS:
                    self.findings.append(Finding.artifact(
                        rule_id="TF-011",
                        title=f"High-risk op in tf.function: {node_op}",
                        description=f"Function '{func_name}' contains high-risk "
                                    f"operator '{node_op}'.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"function={func_name}, op={node_op}",
                        cwe_ids=["CWE-94"],
                    ))

    def _check_assets(self, assets_dir: Path, filepath: str) -> None:
        """Scan SavedModel assets directory for malicious files."""
        try:
            for item in assets_dir.rglob("*"):
                rel = item.relative_to(assets_dir)

                if item.is_symlink():
                    target = os.readlink(str(item))
                    self.findings.append(Finding.artifact(
                        rule_id="TF-020",
                        title=f"Symlink in assets: {rel}",
                        description=f"Asset '{rel}' is a symlink pointing to '{target}'. "
                                    "Symlinks can be used to access files outside the model.",
                        severity=Severity.CRITICAL, target=filepath,
                        evidence=f"symlink={rel}, target={target}",
                        cwe_ids=["CWE-59"],
                    ))
                    continue

                if not item.is_file():
                    continue

                ext = item.suffix.lower()
                if ext in EXECUTABLE_EXTENSIONS:
                    self.findings.append(Finding.artifact(
                        rule_id="TF-021",
                        title=f"Executable in assets: {rel}",
                        description=f"Asset '{rel}' has executable extension '{ext}'. "
                                    "Executable files in model assets are dangerous.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"file={rel}, extension={ext}",
                        cwe_ids=["CWE-94"],
                    ))

                name_lower = item.name.lower()
                for pattern in SUSPICIOUS_ASSET_NAMES:
                    if pattern in name_lower:
                        self.findings.append(Finding.artifact(
                            rule_id="TF-022",
                            title=f"Suspicious asset name: {rel}",
                            description=f"Asset '{rel}' has a suspicious name "
                                        f"containing '{pattern}'.",
                            severity=Severity.HIGH, target=filepath,
                            evidence=f"file={rel}, pattern={pattern}",
                        ))
                        break

        except OSError as e:
            self.findings.append(Finding.artifact(
                rule_id="TF-029", title="Asset scan error",
                description=f"Failed to scan assets directory: {e}",
                severity=Severity.MEDIUM, target=filepath,
                evidence=str(e),
            ))

    def _check_protobuf_sanity(self, pb_path: Path, filepath: str) -> None:
        """Check protobuf file for DoS-inducing properties."""
        try:
            file_size = pb_path.stat().st_size

            if file_size > 500_000_000:  # 500MB
                self.findings.append(Finding.artifact(
                    rule_id="TF-030",
                    title=f"Oversized SavedModel: {file_size / 1e6:.0f}MB",
                    description=f"SavedModel protobuf is {file_size / 1e6:.0f}MB — "
                                "unusually large, may cause denial of service.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"file_size={file_size}",
                    cwe_ids=["CWE-400"],
                ))

        except OSError:
            pass
