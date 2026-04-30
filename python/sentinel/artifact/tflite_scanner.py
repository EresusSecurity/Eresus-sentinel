"""
Eresus Sentinel — TFLite / LiteRT Scanner.

Deep-inspects TFLite model files (.tflite) for security threats using
the FlatBuffer wire format parser. TFLite is the dominant format for
mobile and edge AI inference.

Covers PAIT threat IDs:
  - PAIT-LITERT-300: Malformed FlatBuffer structures (OOB reads)
  - PAIT-LITERT-301: Custom/dangerous operator delegates
  - PAIT-LITERT-302: Integer overflow in tensor dimensions

TFLite file structure (FlatBuffer):
  offset 0: root_table_offset (uint32)
  offset 4: file_identifier "TFL3" (4 bytes)
  Root table = Model:
    field 0: version (uint32)
    field 1: operator_codes (vector of OperatorCode tables)
    field 2: subgraphs (vector of SubGraph tables)
    field 3: description (string)
    field 4: buffers (vector of Buffer tables)
    field 5: metadata_buffer (vector of int32)
    field 6: metadata (vector of Metadata tables)

No tensorflow or tflite-runtime dependency required.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from ..finding import Finding, Severity
from ..rules import load_scanner_rules
from .flatbuffer_parser import FlatBufferParser

_rules = load_scanner_rules()
_tflite_rules = _rules.get("tflite", {})
_common = _rules.get("common", {})

TFLITE_MAGIC = b"TFL3"
BUILTIN_OP_COUNT = _tflite_rules.get("builtin_op_count", 210)
MAX_TENSOR_DIM = _tflite_rules.get("max_tensor_dim", 1_073_741_824)
MAX_TENSOR_RANK = _tflite_rules.get("max_tensor_rank", 16)

SUSPICIOUS_NAMES = _common.get("suspicious_names", [
    "backdoor", "trojan", "payload", "exploit", "malware",
    "reverse_shell", "c2", "exfil", "keylogger",
])


class TFLiteScanner:
    """Deep-inspect TFLite model files for security threats.

    Uses FlatBuffer wire format parsing. Does NOT require tflite-runtime.
    """

    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a TFLite model file.

        Args:
            path: Path to a .tflite file.

        Returns:
            List of security findings.
        """
        self.findings = []
        p = Path(path)

        if not p.exists():
            self.findings.append(Finding.artifact(
                rule_id="TFLITE-000", title="File not found",
                description=f"TFLite file not found: {path}",
                severity=Severity.HIGH, target=path,
            ))
            return self.findings

        if not p.is_file():
            self.findings.append(Finding.artifact(
                rule_id="TFLITE-000", title="Not a file",
                description=f"Path is not a file: {path}",
                severity=Severity.HIGH, target=path,
            ))
            return self.findings

        try:
            data = p.read_bytes()
        except OSError as e:
            self.findings.append(Finding.artifact(
                rule_id="TFLITE-099", title="TFLite read error",
                description=f"Failed to read TFLite file: {e}",
                severity=Severity.MEDIUM, target=path,
                evidence=str(e),
            ))
            return self.findings

        if len(data) < 8:
            self.findings.append(Finding.artifact(
                rule_id="TFLITE-050", title="File too small",
                description="TFLite file is too small to contain a valid FlatBuffer.",
                severity=Severity.HIGH, target=path,
                evidence=f"size={len(data)}",
            ))
            return self.findings

        # Validate file identifier
        if data[4:8] != TFLITE_MAGIC:
            self.findings.append(Finding.artifact(
                rule_id="TFLITE-051", title="Invalid TFLite magic",
                description=f"Expected file identifier 'TFL3', got '{data[4:8]!r}'. "
                            "File may not be a valid TFLite model.",
                severity=Severity.HIGH, target=path,
                evidence=f"magic={data[4:8]!r}",
            ))
            return self.findings

        try:
            fb = FlatBufferParser(data)
            self._scan_model(fb, path)
        except Exception as e:
            self.findings.append(Finding.artifact(
                rule_id="TFLITE-099", title="TFLite parse error",
                description=f"Failed to parse TFLite FlatBuffer: {e}",
                severity=Severity.MEDIUM, target=path,
                evidence=str(e),
            ))

        return self.findings

    def _scan_model(self, fb: FlatBufferParser, filepath: str) -> None:
        """Parse root Model table and run all checks."""
        root_offset = fb.root_table_offset()

        # Validate root table is within bounds
        if root_offset + 4 > fb.size:
            self.findings.append(Finding.artifact(
                rule_id="TFLITE-001",
                title="Root table offset out of bounds",
                description=f"Root table offset {root_offset} exceeds buffer size {fb.size}.",
                severity=Severity.HIGH, target=filepath,
                evidence=f"root_offset={root_offset}, buf_size={fb.size}",
                cwe_ids=["CWE-125"],
            ))
            return

        try:
            vtable_size, table_size, field_offsets = fb.read_vtable(root_offset)
        except ValueError as e:
            self.findings.append(Finding.artifact(
                rule_id="TFLITE-001",
                title="Malformed root vtable",
                description=f"Failed to read root table vtable: {e}",
                severity=Severity.HIGH, target=filepath,
                evidence=str(e),
                cwe_ids=["CWE-125"],
            ))
            return

        # Validate vtable sanity (PAIT-LITERT-300)
        if vtable_size > 1024:
            self.findings.append(Finding.artifact(
                rule_id="TFLITE-001",
                title=f"Oversized vtable: {vtable_size} bytes",
                description=f"Root table vtable is {vtable_size} bytes — "
                            "unusually large, may indicate malformed FlatBuffer.",
                severity=Severity.HIGH, target=filepath,
                evidence=f"vtable_size={vtable_size}",
                cwe_ids=["CWE-125"],
            ))

        # Check operator_codes (field index 1)
        self._check_operator_codes(fb, root_offset, field_offsets, filepath)

        # Check subgraphs → tensors (field index 2)
        self._check_subgraphs(fb, root_offset, field_offsets, filepath)

        # Check description (field index 3) for injection
        self._check_description(fb, root_offset, field_offsets, filepath)

        # Check metadata (field index 6) for suspicious content
        self._check_metadata(fb, root_offset, field_offsets, filepath)

    def _check_operator_codes(
        self, fb: FlatBufferParser, root_offset: int,
        field_offsets: List[int], filepath: str
    ) -> None:
        """PAIT-LITERT-301: Check for custom or dangerous operator codes."""
        if len(field_offsets) <= 1 or field_offsets[1] == 0:
            return

        opcodes_offset = root_offset + field_offsets[1]

        try:
            op_table_offsets = fb.read_vector_offsets(opcodes_offset)
        except ValueError:
            return

        for i, op_offset in enumerate(op_table_offsets):
            try:
                _, _, op_fields = fb.read_vtable(op_offset)
            except ValueError:
                continue

            # OperatorCode table:
            #   field 0: deprecated_builtin_code (uint8, deprecated)
            #   field 1: custom_code (string)
            #   field 2: version (int32)
            #   field 3: builtin_code (int32) — the actual opcode since schema v3a

            # Check custom_code (field 1)
            if len(op_fields) > 1 and op_fields[1] != 0:
                custom_offset = op_offset + op_fields[1]
                try:
                    custom_name = fb.read_string(custom_offset)
                    if custom_name:
                        self.findings.append(Finding.artifact(
                            rule_id="TFLITE-010",
                            title=f"Custom operator: {custom_name}",
                            description=f"TFLite model uses custom operator '{custom_name}' "
                                        "(index {i}). Custom operators can execute arbitrary "
                                        "native code via delegate libraries.",
                            severity=Severity.CRITICAL, target=filepath,
                            evidence=f"op_index={i}, custom_code={custom_name}",
                            cwe_ids=["CWE-94"],
                        ))
                except ValueError:
                    pass

            # Check builtin_code (field 3) for out-of-range values
            if len(op_fields) > 3 and op_fields[3] != 0:
                builtin_offset = op_offset + op_fields[3]
                try:
                    builtin_code = fb.read_int32(builtin_offset)
                    if builtin_code < 0 or builtin_code >= BUILTIN_OP_COUNT:
                        self.findings.append(Finding.artifact(
                            rule_id="TFLITE-011",
                            title=f"Unknown builtin opcode: {builtin_code}",
                            description=f"Operator index {i} has builtin_code={builtin_code} "
                                        f"which is outside the known range (0-{BUILTIN_OP_COUNT - 1}). "
                                        "This may indicate a custom operator disguised as builtin.",
                            severity=Severity.HIGH, target=filepath,
                            evidence=f"op_index={i}, builtin_code={builtin_code}",
                            cwe_ids=["CWE-94"],
                        ))
                except ValueError:
                    pass

            # Check deprecated_builtin_code (field 0) — uint8
            if len(op_fields) > 0 and op_fields[0] != 0:
                dep_offset = op_offset + op_fields[0]
                try:
                    dep_code = fb.read_uint8(dep_offset)
                    if dep_code >= BUILTIN_OP_COUNT and dep_code != 0:
                        self.findings.append(Finding.artifact(
                            rule_id="TFLITE-012",
                            title=f"Unknown deprecated opcode: {dep_code}",
                            description=f"Operator index {i} has deprecated_builtin_code={dep_code} "
                                        f"outside known range.",
                            severity=Severity.MEDIUM, target=filepath,
                            evidence=f"op_index={i}, deprecated_code={dep_code}",
                        ))
                except ValueError:
                    pass

    def _check_subgraphs(
        self, fb: FlatBufferParser, root_offset: int,
        field_offsets: List[int], filepath: str
    ) -> None:
        """PAIT-LITERT-302: Check tensor dimensions for integer overflow."""
        if len(field_offsets) <= 2 or field_offsets[2] == 0:
            return

        subgraphs_offset = root_offset + field_offsets[2]

        try:
            sg_offsets = fb.read_vector_offsets(subgraphs_offset)
        except ValueError:
            return

        for sg_idx, sg_offset in enumerate(sg_offsets):
            try:
                _, _, sg_fields = fb.read_vtable(sg_offset)
            except ValueError:
                continue

            # SubGraph table:
            #   field 0: tensors (vector of Tensor tables)
            #   field 1: inputs (vector of int32)
            #   field 2: outputs (vector of int32)
            #   field 3: operators (vector of Operator tables)
            #   field 4: name (string)

            # Check tensors (field 0)
            if len(sg_fields) > 0 and sg_fields[0] != 0:
                tensors_offset = sg_offset + sg_fields[0]
                self._check_tensors(fb, tensors_offset, sg_idx, filepath)

            # Check subgraph name for suspicious patterns (field 4)
            if len(sg_fields) > 4 and sg_fields[4] != 0:
                name_offset = sg_offset + sg_fields[4]
                try:
                    name = fb.read_string(name_offset)
                    name_lower = name.lower()
                    for pattern in SUSPICIOUS_NAMES:
                        if pattern in name_lower:
                            self.findings.append(Finding.artifact(
                                rule_id="TFLITE-030",
                                title=f"Suspicious subgraph name: {name}",
                                description=f"Subgraph {sg_idx} has suspicious name '{name}'.",
                                severity=Severity.HIGH, target=filepath,
                                evidence=f"subgraph={sg_idx}, name={name}",
                            ))
                            break
                except ValueError:
                    pass

    def _check_tensors(
        self, fb: FlatBufferParser, tensors_offset: int,
        sg_idx: int, filepath: str
    ) -> None:
        """Check individual tensor dimensions for overflow."""
        try:
            tensor_offsets = fb.read_vector_offsets(tensors_offset)
        except ValueError:
            return

        for t_idx, t_offset in enumerate(tensor_offsets):
            try:
                _, _, t_fields = fb.read_vtable(t_offset)
            except ValueError:
                continue

            # Tensor table:
            #   field 0: shape (vector of int32)
            #   field 1: type (uint8 — TensorType enum)
            #   field 2: buffer (uint32)
            #   field 3: name (string)

            # Check shape (field 0)
            if len(t_fields) > 0 and t_fields[0] != 0:
                shape_offset = t_offset + t_fields[0]
                try:
                    dims = fb.read_vector_scalars_int32(shape_offset)
                except ValueError:
                    continue

                # Check rank
                if len(dims) > MAX_TENSOR_RANK:
                    self.findings.append(Finding.artifact(
                        rule_id="TFLITE-020",
                        title=f"Excessive tensor rank: {len(dims)}",
                        description=f"Tensor {t_idx} in subgraph {sg_idx} has "
                                    f"rank {len(dims)} (max expected: {MAX_TENSOR_RANK}).",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"tensor={t_idx}, subgraph={sg_idx}, rank={len(dims)}",
                        cwe_ids=["CWE-190"],
                    ))

                # Check negative dimensions
                for d_idx, dim in enumerate(dims):
                    if dim < 0:
                        self.findings.append(Finding.artifact(
                            rule_id="TFLITE-021",
                            title=f"Negative tensor dimension: {dim}",
                            description=f"Tensor {t_idx} in subgraph {sg_idx} has "
                                        f"negative dimension {dim} at axis {d_idx}. "
                                        "This could cause integer overflow during allocation.",
                            severity=Severity.HIGH, target=filepath,
                            evidence=f"tensor={t_idx}, axis={d_idx}, dim={dim}",
                            cwe_ids=["CWE-190"],
                        ))

                # Check dimension product overflow
                if dims:
                    product = 1
                    overflow = False
                    for dim in dims:
                        if dim <= 0:
                            continue
                        if dim > MAX_TENSOR_DIM:
                            overflow = True
                            break
                        product *= dim
                        if product > MAX_TENSOR_DIM:
                            overflow = True
                            break

                    if overflow:
                        self.findings.append(Finding.artifact(
                            rule_id="TFLITE-022",
                            title="Tensor dimension overflow risk",
                            description=f"Tensor {t_idx} in subgraph {sg_idx} has "
                                        f"dimensions {dims} that may cause integer overflow "
                                        "during memory allocation.",
                            severity=Severity.HIGH, target=filepath,
                            evidence=f"tensor={t_idx}, dims={dims}",
                            cwe_ids=["CWE-190"],
                        ))

            # Check tensor name for suspicious patterns (field 3)
            if len(t_fields) > 3 and t_fields[3] != 0:
                name_offset = t_offset + t_fields[3]
                try:
                    name = fb.read_string(name_offset)
                    name_lower = name.lower()
                    for pattern in SUSPICIOUS_NAMES:
                        if pattern in name_lower:
                            self.findings.append(Finding.artifact(
                                rule_id="TFLITE-031",
                                title=f"Suspicious tensor name: {name}",
                                description=f"Tensor {t_idx} has suspicious name '{name}'.",
                                severity=Severity.HIGH, target=filepath,
                                evidence=f"tensor={t_idx}, name={name}",
                            ))
                            break
                except ValueError:
                    pass

    def _check_description(
        self, fb: FlatBufferParser, root_offset: int,
        field_offsets: List[int], filepath: str
    ) -> None:
        """Check model description for injection patterns."""
        if len(field_offsets) <= 3 or field_offsets[3] == 0:
            return

        desc_offset = root_offset + field_offsets[3]
        try:
            desc = fb.read_string(desc_offset)
        except ValueError:
            return

        injection_patterns = [
            "__import__", "os.system", "eval(", "exec(",
            "subprocess", "<script", "javascript:",
        ]
        for pattern in injection_patterns:
            if pattern in desc.lower():
                self.findings.append(Finding.artifact(
                    rule_id="TFLITE-040",
                    title=f"Injection pattern in description: {pattern}",
                    description=f"Model description contains '{pattern}' which suggests "
                                "potential code injection via metadata.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"pattern={pattern}, desc_preview={desc[:200]}",
                    cwe_ids=["CWE-94"],
                ))

    def _check_metadata(
        self, fb: FlatBufferParser, root_offset: int,
        field_offsets: List[int], filepath: str
    ) -> None:
        """Check model metadata for suspicious content."""
        if len(field_offsets) <= 6 or field_offsets[6] == 0:
            return

        meta_offset = root_offset + field_offsets[6]
        try:
            meta_offsets = fb.read_vector_offsets(meta_offset)
        except ValueError:
            return

        for m_idx, m_offset in enumerate(meta_offsets):
            try:
                _, _, m_fields = fb.read_vtable(m_offset)
            except ValueError:
                continue

            # Metadata table:
            #   field 0: name (string)
            #   field 1: buffer (uint32)

            if len(m_fields) > 0 and m_fields[0] != 0:
                name_offset = m_offset + m_fields[0]
                try:
                    name = fb.read_string(name_offset)
                    name_lower = name.lower()
                    for pattern in SUSPICIOUS_NAMES:
                        if pattern in name_lower:
                            self.findings.append(Finding.artifact(
                                rule_id="TFLITE-041",
                                title=f"Suspicious metadata name: {name}",
                                description=f"Metadata entry {m_idx} has suspicious "
                                            f"name '{name}'.",
                                severity=Severity.MEDIUM, target=filepath,
                                evidence=f"metadata_index={m_idx}, name={name}",
                            ))
                            break
                except ValueError:
                    pass
