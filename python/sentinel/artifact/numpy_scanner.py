"""
Eresus Sentinel - NumPy Artifact Scanner.

Detects unsafe operations in NumPy serialized files:
  - .npy files: NumPy native binary format
  - .npz files: ZIP archives of .npy files

Security concern: NumPy's np.load() with allow_pickle=True can execute
arbitrary code via pickle deserialization. This scanner:
  1. Validates .npy magic bytes and header structure
  2. Detects pickle-enabled .npy files (dtype=object forces pickle)
  3. Scans .npz archives for embedded pickle payloads
  4. Checks for suspicious dtype descriptors
  5. Validates array dimensions against resource exhaustion attacks

Reference:
  - CVE-2019-6446: NumPy allow_pickle=True RCE
  - NumPy format specification: https://numpy.org/neps/nep-0001-npy-format.html

Tags:
  CWE-502: Deserialization of Untrusted Data
  OWASP ML08: Model/Data Poisoning
"""

from __future__ import annotations

import io
import logging
import struct
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Tuple, Union

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

# NumPy .npy magic bytes
NPY_MAGIC = b"\x93NUMPY"
NPY_MAGIC_LEN = 6

# Maximum reasonable header size (prevent DoS via huge headers)
MAX_HEADER_SIZE = 1_000_000  # 1 MB

# Maximum reasonable array dimensions
MAX_NDIM = 32
MAX_SHAPE_ELEMENT = 10_000_000_000  # 10 billion elements per dimension
MAX_TOTAL_ELEMENTS = 100_000_000_000  # 100 billion total elements


class NpySeverity(str, Enum):
    """NumPy-specific finding severity levels."""
    CRITICAL = "critical"    # Pickle-based deserialization possible
    HIGH = "high"            # Suspicious dtype or oversized arrays
    MEDIUM = "medium"        # Non-standard header or version
    LOW = "low"              # Informational findings
    INFO = "info"


@dataclass
class NpyHeader:
    """Parsed .npy file header."""
    major_version: int
    minor_version: int
    header_len: int
    descr: str             # dtype descriptor string
    fortran_order: bool    # Column-major (Fortran) vs row-major (C) order
    shape: Tuple[int, ...]
    raw_header: str        # Full header dict as string
    has_pickle_dtype: bool = False


@dataclass
class NumpyScanResult:
    """Result of scanning a NumPy file."""
    file_path: str
    is_safe: bool = True
    findings: List[Finding] = field(default_factory=list)
    header: Optional[NpyHeader] = None
    files_scanned: int = 0      # For .npz archives
    embedded_pickles: int = 0   # Count of pickle-based arrays


# =====================================================================
#  SUSPICIOUS DTYPE PATTERNS
# =====================================================================

# Object dtypes trigger pickle deserialization
_PICKLE_DTYPE_INDICATORS = [
    "object",   # np.object_ triggers pickle
    "'O'",      # Short form for object dtype
    "|O",       # NumPy format for object
    "O8",       # Object with size
    "V",        # Void type (can contain arbitrary data)
]

# Suspicious descriptor patterns that may indicate tampering
_SUSPICIOUS_DESCRIPTORS = [
    "__import__",
    "__builtins__",
    "__reduce__",
    "__reduce_ex__",
    "exec(",
    "eval(",
    "os.system",
    "subprocess",
    "pickle",
    "shelve",
    "marshal",
    "builtins",
    "compile(",
]


class NumpyScanner:
    """Scans NumPy .npy and .npz files for security issues.

    Detection capabilities:
      - Pickle deserialization via object dtypes (CVE-2019-6446)
      - Malformed headers with embedded code
      - Resource exhaustion via enormous array shapes
      - Suspicious dtype descriptors
      - Embedded pickle files in .npz archives
    """

    def __init__(
        self,
        max_array_elements: int = MAX_TOTAL_ELEMENTS,
        allow_pickle_dtype: bool = False,
        max_header_size: int = MAX_HEADER_SIZE,
    ):
        """Initialize the numpy scanner.

        Args:
            max_array_elements: Maximum total elements allowed.
            allow_pickle_dtype: If True, don't flag object dtypes.
            max_header_size: Maximum header size in bytes.
        """
        self._max_elements = max_array_elements
        self._allow_pickle = allow_pickle_dtype
        self._max_header = max_header_size

    def scan_file(self, path: Union[str, Path]) -> NumpyScanResult:
        """Scan a .npy or .npz file.

        Args:
            path: Path to the file to scan.

        Returns:
            NumpyScanResult with findings.
        """
        path = Path(path)
        suffix = path.suffix.lower()

        if suffix == ".npz":
            return self._scan_npz(path)
        elif suffix == ".npy":
            return self._scan_npy(path)
        else:
            result = NumpyScanResult(file_path=str(path))
            result.findings.append(self._make_finding(
                rule_id="NUMPY-001",
                title="Unknown file extension",
                description=f"File '{path.name}' has extension '{suffix}', expected .npy or .npz.",
                severity=Severity.LOW,
                target=str(path),
            ))
            return result

    def scan_bytes(self, data: bytes, filename: str = "<bytes>") -> NumpyScanResult:
        """Scan raw bytes as a .npy file.

        Args:
            data: Raw bytes to scan.
            filename: Display name for findings.

        Returns:
            NumpyScanResult with findings.
        """
        return self._scan_npy_stream(io.BytesIO(data), filename)

    # -----------------------------------------------------------------
    #  .npy scanning
    # -----------------------------------------------------------------

    def _scan_npy(self, path: Path) -> NumpyScanResult:
        """Scan a single .npy file."""
        result = NumpyScanResult(file_path=str(path), files_scanned=1)

        try:
            with open(path, "rb") as f:
                return self._scan_npy_stream(f, str(path))
        except PermissionError:
            result.findings.append(self._make_finding(
                rule_id="NUMPY-ERR-001",
                title="Permission denied",
                description=f"Cannot read file: {path.name}",
                severity=Severity.MEDIUM,
                target=str(path),
            ))
            return result
        except Exception as e:
            result.findings.append(self._make_finding(
                rule_id="NUMPY-ERR-002",
                title="Scan error",
                description=f"Error scanning {path.name}: {type(e).__name__}: {e}",
                severity=Severity.MEDIUM,
                target=str(path),
            ))
            return result

    def _scan_npy_stream(self, stream: BinaryIO, filename: str) -> NumpyScanResult:
        """Scan a .npy stream for security issues."""
        result = NumpyScanResult(file_path=filename, files_scanned=1)

        # Check magic bytes
        magic = stream.read(NPY_MAGIC_LEN)
        if magic != NPY_MAGIC:
            result.is_safe = False
            result.findings.append(self._make_finding(
                rule_id="NUMPY-010",
                title="Invalid .npy magic bytes",
                description=(
                    f"File does not start with NumPy magic bytes "
                    f"(expected \\x93NUMPY, got {magic!r}). "
                    f"File may be corrupted or disguised."
                ),
                severity=Severity.HIGH,
                target=filename,
                evidence=f"Magic: {magic.hex()}",
            ))
            return result

        # Parse version
        version = stream.read(2)
        if len(version) < 2:
            result.is_safe = False
            result.findings.append(self._make_finding(
                rule_id="NUMPY-011",
                title="Truncated .npy header",
                description="File too short to contain version bytes.",
                severity=Severity.HIGH,
                target=filename,
            ))
            return result

        major, minor = version[0], version[1]

        # Parse header length
        if major == 1:
            header_len_bytes = stream.read(2)
            if len(header_len_bytes) < 2:
                result.is_safe = False
                result.findings.append(self._make_finding(
                    rule_id="NUMPY-012",
                    title="Truncated header length",
                    description="Cannot read 2-byte header length for v1.x.",
                    severity=Severity.HIGH,
                    target=filename,
                ))
                return result
            header_len = struct.unpack("<H", header_len_bytes)[0]
        elif major in (2, 3):
            header_len_bytes = stream.read(4)
            if len(header_len_bytes) < 4:
                result.is_safe = False
                result.findings.append(self._make_finding(
                    rule_id="NUMPY-013",
                    title="Truncated header length",
                    description=f"Cannot read 4-byte header length for v{major}.x.",
                    severity=Severity.HIGH,
                    target=filename,
                ))
                return result
            header_len = struct.unpack("<I", header_len_bytes)[0]
        else:
            result.findings.append(self._make_finding(
                rule_id="NUMPY-014",
                title=f"Unknown .npy version: {major}.{minor}",
                description=f"Unexpected format version {major}.{minor}.",
                severity=Severity.MEDIUM,
                target=filename,
            ))
            # Try to continue with 2-byte header length
            header_len_bytes = stream.read(2)
            header_len = struct.unpack("<H", header_len_bytes)[0] if len(header_len_bytes) >= 2 else 0

        # Validate header length
        if header_len > self._max_header:
            result.is_safe = False
            result.findings.append(self._make_finding(
                rule_id="NUMPY-020",
                title="Oversized .npy header",
                description=(
                    f"Header length {header_len:,} exceeds maximum "
                    f"{self._max_header:,} bytes. Possible DoS attack."
                ),
                severity=Severity.HIGH,
                target=filename,
                evidence=f"header_len={header_len}",
            ))
            return result

        # Read and parse header
        raw_header = stream.read(header_len)
        if len(raw_header) < header_len:
            result.is_safe = False
            result.findings.append(self._make_finding(
                rule_id="NUMPY-021",
                title="Truncated header data",
                description=f"Expected {header_len} header bytes, got {len(raw_header)}.",
                severity=Severity.HIGH,
                target=filename,
            ))
            return result

        header_str = raw_header.decode("latin1").strip()

        # Parse the header dict (it's a Python literal dict)
        header = self._parse_header_dict(header_str, major, minor, header_len, filename, result)
        if header is None:
            return result  # Findings already added

        result.header = header

        # Check for pickle-based dtype (CRITICAL vulnerability)
        if header.has_pickle_dtype and not self._allow_pickle:
            result.is_safe = False
            result.embedded_pickles += 1
            result.findings.append(self._make_finding(
                rule_id="NUMPY-100",
                title="Pickle deserialization detected (CVE-2019-6446)",
                description=(
                    f"Array dtype '{header.descr}' requires pickle deserialization. "
                    f"Loading this file with np.load() and allow_pickle=True "
                    f"will execute arbitrary code. This is a CRITICAL RCE vector."
                ),
                severity=Severity.CRITICAL,
                target=filename,
                evidence=f"dtype={header.descr}",
                cwe_ids=["CWE-502"],
            ))

        # Check for suspicious content in header
        header_lower = header_str.lower()
        for pattern in _SUSPICIOUS_DESCRIPTORS:
            if pattern.lower() in header_lower:
                result.is_safe = False
                result.findings.append(self._make_finding(
                    rule_id="NUMPY-110",
                    title="Suspicious content in header",
                    description=(
                        f"Header contains suspicious pattern '{pattern}'. "
                        f"This may indicate embedded code execution."
                    ),
                    severity=Severity.CRITICAL,
                    target=filename,
                    evidence=f"pattern='{pattern}'",
                    cwe_ids=["CWE-94"],
                ))

        # Check for resource exhaustion
        total_elements = 1
        for dim in header.shape:
            if dim > MAX_SHAPE_ELEMENT:
                result.findings.append(self._make_finding(
                    rule_id="NUMPY-120",
                    title="Extremely large array dimension",
                    description=f"Dimension size {dim:,} exceeds limit {MAX_SHAPE_ELEMENT:,}.",
                    severity=Severity.HIGH,
                    target=filename,
                    evidence=f"shape={header.shape}",
                ))
            total_elements *= max(dim, 1)

        if total_elements > self._max_elements:
            result.findings.append(self._make_finding(
                rule_id="NUMPY-121",
                title="Array too large (resource exhaustion risk)",
                description=(
                    f"Total elements {total_elements:,} exceeds limit "
                    f"{self._max_elements:,}. Loading may exhaust memory."
                ),
                severity=Severity.HIGH,
                target=filename,
                evidence=f"shape={header.shape}, total={total_elements}",
            ))

        # Check ndim
        if len(header.shape) > MAX_NDIM:
            result.findings.append(self._make_finding(
                rule_id="NUMPY-122",
                title="Too many array dimensions",
                description=f"Array has {len(header.shape)} dimensions (max: {MAX_NDIM}).",
                severity=Severity.MEDIUM,
                target=filename,
            ))

        return result

    def _parse_header_dict(
        self, header_str: str, major: int, minor: int,
        header_len: int, filename: str, result: NumpyScanResult
    ) -> Optional[NpyHeader]:
        """Parse the header dictionary string safely."""
        try:
            # Use ast.literal_eval for safe parsing
            import ast
            header_dict = ast.literal_eval(header_str)
        except (ValueError, SyntaxError) as e:
            result.is_safe = False
            result.findings.append(self._make_finding(
                rule_id="NUMPY-030",
                title="Malformed .npy header",
                description=(
                    f"Cannot parse header dictionary: {e}. "
                    f"Header may contain embedded code."
                ),
                severity=Severity.HIGH,
                target=filename,
                evidence=header_str[:200],
                cwe_ids=["CWE-94"],
            ))
            return None

        descr = str(header_dict.get("descr", ""))
        fortran_order = bool(header_dict.get("fortran_order", False))
        shape = tuple(header_dict.get("shape", ()))

        # Check if dtype indicates pickle
        has_pickle = any(
            indicator in descr
            for indicator in _PICKLE_DTYPE_INDICATORS
        )

        return NpyHeader(
            major_version=major,
            minor_version=minor,
            header_len=header_len,
            descr=descr,
            fortran_order=fortran_order,
            shape=shape,
            raw_header=header_str,
            has_pickle_dtype=has_pickle,
        )

    # -----------------------------------------------------------------
    #  .npz scanning
    # -----------------------------------------------------------------

    def _scan_npz(self, path: Path) -> NumpyScanResult:
        """Scan a .npz archive (ZIP of .npy files)."""
        result = NumpyScanResult(file_path=str(path))

        try:
            with zipfile.ZipFile(path, "r") as zf:
                members = zf.namelist()
                result.files_scanned = len(members)

                for member_name in members:
                    # Check for path traversal
                    if ".." in member_name or member_name.startswith("/"):
                        result.is_safe = False
                        result.findings.append(self._make_finding(
                            rule_id="NUMPY-200",
                            title="Path traversal in .npz archive",
                            description=(
                                f"Archive member '{member_name}' contains "
                                f"path traversal. Possible zip slip attack."
                            ),
                            severity=Severity.CRITICAL,
                            target=f"{path}!{member_name}",
                            cwe_ids=["CWE-22"],
                        ))
                        continue

                    # Check for non-.npy files (suspicious)
                    if not member_name.endswith(".npy"):
                        result.findings.append(self._make_finding(
                            rule_id="NUMPY-201",
                            title="Non-.npy file in .npz archive",
                            description=(
                                f"Archive contains '{member_name}' which is not "
                                f"a .npy file. May contain embedded payloads."
                            ),
                            severity=Severity.MEDIUM,
                            target=f"{path}!{member_name}",
                        ))

                    # Scan each .npy member
                    try:
                        with zf.open(member_name) as member_file:
                            member_data = member_file.read()
                            member_result = self.scan_bytes(
                                member_data,
                                filename=f"{path}!{member_name}",
                            )

                            if not member_result.is_safe:
                                result.is_safe = False
                            result.findings.extend(member_result.findings)
                            result.embedded_pickles += member_result.embedded_pickles

                    except Exception as e:
                        result.findings.append(self._make_finding(
                            rule_id="NUMPY-ERR-010",
                            title=f"Error scanning member: {member_name}",
                            description=f"{type(e).__name__}: {e}",
                            severity=Severity.MEDIUM,
                            target=f"{path}!{member_name}",
                        ))

        except zipfile.BadZipFile:
            result.is_safe = False
            result.findings.append(self._make_finding(
                rule_id="NUMPY-210",
                title="Corrupt .npz archive",
                description="File is not a valid ZIP archive.",
                severity=Severity.HIGH,
                target=str(path),
            ))
        except Exception as e:
            result.findings.append(self._make_finding(
                rule_id="NUMPY-ERR-011",
                title="Error scanning .npz",
                description=f"{type(e).__name__}: {e}",
                severity=Severity.MEDIUM,
                target=str(path),
            ))

        return result

    # -----------------------------------------------------------------
    #  Helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _make_finding(
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        target: str,
        evidence: str = "",
        cwe_ids: Optional[List[str]] = None,
    ) -> Finding:
        """Create a standardized Finding."""
        return Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            target=target,
            evidence=evidence,
            cwe_ids=cwe_ids or [],
            tags=["artifact", "numpy", "deserialization"],
        )
