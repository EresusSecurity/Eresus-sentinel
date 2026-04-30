"""
Eresus Sentinel — Shared data types for format reverse engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..finding import Finding


@dataclass
class TensorInfo:
    """Parsed tensor metadata."""
    name: str = ""
    n_dims: int = 0
    shape: List[int] = field(default_factory=list)
    dtype: str = ""
    offset: int = 0
    size_bytes: int = 0


@dataclass
class FormatReport:
    """Complete format analysis report."""
    format_name: str = ""
    file_path: str = ""
    file_size: int = 0
    header: Any = None
    tensors: List[TensorInfo] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
