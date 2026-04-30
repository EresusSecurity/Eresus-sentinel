"""
Advanced static analysis framework.

Subpackages:
  parser/           Language-agnostic parsing abstraction (ast primary, tree-sitter optional).
  cfg/              Control-flow graph builders.
  dataflow/         Forward/backward dataflow analyses.
  interprocedural/  Call graphs and cross-file taint propagation.
  semantic/         Name resolution and type inference.
  taint/            Unified taint engine (source/sink).

The legacy taint_tracker module remains as a thin wrapper for backwards
compatibility; new scanners should import directly from this package.
"""
from __future__ import annotations

from sentinel.sast.static_analysis.cfg.builder import BasicBlock, CFGBuilder, Edge, EdgeKind
from sentinel.sast.static_analysis.parser.python_parser import PythonParser
from sentinel.sast.static_analysis.taint.tracker import TaintEngine, TaintResult

__all__ = [
    "CFGBuilder",
    "BasicBlock",
    "Edge",
    "EdgeKind",
    "TaintEngine",
    "TaintResult",
    "PythonParser",
]
