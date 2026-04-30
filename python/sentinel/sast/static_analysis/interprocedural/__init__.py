"""Interprocedural analyses: call graph + cross-file taint."""
from sentinel.sast.static_analysis.interprocedural.call_graph_analyzer import (
    CallGraph,
    CallGraphAnalyzer,
    CallSite,
)
from sentinel.sast.static_analysis.interprocedural.cross_file_analyzer import (
    CrossFileAnalyzer,
    ModuleIndex,
)

__all__ = [
    "CallGraph",
    "CallGraphAnalyzer",
    "CallSite",
    "CrossFileAnalyzer",
    "ModuleIndex",
]
