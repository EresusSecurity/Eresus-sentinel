"""Unified taint engine — replaces the old inline tracker."""
from sentinel.sast.static_analysis.taint.patterns import (
    SinkPattern,
    SourcePattern,
    TaintPattern,
    default_sinks,
    default_sources,
)
from sentinel.sast.static_analysis.taint.tracker import TaintEngine, TaintFlow, TaintResult

__all__ = [
    "TaintEngine",
    "TaintResult",
    "TaintFlow",
    "TaintPattern",
    "SourcePattern",
    "SinkPattern",
    "default_sources",
    "default_sinks",
]
