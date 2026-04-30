"""Semantic analyses."""
from sentinel.sast.static_analysis.semantic.name_resolver import NameResolver, Scope, Symbol
from sentinel.sast.static_analysis.semantic.type_analyzer import TypeAnalyzer

__all__ = ["NameResolver", "Scope", "Symbol", "TypeAnalyzer"]
