"""Bypass analysis engine — parses fuzz results to identify scanner gaps."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .base import FuzzResult, PayloadCategory


@dataclass
class BypassVector:
    """A categorized scanner bypass."""
    payload_name: str
    category: str
    tags: list[str]
    severity: str
    data_size: int
    vector_class: str = ""


@dataclass
class BypassReport:
    """Full bypass analysis from a fuzz session."""
    total_bypasses: int = 0
    vectors: list[BypassVector] = field(default_factory=list)
    by_category: dict[str, int] = field(default_factory=dict)
    by_vector_class: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    rule_suggestions: list[dict] = field(default_factory=list)
    coverage_matrix: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total_bypasses": self.total_bypasses,
            "by_category": self.by_category,
            "by_vector_class": self.by_vector_class,
            "by_severity": self.by_severity,
            "rule_suggestions": self.rule_suggestions,
            "coverage_matrix": self.coverage_matrix,
            "vectors": [
                {
                    "payload_name": v.payload_name,
                    "category": v.category,
                    "tags": v.tags,
                    "severity": v.severity,
                    "data_size": v.data_size,
                    "vector_class": v.vector_class,
                }
                for v in self.vectors
            ],
        }


VECTOR_CLASSIFIERS = {
    "STACK_GLOBAL": ["STACK_GLOBAL", "stack_global"],
    "COPYREG_EXT": ["copyreg", "EXT", "ext_abuse"],
    "NESTED_DESER": ["nested", "pickle_in_pickle", "deser"],
    "PROTOCOL_MISMATCH": ["protocol", "proto_0", "mixed_protocol"],
    "MULTI_STAGE": ["multi_stage", "chain", "double_reduce"],
    "OBFUSCATION": ["marshal", "base64", "zlib", "codecs", "obfusc"],
    "INTROSPECTION": ["subclass", "introspect", "getattr"],
    "ENCODING_EVASION": ["base64", "rot13", "hex", "unicode"],
    "HOMOGLYPH": ["homoglyph", "zero_width"],
    "DELIMITER_ESCAPE": ["delimiter", "delimiter_escape"],
    "JAILBREAK": ["jailbreak", "dan", "aim", "developer_mode", "roleplay"],
    "PROMPT_INJECTION": ["inject", "prompt_inject", "indirect"],
    "RAG_POISONING": ["poison", "rag_poison", "knowledge_poison"],
    "RETRIEVAL_MANIPULATION": ["retrieval", "ranking", "keyword_stuff"],
    "CITATION_SPOOF": ["citation", "cite", "spoof"],
    "ARTIFACT_OVERFLOW": ["overflow", "gguf", "safetensors", "onnx"],
    "PATH_TRAVERSAL": ["zip_slip", "path_traversal", "traversal"],
    "POLYGLOT": ["polyglot"],
}


class BypassAnalyzer:
    """Analyzes fuzz results to identify and classify scanner blind spots."""

    def analyze(self, results: list[FuzzResult]) -> BypassReport:
        bypasses = [r for r in results if r.is_bypass]
        report = BypassReport(total_bypasses=len(bypasses))

        cat_counts: dict[str, int] = defaultdict(int)
        vec_counts: dict[str, int] = defaultdict(int)
        sev_counts: dict[str, int] = defaultdict(int)
        coverage: dict[str, dict[str, int]] = defaultdict(
            lambda: {"total": 0, "detected": 0, "bypassed": 0}
        )

        for r in results:
            cat = r.payload.category.value
            coverage[cat]["total"] += 1
            if r.detected:
                coverage[cat]["detected"] += 1

        for r in bypasses:
            cat = r.payload.category.value
            sev = r.payload.severity_expected
            tags = r.payload.tags

            cat_counts[cat] += 1
            sev_counts[sev] += 1
            coverage[cat]["bypassed"] += 1

            vec_class = self._classify_vector(r.payload.name, tags)
            vec_counts[vec_class] += 1

            report.vectors.append(BypassVector(
                payload_name=r.payload.name,
                category=cat,
                tags=tags,
                severity=sev,
                data_size=len(r.payload.data),
                vector_class=vec_class,
            ))

        report.by_category = dict(cat_counts)
        report.by_vector_class = dict(vec_counts)
        report.by_severity = dict(sev_counts)
        report.coverage_matrix = {k: dict(v) for k, v in coverage.items()}
        report.rule_suggestions = self._generate_rule_suggestions(report)

        return report

    def _classify_vector(self, name: str, tags: list[str]) -> str:
        combined = name.lower() + " " + " ".join(t.lower() for t in tags)
        for vec_class, keywords in VECTOR_CLASSIFIERS.items():
            if any(kw.lower() in combined for kw in keywords):
                return vec_class
        return "UNKNOWN"

    def _generate_rule_suggestions(self, report: BypassReport) -> list[dict]:
        suggestions = []

        if report.by_vector_class.get("STACK_GLOBAL", 0) > 0:
            suggestions.append({
                "rule": "STACK_GLOBAL_REDUCE",
                "description": "Add STACK_GLOBAL → REDUCE chain detection",
                "priority": "HIGH",
                "bypasses": report.by_vector_class["STACK_GLOBAL"],
            })

        if report.by_vector_class.get("COPYREG_EXT", 0) > 0:
            suggestions.append({
                "rule": "COPYREG_EXT_CHAIN",
                "description": "Add copyreg/EXT opcode chain detection",
                "priority": "HIGH",
                "bypasses": report.by_vector_class["COPYREG_EXT"],
            })

        if report.by_vector_class.get("NESTED_DESER", 0) > 0:
            suggestions.append({
                "rule": "NESTED_DESER",
                "description": "Add nested deserialization detection",
                "priority": "CRITICAL",
                "bypasses": report.by_vector_class["NESTED_DESER"],
            })

        if report.by_vector_class.get("PROTOCOL_MISMATCH", 0) > 0:
            suggestions.append({
                "rule": "PROTO_MISMATCH",
                "description": "Add protocol version mismatch detection",
                "priority": "MEDIUM",
                "bypasses": report.by_vector_class["PROTOCOL_MISMATCH"],
            })

        if report.by_vector_class.get("MULTI_STAGE", 0) > 0:
            suggestions.append({
                "rule": "MULTI_STAGE_CHAIN",
                "description": "Add multi-stage REDUCE chain detection",
                "priority": "HIGH",
                "bypasses": report.by_vector_class["MULTI_STAGE"],
            })

        if report.by_vector_class.get("OBFUSCATION", 0) > 0:
            suggestions.append({
                "rule": "OBFUSCATION_LAYER",
                "description": "Add obfuscation layer unwrapping",
                "priority": "MEDIUM",
                "bypasses": report.by_vector_class["OBFUSCATION"],
            })

        if report.by_vector_class.get("ENCODING_EVASION", 0) > 0:
            suggestions.append({
                "rule": "ENCODING_EVASION",
                "description": "Add encoding-based evasion detection",
                "priority": "HIGH",
                "bypasses": report.by_vector_class["ENCODING_EVASION"],
            })

        if report.by_vector_class.get("JAILBREAK", 0) > 0:
            suggestions.append({
                "rule": "JAILBREAK_PATTERN",
                "description": "Add jailbreak pattern matching",
                "priority": "HIGH",
                "bypasses": report.by_vector_class["JAILBREAK"],
            })

        if report.by_vector_class.get("RAG_POISONING", 0) > 0:
            suggestions.append({
                "rule": "RAG_POISON_DETECT",
                "description": "Add RAG poisoning content analysis",
                "priority": "HIGH",
                "bypasses": report.by_vector_class["RAG_POISONING"],
            })

        return suggestions

    def save_report(self, report: BypassReport, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @staticmethod
    def load_from_fuzz_report(path: str | Path) -> dict:
        """Load a previous fuzz report JSON for re-analysis."""
        return json.loads(Path(path).read_text(encoding="utf-8"))
