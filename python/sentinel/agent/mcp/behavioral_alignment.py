"""MCP Behavioral Alignment Analyzer.

Uses an optional LLM backend to analyze MCP tool source code and classify
whether the tool's actual behaviour aligns with its declared description.
Falls back to heuristic analysis when no LLM is configured.
"""
from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

_SUSPICIOUS_CALLS = {
    "exec", "eval", "compile", "subprocess", "os.system", "os.popen",
    "__import__", "importlib", "open", "socket", "urllib", "requests",
    "httpx", "shutil.rmtree", "os.remove", "os.unlink",
}

_EXFIL_PATTERNS = [
    re.compile(r"\bsend\b.*\bpassword\b", re.IGNORECASE),
    re.compile(r"\bpost\b.*\btoken\b", re.IGNORECASE),
    re.compile(r"\bupload\b.*\bfile\b", re.IGNORECASE),
    re.compile(r"os\.environ", re.IGNORECASE),
]


@dataclass
class AlignmentResult:
    tool_name: str
    aligned: bool
    confidence: float
    issues: list[str] = field(default_factory=list)
    suspicious_calls: list[str] = field(default_factory=list)
    raw_analysis: Optional[str] = None


class BehavioralAlignmentAnalyzer:
    """Analyze whether MCP tool behaviour matches its description.

    Args:
        llm_client: Optional LLM client with a ``complete(prompt) -> str`` interface.
            If ``None``, heuristic-only analysis is performed.
        threshold: Minimum confidence to mark as aligned (default 0.6).
    """

    def __init__(
        self,
        llm_client: Any = None,
        threshold: float = 0.6,
    ) -> None:
        self._llm = llm_client
        self._threshold = threshold

    def analyze(
        self,
        tool_name: str,
        description: str,
        source_code: str,
    ) -> AlignmentResult:
        """Analyze a single MCP tool for behavioral alignment."""
        heuristic = self._heuristic_analyze(tool_name, description, source_code)

        if self._llm is not None:
            llm_result = self._llm_analyze(tool_name, description, source_code)
            merged_confidence = (heuristic.confidence + llm_result.confidence) / 2
            heuristic.confidence = merged_confidence
            heuristic.issues.extend(llm_result.issues)
            heuristic.raw_analysis = llm_result.raw_analysis
            heuristic.aligned = merged_confidence >= self._threshold

        return heuristic

    def _heuristic_analyze(
        self,
        tool_name: str,
        description: str,
        source_code: str,
    ) -> AlignmentResult:
        issues: list[str] = []
        suspicious: list[str] = []
        penalty = 0.0

        try:
            tree = ast.parse(source_code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = _get_call_name(node)
                    if func_name and any(s in func_name for s in _SUSPICIOUS_CALLS):
                        suspicious.append(func_name)
                        penalty += 0.15
        except SyntaxError:
            issues.append("Source code could not be parsed (minified or obfuscated?)")
            penalty += 0.3

        for pat in _EXFIL_PATTERNS:
            if pat.search(source_code):
                issues.append(f"Possible data exfiltration pattern: {pat.pattern}")
                penalty += 0.25

        if description:
            desc_lower = description.lower()
            src_lower = source_code.lower()
            desc_keywords = {w for w in re.findall(r"\w+", desc_lower) if len(w) > 4}
            matched = sum(1 for kw in desc_keywords if kw in src_lower)
            coverage = matched / max(len(desc_keywords), 1)
            if coverage < 0.2:
                issues.append("Source code shares few keywords with description (semantic mismatch)")
                penalty += 0.2

        confidence = max(0.0, 1.0 - penalty)
        return AlignmentResult(
            tool_name=tool_name,
            aligned=confidence >= self._threshold,
            confidence=confidence,
            issues=issues,
            suspicious_calls=list(set(suspicious)),
        )

    def _llm_analyze(
        self,
        tool_name: str,
        description: str,
        source_code: str,
    ) -> AlignmentResult:
        prompt = (
            f"You are a security analyst reviewing an MCP (Model Context Protocol) tool.\n\n"
            f"Tool name: {tool_name}\n"
            f"Declared description: {description}\n\n"
            f"Source code:\n```python\n{source_code[:4000]}\n```\n\n"
            "Does the source code match the declared description? "
            "List any suspicious behaviours, hidden side effects, or exfiltration attempts. "
            "Reply with JSON: {\"aligned\": true/false, \"confidence\": 0.0-1.0, \"issues\": [...]}"
        )
        try:
            raw = self._llm.complete(prompt)
            import json
            data = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
            return AlignmentResult(
                tool_name=tool_name,
                aligned=bool(data.get("aligned", True)),
                confidence=float(data.get("confidence", 0.5)),
                issues=list(data.get("issues", [])),
                raw_analysis=raw,
            )
        except Exception as exc:
            logger.warning("LLM alignment analysis failed for %r: %s", tool_name, exc)
            return AlignmentResult(
                tool_name=tool_name,
                aligned=True,
                confidence=0.5,
                issues=[f"LLM analysis failed: {exc}"],
            )


def _get_call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        cur: Any = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""
