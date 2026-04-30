"""Analyzability scorer for AI skill code.

Measures how difficult code is to analyze — high obfuscation scores indicate
the code may be intentionally hiding its behavior. Checks for:
  - Base64/hex encoding chains
  - Eval chains
  - Name mangling / minification
  - Excessive string concatenation
  - Unicode escape obfuscation
  - Dead code / control flow obfuscation
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Optional

_BASE64_PATTERN = re.compile(
    r'(?:base64|b64decode|b64encode|codecs\.decode)\s*\(', re.IGNORECASE
)
_HEX_PATTERN = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}|(?:0x[0-9a-fA-F]+,?\s*){4,}')
_UNICODE_ESCAPE = re.compile(r'(?:\\u[0-9a-fA-F]{4}){3,}')
_EVAL_CHAIN = re.compile(r'eval\s*\(\s*(?:exec|eval|compile|\w+\()')
_STRING_CONCAT_CHAIN = re.compile(r'(?:"[^"]*"\s*\+\s*){4,}|(?:\'[^\']*\'\s*\+\s*){4,}')
_ROT_DECODE = re.compile(r'rotate|rot\s*13|caesar', re.IGNORECASE)
_MINIFY_INDICATOR = re.compile(r';[^;\n]{200,}')


@dataclass
class ObfuscationSignal:
    name: str
    score_contribution: float
    description: str
    line_no: Optional[int] = None


@dataclass
class AnalyzabilityResult:
    source: str
    analyzability_score: float
    obfuscation_score: float
    signals: list[ObfuscationSignal] = field(default_factory=list)
    verdict: str = "clean"

    @property
    def is_obfuscated(self) -> bool:
        return self.obfuscation_score >= 0.4


class AnalyzabilityScorer:
    """Score code for obfuscation and analyzability.

    Returns an ``analyzability_score`` (1.0 = fully analyzable, 0.0 = opaque)
    and an ``obfuscation_score`` (0.0 = clean, 1.0 = heavily obfuscated).
    """

    def score_source(self, source_code: str, name: str = "<source>") -> AnalyzabilityResult:
        signals: list[ObfuscationSignal] = []
        obfuscation = 0.0

        lines = source_code.splitlines()
        for i, line in enumerate(lines, start=1):
            if _BASE64_PATTERN.search(line):
                signals.append(ObfuscationSignal(
                    "base64_encoding", 0.2,
                    "Base64 encoding/decoding call detected", i
                ))
                obfuscation += 0.2

            if _HEX_PATTERN.search(line):
                signals.append(ObfuscationSignal(
                    "hex_encoding", 0.2,
                    "Hex-encoded byte sequence detected", i
                ))
                obfuscation += 0.2

            if _UNICODE_ESCAPE.search(line):
                signals.append(ObfuscationSignal(
                    "unicode_escape", 0.15,
                    "Unicode escape sequence chain detected", i
                ))
                obfuscation += 0.15

            if _EVAL_CHAIN.search(line):
                signals.append(ObfuscationSignal(
                    "eval_chain", 0.35,
                    "Nested eval/exec chain detected", i
                ))
                obfuscation += 0.35

            if _STRING_CONCAT_CHAIN.search(line):
                signals.append(ObfuscationSignal(
                    "string_concat_chain", 0.1,
                    "Long string concatenation chain (possible obfuscation)", i
                ))
                obfuscation += 0.1

            if _ROT_DECODE.search(line):
                signals.append(ObfuscationSignal(
                    "rot_encoding", 0.1,
                    "ROT/Caesar encoding reference detected", i
                ))
                obfuscation += 0.1

        if _MINIFY_INDICATOR.search(source_code):
            signals.append(ObfuscationSignal(
                "minification", 0.2,
                "Code appears minified (very long single lines)"
            ))
            obfuscation += 0.2

        try:
            tree = ast.parse(source_code)
            short_names = sum(
                1 for node in ast.walk(tree)
                if isinstance(node, (ast.Name, ast.FunctionDef, ast.ClassDef))
                and len(getattr(node, "id", getattr(node, "name", ""))) == 1
            )
            total_names = sum(
                1 for node in ast.walk(tree)
                if isinstance(node, (ast.Name, ast.FunctionDef, ast.ClassDef))
            )
            if total_names > 10 and short_names / total_names > 0.6:
                ratio = short_names / total_names
                signals.append(ObfuscationSignal(
                    "name_mangling", min(0.3, ratio * 0.4),
                    f"High proportion of single-char names ({ratio:.0%}): possible minification"
                ))
                obfuscation += min(0.3, ratio * 0.4)
        except SyntaxError:
            signals.append(ObfuscationSignal(
                "parse_failure", 0.3,
                "Source code failed to parse (possibly obfuscated or compiled)"
            ))
            obfuscation += 0.3

        obfuscation = min(1.0, obfuscation)
        analyzability = 1.0 - obfuscation

        if obfuscation >= 0.6:
            verdict = "heavily_obfuscated"
        elif obfuscation >= 0.4:
            verdict = "obfuscated"
        elif obfuscation >= 0.2:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return AnalyzabilityResult(
            source=name,
            analyzability_score=analyzability,
            obfuscation_score=obfuscation,
            signals=signals,
            verdict=verdict,
        )

    def score_file(self, path: str) -> AnalyzabilityResult:
        from pathlib import Path as _Path
        p = _Path(path)
        if not p.exists():
            return AnalyzabilityResult(
                source=path,
                analyzability_score=0.0,
                obfuscation_score=1.0,
                verdict="not_found",
            )
        return self.score_source(p.read_text(errors="ignore"), path)
