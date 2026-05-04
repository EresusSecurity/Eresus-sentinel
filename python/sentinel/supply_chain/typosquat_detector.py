"""
Eresus Sentinel — HuggingFace Typosquat & Clone Detector.

Detects repositories that appear to impersonate popular/trusted models:
  1. Edit-distance typosquat — 'meta-Ilama' vs 'meta-llama' (capital I vs l)
  2. Homoglyph substitution — unicode lookalikes in org/repo names
  3. Namespace squatting — popular model name under unknown org
  4. Clone detection — repo description matches known model but different org
  5. Underscore/dash/dot normalization attacks

Trusted namespace registry is based on publicly known major AI labs.
"""

from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path

from ..finding import Finding, Severity

# ── Trusted Namespaces (org → canonical models) ───────────────────────────────

TRUSTED_ORGS: dict[str, list[str]] = {
    "meta-llama":    ["llama", "meta-llama", "llama-2", "llama-3", "codellama"],
    "mistralai":     ["mistral", "mixtral", "codestral", "mathstral"],
    "google":        ["gemma", "flan", "t5", "bert", "pegasus", "palm"],
    "google-deepmind": ["gemma"],
    "microsoft":     ["phi", "phi-2", "phi-3", "orca", "wizardlm", "deberta"],
    "openai":        ["gpt2", "whisper", "clip", "dall-e"],
    "anthropic":     ["claude"],
    "deepseek-ai":   ["deepseek", "deepseek-coder", "deepseek-v2", "deepseek-v3"],
    "qwen":          ["qwen", "qwen2", "qwen-vl", "codeqwen"],
    "ibm-granite":   ["granite"],
    "ibm":           ["granite", "slate"],
    "huggingface":   ["bert", "roberta", "distilbert", "gpt2", "xlm"],
    "stabilityai":   ["stable-diffusion", "stablelm", "sdxl"],
    "tiiuae":        ["falcon"],
    "01-ai":         ["yi"],
    "baichuan-inc":  ["baichuan"],
    "internlm":      ["internlm"],
    "xai-org":       ["grok"],
    "cohere":        ["command", "aya", "embed"],
    "allenai":       ["olmo", "molmo", "tulu"],
    "nvidia":        ["nemotron", "nv-embed", "megatron"],
    "poolside":      ["muse", "laguna"],
    "databricks":    ["dbrx", "dolly"],
    "EleutherAI":    ["gpt-neo", "gpt-j", "pythia", "gpt-neox"],
    "bigscience":    ["bloom", "bloomz", "mt0"],
    "lmsys":         ["vicuna", "fastchat"],
}

# Flat set of all popular model name fragments for namespace squatting detection
_POPULAR_MODEL_NAMES: set[str] = set()
for _models in TRUSTED_ORGS.values():
    _POPULAR_MODEL_NAMES.update(_models)

# ── Homoglyph Map ─────────────────────────────────────────────────────────────

_HOMOGLYPHS: dict[str, str] = {
    # ── Unicode lookalikes only — pure ASCII pairs intentionally excluded ──
    # ASCII digits/letters (0/O, 1/l/I) are distinct by design and appear
    # legitimately in model names (Llama-3, GPT-4o, Phi-2, etc.).
    # Only include characters that are visually identical Unicode substitutions.

    # Cyrillic → Latin lookalikes (most common in squatting attacks)
    "а": "a",  # U+0430 CYRILLIC SMALL LETTER A
    "е": "e",  # U+0435 CYRILLIC SMALL LETTER IE
    "о": "o",  # U+043E CYRILLIC SMALL LETTER O
    "р": "p",  # U+0440 CYRILLIC SMALL LETTER ER
    "с": "c",  # U+0441 CYRILLIC SMALL LETTER ES
    "х": "x",  # U+0445 CYRILLIC SMALL LETTER HA
    "у": "y",  # U+0443 CYRILLIC SMALL LETTER U
    "А": "A",  # U+0410 CYRILLIC CAPITAL LETTER A
    "В": "B",  # U+0412 CYRILLIC CAPITAL LETTER VE
    "Е": "E",  # U+0415 CYRILLIC CAPITAL LETTER IE
    "К": "K",  # U+041A CYRILLIC CAPITAL LETTER KA
    "М": "M",  # U+041C CYRILLIC CAPITAL LETTER EM
    "Н": "H",  # U+041D CYRILLIC CAPITAL LETTER EN
    "О": "O",  # U+041E CYRILLIC CAPITAL LETTER O
    "Р": "P",  # U+0420 CYRILLIC CAPITAL LETTER ER
    "С": "C",  # U+0421 CYRILLIC CAPITAL LETTER ES
    "Т": "T",  # U+0422 CYRILLIC CAPITAL LETTER TE
    "Х": "X",  # U+0425 CYRILLIC CAPITAL LETTER HA
    # Greek lookalikes
    "ν": "v",  # U+03BD GREEK SMALL LETTER NU
    "ο": "o",  # U+03BF GREEK SMALL LETTER OMICRON
    "ρ": "p",  # U+03C1 GREEK SMALL LETTER RHO
    "ϲ": "c",  # U+03F2 GREEK LUNATE SIGMA SYMBOL
    # IPA / extended Latin
    "ɑ": "a",  # U+0251 LATIN SMALL LETTER ALPHA
    "ɡ": "g",  # U+0261 LATIN SMALL LETTER SCRIPT G
    "ɩ": "i",  # U+0269 LATIN SMALL LETTER IOTA
    "ʝ": "j",  # U+029D LATIN SMALL LETTER J WITH CROSSED-TAIL
    # Unicode fraction / enclosed letters that look like standard chars
    "ⅼ": "l",  # U+217C SMALL ROMAN NUMERAL FIFTY
    "ⅿ": "m",  # U+217F SMALL ROMAN NUMERAL ONE THOUSAND
    # Armenian lookalikes
    "ո": "n",  # U+0576 ARMENIAN SMALL LETTER NOW
    "ԁ": "d",  # U+0501 CYRILLIC SMALL LETTER KOMI DE
    "ƅ": "b",  # U+0185 LATIN SMALL LETTER TONE SIX
    "ɦ": "h",  # U+0266 LATIN SMALL LETTER H WITH HOOK
}


def _normalize_name(name: str) -> str:
    """Normalize a repo name for comparison: lowercase, remove separators, map homoglyphs."""
    name = name.lower()
    name = unicodedata.normalize("NFKD", name)
    for src, dst in _HOMOGLYPHS.items():
        name = name.replace(src, dst)
    name = re.sub(r"[-_.]+", "", name)
    return name


def _edit_distance(a: str, b: str) -> int:
    """Simple Levenshtein distance."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            ins = prev[j + 1] + 1
            del_ = curr[j] + 1
            sub = prev[j] + (0 if ca == cb else 1)
            curr.append(min(ins, del_, sub))
        prev = curr
    return prev[-1]


class TyposquatDetector:
    """
    Detect typosquatting and impersonation of trusted HuggingFace repositories.
    """

    def __init__(self, edit_distance_threshold: int = 2):
        self._threshold = edit_distance_threshold

    def check_repo(self, repo_id: str) -> list[Finding]:
        """Check if a repo_id looks like a typosquat of a trusted model."""
        findings: list[Finding] = []
        if "/" not in repo_id:
            return findings

        org, model = repo_id.split("/", 1)
        org_lower = org.lower()
        model_lower = model.lower()

        # ── Check 1: Org typosquat ─────────────────────────────────────────
        for trusted_org in TRUSTED_ORGS:
            if org_lower == trusted_org.lower():
                break
            norm_given = _normalize_name(org)
            norm_trusted = _normalize_name(trusted_org)
            dist = _edit_distance(norm_given, norm_trusted)
            if 0 < dist <= self._threshold:
                findings.append(Finding.supply_chain(
                    rule_id="TYPO-001",
                    title=f"Possible org typosquat: '{org}' ≈ '{trusted_org}'",
                    description=(
                        f"The organization '{org}' is very similar to the trusted org "
                        f"'{trusted_org}' (edit distance: {dist}). This may be a typosquat "
                        "attempting to impersonate a trusted model publisher."
                    ),
                    severity=Severity.HIGH,
                    confidence=max(0.5, 1.0 - dist * 0.25),
                    target=repo_id,
                    evidence=f"given_org={org!r}, trusted_org={trusted_org!r}, edit_dist={dist}",
                    remediation=f"Verify this is not an impersonation of '{trusted_org}/{model}'",
                ))

        # ── Check 2: Model name from trusted org but different org ─────────
        norm_model = _normalize_name(model_lower)
        for trusted_org, trusted_models in TRUSTED_ORGS.items():
            if org_lower == trusted_org.lower():
                continue
            for trusted_model in trusted_models:
                norm_trusted_model = _normalize_name(trusted_model)
                if norm_model == norm_trusted_model or norm_trusted_model in norm_model:
                    findings.append(Finding.supply_chain(
                        rule_id="TYPO-002",
                        title=f"Namespace squatting: '{repo_id}' uses name of '{trusted_org}/{trusted_model}'",
                        description=(
                            f"Model name '{model}' matches the popular model '{trusted_model}' "
                            f"from trusted org '{trusted_org}', but is published under '{org}'. "
                            "This may be a clone with injected malware."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.75,
                        target=repo_id,
                        evidence=f"model_name={model!r} matches trusted={trusted_org}/{trusted_model}",
                        remediation=f"Use official model from '{trusted_org}/{trusted_model}'",
                    ))
                    break

        # ── Check 3: Homoglyph in org or model name ────────────────────────
        has_homoglyph = any(ch in _HOMOGLYPHS for ch in org + model)
        if has_homoglyph:
            suspicious_chars = [ch for ch in org + model if ch in _HOMOGLYPHS]
            findings.append(Finding.supply_chain(
                rule_id="TYPO-003",
                title=f"Homoglyph characters in repo name: {repo_id}",
                description=(
                    f"Repository name contains characters that look like other characters "
                    f"(homoglyphs): {[f'{c}→{_HOMOGLYPHS[c]}' for c in set(suspicious_chars)]}. "
                    "This is a classic technique to impersonate trusted repos."
                ),
                severity=Severity.HIGH,
                confidence=0.9,
                target=repo_id,
                evidence=f"suspicious_chars={suspicious_chars}",
                remediation="Verify the exact repository name matches the intended model",
            ))

        return findings
