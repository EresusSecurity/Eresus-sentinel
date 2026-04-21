"""
Heuristic Prompt Injection Scanner.

Detects prompt injection using combinatoric keyword analysis and
sequence similarity matching — a fast, model-free detection layer.

Approach — dual keyword strategy:
  1. Combinatoric generation: 11 verbs × 8 adjectives × 19 objects
     × 5 prepositions = 8,360 systematically generated injection phrases
  2. Original keyword pairs: high-signal 2-word combinations from a
     curated vocabulary of 52 injection-related words

This runs before the ML classifier as a cheap pre-filter.
"""

from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

# ── Combinatoric keyword generation ──────────────────────────────

_VERBS = [
    # English
    "Ignore", "Disregard", "Skip", "Forget", "Neglect",
    "Overlook", "Omit", "Bypass", "Pay no attention to",
    "Do not follow", "Do not obey",
    # Turkish
    "Yok say", "Görmezden gel", "Bırak", "Unut", "Vazgeç",
    "Aldırma", "Atla", "İhmal et", "Önemseme",
    # Spanish
    "Ignora", "Olvida", "Omite", "Pasa por alto", "Desconsidera",
    # Russian
    "Игнорируй", "Забудь", "Пропусти", "Отмени",
    # Arabic
    "تجاهل", "انسى", "تخطَّ",
    # Chinese
    "忽略", "忘记", "跳过", "无视",
    # German
    "Ignoriere", "Vergiss", "Überspringe",
    # French
    "Ignore", "Oublie", "Passe outre",
]

_ADJECTIVES = [
    "", "prior", "previous", "preceding",
    "above", "foregoing", "earlier", "initial",
    "önceki", "tüm", "bütün", "yukarıdaki",
    "anterior", "previa", "precedente",
    "предыдущий", "все",
    "السابقة", "كل",
    "先前的", "所有",
    "vorherige", "alle",
    "précédent", "tous",
]

_PREPOSITIONS = [
    "", "and start over", "and start anew",
    "and begin afresh", "and start from scratch",
]

_OBJECTS = [
    "content", "text", "instructions", "instruction",
    "directives", "directive", "commands", "command",
    "context", "conversation", "input", "inputs",
    "data", "message", "messages", "communication",
    "response", "responses", "request", "requests",
    "talimatları", "talimat", "yönergeleri", "yönerge",
    "kuralları", "kural", "mesajı", "mesaj", "komutları", "komut",
    "instrucciones", "mensajes", "reglas", "órdenes",
    "инструкции", "сообщения", "правила", "команды",
    "التعليمات", "القواعد", "الرسائل",
    "指令", "命令", "规则", "消息",
    "Anweisungen", "Befehle", "Regeln", "Nachrichten",
    "commandes", "règles",
]


def _generate_combinatoric_keywords() -> list[str]:
    """
    Generate combinatoric injection phrases.
    11 × 8 × 19 × 5 = 8,360 permutations.
    """
    phrases: list[str] = []
    for verb in _VERBS:
        for adj in _ADJECTIVES:
            for obj in _OBJECTS:
                for prep in _PREPOSITIONS:
                    parts = [verb, adj, obj, prep]
                    phrase = " ".join(p for p in parts if p).strip()
                    phrases.append(phrase.lower())
    return phrases


# Legacy keyword list (high-signal short patterns)
_LEGACY_KEYWORDS = [
    "ignore", "disregard", "forget", "override", "bypass", "skip",
    "previous", "above", "instructions", "directions", "rules",
    "constraints", "guidelines", "system", "prompt", "context",
    "instead", "actually", "pretend", "roleplay", "new", "different",
    "persona", "character", "respond", "answer", "output", "print",
    "say", "write", "repeat", "reveal", "show", "tell", "secret",
    "hidden", "confidential", "internal", "admin", "developer",
    "mode", "jailbreak", "DAN", "do anything", "no restrictions",
    "no limits", "no rules", "unfiltered", "uncensored", "unrestricted",
]

_BENIGN_CONTEXTS = re.compile(
    r"(?i)(?:"
    r"(?:how|what|why|explain|describe|teach|learn|tutorial|example|lesson)"
    r".*(?:prompt injection|jailbreak|attack|security|defend)"
    r"|(?:prompt injection|jailbreak).*(?:detection|prevention|defense|protect|mitigat)"
    r"|(?:rewrite|edit|revise|update|rephrase|improve).*(?:paragraph|essay|article|document|text|draft|resume|letter)"
    r"|(?:ignore|skip|disregard).*(?:error|warning|deprecat|lint|whitespace|formatting|comment|header|blank|NaN|null|empty|missing|invalid)"
    r"|(?:bypass|skip).*(?:cache|proxy|validation|step|check|queue|buffer|middleware|throttl|switching|overhead|latency|bottleneck)"
    r"|(?:switch\s+to|start\s+over|previous\s+(?:approach|version|method|step|page|chapter|section))"
    r"|(?:ignore|skip|omit).*(?:data|field|column|row|record|entry)\s+(?:that|which|where|if|when)"
    r"|(?:context\s+switch(?:ing|es)?|kernel|thread|process|scheduler|CPU|mutex|semaphore)"
    r")"
)


def _generate_legacy_combos() -> list[str]:
    """Generate 2-word combinations from legacy keyword list."""
    from itertools import combinations
    combos = []
    for a, b in combinations(_LEGACY_KEYWORDS, 2):
        combos.append(f"{a} {b}")
        combos.append(f"{b} {a}")
    return combos


def _normalize(text: str) -> str:
    """Normalize for comparison: NFKC + invisible-strip + confusable-fold
    + lowercase + punctuation strip + whitespace collapse."""
    import re
    from sentinel.normalize import normalize as _nfkc

    result = _nfkc(text).lower()
    result = re.sub(r"[^\w\s]|_", "", result, flags=re.UNICODE)
    result = re.sub(r"\s+", " ", result)
    return result.strip()


# Pre-generate all keyword patterns at module load time
_COMBINATORIC_PHRASES = _generate_combinatoric_keywords()
_LEGACY_COMBOS = _generate_legacy_combos()



class HeuristicInjectionScanner(InputScanner):
    """
    Heuristic prompt injection detector using keyword similarity.

    Uses SequenceMatcher to detect when
    user input contains text similar to known injection patterns.
    This catches novel phrasing that keyword lists miss.

    This is a fast pre-filter — run before the ML classifier.
    """

    def __init__(
        self,
        threshold: float = 0.6,
        window_size: int = 50,
        max_substring_checks: int = 200,
    ):
        """
        Args:
            threshold: Similarity threshold (0.0-1.0). Default 0.6.
            window_size: Character window size for sliding analysis.
            max_substring_checks: Max number of substrings to check per prompt.
        """
        self._threshold = threshold
        self._window_size = window_size
        self._max_checks = max_substring_checks

    def scan(self, prompt: str) -> ScanResult:
        """
        Scan a prompt using dual heuristic injection detection.

        Strategy:
          1. Combinatoric word match — fast O(n) word-overlap against 8,360
             combinatoric phrases for high-recall detection
          2. Legacy fuzzy match — SequenceMatcher against curated
             2-word combos for novel phrasing detection
        """
        if not prompt or len(prompt) < 5:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        from sentinel.normalize import decode_common
        decoded_candidates = decode_common(prompt)
        if decoded_candidates:
            expanded = prompt + "\n" + "\n".join(decoded_candidates)
        else:
            expanded = prompt

        normalized = _normalize(expanded)
        max_score = 0.0
        best_match = ""
        best_combo = ""
        detection_method = "none"

        # ── Step 1: Combinatoric sequential n-gram match (order-aware) ──
        norm_words = normalized.split()
        for phrase in _COMBINATORIC_PHRASES:
            phrase_words = phrase.split()
            n = len(phrase_words)
            if not phrase_words or n > len(norm_words):
                continue
            # Sliding window: phrase words must appear in order within a window
            for i in range(len(norm_words) - n + 1):
                window = norm_words[i:i + n]
                matched = sum(1 for pw, ww in zip(phrase_words, window) if pw == ww)
                score = matched / n
                if matched >= 3:
                    score = min(score + 0.1, 1.0)
                if score > max_score:
                    max_score = score
                    best_match = " ".join(window)
                    best_combo = phrase
                    detection_method = "combinatoric"
                if max_score > 0.9:
                    break
            if max_score > 0.9:
                break

        # ── Step 2: Legacy fuzzy match (if Step 1 didn't trigger) ─
        if max_score < self._threshold:
            substrings = self._extract_substrings(normalized)
            for substring in substrings[:self._max_checks]:
                for combo in _LEGACY_COMBOS:
                    score = SequenceMatcher(None, substring, combo).ratio()
                    if score > max_score:
                        max_score = score
                        best_match = substring
                        best_combo = combo
                        detection_method = "legacy-fuzzy"
                    if score > 0.9:
                        break
                if max_score > 0.9:
                    break

        # Benign context penalty: educational, editing, or technical ignore patterns
        benign_penalty = 0.0
        if _BENIGN_CONTEXTS.search(prompt):
            benign_penalty = 0.35
            max_score = max(0.0, max_score - benign_penalty)

        if max_score < self._threshold:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=max_score,
            )

        # Determine severity based on score
        if max_score > 0.85 and benign_penalty == 0.0:
            severity = Severity.HIGH
            action = ScanAction.BLOCK
        elif max_score > 0.7:
            severity = Severity.MEDIUM
            action = ScanAction.WARN
        else:
            severity = Severity.LOW
            action = ScanAction.WARN

        finding = Finding.firewall_input(
            rule_id="FIREWALL-INPUT-003",
            title="Heuristic prompt injection detected",
            description=(
                f"Input matches injection keyword pattern '{best_combo}' "
                f"with {max_score:.1%} similarity ({detection_method}). "
                f"Substring: '{best_match[:100]}'"
            ),
            severity=severity,
            confidence=max_score,
            target="<prompt>",
            evidence=(
                f"Method: {detection_method}, "
                f"Similarity: {max_score:.3f}, "
                f"Pattern: '{best_combo}', "
                f"Match: '{best_match[:100]}'"
            ),
            cwe_ids=["CWE-77"],  # Command Injection
            remediation="Review prompt for injection attempt. Consider blocking or sanitizing.",
        )

        return ScanResult(
            sanitized=prompt,
            action=action,
            risk_score=max_score,
            findings=[finding],
        )

    def _extract_substrings(self, text: str) -> list[str]:
        """
        Extract overlapping substrings using a sliding window.
        Also includes sentence-level splits for better matching.
        """
        substrings = []

        # Sliding window
        step = max(1, self._window_size // 4)
        for i in range(0, len(text) - self._window_size + 1, step):
            substrings.append(text[i:i + self._window_size])

        # Sentence-level splits
        for separator in [".", "!", "?", "\n", ";", ":"]:
            parts = text.split(separator)
            substrings.extend(part.strip() for part in parts if len(part.strip()) > 5)

        return substrings

