"""
Encoding attack scanner — detection predicates.

All functions return ``bool`` or a list of findings info.
They do NOT create ``Finding`` objects — that is the scanner's job.
"""

from __future__ import annotations

import re

from sentinel.firewall.input._enc_tables import (
    ARABIC_RANGE,
    BRAINFUCK_PATTERN,
    CYRILLIC_RANGE,
    GREEK_RANGE,
    HEBREW_RANGE,
    INJECTION_INDICATORS,
    LATIN_RANGE,
    MORSE_PATTERN,
    VARIATION_SELECTOR_PATTERN,
    ZALGO_PATTERN,
    ZERO_WIDTH_PATTERN,
)


# ─────────────────────────────────────────────────────────────────────────────
# Script / homoglyph detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_mixed_scripts(text: str) -> list[tuple[str, str, str]]:
    """Find words that mix Latin + Cyrillic/Greek/Arabic/Hebrew (homoglyph attack).

    Returns ``[(word, scripts_label, detail), ...]``.
    """
    findings: list[tuple[str, str, str]] = []
    for word in re.findall(r"\S+", text):
        if len(word) < 3:
            continue
        scripts: set[str] = set()
        for ch in word:
            cp = ord(ch)
            if cp in LATIN_RANGE:
                scripts.add("Latin")
            elif cp in CYRILLIC_RANGE:
                scripts.add("Cyrillic")
            elif cp in GREEK_RANGE:
                scripts.add("Greek")
            elif cp in ARABIC_RANGE:
                scripts.add("Arabic")
            elif cp in HEBREW_RANGE:
                scripts.add("Hebrew")
        if len(scripts) > 1:
            findings.append((word, "+".join(sorted(scripts)), f"scripts:{scripts}"))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Steganography / obfuscation detectors
# ─────────────────────────────────────────────────────────────────────────────

def detect_zalgo(text: str) -> bool:
    """Return True if text contains Zalgo-style stacked combining marks."""
    return bool(ZALGO_PATTERN.search(text))


def detect_brainfuck(text: str) -> bool:
    """Return True if text contains a plausible Brainfuck program."""
    return bool(BRAINFUCK_PATTERN.search(text))


def detect_variation_selectors(text: str) -> bool:
    """Return True if text contains emoji variation selectors (steganography)."""
    return bool(VARIATION_SELECTOR_PATTERN.search(text))


def detect_zero_width(text: str) -> tuple[bool, int]:
    """Return ``(found, count)`` of zero-width chars."""
    stripped = ZERO_WIDTH_PATTERN.sub("", text)
    count = len(text) - len(stripped)
    return count > 0, count


def detect_morse(text: str) -> bool:
    """Return True if text contains a Morse-code-like sequence."""
    return bool(MORSE_PATTERN.search(text))


# ─────────────────────────────────────────────────────────────────────────────
# Injection keyword checker
# ─────────────────────────────────────────────────────────────────────────────

def check_injection(text: str) -> str | None:
    """Return the first INJECTION_INDICATORS keyword found in *text*, else None."""
    lower = text.lower()
    for kw in INJECTION_INDICATORS:
        if kw.lower() in lower:
            return kw
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Reverse-shell specific detectors (for decoded content)
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that strongly indicate a reverse shell payload
_REVSHELL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"bash\s+-[ci]\s+['\"]", re.IGNORECASE),
    re.compile(r"\bnc\b.*-e\s+/bin", re.IGNORECASE),
    re.compile(r"\bncat\b.*-e\s+/bin", re.IGNORECASE),
    re.compile(r"mkfifo\s+/tmp/", re.IGNORECASE),
    re.compile(r"0<&\d+[-;]\s+exec\s+\d+<>", re.IGNORECASE),
    re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", re.IGNORECASE),
    re.compile(r"/dev/udp/\d+\.\d+\.\d+\.\d+/\d+", re.IGNORECASE),
    re.compile(r"python[23]?\s+-c\s+['\"]import\s+socket", re.IGNORECASE),
    re.compile(r"perl\s+-e\s+['\"]use\s+Socket", re.IGNORECASE),
    re.compile(r"ruby\s+-rsocket\s+-e", re.IGNORECASE),
    re.compile(r"php\s+-r\s+['\"].*fsockopen", re.IGNORECASE),
    re.compile(r"powershell.*New-Object.*Net\.Sockets\.TCPClient", re.IGNORECASE),
    re.compile(r"cmd\.exe.*Start-Process", re.IGNORECASE),
    re.compile(
        r"(?:exec|shell_exec|system|passthru|popen)\s*\(\s*['\"]"
        r"(?:bash|sh|cmd|nc|ncat|wget|curl)",
        re.IGNORECASE,
    ),
]

_WEBSHELL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<\?php.*(?:eval|system|exec|shell_exec|passthru|assert)\s*\(", re.IGNORECASE | re.DOTALL),
    re.compile(r"<%.*Runtime\.getRuntime\(\)\.exec", re.IGNORECASE | re.DOTALL),
    re.compile(r"<%.*ProcessBuilder", re.IGNORECASE | re.DOTALL),
    re.compile(r"<asp:ObjectDataSource.*TypeName=", re.IGNORECASE),
    re.compile(r"\beval\s*\(\s*base64_decode\s*\(", re.IGNORECASE),
    re.compile(r"\beval\s*\(\s*gzinflate\s*\(", re.IGNORECASE),
    re.compile(r"\beval\s*\(\s*str_rot13\s*\(", re.IGNORECASE),
    re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[['\"]cmd['\"]", re.IGNORECASE),
    re.compile(r"cmd\.exe\s+/c\s+", re.IGNORECASE),
]


def detect_reverse_shell(text: str) -> str | None:
    """Return the matched pattern description if text contains a reverse shell, else None."""
    for pat in _REVSHELL_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group()[:120]
    return None


def detect_web_shell(text: str) -> str | None:
    """Return the matched pattern description if text contains a web shell, else None."""
    for pat in _WEBSHELL_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group()[:120]
    return None


__all__ = [
    "detect_mixed_scripts",
    "detect_zalgo", "detect_brainfuck", "detect_variation_selectors",
    "detect_zero_width", "detect_morse",
    "check_injection",
    "detect_reverse_shell", "detect_web_shell",
]
