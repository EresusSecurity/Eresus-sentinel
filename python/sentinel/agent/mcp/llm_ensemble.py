"""MCP manifest LLM ensemble analyzer.

Provides a three-engine ensemble for MCP manifest security analysis:
  1. YARA rules (fast, deterministic — already in yara_analyzer.py)
  2. Heuristic regex patterns (no AI dependency)
  3. LLM-assisted verdict (optional, requires AI backend)

The ensemble combines signals with weighted voting. LLM enrichment is
optional — core detection never depends on it.

Architecture
------------
  MCPEnsembleAnalyzer.analyze(manifest_text) → EnsembleResult
    ├─ YaraEngine → findings[]
    ├─ HeuristicEngine → signals[]
    └─ LLMEngine (if enabled) → LLMVerdict

Weights: YARA 0.50 · Heuristic 0.30 · LLM 0.20
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ── Heuristic patterns ────────────────────────────────────────

# Pattern → (signal_name, weight)
_HEURISTIC_RULES: list[tuple[re.Pattern[str], str, float]] = [
    # Tool name abuse / squatting
    (re.compile(r'"name"\s*:\s*"[^"]*(?:eval|exec|shell|bash|cmd|powershell)[^"]*"', re.I),
     "suspicious_tool_name", 0.4),
    # Excessively broad permissions
    (re.compile(r'"permissions"\s*:\s*\[[^\]]*"\*"[^\]]*\]', re.I),
     "wildcard_permissions", 0.5),
    # Remote code execution gadgets in description
    (re.compile(r'"description"\s*:\s*"[^"]*(?:__import__|subprocess|os\.system|eval\(|exec\()[^"]*"', re.I),
     "rce_in_description", 0.7),
    # Prompt injection in tool description
    (re.compile(r'"description"\s*:\s*"[^"]*(?:ignore|disregard|forget).{0,60}(?:instruction|rule|guideline)[^"]*"', re.I),
     "prompt_injection_in_description", 0.8),
    # Excessive scope declarations
    (re.compile(r'"scopes"\s*:\s*\[[^\]]{200,}\]', re.I),
     "excessive_scopes", 0.3),
    # HTTP endpoint pointing to non-standard ports
    (re.compile(r'"url"\s*:\s*"https?://[^"]*:(?!443|80|8080|8443)\d{4,5}[^"]*"', re.I),
     "non_standard_port", 0.25),
    # Data exfiltration patterns
    (re.compile(r'"url"\s*:\s*"[^"]*(?:ngrok|burpcollaborator|requestbin|webhook\.site)[^"]*"', re.I),
     "data_exfil_endpoint", 0.9),
    # Localhost tunnel/forward
    (re.compile(r'"url"\s*:\s*"[^"]*localhost[^"]*"', re.I),
     "localhost_endpoint", 0.15),
    # Unicode/homoglyph in tool names
    (re.compile(r'"name"\s*:\s*"[^"]*[\u0430-\u044f\u03b1-\u03c9\u0400-\u04ff][^"]*"'),
     "homoglyph_in_name", 0.6),
    # Tool arity bomb (>50 parameters)
    (re.compile(r'"parameters"\s*:\s*\{[^}]{3000,}\}', re.I),
     "parameter_bomb", 0.35),
    # Missing authentication on sensitive tools
    (re.compile(r'"auth"\s*:\s*(?:null|false|"none")', re.I),
     "missing_auth", 0.2),
    # Recursive tool calls
    (re.compile(r'"tool_choice"\s*:\s*"[^"]*(?:recursive|loop|repeat)[^"]*"', re.I),
     "recursive_tool_choice", 0.4),
]


# ── LLM verdict ───────────────────────────────────────────────

@dataclass
class LLMVerdict:
    risk_score: float = 0.0        # 0.0 – 1.0
    summary: str = ""
    signals: list[str] = field(default_factory=list)
    model: str = ""
    latency_ms: float = 0.0
    error: Optional[str] = None

    @property
    def available(self) -> bool:
        return self.error is None


_LLM_SYSTEM_PROMPT = """\
You are a security analyst reviewing an MCP (Model Context Protocol) manifest.
Your task: identify security risks in this JSON manifest.

Respond ONLY with valid JSON matching this schema:
{
  "risk_score": <float 0.0-1.0>,
  "signals": [<list of short signal strings>],
  "summary": "<one sentence>"
}

Risk score guide:
  0.0-0.2 = clean / low risk
  0.3-0.5 = suspicious, warrants review
  0.6-0.8 = high risk, likely malicious
  0.9-1.0 = critical, almost certainly malicious

Focus on: prompt injection in descriptions, tool name squatting, wildcard
permissions, data exfiltration endpoints, missing auth on sensitive tools,
recursive tool patterns, homoglyph attacks, RCE gadgets.
"""

_MAX_MANIFEST_CHARS = 8_000  # truncate before sending to LLM


def _call_llm(manifest_text: str) -> LLMVerdict:
    """Best-effort LLM call using the sentinel AI provider stack.

    Falls back gracefully if no AI backend is configured.
    """
    truncated = manifest_text[:_MAX_MANIFEST_CHARS]
    t0 = time.perf_counter()
    try:
        # Try OpenAI first, then Anthropic
        api_key = os.getenv("OPENAI_API_KEY")
        if api_key:
            return _call_openai(truncated, api_key, t0)
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            return _call_anthropic(truncated, api_key, t0)
    except Exception as e:
        logger.debug("LLM ensemble call failed: %s", e)
        return LLMVerdict(error=str(e))
    return LLMVerdict(error="no_ai_backend_configured")


def _call_openai(text: str, api_key: str, t0: float) -> LLMVerdict:
    import urllib.request
    payload = json.dumps({
        "model": "gpt-4.1-mini",
        "messages": [
            {"role": "system", "content": _LLM_SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this MCP manifest:\n\n```json\n{text}\n```"},
        ],
        "max_tokens": 256,
        "temperature": 0.0,
    }).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        body = json.loads(resp.read())
    content = body["choices"][0]["message"]["content"]
    parsed = json.loads(content)
    elapsed = (time.perf_counter() - t0) * 1000
    return LLMVerdict(
        risk_score=float(parsed.get("risk_score", 0.0)),
        signals=list(parsed.get("signals", [])),
        summary=str(parsed.get("summary", "")),
        model="gpt-4.1-mini",
        latency_ms=round(elapsed, 1),
    )


def _call_anthropic(text: str, api_key: str, t0: float) -> LLMVerdict:
    import urllib.request
    payload = json.dumps({
        "model": "claude-haiku-4-5",
        "max_tokens": 256,
        "system": _LLM_SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": f"Analyze this MCP manifest:\n\n```json\n{text}\n```"},
        ],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        body = json.loads(resp.read())
    content = body["content"][0]["text"]
    parsed = json.loads(content)
    elapsed = (time.perf_counter() - t0) * 1000
    return LLMVerdict(
        risk_score=float(parsed.get("risk_score", 0.0)),
        signals=list(parsed.get("signals", [])),
        summary=str(parsed.get("summary", "")),
        model="claude-haiku-4-5",
        latency_ms=round(elapsed, 1),
    )


# ── Ensemble result ───────────────────────────────────────────

@dataclass
class EnsembleResult:
    """Combined result from all three detection engines."""

    manifest_source: str
    final_score: float                          # 0.0 – 1.0, weighted ensemble
    verdict: str                                # clean / suspicious / malicious / critical
    signals: list[str] = field(default_factory=list)
    yara_findings: list[Any] = field(default_factory=list)   # sentinel Finding objects
    heuristic_signals: list[str] = field(default_factory=list)
    llm_verdict: Optional[LLMVerdict] = None
    latency_ms: float = 0.0

    @property
    def is_malicious(self) -> bool:
        return self.verdict in ("malicious", "critical")


def _score_to_verdict(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.55:
        return "malicious"
    if score >= 0.25:
        return "suspicious"
    return "clean"


# ── Main analyzer ─────────────────────────────────────────────

class MCPEnsembleAnalyzer:
    """Three-engine ensemble scanner for MCP manifests.

    Args:
        enable_llm: Whether to call the LLM engine (default: auto, checks
                    for OPENAI_API_KEY / ANTHROPIC_API_KEY).
        yara_weight: Weight for YARA findings (default 0.50).
        heuristic_weight: Weight for heuristic signals (default 0.30).
        llm_weight: Weight for LLM verdict (default 0.20).
    """

    YARA_WEIGHT = 0.50
    HEURISTIC_WEIGHT = 0.30
    LLM_WEIGHT = 0.20

    def __init__(
        self,
        enable_llm: Optional[bool] = None,
        yara_weight: float = YARA_WEIGHT,
        heuristic_weight: float = HEURISTIC_WEIGHT,
        llm_weight: float = LLM_WEIGHT,
    ) -> None:
        self._enable_llm = enable_llm if enable_llm is not None else (
            bool(os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"))
        )
        self._yw = yara_weight
        self._hw = heuristic_weight
        self._lw = llm_weight

    # ─── Public API ───────────────────────────────────────────

    def analyze(
        self,
        manifest_text: str,
        source: str = "<manifest>",
    ) -> EnsembleResult:
        """Run full ensemble analysis on a manifest JSON string."""
        t0 = time.perf_counter()

        # 1. Heuristic pass (always runs)
        heuristic_score, heuristic_signals = self._heuristic(manifest_text)

        # 2. YARA pass (always runs, degrades if yara unavailable)
        yara_findings, yara_score = self._yara(manifest_text, source)

        # 3. LLM pass (optional)
        llm_verdict: Optional[LLMVerdict] = None
        if self._enable_llm:
            llm_verdict = _call_llm(manifest_text)

        # 4. Weighted ensemble
        llm_score = llm_verdict.risk_score if (llm_verdict and llm_verdict.available) else 0.0

        if self._enable_llm and llm_verdict and llm_verdict.available:
            total_w = self._yw + self._hw + self._lw
            final = (
                yara_score * self._yw
                + heuristic_score * self._hw
                + llm_score * self._lw
            ) / total_w
        else:
            total_w = self._yw + self._hw
            final = (yara_score * self._yw + heuristic_score * self._hw) / total_w

        final = min(1.0, final)

        # Merge signals
        all_signals = list(dict.fromkeys(
            heuristic_signals
            + [f.rule_id for f in yara_findings if hasattr(f, "rule_id")]
            + (llm_verdict.signals if llm_verdict and llm_verdict.available else [])
        ))

        elapsed = (time.perf_counter() - t0) * 1000
        return EnsembleResult(
            manifest_source=source,
            final_score=round(final, 4),
            verdict=_score_to_verdict(final),
            signals=all_signals,
            yara_findings=yara_findings,
            heuristic_signals=heuristic_signals,
            llm_verdict=llm_verdict,
            latency_ms=round(elapsed, 1),
        )

    # ─── Private engines ──────────────────────────────────────

    def _heuristic(self, text: str) -> tuple[float, list[str]]:
        signals: list[str] = []
        score = 0.0
        for pat, name, weight in _HEURISTIC_RULES:
            if pat.search(text):
                signals.append(name)
                score = min(1.0, score + weight)
        return score, signals

    def _yara(self, text: str, source: str) -> tuple[list[Any], float]:
        try:
            from sentinel.agent.yara_analyzer import YaraAnalyzer
            analyzer = YaraAnalyzer()
            findings = analyzer.scan_text(text, source=source)
            if not findings:
                return [], 0.0
            # Map severity to score contribution
            from sentinel.finding import Severity
            sev_weights = {
                Severity.CRITICAL: 0.9,
                Severity.HIGH: 0.7,
                Severity.MEDIUM: 0.4,
                Severity.LOW: 0.2,
                Severity.INFO: 0.05,
            }
            score = min(1.0, sum(sev_weights.get(f.severity, 0.3) for f in findings) / max(1, len(findings)))
            return findings, score
        except Exception as e:
            logger.debug("YARA engine unavailable: %s", e)
            return [], 0.0
