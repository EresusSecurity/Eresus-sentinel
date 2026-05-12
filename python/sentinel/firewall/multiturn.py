"""Multi-turn conversation context tracker for the firewall.

Tracks per-session conversation history and detects attacks that span
multiple turns (slow escalation, benign-then-malicious chaining, context
poisoning, token-budget exhaustion, jailbreak across system/user split).

Usage
-----
    tracker = MultiTurnTracker()
    ctx = tracker.get_or_create("session-abc")
    ctx.add_turn("user", user_input)
    result = ctx.analyze()
    if result.threat_level >= ThreatLevel.HIGH:
        ...

Thread-safe via per-session locks. Sessions expire after SESSION_TTL seconds.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Literal, Optional

# ── Config ────────────────────────────────────────────────────

SESSION_TTL: float = 3600.0          # seconds before idle session is evicted
MAX_TURNS_PER_SESSION: int = 200     # rolling window
MAX_SESSIONS: int = 10_000           # global cap (LRU eviction)
ESCALATION_WINDOW: int = 5           # turns to look back for escalation
SUSPICION_DECAY: float = 0.15        # per-turn decay of accumulated suspicion
VELOCITY_WINDOW: float = 10.0        # seconds for turn-velocity check
VELOCITY_THRESHOLD: int = 6          # turns within VELOCITY_WINDOW → suspicious
MANY_SHOT_THRESHOLD: int = 3         # repeated harmful-example pairs = many-shot attack


class ThreatLevel(IntEnum):
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Turn:
    role: Literal["system", "user", "assistant"]
    text: str
    timestamp: float = field(default_factory=time.monotonic)
    suspicious: bool = False
    signals: list[str] = field(default_factory=list)


@dataclass
class MultiTurnAnalysis:
    session_id: str
    threat_level: ThreatLevel
    score: float                      # 0.0–1.0
    signals: list[str] = field(default_factory=list)
    turn_count: int = 0
    window_turns: int = 0


# ── Pattern sets ─────────────────────────────────────────────

# Slow-escalation: innocent probes that build toward exploitation
_PROBE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(hypothetically|theoretically|imagine|pretend|suppose)\b", re.I),
    re.compile(r"\b(for a story|in fiction|role.?play|as a character)\b", re.I),
    re.compile(r"\b(just curious|purely academic|no harm|thought experiment)\b", re.I),
]

_ESCALATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(ignore|forget|disregard).{0,30}(instruction|rule|guideline|constraint|policy)\b", re.I),
    re.compile(r"\b(override|bypass|disable).{0,30}(safety|filter|restriction|guardrail)\b", re.I),
    re.compile(r"\b(now that you|since you|given that you).{0,50}(tell me|show me|give me)\b", re.I),
    re.compile(r"\b(actually|wait|instead).{0,30}(do|say|provide|generate)\b", re.I),
    re.compile(r"(DAN|jailbreak|developer mode|god mode|unrestricted mode)", re.I),
]

_CONTEXT_POISON_PATTERNS: list[re.Pattern[str]] = [
    # Attempts to rewrite earlier turns or claim the AI said something it didn't
    re.compile(r"\b(you (already|just|previously) (said|told|agreed|confirmed))\b", re.I),
    re.compile(r"\b(remember when you|earlier you|before you)\b", re.I),
    re.compile(r"\b(system (prompt|instruction) (says|tells|allows))\b", re.I),
]

_TOKEN_EXHAUST_PATTERNS: list[re.Pattern[str]] = [
    # Padding attacks to push safety rules out of context window
    re.compile(r"(.)\1{80,}"),            # Long repeating character runs
    re.compile(r"(\w{2,5}\s){50,}"),      # Word-spam padding
]

_GOAL_HIJACK_PATTERNS: list[re.Pattern[str]] = [
    # Indirect prompt injection via benign-looking content
    re.compile(r"<\|?(im_start|system|assistant|human)\|?>", re.I),
    re.compile(r"\[INST\]|\[/INST\]|<s>|</s>", re.I),
    re.compile(r"\{\{[^}]{0,200}\}\}", re.I),    # Template injection
    re.compile(r"(###|---)\s*(System|Assistant|Instruction)", re.I),
]

# Crescendo: progressively more harmful topic escalation
_CRESCENDO_HARM_LEVELS: list[tuple[int, re.Pattern[str]]] = [
    (1, re.compile(r"\b(explain|describe|tell me about)\b", re.I)),
    (2, re.compile(r"\b(how to|steps to|guide|tutorial|walkthrough)\b", re.I)),
    (3, re.compile(r"\b(detailed|specific|exact|precise|step.by.step)\b", re.I)),
    (4, re.compile(r"\b(without|bypass|avoid|evade).{0,30}(detection|filter|safety|law|rule)\b", re.I)),
]

# Many-shot jailbreaking: user provides many harmful Q&A examples
_MANY_SHOT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(human|user|h):\s*.+\n(assistant|ai|a):\s*.+", re.I | re.DOTALL),
    re.compile(r"Q:\s*.+\nA:\s*.+", re.I | re.DOTALL),
    re.compile(r"example \d+[:\.]?", re.I),
]

# Persona persistence: maintaining a jailbreak persona across turns
_PERSONA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(stay in character|don't break character|remain as|you are still|keep playing)\b", re.I),
    re.compile(r"\b(as (DAN|AIM|DUDE|STAN|BH|evil|uncensored|unfiltered))\b", re.I),
    re.compile(r"\b(your (true|real|inner|secret) (self|personality|mode))\b", re.I),
]

# Payload fragmentation: splitting a harmful request across multiple turns
_FRAGMENT_CONTINUATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^(continue|go on|and then|next step|part \d|step \d)", re.I),
    re.compile(r"\b(finish|complete|the rest of|remaining steps|keep going)\b", re.I),
]


# ── Session context ───────────────────────────────────────────

class SessionContext:
    """Per-session conversation history and threat accumulation."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.turns: list[Turn] = []
        self._lock = threading.Lock()
        self._last_access = time.monotonic()
        self._accumulated_score: float = 0.0

    def add_turn(
        self,
        role: Literal["system", "user", "assistant"],
        text: str,
    ) -> None:
        with self._lock:
            now = time.monotonic()
            self._last_access = now
            turn = Turn(role=role, text=text)
            signals: list[str] = []
            score = 0.0

            for pat in _PROBE_PATTERNS:
                if pat.search(text):
                    signals.append(f"probe:{pat.pattern[:30]}")
                    score += 0.1

            for pat in _ESCALATION_PATTERNS:
                if pat.search(text):
                    signals.append(f"escalation:{pat.pattern[:30]}")
                    score += 0.3

            for pat in _CONTEXT_POISON_PATTERNS:
                if pat.search(text):
                    signals.append(f"context_poison:{pat.pattern[:30]}")
                    score += 0.25

            for pat in _TOKEN_EXHAUST_PATTERNS:
                if pat.search(text):
                    signals.append("token_exhaust")
                    score += 0.2

            for pat in _GOAL_HIJACK_PATTERNS:
                if pat.search(text):
                    signals.append(f"goal_hijack:{pat.pattern[:30]}")
                    score += 0.35

            # Persona persistence
            for pat in _PERSONA_PATTERNS:
                if pat.search(text):
                    signals.append("persona_persistence")
                    score += 0.3
                    break

            # Payload fragmentation (only meaningful after ≥2 turns)
            if len(self.turns) >= 2:
                for pat in _FRAGMENT_CONTINUATION_PATTERNS:
                    if pat.search(text):
                        # Only flag if a previous turn was suspicious
                        if any(t.suspicious for t in self.turns[-3:]):
                            signals.append("payload_fragmentation")
                            score += 0.25
                        break

            # Many-shot: long text with multiple Q&A-style examples
            ms_hits = sum(1 for pat in _MANY_SHOT_PATTERNS if pat.search(text))
            if ms_hits >= 2:
                signals.append("many_shot_examples")
                score += 0.35

            # Turn velocity: many turns submitted very quickly (automation)
            recent_turns = [
                t for t in self.turns[-(VELOCITY_THRESHOLD + 1):]
                if (now - t.timestamp) <= VELOCITY_WINDOW
            ]
            if len(recent_turns) >= VELOCITY_THRESHOLD:
                signals.append("high_turn_velocity")
                score += 0.15

            turn.suspicious = score > 0
            turn.signals = signals

            # Decay then add
            self._accumulated_score = max(0.0, self._accumulated_score - SUSPICION_DECAY)
            self._accumulated_score = min(1.0, self._accumulated_score + score)

            self.turns.append(turn)
            if len(self.turns) > MAX_TURNS_PER_SESSION:
                self.turns.pop(0)

    def analyze(self) -> MultiTurnAnalysis:
        with self._lock:
            self._last_access = time.monotonic()
            score = self._accumulated_score
            signals: list[str] = []

            # Look at recent suspicious turns
            window = self.turns[-ESCALATION_WINDOW:]
            sus_count = sum(1 for t in window if t.suspicious)
            window_signals = [s for t in window for s in t.signals]
            signals.extend(dict.fromkeys(window_signals))  # deduplicate, preserve order

            # Slow-escalation bonus: probe followed by escalation
            if sus_count >= 2:
                probe_then_escalate = any(
                    "probe:" in t.signals for t in window
                ) and any(
                    "escalation:" in t.signals for t in window
                )
                if probe_then_escalate:
                    score = min(1.0, score + 0.25)
                    signals.append("slow_escalation_pattern")

            # Context poisoning across turns
            poison_count = sum(
                1 for t in self.turns if any("context_poison" in s for s in t.signals)
            )
            if poison_count >= 2:
                score = min(1.0, score + 0.2)
                signals.append("repeated_context_poisoning")

            # Long-session escalation: first half clean, second half suspicious
            if len(self.turns) >= 10:
                mid = len(self.turns) // 2
                early_sus = sum(1 for t in self.turns[:mid] if t.suspicious)
                late_sus = sum(1 for t in self.turns[mid:] if t.suspicious)
                if early_sus == 0 and late_sus >= 3:
                    score = min(1.0, score + 0.3)
                    signals.append("late_session_escalation")

            # Crescendo: increasing harm level across turns
            if len(self.turns) >= 4:
                harm_levels = []
                for t in self.turns[-6:]:
                    for lvl, pat in _CRESCENDO_HARM_LEVELS:
                        if pat.search(t.text):
                            harm_levels.append(lvl)
                            break
                if len(harm_levels) >= 3 and harm_levels == sorted(harm_levels) and harm_levels[-1] >= 3:
                    score = min(1.0, score + 0.35)
                    signals.append("crescendo_escalation")

            # Sustained persona persistence across session
            persona_turns = sum(
                1 for t in self.turns if any("persona_persistence" in s for s in t.signals)
            )
            if persona_turns >= 2:
                score = min(1.0, score + 0.2)
                signals.append("sustained_persona_attack")

            # Fragmentation chain: ≥3 continuation turns in a row
            frag_chain = 0
            for t in reversed(self.turns[-6:]):
                if any("payload_fragmentation" in s for s in t.signals):
                    frag_chain += 1
                else:
                    break
            if frag_chain >= 3:
                score = min(1.0, score + 0.3)
                signals.append("fragmentation_chain")

            if score >= 0.8:
                level = ThreatLevel.CRITICAL
            elif score >= 0.6:
                level = ThreatLevel.HIGH
            elif score >= 0.35:
                level = ThreatLevel.MEDIUM
            elif score >= 0.15:
                level = ThreatLevel.LOW
            else:
                level = ThreatLevel.CLEAN

            return MultiTurnAnalysis(
                session_id=self.session_id,
                threat_level=level,
                score=round(score, 4),
                signals=signals,
                turn_count=len(self.turns),
                window_turns=len(window),
            )

    @property
    def last_access(self) -> float:
        return self._last_access


# ── Global tracker ────────────────────────────────────────────

class MultiTurnTracker:
    """Global session registry with TTL eviction and LRU cap."""

    def __init__(
        self,
        ttl: float = SESSION_TTL,
        max_sessions: int = MAX_SESSIONS,
    ) -> None:
        self._sessions: dict[str, SessionContext] = {}
        self._lock = threading.Lock()
        self._ttl = ttl
        self._max_sessions = max_sessions

    def get_or_create(self, session_id: str) -> SessionContext:
        with self._lock:
            self._evict_expired()
            if session_id not in self._sessions:
                if len(self._sessions) >= self._max_sessions:
                    # Evict LRU
                    oldest = min(
                        self._sessions, key=lambda k: self._sessions[k].last_access
                    )
                    del self._sessions[oldest]
                self._sessions[session_id] = SessionContext(session_id)
            return self._sessions[session_id]

    def get(self, session_id: str) -> Optional[SessionContext]:
        with self._lock:
            return self._sessions.get(session_id)

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired = [
            k for k, v in self._sessions.items()
            if (now - v.last_access) > self._ttl
        ]
        for k in expired:
            del self._sessions[k]

    @property
    def active_sessions(self) -> int:
        with self._lock:
            return len(self._sessions)


# Module-level singleton (shared across requests in the same process)
_default_tracker = MultiTurnTracker()


def get_tracker() -> MultiTurnTracker:
    """Return the process-wide MultiTurnTracker singleton."""
    return _default_tracker
