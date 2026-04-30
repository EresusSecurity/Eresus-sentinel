"""
Session store for the deception guardrail.

Tracks cumulative risk scores and query history per session.
Supports in-memory (default) and optional Redis backend.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

_log = logging.getLogger("sentinel.deception.session")


class SessionStore:
    """Session store with optional Redis backend and TTL-based eviction."""

    SESSION_TTL = 86_400  # 24 hours

    def __init__(self, redis_url: Optional[str] = None):
        self._redis = None
        self._last_cleanup: float = 0.0
        if redis_url:
            try:
                import redis as _redis
                self._redis = _redis.from_url(redis_url, decode_responses=True)
                _log.info("Session store: Redis (%s)", redis_url)
            except Exception as exc:
                _log.warning("Redis unavailable (%s) — falling back to in-memory", exc)
        self._scores: dict[str, float] = {}
        self._history: dict[str, list] = {}
        self._timestamps: dict[str, float] = {}

    def add(self, session_id: str, score: float, entry: dict) -> float:
        """Add a score to a session and append a history entry. Returns cumulative score."""
        if not self._redis:
            self._timestamps[session_id] = time.time()
            self._maybe_cleanup()
        cumulative = self._get_score(session_id) + score
        self._set_score(session_id, cumulative)
        self._append_history(session_id, entry)
        return cumulative

    def get_score(self, session_id: str) -> float:
        return self._get_score(session_id)

    def get_history(self, session_id: str) -> list:
        return self._get_history(session_id)

    def reset(self, session_id: str) -> None:
        """Delete all data for a session."""
        if self._redis:
            self._redis.delete(f"deception:score:{session_id}", f"deception:history:{session_id}")
        else:
            self._scores.pop(session_id, None)
            self._history.pop(session_id, None)
            self._timestamps.pop(session_id, None)

    def flush_all(self) -> int:
        """Delete every session. Returns the count of sessions removed."""
        if self._redis:
            keys = list(self._redis.scan_iter("deception:score:*")) + list(self._redis.scan_iter("deception:history:*"))
            if keys:
                self._redis.delete(*keys)
            return len(keys) // 2
        count = len(self._scores)
        self._scores.clear()
        self._history.clear()
        self._timestamps.clear()
        return count

    def update_entry(self, session_id: str, query_id: str, extra: dict) -> None:
        """Merge *extra* fields into the history entry matching *query_id*."""
        history = self._get_history(session_id)
        for entry in reversed(history):
            if entry.get("query_id") == query_id:
                entry.update(extra)
                break
        self._save_history(session_id, history)

    # -- Internal -----------------------------------------------------------

    def _maybe_cleanup(self) -> None:
        """Evict in-memory sessions idle for longer than SESSION_TTL."""
        now = time.time()
        if now - self._last_cleanup < 3600:
            return
        self._last_cleanup = now
        expired = [
            sid for sid, ts in self._timestamps.items()
            if now - ts > self.SESSION_TTL
        ]
        for sid in expired:
            self._scores.pop(sid, None)
            self._history.pop(sid, None)
            self._timestamps.pop(sid, None)
        if expired:
            _log.debug("SessionStore: evicted %d expired sessions", len(expired))

    def _get_score(self, sid: str) -> float:
        if self._redis:
            v = self._redis.get(f"deception:score:{sid}")
            return float(v) if v else 0.0
        return self._scores.get(sid, 0.0)

    def _set_score(self, sid: str, score: float) -> None:
        if self._redis:
            self._redis.setex(f"deception:score:{sid}", self.SESSION_TTL, score)
        else:
            self._scores[sid] = score

    def _get_history(self, sid: str) -> list:
        if self._redis:
            raw = self._redis.get(f"deception:history:{sid}")
            return json.loads(raw) if raw else []
        return list(self._history.get(sid, []))

    def _append_history(self, sid: str, entry: dict) -> None:
        history = self._get_history(sid)
        history.append(entry)
        self._save_history(sid, history)

    def _save_history(self, sid: str, history: list) -> None:
        if self._redis:
            self._redis.setex(f"deception:history:{sid}", self.SESSION_TTL, json.dumps(history))
        else:
            self._history[sid] = history
