"""SQLite audit store for durable Sentinel event history."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

AUDIT_STORE_SCHEMA_VERSION = "audit.sqlite.v1"
_SENSITIVE_KEYS = ("authorization", "api_key", "apikey", "password", "secret", "token", "private_key")


@dataclass(frozen=True)
class AuditEvent:
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = "scan"
    target: str = ""
    verdict: str = "unknown"
    evidence_hash: str = ""
    session_id: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def as_row(self) -> tuple[str, str, str, str, str, str, str, str]:
        redacted = redact_payload(self.payload)
        evidence = self.evidence_hash or _hash_json(redacted)
        return (
            self.event_id,
            self.timestamp,
            self.event_type,
            self.target,
            self.verdict,
            evidence,
            self.session_id,
            json.dumps(redacted, sort_keys=True, default=str),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "target": self.target,
            "verdict": self.verdict,
            "evidence_hash": self.evidence_hash,
            "session_id": self.session_id,
            "payload": redact_payload(self.payload),
        }


class AuditStore:
    """Small SQLite audit store with secret-safe payload persistence."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or os.environ.get("SENTINEL_AUDIT_DB", Path.home() / ".sentinel" / "audit.db"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    verdict TEXT NOT NULL DEFAULT 'unknown',
                    evidence_hash TEXT NOT NULL DEFAULT '',
                    session_id TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_verdict ON audit_events(verdict)")

    def record(
        self,
        *,
        event_type: str,
        target: str = "",
        verdict: str = "unknown",
        session_id: str = "",
        payload: dict[str, Any] | None = None,
        evidence_hash: str = "",
    ) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            target=target,
            verdict=verdict,
            session_id=session_id,
            payload=payload or {},
            evidence_hash=evidence_hash,
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events
                (event_id, timestamp, event_type, target, verdict, evidence_hash, session_id, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                event.as_row(),
            )
        return event

    def query(
        self,
        *,
        since: str | None = None,
        event_type: str | None = None,
        verdict: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        since_dt = parse_since(since)
        if since_dt:
            clauses.append("timestamp >= ?")
            params.append(since_dt.isoformat())
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if verdict:
            clauses.append("verdict = ?")
            params.append(verdict)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(max(1, min(limit, 10_000)))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_events{where} ORDER BY timestamp DESC LIMIT ?",
                params,
            ).fetchall()
        return [_row_to_event(row) for row in rows]

    def export_jsonl(self, path: str | Path, *, since: str | None = None) -> int:
        events = self.query(since=since, limit=10_000)
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + ("\n" if events else ""), encoding="utf-8")
        return len(events)

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            by_type = {
                row["event_type"]: row["count"]
                for row in conn.execute("SELECT event_type, COUNT(*) AS count FROM audit_events GROUP BY event_type")
            }
            by_verdict = {
                row["verdict"]: row["count"]
                for row in conn.execute("SELECT verdict, COUNT(*) AS count FROM audit_events GROUP BY verdict")
            }
        return {
            "schema_version": AUDIT_STORE_SCHEMA_VERSION,
            "path": str(self.path),
            "total_events": total,
            "by_type": by_type,
            "by_verdict": by_verdict,
        }


def parse_since(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().lower()
    now = datetime.now(timezone.utc)
    units = {"m": "minutes", "h": "hours", "d": "days"}
    for suffix, attr in units.items():
        if text.endswith(suffix):
            amount = int(float(text[:-1]))
            return now - timedelta(**{attr: amount})
    try:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def redact_payload(value: Any, key: str = "") -> Any:
    if any(token in key.lower() for token in _SENSITIVE_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_payload(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_payload(item, key) for item in value]
    return value


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    payload = json.loads(row["payload_json"] or "{}")
    return {
        "event_id": row["event_id"],
        "timestamp": row["timestamp"],
        "event_type": row["event_type"],
        "target": row["target"],
        "verdict": row["verdict"],
        "evidence_hash": row["evidence_hash"],
        "session_id": row["session_id"],
        "payload": payload,
    }


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
