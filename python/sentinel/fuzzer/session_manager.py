"""Fuzzing session manager — persistent, resumable sessions with JSONL audit trail.

Provides:
  • **FuzzSession** — lifecycle management (create → log → close → resume).
  • **SessionSummary** — typed summary written as JSON at session close.
  • **SessionStore** — index of all sessions in a workspace directory; supports
    listing, filtering by date/status, and loading historical summaries.
  • **Compression** — optionally gzip-compresses the JSONL log on session close.
  • **Integrity check** — SHA-256 hash of the JSONL written to the summary so
    the log can be verified to be untampered.

Each log line is structured as::

    {
      "ts": 1714200000.123,
      "session": "abc...",
      "payload": "payload_name",
      "category": "prompt_injection",
      "detected": true,
      "bypass": false,
      "crash": false,
      "time_ms": 12.34,
      "scanner": "optional_scanner_name",
      ...custom fields
    }

Usage::

    session = FuzzSession("/tmp/fuzz_output", config={"samples": 500})
    session.log_result("evil_payload", "rce", detected=False, is_bypass=True, ...)
    summary = session.close()
    print(summary.reduction_pct)  # bypass rate

    # Resume a previous session
    resumed = FuzzSession.resume("/tmp/fuzz_output", session_id=summary.session_id)
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Session summary model
# ---------------------------------------------------------------------------

@dataclass
class SessionSummary:
    """Immutable record written when a session is closed."""
    session_id: str
    started_at: float
    ended_at: float = 0.0
    total_payloads: int = 0
    detected: int = 0
    bypasses: int = 0
    crashes: int = 0
    tpr: float = 0.0
    fpr: float = 0.0
    f1: float = 0.0
    mcc: float = 0.0
    bypass_rate: float = 0.0
    config: dict = field(default_factory=dict)
    log_sha256: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        end = self.ended_at or time.time()
        return max(0.0, end - self.started_at)

    @property
    def reduction_pct(self) -> float:
        """Bypass rate as a percentage."""
        return round(self.bypass_rate * 100, 2)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["duration_s"] = round(self.duration_s, 2)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SessionSummary":
        valid = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**valid)


# ---------------------------------------------------------------------------
# FuzzSession
# ---------------------------------------------------------------------------

class FuzzSession:
    """Manages a single fuzzing session with a JSONL audit trail.

    Args:
        output_dir:  Directory where JSONL log and summary JSON are stored.
        session_id:  Provide an existing ID to resume (appends to existing log).
        config:      Arbitrary config dict stored in the summary.
        compress:    If True, gzip the JSONL on close() (saves ~85% disk space).
        tags:        Optional list of labels (e.g. ["nightly", "prompt-injection"]).
    """

    def __init__(
        self,
        output_dir: str | Path,
        session_id: Optional[str] = None,
        config: Optional[dict] = None,
        compress: bool = False,
        tags: Optional[list[str]] = None,
    ):
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._session_id = session_id or str(uuid.uuid4())
        self._started_at = time.time()
        self._config = config or {}
        self._compress = compress
        self._tags = tags or []
        self._log_path = self._dir / f"session_{self._session_id}.jsonl"
        self._summary_path = self._dir / f"session_{self._session_id}_summary.json"
        self._closed = False

        self._summary = SessionSummary(
            session_id=self._session_id,
            started_at=self._started_at,
            config=self._config,
            tags=self._tags,
        )

    # ── Properties ───────────────────────────────────────────────────

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def log_path(self) -> Path:
        return self._log_path

    @property
    def is_closed(self) -> bool:
        return self._closed

    # ── Logging ──────────────────────────────────────────────────────

    def log_result(
        self,
        payload_name: str,
        category: str,
        detected: bool,
        is_bypass: bool,
        is_crash: bool,
        time_ms: float,
        scanner: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> None:
        """Append one probe result to the JSONL log.

        This is the hot path — it opens/closes the file each call to guarantee
        durability in the face of interrupts (no buffering).
        """
        if self._closed:
            raise RuntimeError("Cannot log to a closed FuzzSession.")
        record: dict = {
            "ts": round(time.time(), 6),
            "session": self._session_id,
            "payload": payload_name,
            "category": category,
            "detected": detected,
            "bypass": is_bypass,
            "crash": is_crash,
            "time_ms": round(time_ms, 3),
        }
        if scanner:
            record["scanner"] = scanner
        if extra:
            record.update(extra)

        with self._log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

        # Maintain running counters
        self._summary.total_payloads += 1
        if detected:
            self._summary.detected += 1
        if is_bypass:
            self._summary.bypasses += 1
        if is_crash:
            self._summary.crashes += 1

    def log_batch(self, results: list[dict]) -> None:
        """Batch-append multiple results in a single file open (lower overhead)."""
        if self._closed:
            raise RuntimeError("Cannot log to a closed FuzzSession.")
        with self._log_path.open("a", encoding="utf-8") as fh:
            for r in results:
                fh.write(json.dumps(r, default=str) + "\n")
                self._summary.total_payloads += 1
                if r.get("bypass"):
                    self._summary.bypasses += 1
                if r.get("crash"):
                    self._summary.crashes += 1
                if r.get("detected"):
                    self._summary.detected += 1

    # ── Close / finalise ─────────────────────────────────────────────

    def close(self, score: Optional[object] = None) -> SessionSummary:
        """Finalise the session: compute digest, write summary, optionally compress.

        Args:
            score: Optional ``DetectionScore`` object; TPR/FPR/F1/MCC are read
                   via getattr so any compatible score object works.

        Returns:
            A completed ``SessionSummary``.
        """
        if self._closed:
            return self._summary

        self._summary.ended_at = time.time()

        if score is not None:
            self._summary.tpr = round(getattr(score, "tpr", 0.0), 6)
            self._summary.fpr = round(getattr(score, "fpr", 0.0), 6)
            self._summary.f1 = round(getattr(score, "f1", 0.0), 6)
            self._summary.mcc = round(getattr(score, "mcc", 0.0), 6)

        if self._summary.total_payloads > 0:
            self._summary.bypass_rate = round(
                self._summary.bypasses / self._summary.total_payloads, 6
            )

        # Compute log integrity hash
        if self._log_path.exists():
            sha = hashlib.sha256(self._log_path.read_bytes()).hexdigest()
            self._summary.log_sha256 = sha

        self._summary_path.write_text(
            json.dumps(self._summary.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )

        if self._compress and self._log_path.exists():
            compressed = self._log_path.with_suffix(".jsonl.gz")
            with self._log_path.open("rb") as src, gzip.open(compressed, "wb") as dst:
                shutil.copyfileobj(src, dst)
            self._log_path.unlink()
            logger.info("Compressed log → %s", compressed)

        self._closed = True
        logger.info(
            "Session %s closed | payloads=%d bypasses=%d crashes=%d duration=%.1fs",
            self._session_id,
            self._summary.total_payloads,
            self._summary.bypasses,
            self._summary.crashes,
            self._summary.duration_s,
        )
        return self._summary

    # ── Iteration ────────────────────────────────────────────────────

    def iter_log(self) -> Iterator[dict]:
        """Iterate over parsed JSONL log records (reads from disk)."""
        if not self._log_path.exists():
            return
        with self._log_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("Malformed JSONL line: %r", line[:80])

    def verify_integrity(self) -> bool:
        """Verify JSONL log matches the SHA-256 stored in the summary."""
        if not self._summary.log_sha256 or not self._log_path.exists():
            return False
        actual = hashlib.sha256(self._log_path.read_bytes()).hexdigest()
        return actual == self._summary.log_sha256

    # ── Class methods ────────────────────────────────────────────────

    @classmethod
    def resume(
        cls,
        output_dir: str | Path,
        session_id: str,
        config: Optional[dict] = None,
    ) -> "FuzzSession":
        """Resume an existing session — appends to its JSONL log.

        The started_at timestamp is preserved from the original session.
        """
        d = Path(output_dir)
        summary_path = d / f"session_{session_id}_summary.json"
        started_at = time.time()
        existing_config = config or {}

        if summary_path.exists():
            data = json.loads(summary_path.read_text(encoding="utf-8"))
            started_at = data.get("started_at", started_at)
            existing_config = data.get("config", existing_config)

        instance = cls(output_dir=d, session_id=session_id, config=existing_config)
        instance._started_at = started_at
        instance._summary.started_at = started_at
        # Rebuild counters from existing JSONL
        log_path = d / f"session_{session_id}.jsonl"
        if log_path.exists():
            for rec in instance.iter_log():
                instance._summary.total_payloads += 1
                if rec.get("bypass"):
                    instance._summary.bypasses += 1
                if rec.get("crash"):
                    instance._summary.crashes += 1
                if rec.get("detected"):
                    instance._summary.detected += 1
        return instance

    @classmethod
    def load_summary(cls, summary_path: str | Path) -> Optional[SessionSummary]:
        """Load a completed SessionSummary from its JSON file."""
        p = Path(summary_path)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return SessionSummary.from_dict(data)
        except Exception as exc:
            logger.error("Failed to load summary %s: %s", p, exc)
            return None


# ---------------------------------------------------------------------------
# SessionStore — workspace-level index
# ---------------------------------------------------------------------------

class SessionStore:
    """Index of all sessions stored under a given directory.

    Scans for ``*_summary.json`` files and provides filtering / listing helpers.

    Example::

        store = SessionStore("/tmp/fuzz_output")
        recent = store.recent(n=10)
        print(store.total_bypasses())
    """

    def __init__(self, directory: str | Path):
        self._dir = Path(directory)
        self._cache: Optional[list[SessionSummary]] = None

    def _load(self, refresh: bool = False) -> list[SessionSummary]:
        if self._cache is not None and not refresh:
            return self._cache
        summaries = []
        for p in sorted(self._dir.glob("*_summary.json"), reverse=True):
            s = FuzzSession.load_summary(p)
            if s:
                summaries.append(s)
        self._cache = summaries
        return summaries

    def all(self) -> list[SessionSummary]:
        return self._load(refresh=True)

    def recent(self, n: int = 20) -> list[SessionSummary]:
        return sorted(self._load(), key=lambda s: s.started_at, reverse=True)[:n]

    def by_tag(self, tag: str) -> list[SessionSummary]:
        return [s for s in self._load() if tag in s.tags]

    def total_bypasses(self) -> int:
        return sum(s.bypasses for s in self._load())

    def total_payloads(self) -> int:
        return sum(s.total_payloads for s in self._load())

    def aggregate_stats(self) -> dict:
        sessions = self._load()
        n = len(sessions)
        return {
            "sessions": n,
            "total_payloads": self.total_payloads(),
            "total_bypasses": self.total_bypasses(),
            "avg_bypass_rate": (sum(s.bypass_rate for s in sessions) / n) if n else 0.0,
            "avg_tpr": (sum(s.tpr for s in sessions) / n) if n else 0.0,
        }

