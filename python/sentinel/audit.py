"""
Eresus Sentinel — Structured Audit Logger.

Append-only JSONL audit trail for every scan operation.

Features:
  - JSONL format for easy log aggregation (ELK, Loki, CloudWatch)
  - Per-scan structured records (timestamp, scanner, action, risk, latency)
  - GDPR/SOC2 compliance fields (data_subject_id, retention_days)
  - OpenTelemetry span context hooks
  - Configurable output: file, stdout, callback
  - Async-safe with threading lock
  - Auto-rotation by size or date
  - Redaction of sensitive fields before logging

Usage:
    from sentinel.audit import AuditLogger
    audit = AuditLogger(path="audit.jsonl")
    audit.log_scan(scanner="toxicity", action="block", risk=0.95, ...)
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class AuditRecord:
    """Single audit log entry."""
    # Identity
    record_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Scan info
    scanner: str = ""
    scanner_type: str = ""            # input | output
    action: str = ""                  # pass | block | warn | redact
    risk_score: float = 0.0
    finding_count: int = 0
    latency_ms: float = 0.0

    # Context
    prompt_hash: str = ""             # SHA-256 first 16 chars (no raw data)
    output_length: int = 0
    model: str = ""
    session_id: str = ""
    user_id: str = ""

    # Compliance
    data_subject_id: str = ""         # GDPR data subject reference
    retention_days: int = 90
    classification: str = ""          # public | internal | confidential | restricted

    # Findings summary (no raw text, only metadata)
    finding_severities: list[str] = field(default_factory=list)
    finding_rule_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # Tracing
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""

    # Extra
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary, stripping empty fields."""
        d = asdict(self)
        return {k: v for k, v in d.items() if v or v == 0}

    def to_json(self) -> str:
        """Serialize to single-line JSON."""
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)


class AuditLogger:
    """
    Append-only structured audit logger.

    Every scan result is logged as a JSONL record for compliance
    and observability.

    Usage:
        audit = AuditLogger(path="logs/sentinel_audit.jsonl")

        # Manual logging
        audit.log_scan(scanner="toxicity", action="block", risk_score=0.95)

        # From ScanResult
        audit.log_result("toxicity", "output", scan_result, latency_ms=12.5)
    """

    def __init__(
        self,
        path: str | Path | None = None,
        callback: Callable[[AuditRecord], None] | None = None,
        stdout: bool = False,
        max_size_mb: int = 100,
        retention_days: int = 90,
        redact_fields: list[str] | None = None,
    ):
        self._path = Path(path) if path else None
        self._callback = callback
        self._stdout = stdout
        self._max_size_bytes = max_size_mb * 1024 * 1024
        self._retention_days = retention_days
        self._redact_fields = set(redact_fields or [])
        self._lock = threading.Lock()
        self._count = 0

        # Ensure parent dir exists
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def log_scan(
        self,
        scanner: str,
        action: str,
        risk_score: float = 0.0,
        scanner_type: str = "output",
        finding_count: int = 0,
        latency_ms: float = 0.0,
        **kwargs,
    ) -> AuditRecord:
        """Log a scan event."""
        record = AuditRecord(
            scanner=scanner,
            scanner_type=scanner_type,
            action=action,
            risk_score=risk_score,
            finding_count=finding_count,
            latency_ms=latency_ms,
            retention_days=self._retention_days,
            **kwargs,
        )
        self._emit(record)
        return record

    def log_result(
        self,
        scanner_name: str,
        scanner_type: str,
        result,  # ScanResult
        latency_ms: float = 0.0,
        session_id: str = "",
        user_id: str = "",
        model: str = "",
        prompt_hash: str = "",
    ) -> AuditRecord:
        """Log from a ScanResult object."""
        record = AuditRecord(
            scanner=scanner_name,
            scanner_type=scanner_type,
            action=result.action.value if hasattr(result.action, "value") else str(result.action),
            risk_score=result.risk_score,
            finding_count=len(result.findings),
            latency_ms=latency_ms,
            session_id=session_id,
            user_id=user_id,
            model=model,
            prompt_hash=prompt_hash,
            finding_severities=[
                f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                for f in result.findings
            ],
            finding_rule_ids=[f.rule_id for f in result.findings if hasattr(f, "rule_id")],
            retention_days=self._retention_days,
            metadata=getattr(result, "metadata", {}),
        )
        self._emit(record)
        return record

    def log_pipeline(
        self,
        pipeline_type: str,
        result,
        scanners_run: list[str],
        total_latency_ms: float,
        **kwargs,
    ) -> AuditRecord:
        """Log an entire pipeline execution."""
        record = AuditRecord(
            scanner=f"pipeline:{pipeline_type}",
            scanner_type=pipeline_type,
            action=result.action.value if hasattr(result.action, "value") else str(result.action),
            risk_score=result.risk_score,
            finding_count=len(result.findings),
            latency_ms=total_latency_ms,
            tags=scanners_run,
            retention_days=self._retention_days,
            **kwargs,
        )
        self._emit(record)
        return record

    @property
    def count(self) -> int:
        """Number of records emitted."""
        return self._count

    # ── Private ───────────────────────────────────────────────────

    def _emit(self, record: AuditRecord) -> None:
        """Write record to configured outputs."""
        # Redact sensitive fields
        if self._redact_fields:
            for f in self._redact_fields:
                if hasattr(record, f):
                    setattr(record, f, "[REDACTED]")

        line = record.to_json()

        with self._lock:
            # File output
            if self._path:
                self._check_rotation()
                with open(self._path, "a", encoding="utf-8") as fp:
                    fp.write(line + "\n")

            # Stdout
            if self._stdout:
                print(f"[AUDIT] {line}")

            # Callback
            if self._callback:
                try:
                    self._callback(record)
                except Exception as e:
                    logger.error("Audit callback failed: %s", e)

            self._count += 1

        # Async DB write (fire-and-forget from sync context)
        self._emit_to_db(record)

    def _emit_to_db(self, record: AuditRecord) -> None:
        """Best-effort write to PostgreSQL if configured."""
        try:
            from sentinel.db import is_db_enabled
            if not is_db_enabled():
                return
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._async_db_write(record))
            except RuntimeError:
                # No running loop — skip DB write
                pass
        except ImportError:
            pass

    async def _async_db_write(self, record: AuditRecord) -> None:
        """Write audit record to PostgreSQL."""
        try:
            from sentinel.db import AuditLog, get_db
            async with get_db() as db:
                db.add(AuditLog(
                    record_id=record.record_id,
                    scanner=record.scanner,
                    scanner_type=record.scanner_type,
                    action=record.action,
                    risk_score=record.risk_score,
                    finding_count=record.finding_count,
                    latency_ms=record.latency_ms,
                    prompt_hash=record.prompt_hash,
                    output_length=record.output_length,
                    model=record.model,
                    session_id=record.session_id,
                    user_id=record.user_id,
                    data_subject_id=record.data_subject_id,
                    retention_days=record.retention_days,
                    classification=record.classification,
                    finding_severities=record.finding_severities,
                    finding_rule_ids=record.finding_rule_ids,
                    tags=record.tags,
                    trace_id=record.trace_id,
                    span_id=record.span_id,
                    extra_data=record.metadata,
                ))
        except Exception as e:
            logger.debug("Audit DB write failed (non-critical): %s", e)

    def _check_rotation(self) -> None:
        """Rotate log file if it exceeds max size."""
        if self._path and self._path.exists():
            if self._path.stat().st_size >= self._max_size_bytes:
                rotated = self._path.with_suffix(
                    f".{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.jsonl"
                )
                self._path.rename(rotated)
                logger.info("Rotated audit log to %s", rotated)

    # ── Query & Analysis ──────────────────────────────────────────

    def query_records(
        self,
        action: str | None = None,
        scanner: str | None = None,
        min_risk: float | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Query audit records from the log file.

        Args:
            action: Filter by action (block, warn, redact, pass).
            scanner: Filter by scanner name (prefix match).
            min_risk: Filter by minimum risk score.
            since: ISO timestamp to filter records after.
            limit: Maximum number of records to return.

        Returns:
            List of matching AuditRecord dicts (newest first).
        """
        if not self._path or not self._path.exists():
            return []

        results = []
        with open(self._path, "r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Apply filters
                if action and record.get("action") != action:
                    continue
                if scanner and not record.get("scanner", "").startswith(scanner):
                    continue
                if min_risk is not None and record.get("risk_score", 0) < min_risk:
                    continue
                if since and record.get("timestamp", "") < since:
                    continue

                results.append(record)

        # Newest first
        results.reverse()
        return results[:limit]

    def summary(self) -> dict:
        """
        Generate summary statistics from the audit log.

        Returns:
            Dict with action counts, risk distribution, scanner stats, etc.
        """
        if not self._path or not self._path.exists():
            return {"total_records": self._count, "from_memory": True}

        action_counts: dict[str, int] = {}
        scanner_counts: dict[str, int] = {}
        risk_sum = 0.0
        risk_max = 0.0
        total = 0
        block_count = 0

        with open(self._path, "r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                total += 1
                action = record.get("action", "unknown")
                action_counts[action] = action_counts.get(action, 0) + 1
                if action == "block":
                    block_count += 1

                scanner = record.get("scanner", "unknown")
                scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

                risk = record.get("risk_score", 0.0)
                risk_sum += risk
                risk_max = max(risk_max, risk)

        return {
            "total_records": total,
            "action_counts": action_counts,
            "scanner_counts": scanner_counts,
            "block_rate": round(block_count / total, 4) if total > 0 else 0,
            "avg_risk": round(risk_sum / total, 4) if total > 0 else 0,
            "max_risk": round(risk_max, 4),
        }

    def export_csv(self, output_path: str | Path) -> int:
        """
        Export audit records to CSV for compliance/reporting.

        Args:
            output_path: Where to write the CSV.

        Returns:
            Number of records exported.
        """
        import csv

        if not self._path or not self._path.exists():
            return 0

        fieldnames = [
            "timestamp", "scanner", "scanner_type", "action",
            "risk_score", "finding_count", "latency_ms",
            "session_id", "user_id", "model", "record_id",
        ]

        count = 0
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with open(output, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()

            with open(self._path, "r", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        # Sanitize values to prevent CSV formula injection
                        sanitized = {}
                        for k, v in record.items():
                            if isinstance(v, str) and v and v[0] in ('=', '+', '-', '@', '\t', '\r'):
                                sanitized[k] = "'" + v
                            else:
                                sanitized[k] = v
                        writer.writerow(sanitized)
                        count += 1
                    except (json.JSONDecodeError, Exception):
                        continue

        return count

    def cleanup(self, older_than_days: int | None = None) -> int:
        """
        Remove rotated log files older than the given age.

        Args:
            older_than_days: Delete rotated logs older than this. Defaults to retention_days.

        Returns:
            Number of files removed.
        """
        if not self._path:
            return 0

        max_age = older_than_days or self._retention_days
        cutoff = time.time() - (max_age * 86400)
        parent = self._path.parent
        removed = 0

        for f in parent.glob(f"{self._path.stem}.*"):
            if f == self._path:
                continue
            if f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
                logger.info("Removed old audit log: %s", f)

        return removed

