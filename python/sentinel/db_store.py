"""
Eresus Sentinel — Database-backed Stats & History Store.

Drop-in replacement for the in-memory _StatsStore when PostgreSQL is enabled.
Falls back to in-memory when DATABASE_URL is not set.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class DBStatsStore:
    """Async database-backed store for scan stats, history, and timeline."""

    def __init__(self):
        self.instance_id = uuid.uuid4().hex[:16]

    async def record_scan(
        self,
        scan_type: str,
        action: str,
        findings: list[dict],
        latency_ms: float,
        prompt: str = "",
        user_id: str = "",
        session_id: str = "",
        **extra,
    ) -> None:
        from sqlalchemy import update

        from sentinel.db import ScanHistory, ScanStats, TimelineEntry, get_db

        ts = datetime.now(timezone.utc)

        async with get_db() as db:
            # Insert scan history
            db.add(ScanHistory(
                scan_id=uuid.uuid4().hex[:12],
                timestamp=ts,
                scan_type=scan_type,
                prompt_preview=prompt[:200],
                action=action,
                risk_score=extra.get("risk_score", 0.0),
                finding_count=len(findings),
                findings=findings[:20],
                latency_ms=latency_ms,
                user_id=user_id,
                session_id=session_id,
            ))

            # Insert timeline entry
            db.add(TimelineEntry(
                timestamp=ts,
                findings=len(findings),
                latency=latency_ms,
            ))

            # Update aggregate stats atomically
            sev_increments = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in findings:
                sev = f.get("severity", "INFO").upper()
                if sev in sev_increments:
                    sev_increments[sev] += 1

            is_blocked = action.upper() == "BLOCK"
            await db.execute(
                update(ScanStats).where(ScanStats.id == 1).values(
                    total_scans=ScanStats.total_scans + 1,
                    total_findings=ScanStats.total_findings + len(findings),
                    blocked=ScanStats.blocked + (1 if is_blocked else 0),
                    clean=ScanStats.clean + (0 if is_blocked else 1),
                    severity_critical=ScanStats.severity_critical + sev_increments["CRITICAL"],
                    severity_high=ScanStats.severity_high + sev_increments["HIGH"],
                    severity_medium=ScanStats.severity_medium + sev_increments["MEDIUM"],
                    severity_low=ScanStats.severity_low + sev_increments["LOW"],
                    severity_info=ScanStats.severity_info + sev_increments["INFO"],
                )
            )

    async def record_artifact(
        self,
        filename: str,
        findings: list[dict],
        latency_ms: float,
        **extra,
    ) -> None:
        from sqlalchemy import update

        from sentinel.db import ArtifactHistory, ScanStats, get_db

        ts = datetime.now(timezone.utc)

        max_sev = "CLEAN"
        sev_increments = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s = f.get("severity", "").upper()
            if s in sev_increments:
                sev_increments[s] += 1
            if s == "CRITICAL":
                max_sev = "CRITICAL"
            elif s == "HIGH" and max_sev != "CRITICAL":
                max_sev = "WARNING"

        async with get_db() as db:
            db.add(ArtifactHistory(
                artifact_id=uuid.uuid4().hex[:12],
                timestamp=ts,
                filename=filename,
                size=extra.get("size", 0),
                finding_count=len(findings),
                findings=findings[:20],
                latency_ms=latency_ms,
                status=max_sev,
                sha256=extra.get("sha256", ""),
            ))

            await db.execute(
                update(ScanStats).where(ScanStats.id == 1).values(
                    artifacts_scanned=ScanStats.artifacts_scanned + 1,
                    artifact_findings=ScanStats.artifact_findings + len(findings),
                    severity_critical=ScanStats.severity_critical + sev_increments["CRITICAL"],
                    severity_high=ScanStats.severity_high + sev_increments["HIGH"],
                    severity_medium=ScanStats.severity_medium + sev_increments["MEDIUM"],
                    severity_low=ScanStats.severity_low + sev_increments["LOW"],
                    severity_info=ScanStats.severity_info + sev_increments["INFO"],
                )
            )

    async def get_stats(self) -> dict[str, Any]:
        from sqlalchemy import desc, select

        from sentinel.db import ScanStats, TimelineEntry, get_db

        async with get_db() as db:
            # Stats row
            result = await db.execute(select(ScanStats).where(ScanStats.id == 1))
            row = result.scalar_one()

            # Recent timeline (last 100)
            tl_result = await db.execute(
                select(TimelineEntry).order_by(desc(TimelineEntry.id)).limit(100)
            )
            timeline = [
                {
                    "ts": e.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if e.timestamp else "",
                    "findings": e.findings,
                    "latency": e.latency,
                }
                for e in reversed(tl_result.scalars().all())
            ]

            return {
                "total_scans": row.total_scans,
                "total_findings": row.total_findings,
                "blocked": row.blocked,
                "clean": row.clean,
                "severity": {
                    "CRITICAL": row.severity_critical,
                    "HIGH": row.severity_high,
                    "MEDIUM": row.severity_medium,
                    "LOW": row.severity_low,
                    "INFO": row.severity_info,
                },
                "timeline": timeline,
                "artifacts_scanned": row.artifacts_scanned,
                "artifact_findings": row.artifact_findings,
            }

    async def get_history(self) -> dict[str, Any]:
        from sqlalchemy import desc, select

        from sentinel.db import ArtifactHistory, ScanHistory, get_db

        async with get_db() as db:
            # Recent scans (last 50)
            scan_result = await db.execute(
                select(ScanHistory).order_by(desc(ScanHistory.id)).limit(50)
            )
            scans = [
                {
                    "id": s.scan_id,
                    "timestamp": s.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if s.timestamp else "",
                    "type": s.scan_type,
                    "prompt": s.prompt_preview,
                    "action": s.action,
                    "risk_score": s.risk_score,
                    "finding_count": s.finding_count,
                    "findings": s.findings or [],
                    "latency_ms": s.latency_ms,
                }
                for s in scan_result.scalars().all()
            ]

            # Recent artifacts (last 50)
            art_result = await db.execute(
                select(ArtifactHistory).order_by(desc(ArtifactHistory.id)).limit(50)
            )
            artifacts = [
                {
                    "id": a.artifact_id,
                    "timestamp": a.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if a.timestamp else "",
                    "filename": a.filename,
                    "size": a.size,
                    "finding_count": a.finding_count,
                    "findings": a.findings or [],
                    "latency_ms": a.latency_ms,
                    "status": a.status,
                    "sha256": a.sha256,
                }
                for a in art_result.scalars().all()
            ]

            return {"scans": scans, "artifacts": artifacts}
