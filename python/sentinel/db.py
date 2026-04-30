"""
Eresus Sentinel — PostgreSQL Database Layer.

Async SQLAlchemy + asyncpg backed persistence for scan history,
audit logs, auth tokens, stats, and vault entries.

Environment:
    DATABASE_URL  — PostgreSQL connection string
                    Default: postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel

Usage:
    from sentinel.db import get_db, init_db

    # On app startup
    await init_db()

    # In request handlers
    async with get_db() as db:
        await db.execute(...)
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)

# ── Connection ────────────────────────────────────────────────────

# SECURITY: no hardcoded default credentials — require explicit DATABASE_URL
DATABASE_URL = os.environ.get("DATABASE_URL", "")

_engine = None
_session_factory = None


class Base(DeclarativeBase):
    pass


# ── Models ────────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="admin")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AuthToken(Base):
    __tablename__ = "auth_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(255), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(32), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    scan_type = Column(String(50), nullable=False, index=True)  # input, output, conversation, etc.
    prompt_preview = Column(String(200), default="")
    action = Column(String(20), nullable=False)  # pass, block, warn
    risk_score = Column(Float, default=0.0)
    finding_count = Column(Integer, default=0)
    findings = Column(JSONB, default=list)
    latency_ms = Column(Float, default=0.0)
    user_id = Column(String(255), default="")
    session_id = Column(String(255), default="")


class ArtifactHistory(Base):
    __tablename__ = "artifact_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    artifact_id = Column(String(32), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    filename = Column(String(1024), nullable=False)
    size = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    findings = Column(JSONB, default=list)
    latency_ms = Column(Float, default=0.0)
    status = Column(String(20), default="CLEAN")  # CLEAN, WARNING, CRITICAL
    sha256 = Column(String(64), default="")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    record_id = Column(String(32), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    scanner = Column(String(100), nullable=False)
    scanner_type = Column(String(20), default="")
    action = Column(String(20), nullable=False)
    risk_score = Column(Float, default=0.0)
    finding_count = Column(Integer, default=0)
    latency_ms = Column(Float, default=0.0)
    prompt_hash = Column(String(64), default="")
    output_length = Column(Integer, default=0)
    model = Column(String(255), default="")
    session_id = Column(String(255), default="")
    user_id = Column(String(255), default="")
    data_subject_id = Column(String(255), default="")
    retention_days = Column(Integer, default=90)
    classification = Column(String(50), default="")
    finding_severities = Column(JSONB, default=list)
    finding_rule_ids = Column(JSONB, default=list)
    tags = Column(JSONB, default=list)
    trace_id = Column(String(64), default="")
    span_id = Column(String(32), default="")
    extra_data = Column("metadata", JSONB, default=dict)


class ScanStats(Base):
    """Persistent aggregate stats — single row, updated atomically."""
    __tablename__ = "scan_stats"

    id = Column(Integer, primary_key=True, default=1)
    total_scans = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    blocked = Column(Integer, default=0)
    clean = Column(Integer, default=0)
    artifacts_scanned = Column(Integer, default=0)
    artifact_findings = Column(Integer, default=0)
    severity_critical = Column(Integer, default=0)
    severity_high = Column(Integer, default=0)
    severity_medium = Column(Integer, default=0)
    severity_low = Column(Integer, default=0)
    severity_info = Column(Integer, default=0)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class TimelineEntry(Base):
    __tablename__ = "timeline"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    findings = Column(Integer, default=0)
    latency = Column(Float, default=0.0)


class VaultEntry(Base):
    __tablename__ = "vault_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    placeholder = Column(String(255), unique=True, nullable=False, index=True)
    original_encrypted = Column(Text, nullable=False)  # Fernet-encrypted or raw
    category = Column(String(50), nullable=False)  # PERSON, EMAIL, SSN, API_KEY, etc.
    original_hash = Column(String(64), nullable=False, index=True)  # SHA-256 for reverse lookup
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    extra_data = Column("metadata", JSONB, default=dict)


# ── Engine & Session ──────────────────────────────────────────────


async def init_db(url: str | None = None) -> None:
    """Initialize engine, create tables if they don't exist."""
    global _engine, _session_factory

    db_url = url or DATABASE_URL
    logger.info("Connecting to PostgreSQL: %s", db_url.split("@")[-1] if "@" in db_url else "***")

    _engine = create_async_engine(
        db_url,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=300,
        echo=os.environ.get("SENTINEL_DB_ECHO", "").lower() in ("1", "true"),
    )
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Ensure stats row exists
    async with _session_factory() as session:
        from sqlalchemy import select
        result = await session.execute(select(ScanStats).where(ScanStats.id == 1))
        if not result.scalar_one_or_none():
            session.add(ScanStats(id=1))
            await session.commit()

    logger.info("PostgreSQL initialized — tables ready")


async def close_db() -> None:
    """Dispose engine on shutdown."""
    global _engine
    if _engine:
        await _engine.dispose()
        _engine = None
        logger.info("PostgreSQL connection closed")


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async session."""
    if not _session_factory:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def is_db_enabled() -> bool:
    """Check if database URL is configured (not empty/default-disabled)."""
    url = os.environ.get("DATABASE_URL", "")
    return bool(url) and url != "disabled"
