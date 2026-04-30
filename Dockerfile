# ============================================================================
# Eresus Sentinel — Production Docker Image
# Multi-stage build for minimal attack surface
# ============================================================================
# Usage:
#   docker build -t eresus/sentinel .
#   docker run -p 8080:8080 eresus/sentinel
#
# With custom config:
#   docker run -p 8080:8080 \
#     -v ./config:/app/config:ro \
#     -v ./rules:/app/rules:ro \
#     -e SENTINEL_POLICY=/app/config/policy.yaml \
#     eresus/sentinel
# ============================================================================

# ── Stage 1: Builder ─────────────────────────────────────────────────
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

# Install only the dependencies needed for the dashboard/API image.
RUN pip install --no-cache-dir --upgrade pip && \
        pip install --no-cache-dir --prefix=/install .[all]

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/eresus-security/sentinel"
LABEL org.opencontainers.image.title="Eresus Sentinel"
LABEL org.opencontainers.image.description="Production-grade AI/LLM Security Platform"
LABEL org.opencontainers.image.vendor="Eresus Security"
LABEL org.opencontainers.image.licenses="Proprietary"
LABEL org.opencontainers.image.version="0.1.0"

# Security: non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel -d /app -s /sbin/nologin sentinel

# Runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# App directory
WORKDIR /app

# Copy source + rules + config
COPY --chown=sentinel:sentinel python/ ./python/
COPY --chown=sentinel:sentinel rules/ ./rules/
COPY --chown=sentinel:sentinel config/ ./config/
COPY --chown=sentinel:sentinel sentinel.toml ./
COPY --chown=sentinel:sentinel pyproject.toml ./

# Create directories for runtime data
RUN mkdir -p /app/logs /app/data && \
    chown -R sentinel:sentinel /app

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/python \
    SENTINEL_ENV=production \
    SENTINEL_LOG_LEVEL=INFO \
    SENTINEL_METRICS=1 \
    SENTINEL_AUDIT_LOG=/app/logs/audit.jsonl \
    SENTINEL_POLICY=/app/config/policy.yaml \
    SENTINEL_DATA_DIR=/app/python/sentinel/data \
    PORT=8080

# Switch to non-root
USER sentinel

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Use tini as PID 1 for proper signal handling
ENTRYPOINT ["tini", "--"]

# Default: start web dashboard + JSON API server
CMD ["python", "-m", "uvicorn", "sentinel.server:create_app", \
     "--factory", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "2", \
     "--log-level", "info", \
     "--access-log"]
