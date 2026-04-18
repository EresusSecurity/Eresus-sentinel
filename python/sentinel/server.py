"""
Eresus Sentinel — REST API Server.

FastAPI-powered HTTP service for the entire security platform.

Endpoints:
  POST /scan/input          — Run input pipeline
  POST /scan/output         — Run output pipeline
  POST /scan/conversation   — Run both pipelines
  POST /scan/batch          — Batch scan (concurrent)
  POST /scan/artifact       — Scan a model artifact file
  POST /hf/assess           — Pre-download HF repo assessment
  GET  /health              — Health check with scanner readiness
  GET  /ready               — Readiness probe for k8s
  GET  /metrics             — Prometheus metrics endpoint
  GET  /scanners            — List available scanners
  GET  /plugins             — List auto-discovered plugins
  GET  /policy              — Current policy config
  GET  /vault/stats         — Vault statistics

Usage:
    # Start server
    uvicorn sentinel.server:app --host 0.0.0.0 --port 8080

    # Or programmatically
    from sentinel.server import create_app
    app = create_app(policy_path="policy.yaml")
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Defer FastAPI import to runtime
_app = None


def create_app(
    policy_path: str | None = None,
    audit_path: str | None = None,
    enable_metrics: bool = True,
    enable_vault: bool = False,
    max_batch_workers: int = 4,
) -> Any:
    """
    Create the FastAPI application.

    Args:
        policy_path: Path to YAML policy file (uses default if None).
        audit_path: Path for JSONL audit log.
        enable_metrics: Enable Prometheus metrics endpoint.
        enable_vault: Enable PII vault for redact/restore.
        max_batch_workers: Max concurrent workers for batch scanning.

    Returns:
        FastAPI application instance.
    """
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import JSONResponse
        from pydantic import BaseModel, Field
    except ImportError:
        raise ImportError(
            "FastAPI is required for the REST API server. "
            "Install it with: pip install 'eresus-sentinel[api]'"
        )

    from sentinel import __version__
    from sentinel.sdk import Sentinel, ConversationResult
    from sentinel.metrics import MetricsCollector
    from sentinel.audit import AuditLogger

    # ── Init ──────────────────────────────────────────────────────

    app = FastAPI(
        title="Eresus Sentinel",
        description=(
            "Production-grade AI/LLM Security Platform API.\n\n"
            "Provides real-time input/output guardrails, artifact scanning, "
            "HuggingFace repo assessment, and compliance audit logging."
        ),
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_tags=[
            {"name": "scan", "description": "Real-time input/output scanning"},
            {"name": "artifact", "description": "Model artifact security scanning"},
            {"name": "huggingface", "description": "HuggingFace model repository analysis"},
            {"name": "observability", "description": "Health, metrics, and monitoring"},
            {"name": "config", "description": "Configuration and scanner management"},
        ],
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("SENTINEL_CORS_ORIGINS", "*").split(","),
        allow_credentials=True,
        allow_methods=["POST", "GET", "OPTIONS"],
        allow_headers=["*"],
    )

    # Init Sentinel
    if policy_path:
        sentinel = Sentinel.from_policy(policy_path)
    else:
        sentinel = Sentinel.default()

    metrics = MetricsCollector() if enable_metrics else None
    audit = AuditLogger(path=audit_path) if audit_path else None

    vault = None
    if enable_vault:
        from sentinel.vault import Vault
        vault = Vault()

    _startup_time = time.time()

    # ── Request ID middleware ─────────────────────────────────────

    @app.middleware("http")
    async def add_request_id(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex[:16])
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Powered-By"] = f"Eresus Sentinel/{__version__}"
        return response

    # ── Error handler ─────────────────────────────────────────────

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled error: %s", exc, exc_info=True)
        # Never leak internal error details in production
        env = os.environ.get("SENTINEL_ENV", "production")
        detail = str(exc) if env in ("development", "dev", "local") else "An internal error occurred"
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "detail": detail},
        )

    # ── Models ────────────────────────────────────────────────────

    class InputScanRequest(BaseModel):
        prompt: str = Field(..., min_length=1, max_length=100_000, description="User prompt to scan")
        session_id: str = Field("", description="Session identifier for audit trail")
        user_id: str = Field("", description="User identifier for audit trail")
        vault_enabled: bool = Field(False, description="Enable PII redaction via Vault")

    class OutputScanRequest(BaseModel):
        prompt: str = Field(..., min_length=1, max_length=100_000)
        output: str = Field(..., min_length=1, max_length=500_000, description="LLM output to scan")
        session_id: str = ""
        user_id: str = ""
        model: str = Field("", description="Model identifier for cost tracking")
        vault_restore: bool = Field(False, description="Restore vault placeholders in output")

    class ConversationScanRequest(BaseModel):
        prompt: str = Field(..., min_length=1, max_length=100_000)
        output: str = Field(..., min_length=1, max_length=500_000)
        session_id: str = ""
        user_id: str = ""
        model: str = ""

    class BatchScanRequest(BaseModel):
        items: list[ConversationScanRequest] = Field(..., max_length=100)

    class HFAssessRequest(BaseModel):
        repo_id: str = Field(..., description="HuggingFace repo (e.g. 'org/model')")
        revision: str = Field("main", description="Branch or commit hash")
        block_pickle: bool = False
        require_safetensors: bool = False

    class ScanResponse(BaseModel):
        action: str
        risk_score: float
        is_valid: bool
        finding_count: int
        findings: list[dict] = []
        sanitized_preview: str = Field("", description="First 200 chars of sanitized text")
        metadata: dict = {}
        latency_ms: float = 0.0

    class ConversationResponse(BaseModel):
        blocked: bool
        reason: str = ""
        risk_score: float
        total_findings: int
        latency_ms: float = 0.0
        input_action: str = ""
        input_risk: float = 0.0
        input_findings: int = 0
        output_action: str = ""
        output_risk: float = 0.0
        output_findings: int = 0

    class HealthResponse(BaseModel):
        status: str
        version: str
        uptime_seconds: float = 0.0
        scanners: dict[str, int] = {}
        vault_enabled: bool = False

    # ── Scan Endpoints ────────────────────────────────────────────

    @app.post("/scan/input", response_model=ScanResponse, tags=["scan"])
    async def scan_input(req: InputScanRequest):
        """Scan user input through the input firewall pipeline."""
        start = time.perf_counter()

        # Optional vault redaction
        prompt = req.prompt
        if req.vault_enabled and vault:
            from sentinel.vault import Vault as _V
            # Auto-detect PII patterns and redact
            prompt_vault = vault.redact(prompt, "PROMPT")

        result = sentinel.scan_input(prompt)
        elapsed_ms = (time.perf_counter() - start) * 1000

        if metrics:
            metrics.record_result("input_pipeline", "input", result, duration_seconds=elapsed_ms / 1000)
        if audit:
            audit.log_result("input_pipeline", "input", result, latency_ms=elapsed_ms,
                             session_id=req.session_id, user_id=req.user_id,
                             prompt_hash=hashlib.sha256(req.prompt.encode()).hexdigest()[:16])

        return ScanResponse(
            action=result.action.value,
            risk_score=round(result.risk_score, 4),
            is_valid=result.is_valid,
            finding_count=len(result.findings),
            findings=[_finding_to_dict(f) for f in result.findings],
            sanitized_preview=result.sanitized[:200] if result.sanitized != req.prompt else "",
            metadata=getattr(result, "metadata", {}),
            latency_ms=round(elapsed_ms, 2),
        )

    @app.post("/scan/output", response_model=ScanResponse, tags=["scan"])
    async def scan_output(req: OutputScanRequest):
        """Scan model output through the output firewall pipeline."""
        start = time.perf_counter()
        result = sentinel.scan_output(req.prompt, req.output)
        elapsed_ms = (time.perf_counter() - start) * 1000

        output_text = result.sanitized
        if req.vault_restore and vault:
            output_text = vault.restore(output_text)

        if metrics:
            metrics.record_result("output_pipeline", "output", result, duration_seconds=elapsed_ms / 1000)
        if audit:
            audit.log_result("output_pipeline", "output", result, latency_ms=elapsed_ms,
                             session_id=req.session_id, user_id=req.user_id, model=req.model,
                             prompt_hash=hashlib.sha256(req.prompt.encode()).hexdigest()[:16])

        return ScanResponse(
            action=result.action.value,
            risk_score=round(result.risk_score, 4),
            is_valid=result.is_valid,
            finding_count=len(result.findings),
            findings=[_finding_to_dict(f) for f in result.findings],
            sanitized_preview=output_text[:200] if output_text != req.output else "",
            metadata=getattr(result, "metadata", {}),
            latency_ms=round(elapsed_ms, 2),
        )

    @app.post("/scan/conversation", response_model=ConversationResponse, tags=["scan"])
    async def scan_conversation(req: ConversationScanRequest):
        """Scan both input and output in a single call."""
        start = time.perf_counter()
        conv_result = sentinel.scan_conversation(req.prompt, req.output)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return ConversationResponse(
            blocked=conv_result.blocked,
            reason=conv_result.reason,
            risk_score=round(conv_result.risk_score, 4),
            total_findings=conv_result.total_findings,
            latency_ms=round(elapsed_ms, 2),
            input_action=conv_result.input_result.action.value if conv_result.input_result else "skip",
            input_risk=round(conv_result.input_result.risk_score, 4) if conv_result.input_result else 0,
            input_findings=len(conv_result.input_result.findings) if conv_result.input_result else 0,
            output_action=conv_result.output_result.action.value if conv_result.output_result else "skip",
            output_risk=round(conv_result.output_result.risk_score, 4) if conv_result.output_result else 0,
            output_findings=len(conv_result.output_result.findings) if conv_result.output_result else 0,
        )

    @app.post("/scan/batch", tags=["scan"])
    async def scan_batch(req: BatchScanRequest):
        """Batch scan multiple conversations concurrently."""
        start = time.perf_counter()

        def _scan_one(item):
            return sentinel.scan_conversation(item.prompt, item.output)

        with ThreadPoolExecutor(max_workers=max_batch_workers) as pool:
            conv_results = list(pool.map(_scan_one, req.items))

        results = []
        for conv in conv_results:
            results.append({
                "blocked": conv.blocked,
                "reason": conv.reason,
                "risk_score": round(conv.risk_score, 4),
                "total_findings": conv.total_findings,
            })

        return {
            "results": results,
            "count": len(results),
            "total_latency_ms": round((time.perf_counter() - start) * 1000, 2),
        }

    # ── HuggingFace Endpoints ─────────────────────────────────────

    @app.post("/hf/assess", tags=["huggingface"])
    async def hf_assess(req: HFAssessRequest):
        """Pre-download risk assessment for a HuggingFace model repo."""
        from sentinel.hf_guard import HFGuard

        start = time.perf_counter()
        guard = HFGuard(
            block_pickle=req.block_pickle,
            require_safetensors=req.require_safetensors,
        )
        assessment = guard.assess(req.repo_id, req.revision)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return {
            **assessment.to_dict(),
            "latency_ms": round(elapsed_ms, 2),
            "dangerous_files": assessment.dangerous_files[:20],
            "recommendations": assessment.recommendations,
            "model_card_warnings": assessment.model_card_warnings,
        }

    # ── Observability Endpoints ───────────────────────────────────

    @app.get("/health", response_model=HealthResponse, tags=["observability"])
    async def health():
        """Health check with scanner readiness."""
        from sentinel.policy import PolicyEngine
        available = PolicyEngine.default().list_scanners()
        return HealthResponse(
            status="ok",
            version=__version__,
            uptime_seconds=round(time.time() - _startup_time, 1),
            scanners={k: len(v) for k, v in available.items()},
            vault_enabled=vault is not None,
        )

    @app.get("/ready", tags=["observability"])
    async def ready():
        """Readiness probe for Kubernetes."""
        return {"ready": True, "version": __version__}

    @app.get("/metrics", tags=["observability"])
    async def prometheus_metrics():
        """Prometheus-compatible metrics export."""
        if not metrics:
            raise HTTPException(status_code=404, detail="Metrics not enabled")
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(
            content=metrics.export_prometheus(),
            media_type="text/plain; version=0.0.4",
        )

    @app.get("/vault/stats", tags=["observability"])
    async def vault_stats():
        """Vault statistics (entries, categories, etc.)."""
        if not vault:
            return {"enabled": False}
        return {"enabled": True, **vault.stats()}

    # ── Config Endpoints ──────────────────────────────────────────

    @app.get("/scanners", tags=["config"])
    async def list_scanners():
        """List all available scanners grouped by type."""
        from sentinel.policy import PolicyEngine
        return PolicyEngine.default().list_scanners()

    @app.get("/plugins", tags=["config"])
    async def list_plugins():
        """List all auto-discovered scanner plugins."""
        try:
            from sentinel._plugins import list_all_plugins
            return list_all_plugins()
        except Exception as e:
            return {"error": str(e)}

    return app


def _finding_to_dict(finding) -> dict:
    """Convert a Finding to a JSON-safe dict."""
    return {
        "rule_id": getattr(finding, "rule_id", ""),
        "title": getattr(finding, "title", ""),
        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        "confidence": round(getattr(finding, "confidence", 0.0), 4),
        "description": getattr(finding, "description", ""),
        "evidence": getattr(finding, "evidence", "")[:500],
        "remediation": getattr(finding, "remediation", ""),
        "tags": getattr(finding, "tags", []),
        "category": getattr(finding, "category", ""),
        "owasp_llm": getattr(finding, "owasp_llm", ""),
        "target": getattr(finding, "target", ""),
    }


# ── Module-level lazy app for `uvicorn sentinel.server:app` ──────────
# Uses a module __getattr__ trick so `import sentinel.server` does NOT
# trigger FastAPI creation.  Only `sentinel.server.app` does.

def _get_app():
    global _app
    if _app is None:
        _app = create_app(
            policy_path=os.environ.get("SENTINEL_POLICY"),
            audit_path=os.environ.get("SENTINEL_AUDIT_LOG"),
            enable_metrics=os.environ.get("SENTINEL_METRICS", "1") == "1",
            enable_vault=os.environ.get("SENTINEL_VAULT", "0") == "1",
        )
    return _app


def __getattr__(name: str):
    """Lazy module attribute — only create app on explicit access."""
    if name == "app":
        return _get_app()
    raise AttributeError(f"module 'sentinel.server' has no attribute {name!r}")

