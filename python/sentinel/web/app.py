"""
Eresus Sentinel — Hardened Web Dashboard API.

Security-hardened React SPA + JSON API backend:
  - Strict CSP, HSTS, X-Frame-Options, X-Content-Type-Options
  - Per-IP rate limiting (token bucket)
  - Input validation & size limits
  - File upload size + type restrictions
  - No directory traversal in SPA fallback
  - CORS locked to localhost in dev, configurable in prod
  - All API responses are JSON, no template injection

Usage:
    sentinel serve --ui
    # Opens http://localhost:8080
"""

from __future__ import annotations

import hashlib
import html
import logging
import os
import re
import secrets
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_WEB_DIR = Path(__file__).parent
_DIST_DIR = _WEB_DIR / "dist"

# ── Security Constants ───────────────────────────────────────────

MAX_PROMPT_LENGTH = 50_000          # 50KB max prompt
MAX_UPLOAD_SIZE = 500 * 1024 * 1024 # 500MB max upload
MAX_HISTORY_SIZE = 10_000           # max entries in memory
RATE_LIMIT_RPS = 30                 # requests per second per IP
RATE_LIMIT_BURST = 60               # burst capacity
ALLOWED_UPLOAD_EXTENSIONS = {
    ".pkl", ".pickle", ".p", ".dill",
    ".pt", ".pth", ".bin", ".ckpt",
    ".safetensors", ".gguf", ".pb",
    ".onnx", ".keras", ".h5", ".hdf5",
    ".tflite", ".llamafile",
    ".xgb", ".ubj", ".model", ".lgb",
    ".joblib", ".npy", ".npz",
    ".nemo", ".mar", ".tar", ".tgz", ".zip",
    ".torchscript", ".ptc", ".ptl",
}


def create_dashboard_app(
    policy_path: str | None = None,
    host: str = "0.0.0.0",
    port: int = 8080,
) -> Any:
    """Create security-hardened FastAPI app with React SPA + JSON API."""
    try:
        from fastapi import FastAPI, Request, UploadFile, File, HTTPException
        from fastapi.responses import JSONResponse, FileResponse, Response
        from fastapi.staticfiles import StaticFiles
        from fastapi.middleware.cors import CORSMiddleware
        from starlette.middleware.base import BaseHTTPMiddleware
    except ImportError:
        raise ImportError(
            "FastAPI required for web UI. "
            "Install: pip install 'eresus-sentinel[web]'"
        )

    from sentinel import __version__
    from sentinel.policy import PolicyEngine
    from pydantic import BaseModel, Field, field_validator

    # ── CSP nonce ────────────────────────────────────────────────

    _csp_nonce = secrets.token_urlsafe(16)

    # ── Request Validation Models ────────────────────────────────

    class FirewallScanRequest(BaseModel):
        prompt: str = Field(..., min_length=1, max_length=MAX_PROMPT_LENGTH)
        scan_type: str = Field(default="input", pattern=r"^(input|output)$")

        @field_validator("prompt")
        @classmethod
        def sanitize_prompt(cls, v: str) -> str:
            # Strip null bytes and control chars (except newline/tab)
            return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", v)

    # ── Rate Limiter ─────────────────────────────────────────────

    class TokenBucketRateLimiter:
        """Per-IP token bucket rate limiter."""

        def __init__(self, rate: float = RATE_LIMIT_RPS, burst: int = RATE_LIMIT_BURST):
            self.rate = rate
            self.burst = burst
            self._buckets: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_time)

        def allow(self, ip: str) -> bool:
            now = time.monotonic()
            tokens, last = self._buckets.get(ip, (float(self.burst), now))
            elapsed = now - last
            tokens = min(self.burst, tokens + elapsed * self.rate)
            if tokens >= 1.0:
                self._buckets[ip] = (tokens - 1.0, now)
                return True
            self._buckets[ip] = (tokens, now)
            return False

        def cleanup(self, max_age: float = 300):
            """Remove stale entries older than max_age seconds."""
            now = time.monotonic()
            self._buckets = {
                ip: (t, ts)
                for ip, (t, ts) in self._buckets.items()
                if now - ts < max_age
            }

    rate_limiter = TokenBucketRateLimiter()

    # ── Security Headers Middleware ───────────────────────────────

    class SecurityHeadersMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            response = await call_next(request)

            # Content Security Policy — strict
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: blob:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "object-src 'none'; "
                "upgrade-insecure-requests"
            )
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = (
                "camera=(), microphone=(), geolocation=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=()"
            )
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

            # Remove server header
            response.headers.pop("server", None)

            return response

    # ── Rate Limit Middleware ────────────────────────────────────

    class RateLimitMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            # Don't rate-limit static assets
            if request.url.path.startswith("/assets/"):
                return await call_next(request)

            client_ip = request.client.host if request.client else "unknown"
            if not rate_limiter.allow(client_ip):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Try again later."},
                    headers={"Retry-After": "1"},
                )
            return await call_next(request)

    # ── App Init ─────────────────────────────────────────────────

    app = FastAPI(
        title="Eresus Sentinel API",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    # Security middleware (order matters — outermost first)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)

    # CORS — strict in production, permissive for dev
    allowed_origins = os.environ.get(
        "SENTINEL_CORS_ORIGINS",
        "http://localhost:5173,http://localhost:8080,http://127.0.0.1:5173,http://127.0.0.1:8080"
    ).split(",")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
        allow_credentials=False,
        max_age=3600,
    )

    # ── State ────────────────────────────────────────────────────

    engine = PolicyEngine.from_file(policy_path) if policy_path else PolicyEngine.default()
    input_pipe = engine.build_input_pipeline()
    output_pipe = engine.build_output_pipeline()

    scan_history: list[dict] = []
    artifact_history: list[dict] = []
    _start_time = time.time()
    _instance_id = secrets.token_hex(8)

    # ── Helpers ──────────────────────────────────────────────────

    def _trim_history():
        """Prevent unbounded memory growth."""
        while len(scan_history) > MAX_HISTORY_SIZE:
            scan_history.pop(0)
        while len(artifact_history) > MAX_HISTORY_SIZE:
            artifact_history.pop(0)

    def _safe_str(s: str, max_len: int = 500) -> str:
        """Truncate and strip dangerous chars."""
        s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
        return s[:max_len]

    def _finding_to_dict(f) -> dict:
        """Convert any Finding object to a safe API dict."""
        sev = getattr(f, "severity", "INFO")
        sev_str = sev.name if hasattr(sev, "name") else (sev.value if hasattr(sev, "value") else str(sev))
        return {
            "rule_id": _safe_str(str(getattr(f, "rule_id", "")), 100),
            "title": _safe_str(str(getattr(f, "title", "")), 200),
            "severity": _safe_str(sev_str, 10),
            "confidence": min(1.0, max(0.0, float(getattr(f, "confidence", 0.0)))),
            "description": _safe_str(str(getattr(f, "description", "")), 500),
            "evidence": _safe_str(str(getattr(f, "evidence", "")), 300),
            "cwe_ids": getattr(f, "cwe_ids", [])[:10],
            "remediation": _safe_str(str(getattr(f, "remediation", "")), 300),
        }

    # ── API: Stats ───────────────────────────────────────────────

    @app.get("/api/stats")
    async def api_stats():
        total = len(scan_history)
        findings = sum(s.get("finding_count", 0) for s in scan_history)
        blocked = sum(1 for s in scan_history if s.get("action") == "block")

        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for s in scan_history:
            for f in s.get("findings", []):
                sv = f.get("severity", "INFO")
                if sv in sev:
                    sev[sv] += 1

        timeline = [
            {"ts": s["timestamp"], "findings": s["finding_count"], "latency": s.get("latency_ms", 0)}
            for s in scan_history[-30:]
        ]

        return {
            "total_scans": total,
            "total_findings": findings,
            "blocked": blocked,
            "clean": total - blocked,
            "severity": sev,
            "timeline": timeline,
            "artifacts_scanned": len(artifact_history),
            "artifact_findings": sum(a.get("finding_count", 0) for a in artifact_history),
        }

    # ── API: Scanners ────────────────────────────────────────────

    @app.get("/api/scanners")
    async def api_scanners():
        return {
            "input": [s.__class__.__name__ for s in input_pipe._scanners],
            "output": [s.__class__.__name__ for s in output_pipe._scanners],
            "input_count": len(input_pipe._scanners),
            "output_count": len(output_pipe._scanners),
        }

    # ── API: Firewall Scan ───────────────────────────────────────

    @app.post("/api/firewall/scan")
    async def firewall_scan(body: FirewallScanRequest):
        start = time.perf_counter()
        try:
            if body.scan_type == "input":
                result = input_pipe.scan(body.prompt)
            else:
                result = output_pipe.scan(body.prompt)
        except Exception as exc:
            logger.exception("Scan engine error")
            raise HTTPException(status_code=500, detail="Scan engine error")
        elapsed = (time.perf_counter() - start) * 1000

        findings = []
        for f in result.findings:
            findings.append({
                "rule_id": _safe_str(str(getattr(f, "rule_id", "")), 100),
                "title": _safe_str(str(getattr(f, "title", "")), 200),
                "severity": _safe_str(
                    f.severity.name if hasattr(f.severity, "name") else str(f.severity), 10
                ),
                "confidence": min(1.0, max(0.0, float(getattr(f, "confidence", 0.0)))),
                "description": _safe_str(str(getattr(f, "description", "")), 500),
                "evidence": _safe_str(str(getattr(f, "evidence", "")), 300),
            })

        entry = {
            "id": uuid.uuid4().hex[:12],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": body.scan_type,
            "prompt": _safe_str(body.prompt, 500),
            "action": _safe_str(
                result.action.name if hasattr(result.action, "name") else str(result.action), 20
            ),
            "risk_score": round(min(1.0, max(0.0, result.risk_score)), 3),
            "finding_count": len(findings),
            "findings": findings,
            "latency_ms": round(elapsed, 1),
        }
        scan_history.append(entry)
        _trim_history()
        return entry

    # ── API: Artifact Scan ───────────────────────────────────────

    @app.post("/api/artifacts/scan")
    async def artifact_scan(file: UploadFile = File(...)):
        import tempfile
        from sentinel.cli_dispatch import dispatch_artifact

        # Validate filename
        if not file.filename:
            raise HTTPException(status_code=400, detail="Filename required")

        # Sanitize filename — prevent path traversal
        safe_name = Path(file.filename).name  # strip directory components
        if not safe_name or safe_name.startswith("."):
            raise HTTPException(status_code=400, detail="Invalid filename")

        # Validate extension
        suffix = Path(safe_name).suffix.lower()
        if suffix not in ALLOWED_UPLOAD_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: {suffix}. Allowed: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}",
            )

        # Read with size limit
        start = time.perf_counter()
        content = await file.read()
        if len(content) > MAX_UPLOAD_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum: {MAX_UPLOAD_SIZE // (1024*1024)}MB",
            )
        if len(content) == 0:
            raise HTTPException(status_code=400, detail="Empty file")

        # Write to temp with restricted permissions
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=f"_{safe_name}",
                prefix="sentinel_scan_",
            ) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            os.chmod(tmp_path, 0o600)

            findings_raw = dispatch_artifact(tmp_path)
            elapsed = (time.perf_counter() - start) * 1000

            findings = []
            for f in findings_raw:
                findings.append({
                    "rule_id": _safe_str(str(getattr(f, "rule_id", "")), 100),
                    "title": _safe_str(str(getattr(f, "title", "")), 200),
                    "severity": _safe_str(
                        f.severity.name if hasattr(f.severity, "name") else str(f.severity), 10
                    ),
                    "confidence": min(1.0, max(0.0, float(getattr(f, "confidence", 0.0)))),
                    "description": _safe_str(str(getattr(f, "description", "")), 500),
                    "evidence": _safe_str(str(getattr(f, "evidence", "")), 300),
                    "cwe_ids": getattr(f, "cwe_ids", [])[:10],
                    "remediation": _safe_str(str(getattr(f, "remediation", "")), 300),
                })

            entry = {
                "id": uuid.uuid4().hex[:12],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "filename": _safe_str(safe_name, 255),
                "size": len(content),
                "finding_count": len(findings),
                "findings": findings,
                "latency_ms": round(elapsed, 1),
                "status": (
                    "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else
                    "WARNING" if findings else "CLEAN"
                ),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            artifact_history.append(entry)
            _trim_history()
            return entry

        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Artifact scan error")
            raise HTTPException(status_code=500, detail="Artifact scan engine error")
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # ── API: SAST Scan ───────────────────────────────────────────

    class SastScanRequest(BaseModel):
        path: str = Field(..., min_length=1, max_length=4096)

    @app.post("/api/sast/scan")
    async def sast_scan(body: SastScanRequest):
        from sentinel.cli_dispatch import dispatch_sast
        start = time.perf_counter()
        raw = dispatch_sast(body.path)
        elapsed = (time.perf_counter() - start) * 1000
        findings = [_finding_to_dict(f) for f in raw]
        return {"findings": findings, "count": len(findings), "latency_ms": round(elapsed, 1)}

    # ── API: Agent/MCP Scan ──────────────────────────────────────

    @app.post("/api/agent/scan")
    async def agent_scan(body: SastScanRequest):
        from sentinel.cli_dispatch import dispatch_agent
        start = time.perf_counter()
        raw = dispatch_agent(body.path)
        elapsed = (time.perf_counter() - start) * 1000
        findings = [_finding_to_dict(f) for f in raw]
        return {"findings": findings, "count": len(findings), "latency_ms": round(elapsed, 1)}

    # ── API: Supply Chain ────────────────────────────────────────

    @app.post("/api/supply-chain/scan")
    async def supply_chain_scan(body: SastScanRequest):
        from sentinel.cli_dispatch import dispatch_supply_chain
        start = time.perf_counter()
        raw = dispatch_supply_chain(body.path)
        elapsed = (time.perf_counter() - start) * 1000
        findings = [_finding_to_dict(f) for f in raw]
        return {"findings": findings, "count": len(findings), "latency_ms": round(elapsed, 1)}

    # ── API: Diff Scan ───────────────────────────────────────────

    class DiffScanRequest(BaseModel):
        target: str = Field(default="--staged", max_length=4096)

    @app.post("/api/diff/scan")
    async def diff_scan(body: DiffScanRequest):
        from sentinel.cli_dispatch import dispatch_diff
        start = time.perf_counter()
        raw = dispatch_diff(body.target)
        elapsed = (time.perf_counter() - start) * 1000
        findings = [_finding_to_dict(f) for f in raw]
        return {"findings": findings, "count": len(findings), "latency_ms": round(elapsed, 1)}

    # ── API: Notebook Scan ───────────────────────────────────────

    @app.post("/api/notebook/scan")
    async def notebook_scan(body: SastScanRequest):
        from sentinel.cli_dispatch import dispatch_notebook
        start = time.perf_counter()
        raw = dispatch_notebook(body.path)
        elapsed = (time.perf_counter() - start) * 1000
        findings = [_finding_to_dict(f) for f in raw]
        return {"findings": findings, "count": len(findings), "latency_ms": round(elapsed, 1)}

    # ── API: Red Team ────────────────────────────────────────────

    class RedTeamRequest(BaseModel):
        target: str = Field(..., min_length=1, max_length=4096)

    @app.post("/api/redteam/scan")
    async def redteam_scan(body: RedTeamRequest):
        from sentinel.cli_dispatch import dispatch_redteam
        start = time.perf_counter()
        raw = dispatch_redteam(body.target)
        elapsed = (time.perf_counter() - start) * 1000
        findings = [_finding_to_dict(f) for f in raw]
        return {"findings": findings, "count": len(findings), "latency_ms": round(elapsed, 1)}

    # ── API: Secrets Scan ────────────────────────────────────────

    class SecretsScanRequest(BaseModel):
        path: str = Field(..., min_length=1, max_length=4096)
        enable_entropy: bool = True
        git_history: bool = False

    @app.post("/api/secrets/scan")
    async def secrets_scan(body: SecretsScanRequest):
        from sentinel.sast.secrets_scanner import SecretsScanner
        start = time.perf_counter()
        scanner = SecretsScanner(enable_entropy=body.enable_entropy)
        p = Path(body.path)
        raw = scanner.scan_directory(str(p)) if p.is_dir() else scanner.scan_file(str(p))
        if body.git_history:
            raw.extend(scanner.scan_git_history(str(p)))
        raw.extend(scanner.scan_config_files(str(p)))
        elapsed = (time.perf_counter() - start) * 1000
        findings = [_finding_to_dict(f) for f in raw]
        return {"findings": findings, "count": len(findings), "latency_ms": round(elapsed, 1)}

    # ── API: Dep Scan ────────────────────────────────────────────

    class DepScanRequest(BaseModel):
        path: str = Field(..., min_length=1, max_length=4096)
        ecosystem: str = Field(default="pypi", pattern=r"^(pypi|npm)$")

    @app.post("/api/dep-scan/scan")
    async def dep_scan(body: DepScanRequest):
        from sentinel.supply_chain.live_scanner import LiveDependencyScanner
        start = time.perf_counter()
        scanner = LiveDependencyScanner(ecosystem=body.ecosystem)
        raw = scanner.full_audit(body.path)
        elapsed = (time.perf_counter() - start) * 1000
        findings = [_finding_to_dict(f) for f in raw]
        return {"findings": findings, "count": len(findings), "latency_ms": round(elapsed, 1)}

    # ── API: Evaluate ────────────────────────────────────────────

    @app.get("/api/evaluate")
    async def api_evaluate():
        from sentinel.evaluator import ScannerEvaluator
        evaluator = ScannerEvaluator()
        results = evaluator.evaluate_all_input()
        return [
            {
                "scanner_name": r.scanner_name,
                "tp": r.tp, "fp": r.fp, "fn": r.fn, "tn": r.tn,
                "precision": round(r.precision, 3),
                "recall": round(r.recall, 3),
                "f1": round(r.f1, 3),
            }
            for r in results
        ]

    # ── API: Plugins ─────────────────────────────────────────────

    @app.get("/api/plugins")
    async def api_plugins():
        from sentinel._plugins import list_all_plugins, get_plugin_info
        plugins = list_all_plugins()
        result = {}
        for cat, names in plugins.items():
            result[cat] = []
            for name in names:
                info = get_plugin_info(cat, name)
                result[cat].append({"name": name, "doc": info.get("docstring", "")[:100]})
        return result

    # ── API: Doctor ──────────────────────────────────────────────

    @app.get("/api/doctor")
    async def api_doctor():
        import platform as _platform
        checks = []

        # Python
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        checks.append({"name": "Python", "ok": sys.version_info >= (3, 10), "detail": py_ver})
        checks.append({"name": "Platform", "ok": True, "detail": f"{_platform.system()}/{_platform.machine()} · {os.cpu_count()} cores"})

        # Core modules
        for mod, label in [
            ("sentinel.finding", "Finding"), ("sentinel.artifact", "Artifact"),
            ("sentinel.firewall", "Firewall"), ("sentinel.redteam", "Red Team"),
            ("sentinel.sast", "SAST"), ("sentinel.agent", "Agent/MCP"),
            ("sentinel.supply_chain", "Supply Chain"), ("sentinel.policy", "Policy"),
        ]:
            try:
                __import__(mod)
                checks.append({"name": label, "ok": True, "detail": mod})
            except ImportError as e:
                checks.append({"name": label, "ok": False, "detail": str(e)})

        passed = sum(1 for c in checks if c["ok"])
        return {"checks": checks, "passed": passed, "total": len(checks)}

    # ── API: Policy ──────────────────────────────────────────────

    @app.get("/api/policy")
    async def api_policy():
        scanners = engine.list_scanners()
        return {
            "input_scanners": scanners["input"],
            "output_scanners": scanners["output"],
            "mode": "enforce",
        }

    # ── API: Config ──────────────────────────────────────────────

    @app.get("/api/config")
    async def api_config():
        scanners = engine.list_scanners()
        return {
            "input": scanners["input"],
            "output": scanners["output"],
            "total": len(scanners["input"]) + len(scanners["output"]),
        }

    # ── API: History ─────────────────────────────────────────────

    @app.get("/api/history")
    async def api_history():
        return {
            "scans": list(reversed(scan_history[-200:])),
            "artifacts": list(reversed(artifact_history[-200:])),
        }

    # ── API: Health ──────────────────────────────────────────────

    @app.get("/api/health")
    @app.get("/health")
    async def health():
        return {
            "status": "healthy",
            "version": __version__,
            "uptime_s": round(time.time() - _start_time, 1),
            "scans_processed": len(scan_history),
            "artifacts_processed": len(artifact_history),
            "instance_id": _instance_id,
        }

    # ── SPA Serving ──────────────────────────────────────────────

    if _DIST_DIR.is_dir() and (_DIST_DIR / "index.html").is_file():
        # Serve hashed static assets
        assets_dir = _DIST_DIR / "assets"
        if assets_dir.is_dir():
            app.mount(
                "/assets",
                StaticFiles(directory=str(assets_dir)),
                name="assets",
            )

        @app.get("/{path:path}")
        async def spa_fallback(path: str):
            # Prevent path traversal
            if ".." in path or path.startswith("/"):
                raise HTTPException(status_code=400, detail="Invalid path")

            # Try serving exact static file from dist
            if path:
                file_path = (_DIST_DIR / path).resolve()
                # Ensure resolved path is within dist directory
                if file_path.is_file() and str(file_path).startswith(str(_DIST_DIR.resolve())):
                    return FileResponse(file_path)

            # SPA fallback: serve index.html for all routes
            return FileResponse(_DIST_DIR / "index.html")

    return app
