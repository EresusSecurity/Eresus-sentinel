"""
Eresus Sentinel — Hardened Web Dashboard API.

Modular architecture:
  - state.py      → AppState + security constants
  - models.py     → Pydantic request models
  - helpers.py    → Path validation, finding conversion
  - middleware.py  → SecurityHeaders, RateLimit, Auth
  - routes_auth.py     → /api/auth/*
  - routes_firewall.py → /api/firewall/*
  - routes_artifact.py → /api/artifacts/*
  - routes_scan.py     → /api/sast, agent, supply-chain, diff, notebook, redteam, secrets, dep-scan
  - routes_info.py     → /api/stats, scanners, evaluate, plugins, doctor, policy, config, history, health
  - routes_extra.py    → /api/mcp, a2a, aibom, hf, validate, benchmark

Usage:
    sentinel dashboard
    sentinel serve --ui
    # Opens http://localhost:8080
"""

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_WEB_DIR = Path(__file__).parent
_DIST_DIR = _WEB_DIR / "dist"


def create_dashboard_app(
    policy_path: str | None = None,
    host: str = "0.0.0.0",
    port: int = 8080,
) -> Any:
    """Create security-hardened FastAPI app with React SPA + JSON API."""
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError:
        raise ImportError(
            "FastAPI required for web UI. "
            "Install: pip install 'eresus-sentinel[web]'"
        )

    from sentinel import __version__
    from sentinel.firewall.async_pipeline import AsyncFirewallPipeline
    from sentinel.policy import PolicyEngine
    from sentinel.web import (
        routes_artifact,
        routes_auth,
        routes_deception,
        routes_extra,
        routes_firewall,
        routes_info,
        routes_scan,
        routes_users,
    )
    from sentinel.web.middleware import (
        RateLimitMiddleware,
        SecurityHeadersMiddleware,
        create_auth_middleware,
    )
    from sentinel.web.state import AppState

    # ── State ────────────────────────────────────────────────────

    engine = PolicyEngine.from_file(policy_path) if policy_path else PolicyEngine.default()
    state = AppState(
        engine,
        AsyncFirewallPipeline(engine.build_input_pipeline()),
        AsyncFirewallPipeline(engine.build_output_pipeline()),
    )

    # ── App Init ─────────────────────────────────────────────────

    app = FastAPI(
        title="Eresus Sentinel API",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    # Global exception handler — never leak stack traces
    @app.exception_handler(Exception)
    async def _global_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        env = os.environ.get("SENTINEL_ENV", "production")
        detail = str(exc) if env == "development" else "Internal server error"
        return JSONResponse(status_code=500, content={"detail": detail})

    # Middleware (Starlette runs the last added middleware outermost).
    app.add_middleware(RateLimitMiddleware)
    AuthMiddleware = create_auth_middleware(state)
    app.add_middleware(AuthMiddleware)

    # CORS
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
    app.add_middleware(SecurityHeadersMiddleware)

    # ── Register Routers ─────────────────────────────────────────

    routes_auth.init(state)
    routes_firewall.init(state)
    routes_artifact.init(state)
    routes_info.init(state, __version__)
    routes_users.init(state)
    routes_deception.init(state)

    app.include_router(routes_auth.router)
    app.include_router(routes_users.router)
    app.include_router(routes_firewall.router)
    app.include_router(routes_artifact.router)
    app.include_router(routes_scan.router)
    app.include_router(routes_info.router)
    app.include_router(routes_extra.router)
    app.include_router(routes_deception.router)

    # Duplicate /health at root level (no /api prefix)
    @app.get("/health")
    async def root_health():
        from sentinel.web.routes_info import health
        return await health()

    # ── SPA Serving ──────────────────────────────────────────────

    if _DIST_DIR.is_dir() and (_DIST_DIR / "index.html").is_file():
        assets_dir = _DIST_DIR / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/{path:path}")
        async def spa_fallback(path: str):
            if ".." in path or path.startswith("/"):
                raise HTTPException(status_code=400, detail="Invalid path")
            if path:
                file_path = (_DIST_DIR / path).resolve()
                if file_path.is_file() and str(file_path).startswith(str(_DIST_DIR.resolve())):
                    return FileResponse(file_path)
            return FileResponse(_DIST_DIR / "index.html")
    else:
        @app.get("/{path:path}")
        async def spa_missing(path: str):
            if path.startswith("api/") or path == "health":
                raise HTTPException(status_code=404, detail="Not found")
            return HTMLResponse(
                status_code=503,
                content=(
                    "<!doctype html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Eresus Sentinel Dashboard</title>"
                    "<style>body{font-family:system-ui,sans-serif;background:#0b0f19;"
                    "color:#e5e7eb;margin:0;display:grid;place-items:center;min-height:100vh}"
                    "main{max-width:720px;padding:32px}code{background:#111827;"
                    "padding:2px 6px;border-radius:4px}</style></head><body><main>"
                    "<h1>Dashboard frontend is not built</h1>"
                    "<p>The Sentinel API is running, but the React dashboard assets "
                    "are missing from <code>python/sentinel/web/dist</code>.</p>"
                    "<p>Build with Node.js 20.19+:</p>"
                    "<pre><code>cd frontend\nnpm install\nnpm run build</code></pre>"
                    "<p>API docs remain available at <code>/api/docs</code>.</p>"
                    "</main></body></html>"
                ),
            )

    return app
