"""Path-based scan routes — sast, agent, supply-chain, diff, notebook, redteam, secrets, dep-scan."""

import logging
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException

from sentinel.web.helpers import finding_to_dict, validate_scan_path
from sentinel.web.models import (
    DepScanRequest,
    DiffScanRequest,
    RedTeamRequest,
    SastScanRequest,
    SecretsScanRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["scan"])


def _scan_response(raw, start):
    elapsed = (time.perf_counter() - start) * 1000
    findings = [finding_to_dict(f) for f in raw]
    return {"findings": findings, "count": len(findings), "latency_ms": round(elapsed, 1)}


# ── SAST ──────────────────────────────────────────────────────

@router.post("/sast/scan")
async def sast_scan(body: SastScanRequest):
    from sentinel.cli_dispatch import dispatch_sast
    safe_path = validate_scan_path(body.path)
    try:
        start = time.perf_counter()
        raw = dispatch_sast(safe_path)
        return _scan_response(raw, start)
    except HTTPException:
        raise
    except Exception:
        logger.exception("SAST scan error")
        raise HTTPException(status_code=500, detail="SAST scan engine error")


# ── Agent / MCP ───────────────────────────────────────────────

@router.post("/agent/scan")
async def agent_scan(body: SastScanRequest):
    from sentinel.cli_dispatch import dispatch_agent
    safe_path = validate_scan_path(body.path)
    try:
        start = time.perf_counter()
        raw = dispatch_agent(safe_path)
        return _scan_response(raw, start)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Agent scan error")
        raise HTTPException(status_code=500, detail="Agent scan engine error")


# ── Supply Chain ──────────────────────────────────────────────

@router.post("/supply-chain/scan")
async def supply_chain_scan(body: SastScanRequest):
    from sentinel.cli_dispatch import dispatch_supply_chain
    safe_path = validate_scan_path(body.path)
    try:
        start = time.perf_counter()
        raw = dispatch_supply_chain(safe_path)
        return _scan_response(raw, start)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Supply chain scan error")
        raise HTTPException(status_code=500, detail="Supply chain scan engine error")


# ── Diff ──────────────────────────────────────────────────────

@router.post("/diff/scan")
async def diff_scan(body: DiffScanRequest):
    from sentinel.cli_dispatch import dispatch_diff
    try:
        start = time.perf_counter()
        raw = dispatch_diff(body.target)
        return _scan_response(raw, start)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Diff scan error")
        raise HTTPException(status_code=500, detail="Diff scan engine error")


# ── Notebook ──────────────────────────────────────────────────

@router.post("/notebook/scan")
async def notebook_scan(body: SastScanRequest):
    from sentinel.cli_dispatch import dispatch_notebook
    safe_path = validate_scan_path(body.path)
    try:
        start = time.perf_counter()
        raw = dispatch_notebook(safe_path)
        return _scan_response(raw, start)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Notebook scan error")
        raise HTTPException(status_code=500, detail="Notebook scan engine error")


# ── Red Team ──────────────────────────────────────────────────

@router.post("/redteam/scan")
async def redteam_scan(body: RedTeamRequest):
    from sentinel.cli_dispatch import dispatch_redteam
    try:
        start = time.perf_counter()
        raw = dispatch_redteam(body.target)
        return _scan_response(raw, start)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Red team scan error")
        raise HTTPException(status_code=500, detail="Red team scan engine error")


# ── Secrets ───────────────────────────────────────────────────

@router.post("/secrets/scan")
async def secrets_scan(body: SecretsScanRequest):
    from sentinel.sast.secrets_scanner import SecretsScanner
    safe_path = validate_scan_path(body.path)
    try:
        start = time.perf_counter()
        scanner = SecretsScanner(enable_entropy=body.enable_entropy)
        p = Path(safe_path)
        raw = scanner.scan_directory(str(p)) if p.is_dir() else scanner.scan_file(str(p))
        if body.git_history:
            raw.extend(scanner.scan_git_history(str(p)))
        raw.extend(scanner.scan_config_files(str(p)))
        return _scan_response(raw, start)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Secrets scan error")
        raise HTTPException(status_code=500, detail="Secrets scan engine error")


# ── Dep Scan ──────────────────────────────────────────────────

@router.post("/dep-scan/scan")
async def dep_scan(body: DepScanRequest):
    from sentinel.supply_chain.live_scanner import LiveDependencyScanner
    safe_path = validate_scan_path(body.path)
    try:
        start = time.perf_counter()
        scanner = LiveDependencyScanner(ecosystem=body.ecosystem)
        raw = scanner.full_audit(safe_path)
        return _scan_response(raw, start)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Dep scan error")
        raise HTTPException(status_code=500, detail="Dependency scan engine error")
