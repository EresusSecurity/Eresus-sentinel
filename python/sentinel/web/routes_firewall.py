"""Firewall scan routes — single scan and batch scan."""

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sentinel.firewall.batch import batch_scan
from sentinel.web.helpers import safe_str
from sentinel.web.models import FirewallScanRequest
from sentinel.web.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/firewall", tags=["firewall"])

_state: AppState = None  # type: ignore[assignment]


def init(state: AppState):
    global _state
    _state = state


# ── Helpers ────────────────────────────────────────────────────

def _serialize_result(result, scan_type: str, prompt: str, elapsed_ms: float) -> dict:
    findings = []
    for f in result.findings:
        findings.append({
            "rule_id":    safe_str(str(getattr(f, "rule_id", "")), 100),
            "title":      safe_str(str(getattr(f, "title", "")), 200),
            "severity":   safe_str(
                f.severity.name if hasattr(f.severity, "name") else str(f.severity), 10
            ),
            "confidence": min(1.0, max(0.0, float(getattr(f, "confidence", 0.0)))),
            "description": safe_str(str(getattr(f, "description", "")), 500),
            "evidence":   safe_str(str(getattr(f, "evidence", "")), 300),
        })
    return {
        "id":            uuid.uuid4().hex[:12],
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "type":          scan_type,
        "prompt":        safe_str(prompt, 500),
        "action":        safe_str(
            result.action.name if hasattr(result.action, "name") else str(result.action), 20
        ),
        "risk_score":    round(min(1.0, max(0.0, result.risk_score)), 3),
        "finding_count": len(findings),
        "findings":      findings,
        "latency_ms":    round(elapsed_ms, 1),
    }


# ── Single scan ────────────────────────────────────────────────

@router.post("/scan")
async def firewall_scan(body: FirewallScanRequest):
    start = time.perf_counter()
    try:
        pipe = _state.input_pipe if body.scan_type == "input" else _state.output_pipe
        result = await pipe.scan(body.prompt)
    except Exception:
        logger.exception("Scan engine error")
        raise HTTPException(status_code=500, detail="Scan engine error")

    entry = _serialize_result(result, body.scan_type, body.prompt,
                              (time.perf_counter() - start) * 1000)
    _state.scan_history.append(entry)
    _state.trim_history()
    return entry


# ── Batch scan ─────────────────────────────────────────────────

class BatchScanRequest(BaseModel):
    prompts: List[str] = Field(..., max_length=100)
    scan_type: str = Field("input", pattern="^(input|output)$")


@router.post("/scan/batch")
async def firewall_batch_scan(body: BatchScanRequest):
    if not body.prompts:
        raise HTTPException(status_code=400, detail="No prompts provided")
    pipe = _state.input_pipe if body.scan_type == "input" else _state.output_pipe
    start = time.perf_counter()
    try:
        results = await batch_scan(pipe, body.prompts)
    except Exception:
        logger.exception("Batch scan error")
        raise HTTPException(status_code=500, detail="Batch scan error")
    total_ms = (time.perf_counter() - start) * 1000

    entries = []
    for prompt, result in zip(body.prompts, results):
        entry = _serialize_result(result, body.scan_type, prompt, total_ms / len(results))
        _state.scan_history.append(entry)
        entries.append(entry)
    _state.trim_history()
    return {"total_latency_ms": round(total_ms, 1), "results": entries}

