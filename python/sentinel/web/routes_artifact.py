"""Artifact upload + scan route."""

import hashlib
import logging
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from sentinel.web.helpers import safe_str
from sentinel.web.state import ALLOWED_UPLOAD_EXTENSIONS, MAX_UPLOAD_SIZE, AppState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/artifacts", tags=["artifacts"])

_state: AppState = None  # type: ignore[assignment]


def init(state: AppState):
    global _state
    _state = state


@router.post("/scan")
async def artifact_scan(file: UploadFile = File(...)):
    from sentinel.cli_dispatch import dispatch_artifact

    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename required")

    safe_name = Path(file.filename).name
    if not safe_name or safe_name.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    suffix = Path(safe_name).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {suffix}. Allowed: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}",
        )

    start = time.perf_counter()
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum: {MAX_UPLOAD_SIZE // (1024*1024)}MB",
        )
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=f"_{safe_name}", prefix="sentinel_scan_",
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        os.chmod(tmp_path, 0o600)

        findings_raw = dispatch_artifact(tmp_path)
        elapsed = (time.perf_counter() - start) * 1000

        from sentinel.web.helpers import finding_to_dict
        findings = [finding_to_dict(f) for f in findings_raw]

        entry = {
            "id": uuid.uuid4().hex[:12],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "filename": safe_str(safe_name, 255),
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
        _state.artifact_history.append(entry)
        _state.trim_history()
        return entry

    except HTTPException:
        raise
    except Exception:
        logger.exception("Artifact scan error")
        raise HTTPException(status_code=500, detail="Artifact scan engine error")
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
