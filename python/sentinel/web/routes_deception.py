"""Deception guardrail routes — check, session, and feedback endpoints."""

import logging
import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sentinel.firewall.deception.engine import Action, DeceptionGuardrail, GuardrailResult
from sentinel.web.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/deception", tags=["deception"])

_state: AppState = None  # type: ignore[assignment]
_guard: DeceptionGuardrail | None = None


def init(state: AppState):
    global _state, _guard
    _state = state
    _guard = DeceptionGuardrail()
    logger.info("Deception guardrail initialized")


def _get_guard() -> DeceptionGuardrail:
    if _guard is None:
        raise HTTPException(status_code=503, detail="Deception guardrail not initialized")
    return _guard


# ── Request / Response models ─────────────────────────────────

class CheckRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    query: str = Field(..., min_length=1, max_length=16384)


class CheckResponse(BaseModel):
    query_id: str
    action: str
    threat_category: str
    score: float
    reason: str
    system_preamble: str | None = None
    decoy_id: str | None = None
    session_cumulative_score: float
    blocked_reason: str | None = None
    elapsed_ms: float = 0.0


class FeedbackRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    score: float = Field(..., ge=0.0, le=100.0)


class FeedbackResponse(BaseModel):
    session_id: str
    new_cumulative_score: float


class RecordResponseRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    query_id: str = Field(..., min_length=1, max_length=64)
    response: str = Field(..., min_length=1, max_length=8192)
    requeried: bool = False


class SessionResponse(BaseModel):
    session_id: str
    cumulative_score: float
    history: list


# ── Routes ────────────────────────────────────────────────────

@router.post("/check", response_model=CheckResponse)
def check_query(req: CheckRequest):
    """Score a query through the deception guardrail detector stack."""
    guard = _get_guard()
    t0 = time.perf_counter()
    result = guard.check(session_id=req.session_id, query=req.query)
    elapsed = (time.perf_counter() - t0) * 1000

    return CheckResponse(
        query_id=result.query_id,
        action=result.action.value,
        threat_category=result.custom_category_name or result.threat_category.value,
        score=result.score,
        reason=result.reason,
        system_preamble=result.system_preamble,
        decoy_id=result.decoy_id,
        session_cumulative_score=result.session_cumulative_score,
        blocked_reason=result.blocked_reason,
        elapsed_ms=round(elapsed, 2),
    )


@router.get("/session/{session_id}", response_model=SessionResponse)
def get_session(session_id: str):
    """Retrieve session history and cumulative score (defender-only endpoint)."""
    guard = _get_guard()
    return SessionResponse(
        session_id=session_id,
        cumulative_score=guard.session_score(session_id),
        history=guard.session_history(session_id),
    )


@router.delete("/session/{session_id}")
def reset_session(session_id: str):
    """Reset a session's cumulative score and history."""
    guard = _get_guard()
    guard.reset_session(session_id)
    return {"status": "ok", "session_id": session_id}


@router.post("/feedback", response_model=FeedbackResponse)
def record_feedback(req: FeedbackRequest):
    """Add a soft refusal signal to the session score without a full query detection cycle."""
    guard = _get_guard()
    new_score = guard.record_feedback_score(req.session_id, req.score)
    return FeedbackResponse(
        session_id=req.session_id,
        new_cumulative_score=new_score,
    )


@router.post("/record-response")
def record_response(req: RecordResponseRequest):
    """Store the final response served to a DECEIVE-flagged query for threat-hunting."""
    guard = _get_guard()
    guard.record_response(
        session_id=req.session_id,
        query_id=req.query_id,
        response=req.response,
        requeried=req.requeried,
    )
    return {"status": "ok"}
