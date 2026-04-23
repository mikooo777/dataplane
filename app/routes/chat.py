"""
chat.py (route)
===============
POST /v1/chat — Multi-turn conversation endpoint (Guide Section 2.1).

Manages session state in memory (keyed by session_id).
Each turn runs the full guard pipeline on the new message only,
then appends the clean turn to the session history before sending to Gemini.

Session lifecycle:
  - Created on first message with a session_id
  - Each subsequent call with the same session_id continues the conversation
  - Sessions auto-expire after session_timeout_minutes (from policy)
"""

import time
from collections import defaultdict
from typing import Optional

import structlog
from fastapi import APIRouter, Request

from app.contracts.api import GuardRequest
from app.contracts.enums import BlockReason, EventType
from app.security import SecurityValidator
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["chat"])


# ── In-memory session store ───────────────────────────────────────────────────
# {session_id: {"history": [...], "last_activity": float, "org_id": str, "user_id": str}}
_SESSIONS: dict[str, dict] = defaultdict(lambda: {
    "history": [],
    "last_activity": time.time(),
    "org_id": "unknown",
    "user_id": "unknown",
})

SESSION_TIMEOUT_SECONDS = 3600  # 1 hour default


# ── Request / Response schemas ────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str = Field(..., description="'user' or 'assistant'")
    content: str


class ChatRequest(BaseModel):
    """POST /v1/chat — multi-turn conversation with full guard pipeline."""
    session_id:      str = Field(..., description="Unique session identifier")
    message:         str = Field(..., description="The user's new message")
    model_requested: str = Field("gemini-2.0-flash")
    org_id:          str = "org_default"
    user_id:         str = "user_anonymous"
    system_prompt:   Optional[str] = Field(
        None,
        description="Optional system prompt (only applied on first turn of session)"
    )


class ChatResponse(BaseModel):
    """Response from /v1/chat."""
    session_id:         str
    response:           str
    blocked:            bool = False
    block_reason:       Optional[BlockReason] = None
    block_detail:       Optional[str] = None
    pii_types_found:    list[str] = Field(default_factory=list)
    injection_detected: bool = False
    ml_guard_score:     float = 0.0
    latency_ms:         float = 0.0
    turn_number:        int = 1


def _prune_expired_sessions():
    """Remove sessions that have been idle longer than SESSION_TIMEOUT_SECONDS."""
    now = time.time()
    expired = [
        sid for sid, sess in _SESSIONS.items()
        if now - sess["last_activity"] > SESSION_TIMEOUT_SECONDS
    ]
    for sid in expired:
        del _SESSIONS[sid]
        logger.info("session_expired", session_id=sid)


def _build_multi_turn_prompt(history: list[ChatMessage], new_user_message: str) -> str:
    """
    Flatten conversation history into a single prompt string for Gemini.
    Format:
        User: ...
        Assistant: ...
        User: <new message>
    """
    parts = []
    for msg in history:
        role = "User" if msg.role == "user" else "Assistant"
        parts.append(f"{role}: {msg['content']}")
    parts.append(f"User: {new_user_message}")
    return "\n".join(parts)


@router.post("/chat", response_model=ChatResponse)
async def chat_endpoint(req: ChatRequest, request: Request):
    """
    Multi-turn chat with full guard pipeline on every turn.

    Flow per turn:
      1. Guard pipeline on the new user message
      2. If blocked → return blocked response (session preserved for context)
      3. Build multi-turn prompt from session history + new message
      4. LLM call with full history context
      5. Response scan
      6. Rehydrate
      7. Append both turns to session history
    """
    t0 = time.time()

    # Input validation
    try:
        SecurityValidator.validate_prompt_length(
            req.message,
            request.app.state.settings.max_prompt_length
        )
    except Exception as e:
        logger.warning("chat_invalid_input", error=str(e))
        raise

    # Prune expired sessions periodically
    _prune_expired_sessions()

    pipeline        = request.app.state.pipeline
    llm_router      = request.app.state.llm_router
    rehydrator      = request.app.state.rehydrator
    response_scanner = request.app.state.response_scanner
    event_emitter   = request.app.state.event_emitter

    # Retrieve or initialise session
    session = _SESSIONS[req.session_id]
    session["last_activity"] = time.time()
    session["org_id"]        = req.org_id
    session["user_id"]       = req.user_id
    turn_number = len(session["history"]) // 2 + 1  # each turn = user + assistant

    logger.info(
        "chat_turn_started",
        session_id=req.session_id,
        turn=turn_number,
        message_length=len(req.message),
    )

    # ── Step 1: Guard the new user message ───────────────────────────────────
    guard_result = await pipeline.guard(req.message)

    if guard_result.blocked:
        event_emitter.queue_event(
            guard_result=guard_result,
            model_requested=req.model_requested,
            model_allowed=False,
            org_id=req.org_id,
            user_id=req.user_id,
            event_type=EventType.GUARD_BLOCKED,
        )
        return ChatResponse(
            session_id=req.session_id,
            response=f"[BLOCKED] {guard_result.block_reason.value}: {guard_result.block_detail or ''}",
            blocked=True,
            block_reason=guard_result.block_reason,
            block_detail=guard_result.block_detail,
            pii_types_found=[d.pii_type.value for d in guard_result.pii_detections],
            injection_detected=guard_result.injection_detected,
            ml_guard_score=guard_result.ml_guard_score,
            latency_ms=(time.time() - t0) * 1000,
            turn_number=turn_number,
        )

    # ── Step 2: Model allowlist check ────────────────────────────────────────
    policy = pipeline.policy_engine.get_policy()
    if policy and req.model_requested not in policy.allowed_models:
        return ChatResponse(
            session_id=req.session_id,
            response=f"[BLOCKED] Model '{req.model_requested}' is not allowed.",
            blocked=True,
            block_reason=BlockReason.MODEL_NOT_ALLOWED,
            block_detail=f"Allowed: {policy.allowed_models}",
            latency_ms=(time.time() - t0) * 1000,
            turn_number=turn_number,
        )

    # ── Step 3: Build multi-turn prompt ──────────────────────────────────────
    # Prepend system prompt if this is the first turn
    history = session["history"]
    if req.system_prompt and not history:
        multi_turn_prompt = (
            f"System: {req.system_prompt}\n"
            + _build_multi_turn_prompt(history, guard_result.clean_text)
        )
    else:
        multi_turn_prompt = _build_multi_turn_prompt(history, guard_result.clean_text)

    # ── Step 4: LLM call ─────────────────────────────────────────────────────
    try:
        llm_response = await llm_router.call(
            clean_prompt=multi_turn_prompt,
            model_requested=req.model_requested,
        )
    except Exception as e:
        logger.error("chat_llm_failed", error_type=type(e).__name__)
        safe_msg = SecurityValidator.sanitize_error_message(e)
        return ChatResponse(
            session_id=req.session_id,
            response=f"[LLM ERROR] {safe_msg}",
            blocked=False,
            pii_types_found=[d.pii_type.value for d in guard_result.pii_detections],
            ml_guard_score=guard_result.ml_guard_score,
            latency_ms=(time.time() - t0) * 1000,
            turn_number=turn_number,
        )

    # ── Step 5: Response scan ────────────────────────────────────────────────
    scanned_response, response_pii, system_leak = response_scanner.scan(llm_response)
    if system_leak:
        scanned_response = "[RESPONSE REDACTED — system prompt leak detected]"

    # ── Step 6: Rehydrate ─────────────────────────────────────────────────────
    final_response = rehydrator.restore(scanned_response, guard_result.placeholder_map)

    # ── Step 7: Update session history ───────────────────────────────────────
    session["history"].append({"role": "user",      "content": guard_result.clean_text})
    session["history"].append({"role": "assistant", "content": final_response})

    # Trim history to last 20 turns (40 messages) to avoid token bloat
    if len(session["history"]) > 40:
        session["history"] = session["history"][-40:]

    # Emit telemetry
    event_emitter.queue_event(
        guard_result=guard_result,
        model_requested=req.model_requested,
        model_allowed=True,
        org_id=req.org_id,
        user_id=req.user_id,
        event_type=EventType.PROMPT_SENT,
    )

    latency_ms = (time.time() - t0) * 1000
    logger.info(
        "chat_turn_completed",
        session_id=req.session_id,
        turn=turn_number,
        latency_ms=round(latency_ms, 2),
    )

    return ChatResponse(
        session_id=req.session_id,
        response=final_response,
        blocked=False,
        pii_types_found=[d.pii_type.value for d in guard_result.pii_detections],
        injection_detected=guard_result.injection_detected,
        ml_guard_score=guard_result.ml_guard_score,
        latency_ms=latency_ms,
        turn_number=turn_number,
    )


@router.delete("/chat/{session_id}")
async def end_chat_session(session_id: str):
    """Explicitly terminate a chat session and free its memory."""
    if session_id in _SESSIONS:
        del _SESSIONS[session_id]
        logger.info("session_deleted", session_id=session_id)
        return {"status": "session_terminated", "session_id": session_id}
    return {"status": "session_not_found", "session_id": session_id}


@router.get("/chat/{session_id}/history")
async def get_chat_history(session_id: str):
    """Return the conversation history for a session (clean text only, no PII)."""
    if session_id not in _SESSIONS:
        return {"session_id": session_id, "history": [], "turn_count": 0}
    session = _SESSIONS[session_id]
    return {
        "session_id": session_id,
        "history": session["history"],
        "turn_count": len(session["history"]) // 2,
    }
