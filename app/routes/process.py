"""
process.py (route)
==================
POST /v1/process — Full end-to-end pipeline.
Guard → LLM → Rehydrate → Response Scan → Return.
"""

from fastapi import APIRouter, Request

from app.contracts.api import ProcessRequest, ProcessResponse
from app.contracts.enums import BlockReason, EventType
from app.security import SecurityValidator

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["process"])


@router.post("/process", response_model=ProcessResponse)
async def process_endpoint(req: ProcessRequest, request: Request):
    """
    Full end-to-end pipeline:
      1. Guard (all phases)
      2. LLM call (clean prompt only)
      3. Rehydrate (restore PII into response)
      4. Response scan (check for leaked PII in LLM output)
    """
    # Validate input
    try:
        SecurityValidator.validate_prompt_length(req.prompt, request.app.state.settings.max_prompt_length)
    except Exception as e:
        logger.warning("invalid_prompt_input", error=str(e))
        raise
    
    pipeline = request.app.state.pipeline
    llm_router = request.app.state.llm_router
    rehydrator = request.app.state.rehydrator
    response_scanner = request.app.state.response_scanner
    event_emitter = request.app.state.event_emitter

    # ── Step 1: Guard ────────────────────────────────────────────────────────
    guard_result = await pipeline.guard(req.prompt)

    if guard_result.blocked:
        # Emit telemetry for blocked prompt
        event_emitter.queue_event(
            guard_result=guard_result,
            model_requested=req.model_requested,
            model_allowed=False,
            org_id=req.org_id,
            user_id=req.user_id,
            event_type=EventType.GUARD_BLOCKED,
        )

        return ProcessResponse(
            response=f"[BLOCKED] {guard_result.block_reason.value if guard_result.block_reason else 'unknown'}: {guard_result.block_detail or ''}",
            blocked=True,
            block_reason=guard_result.block_reason,
            block_detail=guard_result.block_detail,
            pii_types_found=[d.pii_type.value for d in guard_result.pii_detections],
            injection_detected=guard_result.injection_detected,
            ml_guard_score=guard_result.ml_guard_score,
            latency_ms=guard_result.latency_ms,
        )

    # ── Step 2: Model allowlist check ──────────────────────────────────────────
    policy = pipeline.policy_engine.get_policy()
    if policy and req.model_requested not in policy.allowed_models:
        logger.warning(
            "model_not_allowed",
            model=req.model_requested,
            allowed=policy.allowed_models,
        )
        return ProcessResponse(
            response=f"[BLOCKED] Model '{req.model_requested}' is not in the allowed model list.",
            blocked=True,
            block_reason=BlockReason.MODEL_NOT_ALLOWED,
            block_detail=f"Allowed models: {policy.allowed_models}",
            pii_types_found=[d.pii_type.value for d in guard_result.pii_detections],
            ml_guard_score=guard_result.ml_guard_score,
            latency_ms=guard_result.latency_ms,
        )

    # ── Step 3: LLM call ─────────────────────────────────────────────────────
    try:
        llm_response = await llm_router.call(
            clean_prompt=guard_result.clean_text,
            model_requested=req.model_requested,
        )
    except Exception as e:
        logger.error("llm_call_failed_in_process", error_type=type(e).__name__)
        safe_error_msg = SecurityValidator.sanitize_error_message(e)
        return ProcessResponse(
            response=f"[LLM ERROR] {safe_error_msg}",
            blocked=False,
            pii_types_found=[d.pii_type.value for d in guard_result.pii_detections],
            ml_guard_score=guard_result.ml_guard_score,
            latency_ms=guard_result.latency_ms,
        )

    # ── Step 4: Response scan ────────────────────────────────────────────────
    scanned_response, response_pii_types, system_leak = response_scanner.scan(
        llm_response
    )

    if system_leak:
        logger.warning("system_prompt_leak_blocked_in_response")
        scanned_response = "[RESPONSE REDACTED — system prompt leak detected]"

    # ── Step 5: Rehydrate ────────────────────────────────────────────────────
    final_response = rehydrator.restore(scanned_response, guard_result.placeholder_map)

    # ── Emit telemetry ───────────────────────────────────────────────────────
    event_emitter.queue_event(
        guard_result=guard_result,
        model_requested=req.model_requested,
        model_allowed=True,
        org_id=req.org_id,
        user_id=req.user_id,
        event_type=EventType.PROMPT_SENT,
    )

    return ProcessResponse(
        response=final_response,
        blocked=False,
        pii_types_found=[d.pii_type.value for d in guard_result.pii_detections],
        injection_detected=guard_result.injection_detected,
        ml_guard_score=guard_result.ml_guard_score,
        latency_ms=guard_result.latency_ms,
        response_pii_found=response_pii_types,
    )
