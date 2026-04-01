"""
guard.py (route)
================
POST /v1/guard — Guard-only check (no LLM call).
Returns GuardResult so the bridge can decide whether to forward to the LLM.
"""

from fastapi import APIRouter, Request

from app.contracts.api import GuardRequest, GuardResponse

router = APIRouter(prefix="/v1", tags=["guard"])


@router.post("/guard", response_model=GuardResponse)
async def guard_endpoint(req: GuardRequest, request: Request):
    """
    Run the full guard pipeline on a raw prompt.
    Does NOT call the LLM — returns the guard verdict only.
    Use this when the bridge layer handles the LLM call separately.
    """
    pipeline = request.app.state.pipeline

    result = await pipeline.guard(req.prompt)

    return GuardResponse(
        clean_text=result.clean_text,
        blocked=result.blocked,
        block_reason=result.block_reason,
        block_detail=result.block_detail,
        pii_types_found=[d.pii_type.value for d in result.pii_detections],
        pii_count=len(result.pii_detections),
        injection_detected=result.injection_detected,
        ml_guard_score=result.ml_guard_score,
        latency_ms=result.latency_ms,
        phase_timings=result.phase_timings,
        placeholder_map=result.placeholder_map,
    )
