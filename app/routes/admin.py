"""
admin.py (route)
================
GET /v1/logs    — Audit log retrieval (requires API key)
GET /v1/metrics — Prometheus-style metrics (requires API key)
POST /v1/rehydrate — Standalone rehydration endpoint
"""

import sqlite3
from pathlib import Path

from fastapi import APIRouter, Request, Depends, Header

from app.contracts.api import RehydrateRequest, RehydrateResponse
from app.security import SecurityValidator

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["admin"])

EVENTS_DB = Path("foretyx_events.db")


@router.get("/logs")
async def get_logs(limit: int = 50, authorization: str = Header(None), request: Request = None):
    """
    Retrieve recent telemetry events from the local audit log.
    Requires valid API key in Authorization header.
    Note: These logs contain ONLY metadata — no prompts, no PII.
    """
    # Validate API key
    api_key = SecurityValidator.validate_api_key(authorization)
    admin_api_key = request.app.state.settings.admin_api_key.get_secret_value()
    
    if api_key != admin_api_key:
        logger.warning("unauthorized_logs_access_attempt", ip=request.client.host if request.client else "unknown")
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )
    
    # Limit parameter validation
    limit = min(max(limit, 1), 200)
    
    if not EVENTS_DB.exists():
        return {"events": [], "total": 0}

    try:
        conn = sqlite3.connect(str(EVENTS_DB))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, event_json, created_at, sent FROM outbound_events "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {"events": rows, "total": len(rows)}
    except Exception as e:
        logger.error("logs_retrieval_error", error=type(e).__name__)
        return {"error": "Failed to retrieve logs"}


@router.get("/metrics")
async def get_metrics(authorization: str = Header(None), request: Request = None):
    """
    Prometheus-compatible metrics endpoint.
    Requires valid API key in Authorization header.
    Returns counters and gauges for monitoring dashboards.
    """
    # Validate API key
    api_key = SecurityValidator.validate_api_key(authorization)
    admin_api_key = request.app.state.settings.admin_api_key.get_secret_value()
    
    if api_key != admin_api_key:
        logger.warning("unauthorized_metrics_access_attempt", ip=request.client.host if request.client else "unknown")
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )
    
    if not EVENTS_DB.exists():
        return {
            "total_requests": 0,
            "blocked_requests": 0,
            "passed_requests": 0,
            "pending_events": 0,
        }

    try:
        conn = sqlite3.connect(str(EVENTS_DB))
        cursor = conn.cursor()

        total = cursor.execute(
            "SELECT COUNT(*) FROM outbound_events"
        ).fetchone()[0]

        pending = cursor.execute(
            "SELECT COUNT(*) FROM outbound_events WHERE sent=0"
        ).fetchone()[0]

        blocked = cursor.execute(
            "SELECT COUNT(*) FROM outbound_events WHERE event_json LIKE '%guard_blocked%'"
        ).fetchone()[0]

        conn.close()

        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "passed_requests": total - blocked,
            "pending_events": pending,
            "block_rate_pct": round(
                (blocked / total * 100) if total > 0 else 0, 2
            ),
        }
    except Exception as e:
        logger.error("metrics_retrieval_error", error=type(e).__name__)
        return {"error": "Failed to retrieve metrics"}


@router.post("/rehydrate", response_model=RehydrateResponse)
async def rehydrate_endpoint(req: RehydrateRequest, request: Request):
    """
    Standalone rehydration endpoint.
    Restores original PII values into an LLM response using the placeholder map.
    """
    rehydrator = request.app.state.rehydrator
    restored = rehydrator.restore(req.llm_response, req.placeholder_map)
    return RehydrateResponse(restored_response=restored)
