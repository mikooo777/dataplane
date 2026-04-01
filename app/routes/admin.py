"""
admin.py (route)
================
GET /v1/logs    — Audit log retrieval
GET /v1/metrics — Prometheus-style metrics
POST /v1/rehydrate — Standalone rehydration endpoint
"""

import sqlite3
from pathlib import Path

from fastapi import APIRouter, Request

from app.contracts.api import RehydrateRequest, RehydrateResponse

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["admin"])

EVENTS_DB = Path("foretyx_events.db")


@router.get("/logs")
async def get_logs(limit: int = 50):
    """
    Retrieve recent telemetry events from the local audit log.
    Note: These logs contain ONLY metadata — no prompts, no PII.
    """
    if not EVENTS_DB.exists():
        return {"events": [], "total": 0}

    try:
        conn = sqlite3.connect(str(EVENTS_DB))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, event_json, created_at, sent FROM outbound_events "
            "ORDER BY created_at DESC LIMIT ?",
            (min(limit, 200),),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {"events": rows, "total": len(rows)}
    except Exception as e:
        logger.error("logs_retrieval_error", error=str(e))
        return {"error": str(e)}


@router.get("/metrics")
async def get_metrics(request: Request):
    """
    Prometheus-compatible metrics endpoint.
    Returns counters and gauges for monitoring dashboards.
    """
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
        logger.error("metrics_retrieval_error", error=str(e))
        return {"error": str(e)}


@router.post("/rehydrate", response_model=RehydrateResponse)
async def rehydrate_endpoint(req: RehydrateRequest, request: Request):
    """
    Standalone rehydration endpoint.
    Restores original PII values into an LLM response using the placeholder map.
    """
    rehydrator = request.app.state.rehydrator
    restored = rehydrator.restore(req.llm_response, req.placeholder_map)
    return RehydrateResponse(restored_response=restored)
