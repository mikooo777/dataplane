"""
admin.py (route)
================
GET /v1/logs    — Audit log retrieval with filter params (Section 2.3)
GET /v1/metrics — Prometheus-style metrics (requires API key)
POST /v1/rehydrate — Standalone rehydration endpoint
GET /v1/rate-limit/{org_id}/{user_id} — Per-user rate limit stats (Section 2.4)
DELETE /v1/rate-limit/{org_id}/{user_id} — Reset a user's rate limit (admin)
GET /v1/owasp-coverage — OWASP LLM Top 10 coverage report (Section 3.3)
"""

import hmac
import json
import sqlite3
from pathlib import Path
from typing import Optional

import structlog
from fastapi import APIRouter, HTTPException, Request, Header, Query, status, Depends

from app.contracts.api import RehydrateRequest, RehydrateResponse
from app.security import SecurityValidator
from app.security_mtls import require_mtls

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["admin"], dependencies=[Depends(require_mtls)])

EVENTS_DB = Path("foretyx_events.db")


def _validate_admin(authorization: Optional[str], request: Request) -> str:
    """Shared helper: validates admin API key.

    P1 Fix: Uses hmac.compare_digest() instead of == to prevent timing attacks.
    A naive == comparison leaks which bytes of the key are correct; constant-time
    comparison closes that side channel.
    """
    api_key = SecurityValidator.validate_api_key(authorization)
    admin_api_key = request.app.state.settings.admin_api_key.get_secret_value()
    # Constant-time comparison — eliminates timing oracle
    if not hmac.compare_digest(api_key.encode(), admin_api_key.encode()):
        logger.warning(
            "unauthorized_admin_access",
            ip=request.client.host if request.client else "unknown",
            path=str(request.url.path),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )
    return api_key


@router.get("/logs")
async def get_logs(
    # Section 2.3 — filter params
    limit:       int            = Query(50, ge=1, le=200,  description="Max events to return"),
    offset:      int            = Query(0,  ge=0,           description="Pagination offset"),
    event_type:  Optional[str]  = Query(None,               description="Filter by event_type (e.g. 'guard_blocked')"),
    org_id:      Optional[str]  = Query(None,               description="Filter by org_id"),
    user_id:     Optional[str]  = Query(None,               description="Filter by user_id"),
    blocked_only: bool          = Query(False,               description="Return only blocked events"),
    sent:        Optional[bool] = Query(None,               description="Filter by sent status (True=flushed, False=pending)"),
    since:       Optional[str]  = Query(None,               description="ISO 8601 timestamp — return events after this time"),
    authorization: Optional[str] = Header(None),
    request: Request = None,
):
    """
    Retrieve telemetry events from the local audit log with filtering.
    Requires valid API key in Authorization header.
    Note: These logs contain ONLY metadata — no prompts, no PII.

    New filter params (Section 2.3):
      ?event_type=guard_blocked
      ?org_id=org_acme
      ?blocked_only=true
      ?since=2024-01-01T00:00:00Z
      ?sent=false   (pending events only)
    """
    _validate_admin(authorization, request)

    if not EVENTS_DB.exists():
        return {"events": [], "total": 0, "offset": offset, "filters": {}}

    try:
        conn = sqlite3.connect(str(EVENTS_DB))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # ── Build dynamic WHERE clause ────────────────────────────────────────
        conditions: list[str] = []
        params: list = []

        if sent is not None:
            conditions.append("sent = ?")
            params.append(1 if sent else 0)

        if since:
            conditions.append("created_at > ?")
            params.append(since)

        if event_type:
            conditions.append("event_json LIKE ?")
            params.append(f'%"event_type": "{event_type}"%')

        if org_id:
            conditions.append("event_json LIKE ?")
            params.append(f'%"org_id": "{org_id}"%')

        if user_id:
            conditions.append("event_json LIKE ?")
            params.append(f'%"user_id": "{user_id}"%')

        if blocked_only:
            conditions.append("event_json LIKE '%\"blocked\": true%'")

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        # Total count with filters
        total_row = cursor.execute(
            f"SELECT COUNT(*) FROM outbound_events {where_clause}",
            params,
        ).fetchone()
        total = total_row[0] if total_row else 0

        # Paginated results
        rows = cursor.execute(
            f"SELECT id, event_json, created_at, sent FROM outbound_events "
            f"{where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        conn.close()

        events = []
        for row in rows:
            try:
                event_data = json.loads(row["event_json"])
            except Exception:
                event_data = {"raw": row["event_json"]}
            events.append({
                "id":         row["id"],
                "event":      event_data,
                "created_at": row["created_at"],
                "sent":       bool(row["sent"]),
            })

        return {
            "events":  events,
            "total":   total,
            "offset":  offset,
            "limit":   limit,
            "filters": {
                "event_type":   event_type,
                "org_id":       org_id,
                "user_id":      user_id,
                "blocked_only": blocked_only,
                "sent":         sent,
                "since":        since,
            },
        }
    except Exception as e:
        logger.error("logs_retrieval_error", error=type(e).__name__, detail=str(e))
        return {"error": "Failed to retrieve logs"}


@router.get("/metrics")
async def get_metrics(
    authorization: Optional[str] = Header(None),
    request: Request = None,
):
    """
    Prometheus-compatible metrics endpoint.
    Requires valid API key in Authorization header.
    """
    _validate_admin(authorization, request)

    if not EVENTS_DB.exists():
        return {
            "total_requests":  0,
            "blocked_requests": 0,
            "passed_requests":  0,
            "warned_requests":  0,
            "pending_events":   0,
        }

    try:
        conn = sqlite3.connect(str(EVENTS_DB))
        cursor = conn.cursor()

        total = cursor.execute("SELECT COUNT(*) FROM outbound_events").fetchone()[0]
        pending = cursor.execute(
            "SELECT COUNT(*) FROM outbound_events WHERE sent=0"
        ).fetchone()[0]
        blocked = cursor.execute(
            "SELECT COUNT(*) FROM outbound_events "
            "WHERE event_json LIKE '%\"blocked\": true%'"
        ).fetchone()[0]
        warned = cursor.execute(
            "SELECT COUNT(*) FROM outbound_events "
            "WHERE event_json LIKE '%\"warn\": true%'"
        ).fetchone()[0]

        # Block reason breakdown
        rows = cursor.execute(
            "SELECT event_json FROM outbound_events "
            "WHERE event_json LIKE '%block_reason%' LIMIT 1000"
        ).fetchall()
        conn.close()

        reason_counts: dict[str, int] = {}
        for (event_json,) in rows:
            try:
                data = json.loads(event_json)
                reason = (
                    data.get("guard", {}).get("block_reason")
                    or data.get("request", {}).get("block_reason")
                )
                if reason:
                    reason_counts[reason] = reason_counts.get(reason, 0) + 1
            except Exception:
                pass

        return {
            "total_requests":   total,
            "blocked_requests": blocked,
            "passed_requests":  total - blocked,
            "warned_requests":  warned,
            "pending_events":   pending,
            "block_rate_pct":   round((blocked / total * 100) if total > 0 else 0, 2),
            "block_reason_breakdown": reason_counts,
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


@router.get("/rate-limit/{org_id}/{user_id}")
async def get_user_rate_limit_stats(
    org_id: str,
    user_id: str,
    authorization: Optional[str] = Header(None),
    request: Request = None,
):
    """
    Get per-user rate limit stats (Section 2.4).
    Returns current usage, remaining budget, and window size.
    """
    _validate_admin(authorization, request)

    limiter = getattr(request.app.state, "user_rate_limiter", None)
    if limiter is None:
        raise HTTPException(status_code=503, detail="Per-user rate limiter not initialised")

    return limiter.get_stats(org_id, user_id)


@router.delete("/rate-limit/{org_id}/{user_id}")
async def reset_user_rate_limit(
    org_id: str,
    user_id: str,
    authorization: Optional[str] = Header(None),
    request: Request = None,
):
    """Reset a user's rate limit window (admin use — e.g. after a billing event)."""
    _validate_admin(authorization, request)

    limiter = getattr(request.app.state, "user_rate_limiter", None)
    if limiter is None:
        raise HTTPException(status_code=503, detail="Per-user rate limiter not initialised")

    limiter.reset(org_id, user_id)
    return {"status": "reset", "org_id": org_id, "user_id": user_id}


@router.get("/rate-limit")
async def list_rate_limit_stats(
    authorization: Optional[str] = Header(None),
    request: Request = None,
):
    """List rate limit stats for all tracked users."""
    _validate_admin(authorization, request)

    limiter = getattr(request.app.state, "user_rate_limiter", None)
    if limiter is None:
        raise HTTPException(status_code=503, detail="Per-user rate limiter not initialised")

    return {"users": limiter.get_all_stats()}


@router.get("/owasp-coverage")
async def owasp_coverage(
    authorization: Optional[str] = Header(None),
    request: Request = None,
):
    """Return OWASP LLM Top 10 coverage report (Section 3.3)."""
    _validate_admin(authorization, request)

    from app.guards.owasp_scanner import OwaspScanner
    from app.engine.response_scanner import ResponseScanner
    coverage = OwaspScanner.coverage_report()
    coverage.update(ResponseScanner.coverage_report())
    all_categories = ["LLM01","LLM02","LLM03","LLM04","LLM05",
                      "LLM06","LLM07","LLM08","LLM09","LLM10"]
    covered = list(coverage.keys())
    return {
        "total_categories": 10,
        "covered":          len(covered),
        "coverage_pct":     round(len(covered) / 10 * 100, 1),
        "categories":       coverage,
        "not_covered":      [c for c in all_categories if c not in covered],
        "note": "LLM02 (Insecure Output Handling) is covered by response_scanner.py",
    }
