"""
api.py
======
FastAPI-specific request/response schemas.
Separate from internal contracts so API surface can evolve independently.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from app.contracts.enums import BlockReason, PiiType


# ── Guard-only endpoint ──────────────────────────────────────────────────────

class GuardRequest(BaseModel):
    """POST /v1/guard — run the guard pipeline without calling the LLM."""
    prompt:          str
    model_requested: str = "gemini-2.0-flash"


class GuardResponse(BaseModel):
    """Response from /v1/guard."""
    clean_text:         str
    blocked:            bool
    block_reason:       Optional[BlockReason] = None
    block_detail:       Optional[str] = None
    pii_types_found:    list[str]       = Field(default_factory=list)
    pii_count:          int             = 0
    injection_detected: bool            = False
    ml_guard_score:     float           = 0.0
    latency_ms:         float           = 0.0
    phase_timings:      dict[str, float] = Field(default_factory=dict)
    placeholder_map:    dict[str, str]  = Field(default_factory=dict)


# ── Full pipeline endpoint ───────────────────────────────────────────────────

class ProcessRequest(BaseModel):
    """POST /v1/process — full end-to-end: guard → LLM → rehydrate → response scan."""
    prompt:          str
    model_requested: str = "gemini-2.0-flash"
    org_id:          str = "org_dev"
    user_id:         str = "usr_dev"
    session_id:      str = "session_dev"


class ProcessResponse(BaseModel):
    """Response from /v1/process."""
    response:           str
    blocked:            bool
    block_reason:       Optional[BlockReason] = None
    block_detail:       Optional[str] = None
    pii_types_found:    list[str]       = Field(default_factory=list)
    injection_detected: bool            = False
    ml_guard_score:     float           = 0.0
    latency_ms:         float           = 0.0
    response_pii_found: list[str]       = Field(default_factory=list)


# ── Rehydrate endpoint ───────────────────────────────────────────────────────

class RehydrateRequest(BaseModel):
    """POST /v1/rehydrate — restore PII into LLM response."""
    llm_response:    str
    placeholder_map: dict[str, str]


class RehydrateResponse(BaseModel):
    """Response from /v1/rehydrate."""
    restored_response: str
