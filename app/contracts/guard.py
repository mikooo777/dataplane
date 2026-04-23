"""
guard.py
========
Data contracts for the guard pipeline output.
GuardResult is the core output of the Foretyx security scan.

Changes:
  - Added warn + warn_reason fields (Guide Section 4.1 — WARN action)
"""

from __future__ import annotations

import warnings
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from app.contracts.enums import PiiType, BlockReason


class PiiDetection(BaseModel):
    """
    One detected PII entity in the raw prompt.

    Example:
        raw text:    "email me at john@example.com please"
        placeholder: "<<EMAIL_ADDRESS_1>>"
        rehydrated:  "email me at john@example.com please" (restored in response)
    """
    pii_type:    PiiType
    placeholder: str          # e.g. "<<EMAIL_ADDRESS_1>>"
    char_start:  int          # position in original text (for audit, never sent to cloud)
    char_end:    int
    confidence:  float = Field(ge=0.0, le=1.0)

    @field_validator("placeholder")
    @classmethod
    def placeholder_format(cls, v: str) -> str:
        if not (v.startswith("<<") and v.endswith(">>")):
            raise ValueError("placeholder must be wrapped in <<...>>")
        return v


class GuardResult(BaseModel):
    """
    Output of the Foretyx guard pipeline after processing one prompt.

    Fields:
        clean_text         — scrubbed prompt, safe to send to LLM
        blocked            — if True, the prompt MUST NOT be forwarded to LLM
        block_reason       — populated when blocked=True
        block_detail       — human-readable detail about why it was blocked
        pii_detections     — list of what was found and replaced
        injection_detected — prompt injection attempt was flagged
        ml_guard_score     — ONNX model confidence (0.0=safe, 1.0=threat)
        latency_ms         — total guard pipeline latency (SLA target <200ms)
        placeholder_map    — {placeholder: original_value} — NEVER leaves the device
        phase_timings      — per-phase latency breakdown for observability
    """
    clean_text:         str
    blocked:            bool = False
    block_reason:       Optional[BlockReason] = None
    block_detail:       Optional[str] = None
    pii_detections:     list[PiiDetection] = Field(default_factory=list)
    injection_detected: bool = False
    ml_guard_score:     float = Field(default=0.0, ge=0.0, le=1.0)
    latency_ms:         float = Field(ge=0.0)
    placeholder_map:    dict[str, str] = Field(default_factory=dict)
    phase_timings:      dict[str, float] = Field(default_factory=dict)
    # ── WARN action (Section 4.1) ────────────────────────────────────────────
    # warn=True means the prompt passes but risk is elevated.
    # Callers SHOULD surface a warning to the user/admin.
    warn:               bool = False
    warn_reason:        Optional[str] = None

    @model_validator(mode="after")
    def block_reason_required_when_blocked(self) -> GuardResult:
        if self.blocked and self.block_reason is None:
            raise ValueError("block_reason must be set when blocked=True")
        return self

    @model_validator(mode="after")
    def latency_sla_warning(self) -> GuardResult:
        if self.latency_ms > 200:
            warnings.warn(
                f"GuardResult latency {self.latency_ms:.1f}ms exceeds 200ms SLA",
                RuntimeWarning,
                stacklevel=2,
            )
        return self


class SidecarHealth(BaseModel):
    """
    Health check response.
    Bridge layer polls this every 5 seconds.
    If status != "ok" or response takes >500ms → FAIL CLOSED.
    """
    status:           str   = "ok"       # "ok" | "degraded" | "error"
    version:          str   = "2.0.0"
    uptime_s:         float              # seconds since startup
    model_loaded:     bool  = True       # ONNX ML_GUARD model is loaded
    ollama_reachable: bool  = False      # Ollama is connectable
    policy_loaded:    bool  = False      # Policy file is valid
    latency_p95:      Optional[float] = None
