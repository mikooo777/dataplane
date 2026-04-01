"""
events.py
=========
Data contracts for privacy-first telemetry.
MetadataEvent is the ONLY payload that reaches the Control Plane.
Invariant: no raw prompts, no PII values, no response text — ever.
"""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.contracts.enums import PiiType, BlockReason, EventType
from app.contracts.guard import GuardResult


class DeviceInfo(BaseModel):
    """
    Static device fingerprint — collected once at install, never changes.
    No PII: device_id is a random UUID generated at install time.
    """
    device_id:   UUID   = Field(default_factory=uuid4)
    os:          str    = Field(default_factory=lambda: platform.system().lower())
    os_version:  str    = Field(default_factory=platform.version)
    app_version: str    = "2.0.0"
    arch:        str    = Field(default_factory=platform.machine)


class RequestMeta(BaseModel):
    """
    Non-sensitive metadata about the LLM request.
    Assembled from GuardResult + policy check.
    """
    model_requested:       str
    model_allowed:         bool
    prompt_token_estimate: int = Field(ge=0)
    blocked:               bool
    block_reason:          Optional[BlockReason] = None


class GuardMeta(BaseModel):
    """
    Sanitised summary of GuardResult — safe to send to cloud.
    The actual PII values, clean_text, and placeholder_map stay on-device.
    """
    triggered:          bool
    pii_types_detected: list[PiiType]  = Field(default_factory=list)
    pii_count:          int            = Field(ge=0)
    injection_detected: bool           = False
    ml_guard_score:     float          = Field(ge=0.0, le=1.0)
    latency_ms:         float          = Field(ge=0.0)
    phase_timings:      dict[str, float] = Field(default_factory=dict)

    @classmethod
    def from_guard_result(cls, result: GuardResult) -> GuardMeta:
        """
        Convert a full GuardResult into a cloud-safe summary.
        The placeholder_map and clean_text never touch this object.
        """
        return cls(
            triggered=result.blocked or len(result.pii_detections) > 0,
            pii_types_detected=list({d.pii_type for d in result.pii_detections}),
            pii_count=len(result.pii_detections),
            injection_detected=result.injection_detected,
            ml_guard_score=result.ml_guard_score,
            latency_ms=result.latency_ms,
            phase_timings=result.phase_timings,
        )


class MetadataEvent(BaseModel):
    """
    THE payload posted to the Control Plane's POST /events endpoint.
    This is the ONLY data that ever reaches the cloud.

    Invariant: no raw prompts, no PII values, no response text.
    """
    event_id:    UUID      = Field(default_factory=uuid4)
    org_id:      str
    user_id:     str
    event_type:  EventType
    timestamp:   datetime  = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    device:      DeviceInfo
    guard:       GuardMeta
    request:     RequestMeta

    session_id:  Optional[UUID] = None

    model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}
