"""
policy.py
=========
Data contracts for the Control Plane policy system.
PolicyBundle is pushed to every device and enforced by the guard pipeline.
"""

from __future__ import annotations

import warnings
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import PiiType, UserRole, FailBehavior


class PiiRules(BaseModel):
    """
    PII handling rules set per-org in the Control Plane policy editor.
    Pushed down to the Data Plane via PolicyBundle.
    """
    block_on_detect:   bool          = True
    scrub_before_send: bool          = True
    allowed_pii_types: list[PiiType] = Field(default_factory=list)
    # ↑ empty = block ALL PII types. Add types here to allow e.g. first names.


class UserPolicyOverride(BaseModel):
    """
    Per-user overrides within an org's policy.
    Set in the admin dashboard (e.g. give the CISO access to GPT-4o).
    """
    user_id:        str
    role:           UserRole
    allowed_models: Optional[list[str]] = None  # None = inherit org defaults


class PolicyBundle(BaseModel):
    """
    THE payload pushed from the Control Plane to every desktop app.
    Delivered via:
      1. GET /policy/{org_id}  — on sidecar startup
      2. WebSocket push        — real-time updates when admin changes a rule

    Invariant: The bridge owns the refresh cycle. The Data Plane is a consumer.
    """
    policy_version:          str
    org_id:                  str
    pushed_at:               datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Model access control
    allowed_models:          list[str] = Field(
        default_factory=lambda: ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"]
    )
    blocked_keywords:        list[str] = Field(default_factory=list)

    # PII rules
    pii_rules:               PiiRules = Field(default_factory=PiiRules)

    # Fail-CLOSED is the default — NEVER change to OPEN in production
    fail_behavior:           FailBehavior = FailBehavior.CLOSED

    # Token limits
    max_prompt_tokens:       int = Field(default=4000, ge=100, le=128000)

    # Session
    session_timeout_minutes: int = Field(default=60, ge=5)

    # Per-user overrides
    user_overrides:          dict[str, UserPolicyOverride] = Field(default_factory=dict)

    @field_validator("fail_behavior")
    @classmethod
    def no_open_in_prod(cls, v: FailBehavior) -> FailBehavior:
        if v == FailBehavior.OPEN:
            warnings.warn(
                "FailBehavior.OPEN disables the fail-closed guarantee. "
                "NEVER deploy this to production.",
                SecurityWarning,
                stacklevel=2,
            )
        return v

    model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}


class WebSocketPolicyPush(BaseModel):
    """Wrapper sent over WebSocket when a policy changes."""
    message_type: str          = "policy_update"
    org_id:       str
    policy:       PolicyBundle
