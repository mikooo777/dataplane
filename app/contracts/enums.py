"""
enums.py
========
Single source of truth for all enumerations in the Foretyx ecosystem.
All engineers import from here — no magic strings, ever.
"""

from enum import Enum


class PiiType(str, Enum):
    """Detected PII entity types — covers India-specific, global, and credential patterns."""
    # ── India-specific ────────────────────────────────────────────────────────
    AADHAAR            = "AADHAAR"
    PAN                = "PAN"
    IN_MOBILE          = "IN_MOBILE"
    IN_VOTER_ID        = "IN_VOTER_ID"
    IN_PASSPORT        = "IN_PASSPORT"
    IN_DRIVING_LICENSE = "IN_DRIVING_LICENSE"
    IN_BANK_ACCOUNT    = "IN_BANK_ACCOUNT"
    IN_IFSC            = "IN_IFSC"
    IN_GST             = "IN_GST"

    # ── Global ────────────────────────────────────────────────────────────────
    EMAIL_ADDRESS      = "EMAIL_ADDRESS"
    PHONE_NUMBER       = "PHONE_NUMBER"
    CREDIT_CARD        = "CREDIT_CARD"
    PERSON             = "PERSON"
    LOCATION           = "LOCATION"
    IP_ADDRESS         = "IP_ADDRESS"
    IBAN_CODE          = "IBAN_CODE"
    US_SSN             = "US_SSN"
    DATE_OF_BIRTH      = "DATE_OF_BIRTH"

    # ── Credentials & Secrets ────────────────────────────────────────────────
    API_KEY            = "API_KEY"
    PASSWORD           = "PASSWORD"
    CRYPTO_WALLET      = "CRYPTO_WALLET"


class BlockReason(str, Enum):
    """Why a prompt was blocked — used in GuardResult and audit logs."""
    PII_DETECTED         = "pii_detected"
    INJECTION_DETECTED   = "prompt_injection"
    ML_GUARD_TRIGGERED   = "ml_guard_triggered"
    HEURISTIC_JAILBREAK  = "heuristic_jailbreak"
    KEYWORD_BLOCKED      = "keyword_blocked"
    FORBIDDEN_TOPIC      = "forbidden_topic"
    MODEL_NOT_ALLOWED    = "model_not_allowed"
    TOKEN_LIMIT_EXCEEDED = "token_limit_exceeded"
    POLICY_VIOLATION     = "policy_violation"
    PROMPT_TOO_LONG      = "prompt_too_long"
    RATE_LIMITED          = "rate_limited"
    RESPONSE_PII_LEAK    = "response_pii_leak"


class EventType(str, Enum):
    """Telemetry event types sent to the Control Plane."""
    PROMPT_SENT       = "prompt_sent"
    RESPONSE_RECEIVED = "response_received"
    GUARD_BLOCKED     = "guard_blocked"
    POLICY_UPDATED    = "policy_updated"
    SESSION_STARTED   = "session_started"
    SESSION_ENDED     = "session_ended"
    SIDECAR_ERROR     = "sidecar_error"


class UserRole(str, Enum):
    """User roles for access control."""
    EMPLOYEE = "employee"
    ADMIN    = "admin"
    OWNER    = "owner"


class FailBehavior(str, Enum):
    """What to do when a guard is unavailable."""
    CLOSED = "CLOSED"   # Block all traffic (default, production)
    OPEN   = "OPEN"     # Allow traffic through (NEVER use in production)
