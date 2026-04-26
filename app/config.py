"""
config.py
=========
Central configuration for the Foretyx Data Plane.
All values loaded from environment variables via Pydantic Settings.
No hardcoded secrets — ever.
"""

from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr
from typing import List


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Override any value by setting the corresponding env var or adding it to .env.
    """

    # ── LLM API ───────────────────────────────────────────────────────────────
    gemini_api_key: SecretStr = Field(
        ..., description="Google Gemini API key"
    )
    default_llm_model: str = Field(
        "gemini-2.0-flash", description="Default Gemini model to use"
    )
    llm_timeout_seconds: int = Field(
        30, ge=5, le=120, description="LLM API timeout in seconds"
    )
    llm_max_retries: int = Field(
        3, ge=0, le=10, description="Max retries on LLM API failure"
    )

    # ── Ollama (Phase 2 escalation) ───────────────────────────────────────────
    ollama_url: str = Field(
        "http://localhost:11434", description="Ollama API base URL"
    )
    ollama_model: str = Field(
        "foretyx-guard", description="Ollama model name for escalation"
    )
    ollama_timeout_seconds: float = Field(
        3.0, ge=0.5, le=30.0, description="Ollama API timeout in seconds"
    )

    # ── Control Plane telemetry ───────────────────────────────────────────────
    control_plane_url: str = Field(
        "http://localhost:8000", description="Control Plane URL for event relay"
    )
    bridge_token: SecretStr = Field(
        "", description="Bearer token for Control Plane authentication"
    )

    # ── Security / Authentication ──────────────────────────────────────────────
    admin_api_key: SecretStr = Field(
        ..., description="Admin API key for protected endpoints (e.g., /logs, /metrics)"
    )
    require_https: bool = Field(
        False, description="Require HTTPS in production (set via env var)"
    )
    cors_allow_credentials: bool = Field(
        False, description="Allow credentials in CORS (should be False for public APIs)"
    )
    trusted_proxies: str = Field(
        "127.0.0.1", description="Comma-separated list of trusted proxy IPs"
    )

    # ── ML Guard thresholds ───────────────────────────────────────────────────
    ml_block_threshold: float = Field(
        0.98, ge=0.0, le=1.0,
        description="ONNX score >= this → block immediately"
    )
    ml_escalate_threshold: float = Field(
        0.95, ge=0.0, le=1.0,
        description="ONNX score >= this (but < block) → escalate to Ollama"
    )

    # ── Rate limiting ────────────────────────────────────────────────────────
    rate_limit_per_minute: int = Field(
        60, ge=1, le=10000, description="Max requests per minute per client IP"
    )

    # ── Security ─────────────────────────────────────────────────────────────
    fail_behavior: str = Field(
        "CLOSED", description="CLOSED = block on guard failure, OPEN = allow (dev only)"
    )
    cors_allowed_origins: str = Field(
        "http://localhost:3000,http://localhost:8080",
        description="Comma-separated CORS origins"
    )

    # ── Model paths ──────────────────────────────────────────────────────────
    onnx_model_path: str = Field(
        "models/ml_guard.onnx", description="Path to ONNX ML guard model"
    )
    onnx_tokenizer_name: str = Field(
        "distilbert-base-uncased-finetuned-sst-2-english",
        description="HuggingFace tokenizer for ONNX model"
    )

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level: str = Field(
        "INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR)"
    )
    log_format: str = Field(
        "json", description="Log format: 'json' for production, 'console' for dev"
    )

    # ── Server ───────────────────────────────────────────────────────────────
    host: str = Field("0.0.0.0", description="Bind host")
    port: int = Field(8000, ge=1, le=65535, description="Bind port")

    # ── Circuit breaker ──────────────────────────────────────────────────────
    # Critical Fix #2: Threshold reduced from 5 → 3.
    # At 30s timeouts, threshold=5 meant 150s of degraded security.
    # threshold=3 caps max exposure at 90 seconds.
    circuit_breaker_threshold: int = Field(
        3, ge=1, description="Consecutive Ollama failures before opening circuit"
    )
    circuit_breaker_recovery_seconds: int = Field(
        60, ge=10, description="Seconds to wait before retrying after circuit opens"
    )

    # ── Max prompt length ────────────────────────────────────────────────────
    max_prompt_length: int = Field(
        50000, ge=100, description="Maximum raw prompt character length"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def trusted_proxies_list(self) -> List[str]:
        return [p.strip() for p in self.trusted_proxies.split(",") if p.strip()]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }
