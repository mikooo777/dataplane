"""
per_user_rate_limiter.py
========================
Per-user (not per-IP) rate limiting (Guide Section 2.4).

Why per-user vs per-IP?
  - Multiple users share the same corporate NAT / VPN egress IP
  - Per-IP limits unfairly throttle whole offices
  - Per-user limits enforce quotas per authenticated identity

  Per-user rate limiting works on (org_id, user_id) composite keys extracted
  from the request body. The existing RateLimiterMiddleware still enforces the
  global per-IP limit as a DDoS backstop.

Algorithm: Sliding window (same as RateLimiterMiddleware).

Configuration (via env vars or Settings):
  USER_RATE_LIMIT_PER_MINUTE  (default: 20)
  USER_RATE_LIMIT_BURST       (default: 5 — requests allowed before window kicks in)
"""

import time
from collections import defaultdict
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# Default limits (can be overridden via constructor)
DEFAULT_USER_LIMIT_PER_MINUTE = 20
DEFAULT_BURST = 5


class PerUserRateLimiter:
    """
    Token bucket rate limiter keyed by (org_id, user_id) for true burst handling.

    Usage:
        limiter = PerUserRateLimiter(max_rpm=20, burst=5)
        allowed, retry_after = limiter.check("org_acme", "user_42")
        if not allowed:
            raise HTTPException(429, detail=f"Rate limited. Retry after {retry_after}s")
    """

    def __init__(
        self,
        max_rpm: int = DEFAULT_USER_LIMIT_PER_MINUTE,
        burst: int = DEFAULT_BURST,
        window_seconds: int = 60,
    ):
        self.max_rpm        = max_rpm
        self.burst          = burst
        self.window_seconds = window_seconds
        # Tokens added per second
        self.rate           = max_rpm / window_seconds
        # {(org_id, user_id): (tokens_left, last_update_ts)}
        self._buckets: dict[tuple, tuple[float, float]] = {}

    def check(
        self,
        org_id: str,
        user_id: str,
        cost: int = 1,
    ) -> tuple[bool, int]:
        """
        Check if the (org_id, user_id) pair is within the rate limit.
        """
        key = (org_id, user_id)
        now = time.time()

        if key not in self._buckets:
            tokens = float(self.burst)
        else:
            prev_tokens, prev_ts = self._buckets[key]
            elapsed = now - prev_ts
            tokens = min(float(self.burst), prev_tokens + elapsed * self.rate)

        if tokens >= cost:
            self._buckets[key] = (tokens - cost, now)
            logger.debug(
                "per_user_rate_check_passed",
                org_id=org_id,
                user_id=user_id,
                tokens_left=round(tokens - cost, 2),
                limit=self.max_rpm,
            )
            return True, 0

        # Not enough tokens
        needed = cost - tokens
        retry_after = max(int(needed / self.rate) + 1, 1)
        logger.warning(
            "per_user_rate_limited",
            org_id=org_id,
            user_id=user_id,
            tokens_left=round(tokens, 2),
            limit=self.max_rpm,
            retry_after=retry_after,
        )
        return False, retry_after

    def reset(self, org_id: str, user_id: str):
        """Reset the rate limit window for a specific user (admin use)."""
        key = (org_id, user_id)
        if key in self._buckets:
            del self._buckets[key]
            logger.info("per_user_rate_limit_reset", org_id=org_id, user_id=user_id)

    def get_stats(self, org_id: str, user_id: str) -> dict:
        """Return rate limit stats for a user (admin endpoint use)."""
        key = (org_id, user_id)
        now = time.time()
        
        if key not in self._buckets:
            tokens = float(self.burst)
        else:
            prev_tokens, prev_ts = self._buckets[key]
            elapsed = now - prev_ts
            tokens = min(float(self.burst), prev_tokens + elapsed * self.rate)

        return {
            "org_id":        org_id,
            "user_id":       user_id,
            "requests_used": round(self.burst - tokens, 2),
            "requests_left": round(tokens, 2),
            "max_rpm":       self.max_rpm,
            "window_seconds": self.window_seconds,
        }

    def get_all_stats(self) -> list[dict]:
        """Return stats for all tracked users."""
        now = time.time()
        results = []
        for (org_id, user_id), (prev_tokens, prev_ts) in self._buckets.items():
            elapsed = now - prev_ts
            tokens = min(float(self.burst), prev_tokens + elapsed * self.rate)
            results.append({
                "org_id":        org_id,
                "user_id":       user_id,
                "requests_used": round(self.burst - tokens, 2),
                "requests_left": round(tokens, 2),
            })
        return results


# ── Singleton for use across request handlers ─────────────────────────────────
# Initialised in main.py lifespan and attached to app.state.user_rate_limiter

def create_user_rate_limiter(settings=None) -> PerUserRateLimiter:
    """
    Create a PerUserRateLimiter from Settings.
    Falls back to defaults if settings not provided.
    """
    if settings is not None:
        # Allow override via env vars (extend Settings if needed)
        max_rpm = getattr(settings, "user_rate_limit_per_minute", DEFAULT_USER_LIMIT_PER_MINUTE)
        burst   = getattr(settings, "user_rate_limit_burst", DEFAULT_BURST)
    else:
        max_rpm = DEFAULT_USER_LIMIT_PER_MINUTE
        burst   = DEFAULT_BURST

    logger.info(
        "per_user_rate_limiter_created",
        max_rpm=max_rpm,
        burst=burst,
    )
    return PerUserRateLimiter(max_rpm=max_rpm, burst=burst)
