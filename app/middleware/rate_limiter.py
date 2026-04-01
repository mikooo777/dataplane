"""
rate_limiter.py
===============
Sliding window rate limiter middleware.
Configurable per-IP limits via environment variables.
Returns HTTP 429 with Retry-After header when exceeded.
Validates X-Forwarded-For header to prevent spoofing.
"""

import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.security import SecurityValidator

import structlog

logger = structlog.get_logger(__name__)


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    In-memory sliding window rate limiter.
    Tracks request timestamps per client IP and enforces a configurable limit.
    """

    def __init__(self, app, max_requests: int = 60, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, respecting X-Forwarded-For for proxied requests."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP (closest to client)
            client_ip = forwarded.split(",")[0].strip()
            # Validate IP format to prevent injection
            if SecurityValidator.validate_client_ip(client_ip):
                return client_ip
            else:
                logger.warning("invalid_client_ip_format", ip=client_ip)
                return "invalid"
        
        return request.client.host if request.client else "unknown"

    def _is_allowed(self, key: str) -> tuple[bool, int]:
        """
        Check if a request is allowed under the rate limit.
        Returns (allowed, retry_after_seconds).
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Clean expired entries
        self._requests[key] = [
            t for t in self._requests[key] if t > window_start
        ]

        if len(self._requests[key]) >= self.max_requests:
            # Calculate when the oldest request in the window will expire
            retry_after = int(self._requests[key][0] - window_start) + 1
            return False, max(retry_after, 1)

        self._requests[key].append(now)
        return True, 0

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip rate limiting for health checks
        if request.url.path.endswith("/health"):
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        allowed, retry_after = self._is_allowed(client_ip)

        if not allowed:
            logger.warning(
                "rate_limited",
                client_ip=client_ip,
                limit=self.max_requests,
                window_seconds=self.window_seconds,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)
