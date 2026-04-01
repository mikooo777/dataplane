"""
access_log.py
=============
Structured JSON access logging middleware.
Logs every request with: request_id, method, path, status_code, latency_ms, client_ip.
NEVER logs prompt text — only metadata.
Validates IP addresses to prevent injection.
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.security import SecurityValidator

import structlog

logger = structlog.get_logger("access_log")


class AccessLogMiddleware(BaseHTTPMiddleware):
    """
    Structured access log for every HTTP request.
    Output format is controlled by structlog configuration (JSON or console).
    Validates IP addresses to prevent injection.
    """

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
            if SecurityValidator.validate_client_ip(client_ip):
                return client_ip
            else:
                logger.warning("invalid_client_ip_format", ip=client_ip)
                return "invalid"
        return request.client.host if request.client else "unknown"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        t0 = time.perf_counter()

        response = await call_next(request)

        latency_ms = (time.perf_counter() - t0) * 1000
        request_id = getattr(request.state, "request_id", "N/A")

        logger.info(
            "http_request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            latency_ms=round(latency_ms, 2),
            client_ip=self._get_client_ip(request),
        )

        return response
