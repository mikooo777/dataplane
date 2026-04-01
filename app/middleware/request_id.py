"""
request_id.py
=============
Injects X-Request-ID into every request/response for distributed tracing.
All log entries downstream include this ID for end-to-end correlation.
Validates request ID format to prevent injection attacks.
"""

import uuid
import re
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

import structlog

logger = structlog.get_logger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Adds a unique X-Request-ID header to every request and response.
    If the client sends one, it is validated and reused; otherwise a new UUID4 is generated.
    Rejects request IDs that contain suspicious characters.
    """
    
    # Allow alphanumeric, hyphens, underscores, dots (valid UUID and trace ID formats)
    VALID_REQUEST_ID_PATTERN = re.compile(r'^[a-zA-Z0-9\-_.]+$')
    MAX_REQUEST_ID_LENGTH = 256

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Use client-provided ID or generate one
        client_request_id = request.headers.get("X-Request-ID")
        
        if client_request_id:
            # Validate request ID format and length
            if (len(client_request_id) <= self.MAX_REQUEST_ID_LENGTH and 
                self.VALID_REQUEST_ID_PATTERN.match(client_request_id)):
                request_id = client_request_id
            else:
                logger.warning("invalid_request_id_format", received_id=client_request_id[:50])
                request_id = str(uuid.uuid4())
        else:
            request_id = str(uuid.uuid4())

        # Bind to structlog context for all downstream logs
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        # Store in request state for route handlers
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        return response
