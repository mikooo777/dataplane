"""
main.py
=======
Foretyx Data Plane — FastAPI application entry point.

This is the single-process, modular AI security gateway.
All guards, policies, and telemetry run in-process for minimal latency.
Scale horizontally by running N instances behind a load balancer.

Start with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

Production:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
"""

import asyncio
import time
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import Settings
from app.dependencies import get_settings
from app.engine.pipeline import GuardPipeline
from app.engine.llm_router import LLMRouter
from app.engine.rehydrator import Rehydrator
from app.engine.response_scanner import ResponseScanner
from app.engine.event_emitter import EventEmitter
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.rate_limiter import RateLimiterMiddleware
from app.middleware.access_log import AccessLogMiddleware
from app.middleware.per_user_rate_limiter import create_user_rate_limiter
from app.security import get_secure_headers
from app.routes import guard, process, health, admin
from app.routes import chat as chat_route


# ── Structured Logging Configuration ─────────────────────────────────────────

def configure_logging(settings: Settings):
    """Configure structlog for JSON (production) or console (development)."""
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
           settings.log_level.upper()
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


# ── Security Headers Middleware ──────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        # Add security headers
        for header_name, header_value in get_secure_headers().items():
            response.headers[header_name] = header_value
        return response


# ── Application Lifespan ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: Initialize all components, validate dependencies, start background tasks.
    Shutdown: Flush telemetry, clean up resources.
    """
    settings = get_settings()
    configure_logging(settings)
    logger = structlog.get_logger("startup")

    logger.info("foretyx_data_plane_starting", version="2.0.0")

    # Initialize components
    pipeline = GuardPipeline(settings)
    llm_router = LLMRouter(settings)
    rehydrator = Rehydrator()
    response_scanner = ResponseScanner(pipeline.pii_detector)
    event_emitter = EventEmitter(settings)

    # Store in app state for route handlers
    app.state.pipeline = pipeline
    app.state.llm_router = llm_router
    app.state.rehydrator = rehydrator
    app.state.response_scanner = response_scanner
    app.state.event_emitter = event_emitter
    app.state.settings = settings
    app.state.startup_time = time.time()
    app.state.user_rate_limiter = create_user_rate_limiter(settings)

    # Start background telemetry flush loop
    flush_task = asyncio.create_task(event_emitter.start_flush_loop())

    # Startup self-test
    logger.info(
        "startup_status",
        ml_model_loaded=pipeline.injection_detector.is_loaded,
        policy_loaded=pipeline.policy_engine.is_loaded,
        fail_behavior=settings.fail_behavior,
    )

    logger.info(
        "foretyx_data_plane_ready",
        host=settings.host,
        port=settings.port,
        require_https=settings.require_https,
    )

    yield

    # Shutdown
    logger.info("foretyx_data_plane_shutting_down")
    flush_task.cancel()
    await event_emitter.shutdown()
    logger.info("foretyx_data_plane_stopped")


# ── FastAPI Application ──────────────────────────────────────────────────────

app = FastAPI(
    title="Foretyx Data Plane",
    description="AI Security Gateway — guards prompts, scrubs PII, enforces policies, and scans responses before any data reaches or leaves the LLM.",
    version="2.0.0",
    lifespan=lifespan,
)

# ── Middleware Stack (order matters: first added = outermost) ─────────────────
# Note: Middleware executes in reverse order of addition
settings = get_settings()

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AccessLogMiddleware)
app.add_middleware(
    RateLimiterMiddleware,
    max_requests=settings.rate_limit_per_minute,
    window_seconds=60,
)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=3600,
)

# ── Route Registration ───────────────────────────────────────────────────────
app.include_router(guard.router)
app.include_router(process.router)
app.include_router(health.router)
app.include_router(admin.router)
app.include_router(chat_route.router)   # NEW: multi-turn chat (Section 2.1)


# ── Root Endpoint ────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service": "Foretyx Data Plane",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/v1/health",
    }
