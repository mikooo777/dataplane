# ═══════════════════════════════════════════════════════════════════════════════
# Foretyx Data Plane — Production Docker Image
# ═══════════════════════════════════════════════════════════════════════════════
# Multi-stage build: Stage 1 installs deps, Stage 2 copies app.
# Runs as non-root user for security.

# ── Stage 1: Build dependencies ──────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt
RUN python -m spacy download en_core_web_sm

# ── Stage 2: Production image ────────────────────────────────────────────────
FROM python:3.11-slim AS production

LABEL maintainer="Foretyx Engineering <eng@foretyx.com>"
LABEL description="Foretyx Data Plane — AI Security Gateway"

# Security: run as non-root
RUN groupadd -r foretyx && useradd -r -g foretyx -d /app -s /sbin/nologin foretyx

WORKDIR /app

# Copy installed packages
COPY --from=builder /install /usr/local
COPY --from=builder /usr/local/lib/python3.11/site-packages/en_core_web_sm /usr/local/lib/python3.11/site-packages/en_core_web_sm

# Copy application
COPY app/ ./app/
COPY models/ ./models/
COPY Modelfile ./

# Create necessary directories
RUN mkdir -p /app/logs && chown -R foretyx:foretyx /app

USER foretyx

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:8000/v1/health'); exit(0 if r.status_code == 200 else 1)"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
