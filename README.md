# Foretyx Data Plane v2.0

> **The Ultimate AI Security Gateway** — A production-grade, single-process, horizontally-scalable prompt security pipeline that shields your LLM from injection attacks, scrubs PII (22+ types including India-specific identifiers), enforces enterprise policies, and scans responses for leaked data — before any prompt reaches or leaves the model.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Files Not Included in This Repo](#-files-not-included-in-this-repo)
3. [Prerequisites](#prerequisites)
4. [Setup — Native (Recommended for Dev)](#setup--native-recommended-for-dev)
5. [Setup — Docker](#setup--docker)
6. [Configuration](#configuration)
7. [Running the Server](#running-the-server)
8. [Testing](#testing)
9. [API Reference](#api-reference)
10. [Security Architecture](#security-architecture)
11. [Project Structure](#project-structure)
12. [Monitoring](#monitoring)

---

## Architecture

```
                          ┌──────────────────────────────────────────────────────┐
                          │              Foretyx Data Plane v2.0                 │
                          │         Single Process · All Guards In-Process       │
                          │                                                      │
  Raw Prompt ─────────────┤                                                      │
                          │  Phase 1a: Heuristic Scanner     (regex, <1ms)       │
                          │  Phase 1b: OWASP LLM Top 10      (10/10, <1ms)      │
                          │  Phase 1c: Semantic Firewall     (keywords, <1ms)    │
                          │  Phase 1d: PII Scrubber          (Presidio, ~10ms)   │
                          │      └── Aadhaar Verhoeff        (checksum, <1ms)    │
                          │  Phase 2a: ML Injection Guard    (ONNX, ~15ms)       │
                          │  Phase 2b: Ollama Escalation     (LLM, if ambiguous) │
                          │  Phase 3:  Token Budget          (tiktoken, <1ms)    │
                          │  Phase 4:  Policy Engine         (keyword/ACL)       │
                          │                                                      │
                          │  ──────────── Clean Prompt → Gemini API ──────────── │
                          │                                                      │
                          │  Phase 5:  Response Scanner      (PII leak check)    │
                          │  Phase 6:  Encrypted Rehydrator  (AES-256-GCM)       │
                          │                                                      │
  Final Response ◄────────┤  Telemetry → SQLite → Control Plane (no PII sent)   │
                          └──────────────────────────────────────────────────────┘
```

### Why Single-Process?

| Concern | Microservices | Single-Process v2.0 |
|---------|--------------|---------------------|
| Latency per phase | +5–15ms HTTP overhead | ~0ms (function call) |
| 3-phase pipeline | 15–45ms wasted on network | 0ms wasted |
| Horizontal scaling | Complex (4 services × N) | Simple (N instances behind LB) |
| Deployment | 4 terminals, 4 processes | 1 command |

---

## ⚠️ Files Not Included in This Repo

The following files are **gitignored** and will not be present after cloning. You must obtain or generate them manually before the server will start.

| File | Size | Why Missing | How to Get It |
|------|------|-------------|---------------|
| `.env` | — | Contains secrets | Copy `.env.example` → `.env` and fill in your keys |
| `models/ml_guard.onnx` | ~780 KB | Binary model file | Run `python export_model.py` (see Step 4 below) |
| `models/ml_guard.onnx.data` | ~256 MB | Binary weights — too large for git | Run `python export_model.py` (see Step 4 below) |
| `gemma-3-1b-it.Q4_K_M.gguf` | ~806 MB | Too large for git | Download from Hugging Face (see Step 5 below) |
| `foretyx_events.db` | — | Runtime SQLite — auto-created on first run | Created automatically by the server |
| `venv/` | — | Virtual environment | Created locally by you |

> **The server will still start without the GGUF model and Ollama.** Phase 2b (Ollama escalation) will be skipped gracefully via the circuit breaker. The ONNX model files (`models/`) are required for Phase 2a.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | 3.10 minimum, 3.11 recommended |
| pip | Latest | `python -m pip install --upgrade pip` |
| Ollama | Latest | Optional — for Phase 2b LLM escalation |
| Docker + Docker Compose | Latest | Only if using the Docker path |
| Google Gemini API Key | — | Required for `/v1/process` and `/v1/chat` |

---

## Setup — Native (Recommended for Dev)

### Step 1 — Clone the repo

```bash
git clone https://github.com/that-blacksheep/dataplane-final.git
cd dataplane-final
```

### Step 2 — Create and activate a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**Linux / macOS:**
```bash
python -m venv venv
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Then download the spaCy language model (required for Presidio PII detection):

```bash
python -m spacy download en_core_web_sm
```

### Step 4 — Generate the ONNX ML model files

> **Skip this step if you already have `models/ml_guard.onnx` and `models/ml_guard.onnx.data`.**

Install the extra dependencies needed for export (not in `requirements.txt` since they are build-time only):

```bash
pip install torch onnx onnxscript
```

Then run the export script:

```bash
python export_model.py
```

This will create:
```
models/
├── ml_guard.onnx        (~780 KB)
└── ml_guard.onnx.data   (~256 MB)
```

> **Expected output:**
> ```
> [1/4] Downloading model: distilbert-base-uncased-finetuned-sst-2-english
> [2/4] Creating dummy input
> [3/4] Creating output directory
> [4/4] Exporting to ONNX: models/ml_guard.onnx
> ✓ Done — models/ml_guard.onnx created (763 KB)
> ```

### Step 5 — (Optional) Set up Ollama for Phase 2b escalation

> **The server runs fine without this.** Ollama is only used for ambiguous prompts that score between the escalate and block thresholds. If Ollama is unavailable, the circuit breaker will default to blocking those prompts.

**5a. Install Ollama** from [https://ollama.com](https://ollama.com)

**5b. Download the GGUF model** (~806 MB) from Hugging Face:

```
Model: google/gemma-3-1b-it — GGUF Q4_K_M variant
File:  gemma-3-1b-it.Q4_K_M.gguf
Place: project root (same directory as Modelfile)
```

Direct download link:
```
https://huggingface.co/bartowski/google_gemma-3-1b-it-GGUF
```

**5c. Start Ollama and register the guard model:**

```bash
ollama serve
```

In a separate terminal:

```bash
ollama create foretyx-guard -f Modelfile
```

Verify it works:
```bash
ollama list
# foretyx-guard should appear
```

### Step 6 — Configure environment variables

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

Open `.env` and set the required values:

```env
# REQUIRED — your Google Gemini API key
GEMINI_API_KEY=your-gemini-api-key-here

# REQUIRED — admin key for /v1/logs and /v1/metrics
# Generate one: python -c "import secrets; print(secrets.token_urlsafe(32))"
ADMIN_API_KEY=your_secure_admin_key_here
```

All other values have sensible defaults and can be left as-is for local development.

---

## Setup — Docker

If you prefer Docker, this spins up both the gateway and Ollama in one command.

> **Prerequisite:** Docker Desktop must be running. Place `gemma-3-1b-it.Q4_K_M.gguf` in the project root and have `models/` populated before building.

```bash
# Copy and configure .env first
cp .env.example .env
# Edit .env with your GEMINI_API_KEY and ADMIN_API_KEY

# Build and start everything
docker compose up --build
```

The gateway will be available at `http://localhost:8000`.

To run in detached mode:
```bash
docker compose up --build -d
```

To stop:
```bash
docker compose down
```

---

## Running the Server

Once setup is complete, start the development server:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

For production (multi-worker, no reload):
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

**You should see output like:**
```
INFO:     Started server process
INFO:     Waiting for application startup.
{"event": "foretyx_data_plane_starting", "version": "2.0.0"}
{"event": "startup_status", "ml_model_loaded": true, "policy_loaded": true}
{"event": "foretyx_data_plane_ready", "host": "0.0.0.0", "port": 8000}
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

- **Swagger UI (interactive docs):** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health endpoint:** [http://localhost:8000/v1/health](http://localhost:8000/v1/health)

---

## Testing

### Run the full test suite

```bash
pytest tests/ -v
```

To run a specific test file:
```bash
pytest tests/test_heuristic_scanner.py -v
pytest tests/test_pii_detector.py -v
pytest tests/test_pipeline_integration.py -v
pytest tests/test_100_prompts.py -v
```

---

### 4 Quick Manual Test Commands

Replace `YOUR_ADMIN_KEY` below with the value of `ADMIN_API_KEY` from your `.env` file.

**Windows (PowerShell):**

**1. Health Check** — verify the server and all components are live
```powershell
Invoke-RestMethod http://localhost:8000/v1/health
```

**2. Guard-Only Scan** — inspect a benign prompt (no LLM call, instant response)
```powershell
Invoke-RestMethod -Method POST http://localhost:8000/v1/guard `
  -ContentType "application/json" `
  -Body '{"prompt": "What is the capital of France?"}'
```

**3. PII Scrub + Full Pipeline** — sends a prompt containing PII through all 6 phases, calls Gemini, and rehydrates the response
```powershell
Invoke-RestMethod -Method POST http://localhost:8000/v1/process `
  -ContentType "application/json" `
  -Body '{"prompt": "Send the Q3 report to john@acme.com and CC priya@corp.in", "org_id": "acme", "user_id": "user_001"}'
```

**4. Admin Metrics** — check live request stats (requires admin key)
```powershell
Invoke-RestMethod -Method GET -Uri http://localhost:8000/v1/metrics `
  -Headers @{Authorization="Bearer YOUR_ADMIN_KEY"}
```

---

**Linux / macOS (curl):**

```bash
# 1. Health check
curl http://localhost:8000/v1/health

# 2. Guard-only scan
curl -X POST http://localhost:8000/v1/guard \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is the capital of France?"}'

# 3. Full pipeline with PII
curl -X POST http://localhost:8000/v1/process \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Send the Q3 report to john@acme.com and CC priya@corp.in", "org_id": "acme", "user_id": "user_001"}'

# 4. Admin metrics
curl -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  http://localhost:8000/v1/metrics
```

---

## API Reference

| Method | Endpoint | Auth Required | Description |
|--------|----------|:---:|-------------|
| `GET` | `/v1/health` | No | Deep health check — model loaded, Ollama reachable, policy valid |
| `POST` | `/v1/guard` | No | Guard-only: scan prompt, return verdict (no LLM call) |
| `POST` | `/v1/process` | No | Full pipeline: guard → LLM → response scan → rehydrate |
| `POST` | `/v1/chat` | No | Multi-turn conversation with session memory |
| `DELETE` | `/v1/chat/{session_id}` | No | Terminate a chat session |
| `GET` | `/v1/chat/{session_id}/history` | No | Retrieve chat session history |
| `POST` | `/v1/rehydrate` | No | Standalone PII rehydration |
| `GET` | `/v1/logs` | **Yes** | Audit log retrieval with filter params |
| `GET` | `/v1/metrics` | **Yes** | Prometheus-style metrics |
| `GET` | `/v1/rate-limit/{org}/{user}` | **Yes** | Per-user rate limit stats |
| `GET` | `/v1/owasp-coverage` | **Yes** | OWASP LLM Top 10 coverage report |

> Admin endpoints require `Authorization: Bearer <ADMIN_API_KEY>` header.

---

## Security Architecture

### Guard Pipeline

| Phase | Component | What It Does | Latency |
|-------|-----------|-------------|---------|
| 1a | Heuristic Scanner | 60+ regex patterns for jailbreaks with Unicode normalization | <1ms |
| 1b | OWASP Scanner | All 10 OWASP LLM Top 10 categories (injection, DoS, model theft, etc.) | <1ms |
| 1c | Semantic Firewall | 100+ forbidden topics with category tagging | <1ms |
| 1d | PII Scrubber | 22+ entity types via Presidio (India-specific included) + Aadhaar Verhoeff | ~10ms |
| 2a | ML Injection Guard | ONNX DistilBERT with 3-tier scoring (pass / escalate / block) | ~15ms |
| 2b | Ollama Escalation | Local LLM judge for ambiguous cases (circuit breaker protected) | ~500ms |
| 3 | Token Budget | Accurate BPE token counting via tiktoken | <1ms |
| 4 | Policy Engine | Token limits, keyword blocklist, model allowlist | <1ms |

### Post-LLM Security

| Phase | Component | What It Does |
|-------|-----------|-------------|
| 5 | Response Scanner | Scans LLM output for leaked PII and system prompt exposure |
| 6 | Encrypted Rehydrator | AES-256-GCM encrypted PII restoration (never leaves the device) |

### PII Detection Coverage

| Category | Entity Types |
|----------|-------------|
| **India-specific** | Aadhaar (+ Verhoeff checksum), PAN, IFSC, GST, Voter ID, Passport, Driving License, Mobile, Bank Account |
| **Global** | Email, Phone, Credit Card, IP Address, IBAN, US SSN, Person, Location, DOB |
| **Credentials** | API Keys (OpenAI, AWS, Bearer), Passwords, Crypto Wallets (BTC, ETH) |

### Fail-Closed Design

Every phase fails-closed. If any guard crashes, errors, or times out, the prompt is **blocked** — it is never forwarded to the LLM.

---

## Project Structure

```
dataplane-final/
├── .env.example                    # Environment variable template (copy to .env)
├── .gitignore
├── Dockerfile                      # Multi-stage production build
├── docker-compose.yml              # One-command local deployment (gateway + Ollama)
├── Modelfile                       # Ollama guard model definition (uses GGUF)
├── export_model.py                 # ONNX model export utility
├── requirements.txt                # Pinned Python dependencies
├── README.md
├── SECURITY.md                     # Security audit & fixes documentation
├── SECURITY_AUDIT_SUMMARY.md       # Audit summary
├── walkthrough.md                  # Test suite walkthrough & results
│
├── app/
│   ├── main.py                     # FastAPI app with lifespan manager
│   ├── config.py                   # Pydantic Settings (env-based config)
│   ├── dependencies.py             # Dependency injection helpers
│   ├── security.py                 # Centralized security utilities
│   ├── security_mtls.py            # mTLS certificate validation
│   │
│   ├── contracts/                  # Pydantic v2 data contracts
│   │   ├── enums.py                # PiiType, BlockReason, EventType
│   │   ├── guard.py                # GuardResult, PiiDetection (+ warn fields)
│   │   ├── policy.py               # PolicyBundle, PiiRules
│   │   ├── events.py               # MetadataEvent (privacy-first telemetry)
│   │   └── api.py                  # Request/Response schemas
│   │
│   ├── guards/                     # Security detection modules
│   │   ├── heuristic_scanner.py    # Regex jailbreak patterns
│   │   ├── owasp_scanner.py        # OWASP LLM Top 10 (10/10 coverage)
│   │   ├── semantic_firewall.py    # Forbidden topic detection
│   │   ├── pii_detector.py         # Enhanced Presidio (22+ types)
│   │   ├── verhoeff.py             # Aadhaar Verhoeff checksum
│   │   ├── injection_detector.py   # ONNX ML guard
│   │   └── ollama_guard.py         # Async Ollama with circuit breaker
│   │
│   ├── engine/                     # Core pipeline logic
│   │   ├── pipeline.py             # Guard pipeline orchestrator
│   │   ├── llm_router.py           # Multi-model Gemini router
│   │   ├── rehydrator.py           # PII rehydration
│   │   ├── encrypted_rehydrator.py # AES-256-GCM encrypted rehydration
│   │   ├── response_scanner.py     # LLM response PII leak detection
│   │   ├── policy_engine.py        # Policy loading + enforcement
│   │   ├── token_budget.py         # tiktoken-based token counting
│   │   └── event_emitter.py        # SQLite telemetry buffer + dead-letter queue
│   │
│   ├── middleware/
│   │   ├── request_id.py           # X-Request-ID correlation header
│   │   ├── rate_limiter.py         # Global sliding window rate limiter
│   │   ├── per_user_rate_limiter.py # Per-user (org_id + user_id) rate limiter
│   │   └── access_log.py           # Structured JSON access logs
│   │
│   └── routes/
│       ├── guard.py                # POST /v1/guard
│       ├── process.py              # POST /v1/process
│       ├── chat.py                 # POST /v1/chat (multi-turn)
│       ├── health.py               # GET /v1/health
│       └── admin.py                # GET /v1/logs, /v1/metrics, /v1/rate-limit
│
├── models/                         # ⚠️ GITIGNORED — generate with export_model.py
│   ├── ml_guard.onnx               # ~780 KB
│   └── ml_guard.onnx.data          # ~256 MB
│
├── gemma-3-1b-it.Q4_K_M.gguf      # ⚠️ GITIGNORED — ~806 MB, download separately
│
└── tests/
    ├── conftest.py                 # Shared fixtures
    ├── test_100_prompts.py         # 110-prompt comprehensive suite
    ├── test_heuristic_scanner.py
    ├── test_pii_detector.py
    ├── test_injection_detector.py
    ├── test_pipeline_integration.py
    └── test_api_endpoints.py
```

---

## Configuration

All configuration is via environment variables in `.env`. Copy `.env.example` to get started.

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | *(required)* | Google Gemini API key |
| `ADMIN_API_KEY` | *(required)* | Admin key for `/v1/logs` and `/v1/metrics` |
| `DEFAULT_LLM_MODEL` | `gemini-2.0-flash` | Gemini model to use |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `foretyx-guard` | Ollama model name (from `Modelfile`) |
| `OLLAMA_TIMEOUT_SECONDS` | `30` | Timeout for Ollama escalation |
| `ML_BLOCK_THRESHOLD` | `0.98` | ONNX score ≥ this → block |
| `ML_ESCALATE_THRESHOLD` | `0.95` | ONNX score ≥ this → escalate to Ollama |
| `RATE_LIMIT_PER_MINUTE` | `60` | Max requests per minute per IP |
| `FAIL_BEHAVIOR` | `CLOSED` | `CLOSED` = block on error (production), `OPEN` = allow (dev only) |
| `LOG_FORMAT` | `json` | `json` for production, `console` for dev |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `MAX_PROMPT_LENGTH` | `50000` | Maximum raw prompt character length |
| `REQUIRE_HTTPS` | `false` | Enforce HTTPS in production |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |

---

## Monitoring

### Health Check
```bash
curl http://localhost:8000/v1/health
# {"status":"ok","version":"2.0.0","uptime_s":42.5,"model_loaded":true,"ollama_reachable":false,"policy_loaded":true}
```

### Metrics (requires admin key)
```bash
curl -H "Authorization: Bearer $ADMIN_API_KEY" http://localhost:8000/v1/metrics
# {"total_requests":150,"blocked_requests":12,"passed_requests":138,"warned_requests":3,"block_rate_pct":8.0}
```

### Request Tracing
Every request receives an `X-Request-ID` header. All structured log lines include this ID for end-to-end correlation across the pipeline.

---

## Privacy Guarantees

1. **Raw prompts never leave the device** — only anonymized metadata reaches the Control Plane
2. **PII values never leave the device** — scrubbed before LLM call, rehydrated from encrypted local memory
3. **LLM responses are scanned** — leaked PII in responses is caught and scrubbed before delivery
4. **Audit logs contain no PII** — only event types, scores, latency, and PII type counts
5. **Placeholder maps are AES-256-GCM encrypted** — PII mapping is cryptographically secure in memory

---

## License

Foretyx — Internal Use Only.
