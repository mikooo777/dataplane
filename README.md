# Foretyx Data Plane v2.0

> **Production-grade AI Security Gateway** — A single-process, horizontally-scalable prompt security pipeline that shields your LLM from injection attacks, scrubs PII (22+ entity types including India-specific identifiers), enforces enterprise policies, and scans responses for leaked data — before any prompt reaches or leaves the model.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Security Audit — What Changed in v2.0](#security-audit--what-changed-in-v20)
3. [Files Not Included in This Repo](#-files-not-included-in-this-repo)
4. [Prerequisites](#prerequisites)
5. [Setup — Native (Recommended for Dev)](#setup--native-recommended-for-dev)
6. [Setup — Docker](#setup--docker)
7. [Configuration](#configuration)
8. [Running the Server](#running-the-server)
9. [Testing](#testing)
10. [API Reference](#api-reference)
11. [Security Architecture](#security-architecture)
12. [Project Structure](#project-structure)
13. [Monitoring](#monitoring)
14. [Privacy Guarantees](#privacy-guarantees)
15. [System Flowchart](#system-flowchart)

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
                          │  Phase 2b: Ollama Escalation     (LLM, ambiguous)    │
                          │  Phase 3:  Token Budget          (tiktoken, <1ms)    │
                          │  Phase 4:  Policy Engine         (keyword/ACL)       │
                          │                                                      │
                          │  ──────────── Clean Prompt → Gemini API ──────────── │
                          │                                                      │
                          │  Phase 5:  Response Scanner      (PII leak check)    │
                          │  Phase 6:  Encrypted Rehydrator  (AES-256-GCM)       │
                          │                                                      │
  Final Response ◄────────┤  Telemetry → aiosqlite → Control Plane (no PII)     │
                          └──────────────────────────────────────────────────────┘
```

### Why Single-Process?

| Concern | Microservices | Single-Process v2.0 |
|---------|--------------|---------------------|
| Latency per phase | +5–15ms HTTP overhead | ~0ms (function call) |
| 6-phase pipeline | 30–90ms wasted on network | 0ms wasted |
| Horizontal scaling | Complex (4 services × N) | Simple (N instances behind LB) |
| Deployment | 4 terminals, 4 processes | 1 command |

---

## Security Audit — What Changed in v2.0

This release includes a full security audit pass. The following vulnerabilities were identified and patched:

| # | Priority | Component | Issue | Fix Applied |
|---|----------|-----------|-------|-------------|
| 1 | 🔴 P0 Critical | `chat.py` | `KeyError` crash — Pydantic attr vs. dict access in `_build_multi_turn_prompt` | Fixed attribute access to use dict `.get()` |
| 2 | 🔴 P0 Critical | `chat.py`, `process.py` | Per-user rate limiting was defined but never enforced | `PerUserRateLimiter.check()` wired into both routes |
| 3 | 🔴 Critical | `ollama_guard.py` | Fail-open on `JSONDecodeError` — bad JSON silently passed | Now blocks on any non-JSON response (fail-closed) |
| 4 | 🔴 Critical | `ollama_guard.py` | No response length validation — empty or huge strings bypassed | Added length guard (1–500 chars, else block) |
| 5 | 🔴 Critical | `config.py` | Circuit breaker `failure_threshold=5` gave 150s exposure window | Reduced to 3 failures / 90s window |
| 6 | 🟠 P1 High | `main.py` | `bridge_token` accepted empty string — auth header never sent | Minimum 16-char length check on startup |
| 7 | 🟠 P1 High | `admin.py` | `==` comparison for API key allows timing side-channel attacks | Replaced with `hmac.compare_digest` |
| 8 | 🟠 P1 High | `chat.py` | `/v1/chat/{id}/history` was unauthenticated — exposes session data | Now requires `Authorization: Bearer <ADMIN_API_KEY>` |
| 9 | 🟠 P1 Medium | `main.py` | `EncryptedRehydrator` was imported but `Rehydrator` (plain) was still instantiated | Switched to `EncryptedRehydrator` (AES-256-GCM) |
| 10 | 🟠 P1 Medium | `owasp_scanner.py` | No Unicode normalization — homoglyph characters bypassed regex | Added NFC normalization before all pattern matching |
| 11 | 🟡 P2 Low | `event_emitter.py` | Synchronous `sqlite3` blocked the uvicorn async event loop on every flush | Migrated to `aiosqlite` with WAL mode enabled |
| 12 | 🐛 Bug | `encrypted_rehydrator.py` | `restore()` expected `EncryptedPlaceholderMap` but pipeline passes plain `dict` → runtime crash | Made `restore()` accept both types transparently |
| 13 | 🐛 Bug | `pipeline.py` | Verhoeff-rejected Aadhaar placeholders were re-added to map in carry-over loop | Tracked and excluded rejected placeholders explicitly |
| 14 | 🐛 Bug | `tests/conftest.py` | `ADMIN_API_KEY` missing from test env — `Settings()` fails on import | Added test dummy value to `os.environ.setdefault` |

> **Architecture preserved**: No endpoints, entry points, or core data contracts were changed. All fixes are surgical patches to existing code.

---

## ⚠️ Files Not Included in This Repo

The following files are **gitignored** and will not be present after cloning:

| File | Size | Why Missing | How to Get It |
|------|------|-------------|---------------|
| `.env` | — | Contains secrets | Copy `.env.example` → `.env` and fill in your keys |
| `models/ml_guard.onnx` | ~780 KB | Binary model | Run `python export_model.py` |
| `models/ml_guard.onnx.data` | ~256 MB | Binary weights — too large for git | Run `python export_model.py` |
| `gemma-3-1b-it.Q4_K_M.gguf` | ~806 MB | Too large for git | Download from Hugging Face (see Step 5 below) |
| `foretyx_events.db` | — | Runtime SQLite — auto-created on first run | Created automatically |
| `venv/` | — | Virtual environment | Created locally by you |

> The server starts without the GGUF model and Ollama. Phase 2b escalation is skipped gracefully via the circuit breaker. The ONNX model is required for Phase 2a.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | 3.10 minimum |
| pip | Latest | `python -m pip install --upgrade pip` |
| Ollama | Latest | Optional — Phase 2b LLM escalation only |
| Docker + Compose | Latest | Only if using the Docker path |
| Google Gemini API Key | — | Required for `/v1/process` and `/v1/chat` |

---

## Setup — Native (Recommended for Dev)

### Step 1 — Clone the repo

```bash
git clone https://github.com/foretyxai-ship-it/dataplane-shipment.git
cd dataplane-shipment
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
python -m spacy download en_core_web_sm
```

### Step 4 — Generate the ONNX ML model

> Skip this if you already have `models/ml_guard.onnx`.

```bash
pip install torch onnx onnxscript
python export_model.py
```

Expected output:
```
[1/4] Downloading model: distilbert-base-uncased-finetuned-sst-2-english
[2/4] Creating dummy input
[3/4] Creating output directory
[4/4] Exporting to ONNX: models/ml_guard.onnx
✓ Done — models/ml_guard.onnx created (763 KB)
```

### Step 5 — (Optional) Set up Ollama for Phase 2b escalation

> The server runs without this. Ollama judges only ambiguous prompts.

**5a.** Install Ollama from [https://ollama.com](https://ollama.com)

**5b.** Download the GGUF model (~806 MB):
```
Model : google/gemma-3-1b-it — GGUF Q4_K_M variant
File  : gemma-3-1b-it.Q4_K_M.gguf
Place : project root (same directory as Modelfile)
Source: https://huggingface.co/bartowski/google_gemma-3-1b-it-GGUF
```

**5c.** Register and verify the guard model:
```bash
ollama serve
# in a separate terminal:
ollama create foretyx-guard -f Modelfile
ollama list   # foretyx-guard should appear
```

### Step 6 — Configure environment variables

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

Open `.env` and set the two required values:

```env
GEMINI_API_KEY=your-gemini-api-key-here

# Generate: python -c "import secrets; print(secrets.token_urlsafe(32))"
ADMIN_API_KEY=your_secure_admin_key_here
```

All other values have sensible defaults for local development.

---

## Setup — Docker

```bash
cp .env.example .env
# Edit .env with your GEMINI_API_KEY and ADMIN_API_KEY

docker compose up --build
```

Gateway available at `http://localhost:8000`.

```bash
docker compose up --build -d   # detached
docker compose down            # stop
```

---

## Running the Server

**Development:**
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Production (multi-worker):**
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Successful startup output:
```json
{"event": "foretyx_data_plane_starting", "version": "2.0.0"}
{"event": "startup_status", "ml_model_loaded": true, "policy_loaded": true}
{"event": "foretyx_data_plane_ready", "host": "0.0.0.0", "port": 8000}
```

- **Swagger UI:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health endpoint:** [http://localhost:8000/v1/health](http://localhost:8000/v1/health)

---

## Testing

```bash
# Full suite
pytest tests/ -v

# Individual files
pytest tests/test_heuristic_scanner.py -v
pytest tests/test_pii_detector.py -v
pytest tests/test_pipeline_integration.py -v
pytest tests/test_100_prompts.py -v
```

### Quick Manual Tests

**Windows PowerShell:**
```powershell
# 1. Health check
Invoke-RestMethod http://localhost:8000/v1/health

# 2. Guard-only scan (no LLM call)
Invoke-RestMethod -Method POST http://localhost:8000/v1/guard `
  -ContentType "application/json" `
  -Body '{"prompt": "What is the capital of France?"}'

# 3. Full pipeline with PII
Invoke-RestMethod -Method POST http://localhost:8000/v1/process `
  -ContentType "application/json" `
  -Body '{"prompt": "Send the Q3 report to john@acme.com", "org_id": "acme", "user_id": "user_001"}'

# 4. Admin metrics (replace YOUR_ADMIN_KEY)
Invoke-RestMethod -Method GET -Uri http://localhost:8000/v1/metrics `
  -Headers @{Authorization="Bearer YOUR_ADMIN_KEY"}
```

**Linux / macOS (curl):**
```bash
curl http://localhost:8000/v1/health

curl -X POST http://localhost:8000/v1/guard \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is the capital of France?"}'

curl -X POST http://localhost:8000/v1/process \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Send the Q3 report to john@acme.com", "org_id": "acme", "user_id": "user_001"}'

curl -H "Authorization: Bearer $ADMIN_API_KEY" \
  http://localhost:8000/v1/metrics
```

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|:----:|-------------|
| `GET` | `/v1/health` | No | Deep health check (model, Ollama, policy) |
| `POST` | `/v1/guard` | No | Guard-only scan — no LLM call |
| `POST` | `/v1/process` | No | Full pipeline: guard → LLM → scan → rehydrate |
| `POST` | `/v1/chat` | No | Multi-turn chat with session memory |
| `DELETE` | `/v1/chat/{session_id}` | No | Terminate a chat session |
| `GET` | `/v1/chat/{session_id}/history` | **Yes** | Retrieve session history |
| `POST` | `/v1/rehydrate` | No | Standalone PII rehydration |
| `GET` | `/v1/logs` | **Yes** | Audit log retrieval with filters |
| `GET` | `/v1/metrics` | **Yes** | Prometheus-style pipeline metrics |
| `GET` | `/v1/rate-limit/{org}/{user}` | **Yes** | Per-user rate limit status |
| `GET` | `/v1/owasp-coverage` | **Yes** | OWASP LLM Top 10 coverage report |
| `POST` | `/v1/admin/policy/refresh` | **Yes** | Reload policy bundle from disk |

> Admin endpoints require `Authorization: Bearer <ADMIN_API_KEY>` header.

---

## Security Architecture

### Guard Pipeline

| Phase | Component | What It Does | Latency |
|-------|-----------|-------------|---------|
| 1a | Heuristic Scanner | 60+ regex patterns for jailbreaks with NFC Unicode normalization | <1ms |
| 1b | OWASP Scanner | All 10 OWASP LLM Top 10 categories with NFC normalization | <1ms |
| 1c | Semantic Firewall | 100+ forbidden topics with intent-aware detection | <1ms |
| 1d | PII Scrubber | 22+ entity types via Presidio + Aadhaar Verhoeff checksum validation | ~10ms |
| 2a | ML Injection Guard | ONNX DistilBERT — 3-tier verdict: pass / escalate / block | ~15ms |
| 2b | Ollama Escalation | Local Gemma-3 judge for ambiguous cases (circuit breaker: 3 failures / 60s) | ~500ms |
| 3 | Token Budget | BPE token counting via tiktoken (cl100k_base) | <1ms |
| 4 | Policy Engine | Token limits, keyword blocklist, model allowlist (fail-closed on missing policy) | <1ms |

### Post-LLM Security

| Phase | Component | What It Does |
|-------|-----------|-------------|
| 5 | Response Scanner | Scans LLM output for leaked PII and system prompt exposure patterns |
| 6 | Encrypted Rehydrator | AES-256-GCM encrypted PII restoration — values never leave the device |

### PII Coverage (22+ Types)

| Category | Entity Types |
|----------|-------------|
| **India-specific** | Aadhaar (+ Verhoeff checksum), PAN, IFSC, GST, Voter ID, Passport, Driving License, Mobile, Bank Account |
| **Global** | Email, Phone, Credit Card, IP Address, IBAN, US SSN, Person, Location, Date of Birth |
| **Credentials** | API Keys (OpenAI, AWS, Bearer), Passwords, Crypto Wallets (BTC, ETH) |

### Fail-Closed Design

Every phase is fail-closed. If any guard crashes, errors, or times out, the prompt is **blocked** — never forwarded to the LLM.

---

## Configuration

All configuration via environment variables in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | *(required)* | Google Gemini API key |
| `ADMIN_API_KEY` | *(required, ≥32 chars)* | Admin key for protected endpoints |
| `DEFAULT_LLM_MODEL` | `gemini-2.0-flash` | Gemini model to use |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `foretyx-guard` | Ollama model name |
| `OLLAMA_TIMEOUT_SECONDS` | `30` | Ollama escalation timeout |
| `ML_BLOCK_THRESHOLD` | `0.98` | ONNX score ≥ this → block immediately |
| `ML_ESCALATE_THRESHOLD` | `0.95` | ONNX score ≥ this → escalate to Ollama |
| `CIRCUIT_BREAKER_THRESHOLD` | `3` | Ollama failures before circuit opens |
| `CIRCUIT_BREAKER_RECOVERY_SECONDS` | `60` | Seconds before circuit half-opens |
| `RATE_LIMIT_PER_MINUTE` | `60` | Max requests per minute per IP |
| `FAIL_BEHAVIOR` | `CLOSED` | `CLOSED` = block on error, `OPEN` = allow (dev only) |
| `LOG_FORMAT` | `json` | `json` for production, `console` for dev |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `MAX_PROMPT_LENGTH` | `50000` | Maximum raw prompt character length |
| `REQUIRE_HTTPS` | `false` | Enforce HTTPS in production |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |

---

## Project Structure

```
dataplane-shipment/
├── .env.example                    # Environment variable template
├── .gitignore
├── Dockerfile                      # Multi-stage production build
├── docker-compose.yml              # One-command local deployment
├── Modelfile                       # Ollama guard model definition (GGUF)
├── export_model.py                 # ONNX model export utility
├── requirements.txt                # Pinned Python dependencies
├── README.md
├── SECURITY.md                     # Detailed security architecture
├── SECURITY_AUDIT_SUMMARY.md       # v2.0 audit findings and fixes
├── walkthrough.md                  # Test suite walkthrough and results
├── Foretyx_Flowchart.pdf           # Full system flowchart with clickable Mermaid links
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
│   │   ├── heuristic_scanner.py    # Regex jailbreak patterns (NFC normalized)
│   │   ├── owasp_scanner.py        # OWASP LLM Top 10 (10/10 coverage, NFC)
│   │   ├── semantic_firewall.py    # Forbidden topic + intent detection
│   │   ├── pii_detector.py         # Enhanced Presidio (22+ entity types)
│   │   ├── verhoeff.py             # Aadhaar Verhoeff checksum
│   │   ├── injection_detector.py   # ONNX ML guard (DistilBERT)
│   │   └── ollama_guard.py         # Async Ollama with circuit breaker (fail-closed)
│   │
│   ├── engine/                     # Core pipeline logic
│   │   ├── pipeline.py             # Guard pipeline orchestrator (all 6 phases)
│   │   ├── llm_router.py           # Multi-model Gemini router with retry backoff
│   │   ├── rehydrator.py           # Plain PII rehydration
│   │   ├── encrypted_rehydrator.py # AES-256-GCM encrypted rehydration (active)
│   │   ├── response_scanner.py     # LLM response PII leak + prompt leak detection
│   │   ├── policy_engine.py        # Policy loading + enforcement (fail-closed)
│   │   ├── token_budget.py         # tiktoken BPE token counting
│   │   └── event_emitter.py        # aiosqlite async telemetry buffer + flush loop
│   │
│   ├── middleware/
│   │   ├── request_id.py           # X-Request-ID injection + validation
│   │   ├── rate_limiter.py         # Global sliding window IP rate limiter
│   │   ├── per_user_rate_limiter.py # Per-user (org_id + user_id) rate limiter
│   │   └── access_log.py           # Structured JSON access logs
│   │
│   └── routes/
│       ├── guard.py                # POST /v1/guard
│       ├── process.py              # POST /v1/process
│       ├── chat.py                 # POST /v1/chat (multi-turn, session memory)
│       ├── health.py               # GET /v1/health
│       └── admin.py                # Admin: logs, metrics, rate-limit, OWASP coverage
│
├── models/                         # ⚠️ GITIGNORED — generate with export_model.py
│   ├── ml_guard.onnx               # ~780 KB
│   └── ml_guard.onnx.data          # ~256 MB
│
├── gemma-3-1b-it.Q4_K_M.gguf      # ⚠️ GITIGNORED — ~806 MB, download separately
│
└── tests/
    ├── conftest.py                 # Shared fixtures + test env setup
    ├── test_100_prompts.py         # 110-prompt comprehensive harness
    ├── test_heuristic_scanner.py
    ├── test_pii_detector.py
    ├── test_injection_detector.py
    ├── test_pipeline_integration.py
    └── test_api_endpoints.py
```

---

## Monitoring

### Health Check
```bash
curl http://localhost:8000/v1/health
# {"status":"ok","version":"2.0.0","uptime_s":42.5,"model_loaded":true,"ollama_reachable":false,"policy_loaded":true}
```

### Metrics (admin key required)
```bash
curl -H "Authorization: Bearer $ADMIN_API_KEY" http://localhost:8000/v1/metrics
# {"total_requests":150,"blocked_requests":12,"passed_requests":138,"warned_requests":3,"block_rate_pct":8.0}
```

### Request Tracing
Every request receives an `X-Request-ID` header. All structured log lines include this ID for end-to-end correlation.

---

## Privacy Guarantees

1. **Raw prompts never leave the device** — only anonymized metadata reaches the Control Plane
2. **PII values never leave the device** — scrubbed before LLM call, rehydrated from AES-256-GCM encrypted local memory
3. **LLM responses are scanned** — leaked PII in responses is caught and scrubbed before delivery
4. **Audit logs contain no PII** — only event types, scores, latency, and PII type counts
5. **Placeholder maps are AES-256-GCM encrypted** — cryptographically secured in-process
6. **Telemetry uses aiosqlite (async WAL mode)** — database I/O never blocks the event loop

---

## System Flowchart

The complete system flowchart is included in this repo as **`Foretyx_Flowchart.pdf`**.

It contains 9 detailed sections:

| Section | Contents |
|---------|----------|
| 1 | High-level architecture (Client → Gateway → LLM → Response) |
| 2 | Middleware stack execution order with pass/fail paths |
| 3 | All endpoints with auth requirements |
| 4 | `/v1/process` full request lifecycle |
| 5 | Guard pipeline — all 6 phases with every decision branch |
| 6 | `/v1/chat` multi-turn session flow |
| 7 | Test case matrix — 60+ cases across 10 categories (A–J) |
| 8 | Privacy-first telemetry flow (what is and isn't sent to cloud) |
| 9 | Startup initialization sequence |

Each Mermaid diagram in the PDF includes a **clickable link to the Mermaid Live Editor** so you can view, edit, and export them interactively.

---

## License

Foretyx — Internal Use Only.
