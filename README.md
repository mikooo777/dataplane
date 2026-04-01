# Foretyx Data Plane v2.0

> **The Ultimate AI Security Gateway** — A production-grade, single-process, horizontally-scalable prompt security pipeline that shields your LLM from injection attacks, scrubs PII (22+ types including India-specific), enforces enterprise policies, and scans responses for leaked data — before any prompt reaches or leaves the model.

---

## Architecture

```
                          ┌──────────────────────────────────────────────────────┐
                          │              Foretyx Data Plane v2.0                 │
                          │         Single Process · All Guards In-Process       │
                          │                                                      │
  Raw Prompt ─────────────┤                                                      │
                          │  Phase 1a: Heuristic Scanner     (regex, <1ms)       │
                          │  Phase 1b: Semantic Firewall     (keywords, <1ms)    │
                          │  Phase 1c: PII Scrubber          (Presidio, ~10ms)   │
                          │  Phase 2a: ML Injection Guard    (ONNX, ~15ms)       │
                          │  Phase 2b: Ollama Escalation     (LLM, if ambiguous) │
                          │  Phase 3:  Policy Engine         (token/keyword/ACL) │
                          │                                                      │
                          │  ──────────── Clean Prompt → Gemini API ──────────── │
                          │                                                      │
                          │  Phase 4:  Response Scanner      (PII leak check)    │
                          │  Phase 5:  Rehydrator            (restore PII)       │
                          │                                                      │
  Final Response ◄────────┤  Telemetry → SQLite → Control Plane (no PII sent)   │
                          └──────────────────────────────────────────────────────┘
```

### Why Single-Process?

| Concern | Microservices (old) | Single-Process (v2.0) |
|---------|--------------------|-----------------------|
| Latency per phase | +5-15ms HTTP overhead | ~0ms (function call) |
| 3-phase pipeline | 15-45ms wasted on network | 0ms wasted |
| Horizontal scaling | Complex (4 services × N) | Simple (N instances behind LB) |
| Deployment | 4 terminals, 4 processes | 1 command |
| Failure isolation | One service down = partial | All-or-nothing (simpler) |

---

## Quick Start

### 1. Clone & Setup

```bash
git clone <repo-url>
cd final-data-plane

# Create virtual environment
python -m venv venv

# Activate (Windows)
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy model
python -m spacy download en_core_web_sm
```

### 2. Configure

```bash
copy .env.example .env
# Edit .env and set your GEMINI_API_KEY
```

### 3. Add ML Models

Place the ONNX model files in the `models/` directory:
- `models/ml_guard.onnx` (~780KB)
- `models/ml_guard.onnx.data` (~256MB)

> If you don't have these, run `python export_model.py` (requires PyTorch).

### 4. Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The server is live at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

### 5. Test

```bash
# Health check
curl http://localhost:8000/v1/health

# Guard-only check
curl -X POST http://localhost:8000/v1/guard \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is the capital of France?"}'

# Full pipeline (guard + LLM + rehydrate)
curl -X POST http://localhost:8000/v1/process \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Send report to john@acme.com about Q3 sales"}'

# Run test suite
pytest tests/ -v
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Deep health check (model loaded, Ollama reachable, policy valid) |
| `POST` | `/v1/guard` | Guard-only: scan prompt, return verdict (no LLM call) |
| `POST` | `/v1/process` | Full pipeline: guard → LLM → response scan → rehydrate |
| `POST` | `/v1/rehydrate` | Standalone PII rehydration |
| `GET` | `/v1/logs` | Audit log retrieval (metadata only, no prompts) |
| `GET` | `/v1/metrics` | Prometheus-style metrics (total, blocked, pass rate) |

---

## Security Architecture

### 6-Phase Guard Pipeline

| Phase | Component | What It Does | Latency |
|-------|-----------|-------------|---------|
| 1a | Heuristic Scanner | 60+ regex patterns for jailbreaks with Unicode normalization | <1ms |
| 1b | Semantic Firewall | 100+ forbidden topics with category tagging | <1ms |
| 1c | PII Scrubber | 22+ entity types via Presidio (India-specific included) | ~10ms |
| 2a | ML Injection Guard | ONNX DistilBERT with 3-tier scoring (pass/escalate/block) | ~15ms |
| 2b | Ollama Escalation | Local LLM judge for ambiguous cases (circuit breaker protected) | ~500ms |
| 3 | Policy Engine | Token limits, keyword blocklist, model allowlist from `~/.foretyx/policy.json` | <1ms |

### Post-LLM Security (NEW)

| Phase | Component | What It Does |
|-------|-----------|-------------|
| 4 | Response Scanner | Scans LLM output for leaked PII and system prompt exposure |
| 5 | Rehydrator | Restores original PII values into the response (never left the device) |

### Fail-Closed Everywhere

Every phase fails-closed. If a guard crashes, errors, or is unavailable, the prompt is **blocked** — never forwarded to the LLM.

| Component | On Failure |
|-----------|-----------|
| Heuristic Scanner | Block (regex can't fail) |
| PII Detector | Block |
| ML Guard (ONNX) | Block (model not loaded) |
| Ollama Guard | Block (circuit breaker) |
| Policy Engine | Block (missing policy) |

### PII Detection Coverage

| Category | Entity Types |
|----------|-------------|
| **India-specific** | Aadhaar, PAN, IFSC, GST, Voter ID, Passport, Driving License, Mobile, Bank Account |
| **Global** | Email, Phone, Credit Card, IP Address, IBAN, US SSN, Person, Location, DOB |
| **Credentials** | API Keys (OpenAI, AWS, Bearer), Passwords, Crypto Wallets (BTC, ETH) |

---

## Project Structure

```
final-data-plane/
├── .env.example                    # Environment variable template
├── .gitignore                      # Comprehensive gitignore
├── Dockerfile                      # Multi-stage production build
├── docker-compose.yml              # One-command local deployment
├── Modelfile                       # Ollama guard model definition
├── export_model.py                 # ONNX model export utility
├── requirements.txt                # Pinned dependencies
├── README.md
│
├── app/
│   ├── main.py                     # FastAPI app with lifespan
│   ├── config.py                   # Pydantic Settings (env-based)
│   ├── dependencies.py             # DI helpers
│   │
│   ├── contracts/                  # Pydantic v2 data contracts
│   │   ├── enums.py                # PiiType, BlockReason, EventType
│   │   ├── guard.py                # GuardResult, PiiDetection
│   │   ├── policy.py               # PolicyBundle, PiiRules
│   │   ├── events.py               # MetadataEvent (privacy-first)
│   │   └── api.py                  # Request/Response schemas
│   │
│   ├── guards/                     # Security detection modules
│   │   ├── heuristic_scanner.py    # Regex jailbreak patterns
│   │   ├── semantic_firewall.py    # Forbidden topic detection
│   │   ├── pii_detector.py         # Enhanced Presidio (22+ types)
│   │   ├── injection_detector.py   # ONNX ML guard
│   │   └── ollama_guard.py         # Async Ollama with circuit breaker
│   │
│   ├── engine/                     # Core pipeline logic
│   │   ├── pipeline.py             # Guard pipeline orchestrator
│   │   ├── llm_router.py           # Multi-model Gemini router
│   │   ├── rehydrator.py           # PII rehydration
│   │   ├── response_scanner.py     # LLM response PII leak detection
│   │   ├── policy_engine.py        # Policy loading + enforcement
│   │   └── event_emitter.py        # Privacy-first telemetry
│   │
│   ├── middleware/                  # Request processing
│   │   ├── request_id.py           # X-Request-ID correlation
│   │   ├── rate_limiter.py         # Sliding window rate limiter
│   │   └── access_log.py           # Structured JSON access logs
│   │
│   └── routes/                     # API endpoints
│       ├── guard.py                # POST /v1/guard
│       ├── process.py              # POST /v1/process
│       ├── health.py               # GET /v1/health
│       └── admin.py                # GET /v1/logs, /v1/metrics
│
├── models/                         # ONNX models (gitignored)
│   ├── ml_guard.onnx
│   └── ml_guard.onnx.data
│
└── tests/                          # Comprehensive test suite
    ├── conftest.py                 # Shared fixtures
    ├── test_heuristic_scanner.py   # 16 tests
    ├── test_pii_detector.py        # 13 tests
    ├── test_injection_detector.py  # 6 tests
    ├── test_pipeline_integration.py # 14 tests
    └── test_api_endpoints.py       # 11 tests
```

---

## Configuration

All configuration via environment variables (`.env`). Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | (required) | Google Gemini API key |
| `ML_BLOCK_THRESHOLD` | `0.98` | ONNX score ≥ this → block |
| `ML_ESCALATE_THRESHOLD` | `0.95` | ONNX score ≥ this → escalate to Ollama |
| `RATE_LIMIT_PER_MINUTE` | `60` | Max requests per minute per IP |
| `FAIL_BEHAVIOR` | `CLOSED` | `CLOSED` = block on error, `OPEN` = allow (dev only) |
| `LOG_FORMAT` | `json` | `json` for production, `console` for dev |
| `MAX_PROMPT_LENGTH` | `50000` | Maximum raw prompt character length |

---

## Docker

```bash
# Build and run with Ollama
docker compose up

# Or build standalone
docker build -t foretyx-data-plane .
docker run -p 8000:8000 --env-file .env foretyx-data-plane
```

---

## Monitoring

### Health Check
```bash
curl http://localhost:8000/v1/health
# {"status":"ok","version":"2.0.0","uptime_s":42.5,"model_loaded":true,"ollama_reachable":false,"policy_loaded":true}
```

### Metrics
```bash
curl http://localhost:8000/v1/metrics
# {"total_requests":150,"blocked_requests":12,"passed_requests":138,"pending_events":3,"block_rate_pct":8.0}
```

### Request Tracing
Every request gets an `X-Request-ID` header. All logs include this ID for end-to-end correlation.

---

## Data Contracts

All engineers share the same Pydantic v2 contracts (`app/contracts/`). This prevents magic-string bugs and ensures type safety across:
- **Data Plane** (this repo) → emits `GuardResult`
- **Bridge Layer** (Rishi) → converts to `MetadataEvent`
- **Control Plane** (Soham) → ingests `MetadataEvent`, pushes `PolicyBundle`

---

## Privacy Guarantees

1. **Raw prompts never leave the device** — only anonymized metadata reaches the Control Plane
2. **PII values never leave the device** — scrubbed before LLM call, rehydrated from local memory
3. **LLM responses are scanned** — leaked PII in responses is caught and scrubbed
4. **Audit logs contain no PII** — only event types, scores, latency, and pii type counts

---

## License

Foretyx — Internal Use Only.
