# NetSek IQ API

FastAPI backend for an authorized public-asset assessment and log-triage demo. It converts bounded service checks and local log evidence into findings with severity, evidence, and remediation—not raw scan output.

## Portfolio highlights

- Public-only assessment with DNS resolution validation, a small server-side port allowlist, bounded network timeouts, and DNS-pinned outbound connections.
- TLS certificate and HTTPS-header checks with transparent risk scoring.
- In-memory log analysis and an optional, explicitly requested Gemini enrichment path; deterministic results remain available if AI is disabled or unavailable.
- SQLite-backed, capped assessment history with a non-root Docker image, healthcheck, environment-driven CORS, bearer authentication, and per-process rate limiting.

## Architecture

```text
Browser client ──Bearer token──> FastAPI
                                  ├─ authorized target validation → pinned public IP checks
                                  ├─ local SQLite history
                                  └─ optional sanitized excerpt → Gemini API
```

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn src.main:app --reload --port 8000
```

Interactive documentation is at `http://localhost:8000/docs`; `GET /health` is available without authentication.

## Deploy configuration

Copy `.env.example` into your deployment’s secret/environment manager—never commit a real `.env` file. At minimum set:

```dotenv
ENVIRONMENT=production
NSIQ_API_KEY=generate-a-long-random-value
NSIQ_ALLOWED_ORIGINS=https://your-frontend.example
NSIQ_ALLOWED_TARGETS=.your-company.example
```

All API routes except health and documentation require `Authorization: Bearer <NSIQ_API_KEY>` when a key is configured (always in production). Production also refuses scans unless an exact domain or dot-prefixed domain-suffix allowlist is configured. The included rate limit is per process; enforce a shared rate limit and request-size cap at your reverse proxy/API gateway when scaling.

Do not place `NSIQ_API_KEY` in a browser-visible `NEXT_PUBLIC_*` variable. For the current direct-browser frontend, add a server-side Next.js API route (or an API gateway with OIDC) that holds the backend credential and authorizes the user before forwarding requests.

Run the container with a persistent volume mounted at `/app/data`:

```powershell
docker build -t nsiq-server .
docker run --rm -p 8000:8000 --env-file .env -v "${PWD}/data:/app/data" nsiq-server
```

## Optional Gemini log enrichment

Gemini is disabled by default. Enable it only after assessing your organization’s data-handling requirements: even sanitized log excerpts can contain sensitive operational context.

```dotenv
NSIQ_GEMINI_ENABLED=true
GEMINI_API_KEY=your-key
GEMINI_MODEL=gemini-2.5-flash
```

Request enrichment with `POST /logs/analyze?ai_enrichment=true`. The API redacts common bearer-token, password, and API-key patterns, truncates the excerpt to 12,000 characters, and asks Gemini for structured analyst guidance. This is supplementary, not a malware verdict or security guarantee. The implementation uses Gemini's JSON response mode, documented by [Google AI for Developers](https://ai.google.dev/gemini-api/docs/structured-output).

## API overview

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Health status |
| `POST` | `/scan/assess` | Authorized public-asset assessment |
| `POST` | `/scan/scan` | Bounded selected-port check |
| `GET` | `/scan/history` | Latest 50 local assessments |
| `POST` | `/logs/analyze` | Analyze a `.log` or `.txt` upload |
| `POST` | `/tools/validate` | Resolve and validate a public domain |
| `POST` | `/virus/virus-scan` | SHA-256 metadata only; no malware verdict |

## Safety boundaries and limitations

- Use only on assets you own or are explicitly authorized to assess. The application’s target allowlist and user authentication are technical safeguards, not proof of permission.
- Assessment is intentionally narrow: it is not vulnerability scanning, penetration testing, or continuous monitoring.
- Uploads are processed in memory and are never persisted; uploads are read in chunks and capped at 2 MB for logs and 10 MB for file metadata.
- SQLite history is appropriate for a single-instance demo. Use managed database storage, OIDC/RBAC, centralized audit logs, and a shared rate limiter for a multi-user product.

## Verification

```powershell
python -m compileall -q src
python -m pytest
docker build -t nsiq-server .
```

The tests mock network boundaries and cover authorization acknowledgement, target filtering, DNS-pinned connections, TLS/header analysis, SQLite retention, upload limits, log detections, and the no-malware-verdict contract.
