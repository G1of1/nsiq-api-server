# NetSek IQ server

The backend is a FastAPI service that provides validated public-asset assessment, lightweight domain validation, and in-memory log triage for the NetSek IQ frontend.

For the overall product narrative and full-stack run instructions, see the [project README](../README.md). For the UI, see the [client README](../nsiq-client/README.md).

## Requirements

- Python 3.13 or later
- A network connection when assessing authorized public assets

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8000
```

Interactive API documentation is available at `http://localhost:8000/docs`; a health check is available at `GET /health`.

## API overview

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Service readiness check |
| `POST` | `/scan/assess` | Run an authorized public-asset assessment |
| `GET` | `/scan/history` | Return the latest 50 local assessments |
| `POST` | `/logs/analyze` | Analyze a `.log` or `.txt` file in memory |
| `POST` | `/tools/validate` | Resolve and validate a public domain |
| `POST` | `/virus/virus-scan` | Return file metadata and SHA-256; no malware verdict is made without an engine |

### Assessment request

```json
{
  "target": "example.com",
  "authorized": true,
  "ports": [80, 443, 22, 21, 25, 3389]
}
```

The response includes resolved addresses, reachable selected ports, structured findings, and a risk score. The ports list is restricted server-side to an explicit small allowlist.

## Safety boundaries

- Assessment requests must include `authorized: true`.
- Target validation rejects private, loopback, link-local, and reserved IP ranges.
- Connection checks use bounded timeouts and a short allowlist of commonly relevant ports.
- Log uploads accept only `.log` and `.txt` files up to 2 MB and are processed without being written to disk.
- File intake has a 10 MB limit and returns a SHA-256 identifier only. It never treats a hash as a malware verdict.
- CORS permits the local frontend origin only by default.

## Local data

Assessment history is stored in `nsiq-server/data/assessments.json` at runtime and is excluded from source control. It is intentionally simple for a local demo; use a database, encryption, retention policy, and access controls before multi-user deployment.

## Verification

```powershell
python -m compileall -q src
python -m pytest
```

The pytest suite covers the FastAPI routes, request validation, authorization gates, public-target filtering, bounded port checks, TLS and HTTP-header findings, local history persistence, log-analysis detections, domain validation, and file-intake limits. Network and filesystem boundaries are mocked in service tests, so tests do not assess real assets.

The repository CI installs these dependencies, compiles the API package, runs pytest, and builds the frontend.
