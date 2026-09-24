from __future__ import annotations

import secrets
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from src.config import get_settings
from src.routes import tools, logs, scan, virus

settings = get_settings()
app = FastAPI(title="NetSek IQ API", version="1.1.0", description="Authorized public-asset assessment and log triage API.")
_requests: dict[str, deque[float]] = defaultdict(deque)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def protect_api(request: Request, call_next):
    """Small single-process guard; use a shared gateway limiter when scaling out."""
    if request.url.path not in {"/health", "/docs", "/openapi.json", "/redoc"}:
        if settings.api_key_required:
            presented = request.headers.get("authorization", "").removeprefix("Bearer ")
            if not settings.api_key or not secrets.compare_digest(presented, settings.api_key):
                return JSONResponse({"detail": "Valid bearer authentication is required."}, status_code=401)
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        bucket = _requests[client]
        while bucket and now - bucket[0] >= 60:
            bucket.popleft()
        if len(bucket) >= settings.rate_limit_per_minute:
            return JSONResponse({"detail": "Rate limit exceeded. Try again shortly."}, status_code=429)
        bucket.append(now)
    return await call_next(request)

app.include_router(tools.router, prefix="/tools")
app.include_router(logs.router, prefix="/logs")
app.include_router(scan.router, prefix="/scan")
app.include_router(virus.router, prefix="/virus")

@app.get("/health")
def health():
    return {"status": "ok", "environment": settings.environment}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
