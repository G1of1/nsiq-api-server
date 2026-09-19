from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.routes import tools, logs, scan, virus
app = FastAPI(title="NetSek IQ API", version="1.0.0", description="Authorized public-asset assessment and log triage API.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tools.router, prefix="/tools")
app.include_router(logs.router, prefix="/logs")
app.include_router(scan.router, prefix="/scan")
app.include_router(virus.router, prefix="/virus")

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
