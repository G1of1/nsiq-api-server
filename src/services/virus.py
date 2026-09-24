"""File intake metadata endpoint.

Malware verdicts require a maintained detection engine or an explicitly configured
third-party service; this API intentionally does not present a hash as a verdict.
"""
import hashlib
from fastapi import HTTPException, UploadFile
from src.services.uploads import read_limited


async def virus_scan(file: UploadFile):
    content = await read_limited(file, 10_000_000)
    return {"result": {"filename": file.filename, "sha256": hashlib.sha256(content).hexdigest(), "bytes_received": len(content), "verdict": "unavailable", "message": "No malware engine is configured. This file was not declared safe or malicious."}}
