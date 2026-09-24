from fastapi import APIRouter, HTTPException, UploadFile, File
from src.services import security, virus
from src.schema import AssessmentRequest
from pydantic import BaseModel, Field

router = APIRouter()

class PortScanInput(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    ports: list[int] = Field(max_length=20)
    authorized: bool


@router.post('/port-scan')
def portScan(data: PortScanInput):
    if not data.authorized:
        raise HTTPException(403, "You must confirm authorization before assessing an asset.")
    try:
        host, addresses = security.validate_public_target(data.host)
        security.enforce_target_allowlist(host)
        return {"host": host, "open_ports": security.check_ports(host, addresses, data.ports)}
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/virus-scan")
async def scan_file(file: UploadFile = File(...)):
    return await virus.virus_scan(file)


@router.post('/assess')
def assess_public_asset(data: AssessmentRequest):
    if not data.authorized:
        raise HTTPException(403, "You must confirm authorization before assessing an asset.")
    try:
        return {"result": security.assess(data.target, data.ports)}
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get('/history')
def assessment_history():
    return {"result": security.history_items()}


