from fastapi import APIRouter
from src.services import security
from src.schema import AssessmentRequest
from pydantic import BaseModel

router = APIRouter()

class PortScanInput(BaseModel):
    host: str
    ports: list[int]
    authorized: bool


@router.post('/scan')
def portScan(data: PortScanInput):
    if not data.authorized:
        return {"error": "You must confirm authorization before assessing an asset."}
    try:
        host, _ = security.validate_public_target(data.host)
        return {"host": host, "open_ports": security.check_ports(host, data.ports)}
    except ValueError as exc:
        return {"error": str(exc)}


@router.post('/assess')
def assess_public_asset(data: AssessmentRequest):
    if not data.authorized:
        return {"error": "You must confirm authorization before assessing an asset."}
    try:
        return {"result": security.assess(data.target, data.ports)}
    except ValueError as exc:
        return {"error": str(exc)}


@router.get('/history')
def assessment_history():
    return {"result": security.history_items()}




