from fastapi import APIRouter, HTTPException
from src.schema import DomainRequest
from src.services import validate
router = APIRouter()

@router.post("/validate")
def validate_domain(request: DomainRequest):
    result = validate.validate_domain(request.domain)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result
