from fastapi import APIRouter
from src.schema import DomainRequest
from src.services import validate
router = APIRouter()

@router.post("/validate")
def validate_domain(request: DomainRequest):
    return validate.validate_domain(request.domain)
