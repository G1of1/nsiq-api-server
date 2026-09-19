from fastapi import APIRouter, UploadFile, File
from src.services import virus

router = APIRouter()

@router.post("/virus-scan")
async def scan_file(file: UploadFile = File(...)):
    return await virus.virus_scan(file)

