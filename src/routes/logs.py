from fastapi import HTTPException, UploadFile, File, APIRouter
from src.services.logs import analyze_log

router = APIRouter()


@router.post("/analyze")
async def analyze_uploaded_log(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith((".log", ".txt")):
        raise HTTPException(400, "Upload a .log or .txt file.")
    content = await file.read()
    if len(content) > 2_000_000:
        raise HTTPException(413, "Log files must be smaller than 2 MB.")
    return {"result": analyze_log(content.decode("utf-8", errors="replace"))}



