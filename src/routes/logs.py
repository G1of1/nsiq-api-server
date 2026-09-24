from fastapi import HTTPException, UploadFile, File, APIRouter
from src.services.logs import analyze_log, enrich_with_gemini
from src.services.uploads import read_limited

router = APIRouter()


@router.post("/analyze")
async def analyze_uploaded_log(file: UploadFile = File(...), ai_enrichment: bool = False):
    if not file.filename or not file.filename.lower().endswith((".log", ".txt")):
        raise HTTPException(400, "Upload a .log or .txt file.")
    content = await read_limited(file, 2_000_000)
    result = analyze_log(content.decode("utf-8", errors="replace"))
    if ai_enrichment:
        result["ai_enrichment"] = await enrich_with_gemini(content.decode("utf-8", errors="replace"), result)
    return {"result": result}


