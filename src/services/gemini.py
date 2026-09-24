"""Optional, privacy-aware Gemini enrichment for locally generated log findings."""
from __future__ import annotations

import re

import httpx

from src.config import get_settings

MAX_PROMPT_CHARS = 12_000
_SECRET = re.compile(r"(?i)(authorization:\s*bearer\s+|password[=:]\s*|api[_-]?key[=:]\s*)[^\s&]+")


def _redact(text: str) -> str:
    return _SECRET.sub(r"\1[REDACTED]", text)


async def enrich_log(log_text: str, deterministic_result: dict) -> dict:
    settings = get_settings()
    if not settings.gemini_enabled:
        return {"status": "disabled", "message": "AI enrichment is disabled by configuration."}
    if not settings.gemini_api_key:
        return {"status": "unavailable", "message": "GEMINI_API_KEY is not configured."}

    prompt = (
        "You are assisting a defensive security analyst. Analyze only the supplied sanitized log excerpt. "
        "Do not claim certainty, invent facts, provide exploitation instructions, or output secrets. "
        "Return JSON with keys summary (string), priority (low|medium|high), recommended_actions (array of at most 3 strings), and limitations (string).\n\n"
        f"Deterministic findings: {deterministic_result}\n\nSanitized log excerpt:\n{_redact(log_text)[:MAX_PROMPT_CHARS]}"
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json", "temperature": 0.1, "maxOutputTokens": 500},
    }
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            response = await client.post(url, params={"key": settings.gemini_api_key}, json=payload)
            response.raise_for_status()
        text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        import json
        result = json.loads(text)
        if not isinstance(result, dict) or not isinstance(result.get("summary"), str):
            raise ValueError("Unexpected model response")
        return {"status": "complete", "provider": "gemini", "analysis": result}
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
        return {"status": "unavailable", "message": "AI enrichment could not be completed; deterministic findings remain available."}
