"""Environment-backed runtime configuration. Secrets are never committed."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _csv(name: str, default: str = "") -> tuple[str, ...]:
    return tuple(item.strip().lower().rstrip(".") for item in os.getenv(name, default).split(",") if item.strip())


def _truthy(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    environment: str
    api_key: str | None
    allowed_origins: tuple[str, ...]
    allowed_targets: tuple[str, ...]
    rate_limit_per_minute: int
    database_path: Path
    gemini_enabled: bool
    gemini_api_key: str | None
    gemini_model: str

    @property
    def api_key_required(self) -> bool:
        return self.environment == "production" or bool(self.api_key)


def get_settings() -> Settings:
    environment = os.getenv("ENVIRONMENT", "development").lower()
    api_key = os.getenv("NSIQ_API_KEY") or None
    if environment == "production" and not api_key:
        raise RuntimeError("NSIQ_API_KEY must be set when ENVIRONMENT=production.")
    rate_limit = int(os.getenv("NSIQ_RATE_LIMIT_PER_MINUTE", "20"))
    if rate_limit < 1:
        raise RuntimeError("NSIQ_RATE_LIMIT_PER_MINUTE must be at least 1.")
    return Settings(
        environment=environment,
        api_key=api_key,
        allowed_origins=_csv("NSIQ_ALLOWED_ORIGINS", "http://localhost:3000"),
        allowed_targets=_csv("NSIQ_ALLOWED_TARGETS"),
        rate_limit_per_minute=rate_limit,
        database_path=Path(os.getenv("NSIQ_DATABASE_PATH", "data/assessments.db")),
        gemini_enabled=_truthy("NSIQ_GEMINI_ENABLED"),
        gemini_api_key=os.getenv("GEMINI_API_KEY") or None,
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
    )
