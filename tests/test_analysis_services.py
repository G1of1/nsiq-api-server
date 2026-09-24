import io
import asyncio

import pytest
from fastapi import HTTPException, UploadFile

from src.services import logs, validate, virus
from src.services import gemini


def test_log_analysis_detects_brute_force_and_web_probing():
    content = ("Failed password for root from 8.8.8.8\n" * 5) + "GET /.env HTTP/1.1\n"
    result = logs.analyze_log(content)
    assert result["lines_analyzed"] == 6
    assert result["failed_auth_events"] == 5
    assert {item["title"] for item in result["findings"]} == {"Potential brute-force activity", "Web probing indicators"}


def test_log_analysis_returns_no_finding_for_benign_content():
    result = logs.analyze_log("GET /health HTTP/1.1\n")
    assert result == {"lines_analyzed": 1, "failed_auth_events": 0, "findings": []}


def test_domain_validation_returns_result_or_error(monkeypatch):
    monkeypatch.setattr("src.services.security.validate_public_target", lambda domain: ("example.com", ["93.184.216.34"]))
    assert validate.validate_domain("example.com")["result"]["valid"] is True

    monkeypatch.setattr("src.services.security.validate_public_target", lambda domain: (_ for _ in ()).throw(ValueError("not public")))
    assert validate.validate_domain("localhost") == {"error": "not public"}


def test_file_intake_returns_metadata_and_enforces_limit():
    upload = UploadFile(filename="sample.bin", file=io.BytesIO(b"hello"))
    result = asyncio.run(virus.virus_scan(upload))
    assert result["result"]["bytes_received"] == 5
    assert result["result"]["verdict"] == "unavailable"

    large_upload = UploadFile(filename="large.bin", file=io.BytesIO(b"x" * 10_000_001))
    with pytest.raises(HTTPException) as error:
        asyncio.run(virus.virus_scan(large_upload))
    assert error.value.status_code == 413


def test_gemini_enrichment_is_disabled_without_explicit_configuration(monkeypatch):
    monkeypatch.setenv("NSIQ_GEMINI_ENABLED", "false")
    result = asyncio.run(gemini.enrich_log("password=hunter2", {"findings": []}))
    assert result["status"] == "disabled"


def test_gemini_redacts_common_secret_patterns():
    redacted = gemini._redact("Authorization: Bearer abc123 password=secret api_key: value")
    assert "abc123" not in redacted
    assert "secret" not in redacted
    assert "value" not in redacted
