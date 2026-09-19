import hashlib


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_assessment_requires_authorization(client):
    response = client.post("/scan/assess", json={"target": "example.com", "authorized": False})
    assert response.status_code == 200
    assert "must confirm authorization" in response.json()["error"]


def test_assessment_returns_structured_result(client, monkeypatch):
    expected = {"id": "one", "target": "example.com", "addresses": ["93.184.216.34"], "open_ports": [443], "findings": [], "risk_score": 0}
    monkeypatch.setattr("src.routes.scan.security.assess", lambda target, ports: expected)
    response = client.post("/scan/assess", json={"target": "example.com", "authorized": True, "ports": [443]})
    assert response.status_code == 200
    assert response.json() == {"result": expected}


def test_assessment_returns_validation_error(client, monkeypatch):
    monkeypatch.setattr("src.routes.scan.security.assess", lambda *_: (_ for _ in ()).throw(ValueError("not public")))
    response = client.post("/scan/assess", json={"target": "localhost", "authorized": True})
    assert response.json() == {"error": "not public"}


def test_direct_port_scan_is_authorized_and_bounded(client, monkeypatch):
    monkeypatch.setattr("src.routes.scan.security.validate_public_target", lambda host: ("example.com", ["93.184.216.34"]))
    monkeypatch.setattr("src.routes.scan.security.check_ports", lambda host, ports: [443])
    rejected = client.post("/scan/scan", json={"host": "example.com", "ports": [443], "authorized": False})
    accepted = client.post("/scan/scan", json={"host": "example.com", "ports": [443], "authorized": True})
    assert "error" in rejected.json()
    assert accepted.json() == {"host": "example.com", "open_ports": [443]}


def test_history_route(client, monkeypatch):
    monkeypatch.setattr("src.routes.scan.security.history_items", lambda: [{"id": "latest"}])
    assert client.get("/scan/history").json() == {"result": [{"id": "latest"}]}


def test_domain_validation_route(client, monkeypatch):
    expected = {"result": {"valid": True, "domain": "example.com", "resolved_addresses": ["93.184.216.34"]}}
    monkeypatch.setattr("src.routes.tools.validate.validate_domain", lambda domain: expected)
    response = client.post("/tools/validate", json={"domain": "example.com"})
    assert response.status_code == 200
    assert response.json() == expected


def test_log_route_accepts_log_and_returns_findings(client, monkeypatch):
    expected = {"lines_analyzed": 1, "failed_auth_events": 0, "findings": []}
    monkeypatch.setattr("src.routes.logs.analyze_log", lambda content: expected)
    response = client.post("/logs/analyze", files={"file": ("access.log", b"hello", "text/plain")})
    assert response.status_code == 200
    assert response.json() == {"result": expected}


def test_log_route_rejects_bad_extension_and_large_files(client):
    bad_extension = client.post("/logs/analyze", files={"file": ("access.csv", b"hello", "text/csv")})
    large_file = client.post("/logs/analyze", files={"file": ("access.log", b"x" * 2_000_001, "text/plain")})
    assert bad_extension.status_code == 400
    assert large_file.status_code == 413


def test_file_intake_returns_hash_without_malware_claim(client):
    content = b"sample file"
    response = client.post("/virus/virus-scan", files={"file": ("sample.bin", content, "application/octet-stream")})
    result = response.json()["result"]
    assert response.status_code == 200
    assert result["sha256"] == hashlib.sha256(content).hexdigest()
    assert result["verdict"] == "unavailable"


def test_file_intake_rejects_oversized_file(client):
    response = client.post("/virus/virus-scan", files={"file": ("large.bin", b"x" * 10_000_001, "application/octet-stream")})
    assert response.status_code == 413
