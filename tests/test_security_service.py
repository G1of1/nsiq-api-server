from datetime import datetime, timedelta, timezone

import pytest

from src.services import security


class FakeConnection:
    def __init__(self, certificate=None):
        self.certificate = certificate

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def getpeercert(self):
        return self.certificate


def test_validate_public_target_normalizes_and_returns_public_addresses(monkeypatch):
    monkeypatch.setattr(security.socket, "getaddrinfo", lambda *_: [(None, None, None, None, ("8.8.8.8", 0)), (None, None, None, None, ("1.1.1.1", 0))])
    host, addresses = security.validate_public_target("HTTPS://Example.COM.")
    assert host == "example.com"
    assert addresses == ["1.1.1.1", "8.8.8.8"]


@pytest.mark.parametrize("target", ["", "bad host", "a" * 254])
def test_validate_public_target_rejects_invalid_names(target):
    with pytest.raises(ValueError, match="valid hostname"):
        security.validate_public_target(target)


def test_validate_public_target_rejects_non_public_and_unresolved_targets(monkeypatch):
    monkeypatch.setattr(security.socket, "getaddrinfo", lambda *_: [(None, None, None, None, ("127.0.0.1", 0))])
    with pytest.raises(ValueError, match="Private"):
        security.validate_public_target("localhost")

    def unresolved(*_):
        raise security.socket.gaierror()
    monkeypatch.setattr(security.socket, "getaddrinfo", unresolved)
    with pytest.raises(ValueError, match="could not be resolved"):
        security.validate_public_target("missing.example")


def test_check_ports_filters_allowlist_and_collects_reachable_ports(monkeypatch):
    calls = []

    def create_connection(address, timeout):
        calls.append((address, timeout))
        if address[1] == 443:
            return FakeConnection()
        raise OSError("closed")

    monkeypatch.setattr(security.socket, "create_connection", create_connection)
    assert security.check_ports("example.com", [443, 9999, 22]) == [443]
    assert [call[0][1] for call in calls] == [443, 22]


def test_certificate_finding_reports_expiring_and_invalid_certificates(monkeypatch):
    expires = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")

    class Context:
        def wrap_socket(self, raw_socket, server_hostname):
            assert server_hostname == "example.com"
            return FakeConnection({"notAfter": expires})

    monkeypatch.setattr(security.socket, "create_connection", lambda *_args, **_kwargs: FakeConnection())
    monkeypatch.setattr(security.ssl, "create_default_context", lambda: Context())
    finding = security.certificate_finding("example.com")
    assert finding["severity"] == "high"
    assert finding["title"] == "TLS certificate expires soon"

    monkeypatch.setattr(security.socket, "create_connection", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("no tls")))
    assert security.certificate_finding("example.com")["title"] == "TLS certificate could not be verified"


def test_header_findings_detect_missing_headers_and_ignores_request_failures(monkeypatch):
    class Response(FakeConnection):
        headers = {"Strict-Transport-Security": "max-age=1", "X-Frame-Options": "DENY"}

    monkeypatch.setattr(security, "urlopen", lambda *_args, **_kwargs: Response())
    titles = [item["title"] for item in security.header_findings("example.com")]
    assert "Missing strict-transport-security" not in titles
    assert "Missing x-frame-options" not in titles
    assert "Missing content-security-policy" in titles

    monkeypatch.setattr(security, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")))
    assert security.header_findings("example.com") == []


def test_assessment_scores_findings_and_persists_history(monkeypatch, tmp_path):
    data_file = tmp_path / "assessments.json"
    monkeypatch.setattr(security, "DATA_FILE", data_file)
    monkeypatch.setattr(security, "validate_public_target", lambda target: ("example.com", ["93.184.216.34"]))
    monkeypatch.setattr(security, "check_ports", lambda host, ports: [443, 3389])
    monkeypatch.setattr(security, "certificate_finding", lambda host: security.finding("medium", "TLS certificate expires soon", "soon", "renew"))
    monkeypatch.setattr(security, "header_findings", lambda host: [security.finding("low", "Missing header", "missing", "add")])

    assessment = security.assess("example.com", [443, 3389])
    assert assessment["risk_score"] == 38
    assert assessment["open_ports"] == [443, 3389]
    assert len(security.history_items()) == 1

    data_file.write_text("not json", encoding="utf-8")
    assert security.history_items() == []


def test_history_is_limited_to_fifty_items(monkeypatch, tmp_path):
    monkeypatch.setattr(security, "DATA_FILE", tmp_path / "history.json")
    for index in range(51):
        security._save_assessment({"id": str(index)})
    history = security.history_items()
    assert len(history) == 50
    assert history[0]["id"] == "50"
