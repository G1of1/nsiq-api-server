"""Bounded, public-only asset assessment helpers."""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import sqlite3
import ssl
from datetime import datetime, timezone

from src.config import get_settings

ALLOWED_PORTS = {21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443}
SECURITY_HEADERS = {
    "strict-transport-security": "Enable HSTS to require HTTPS connections.",
    "content-security-policy": "Add a Content-Security-Policy to reduce script injection risk.",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
    "x-frame-options": "Set X-Frame-Options or frame-ancestors to mitigate clickjacking.",
    "referrer-policy": "Set a restrictive Referrer-Policy.",
}


def validate_public_target(target: str) -> tuple[str, list[str]]:
    """Resolve a host once and reject every non-public result before connection."""
    cleaned = target.strip().lower().rstrip(".")
    if "://" in cleaned:
        from urllib.parse import urlparse
        cleaned = urlparse(cleaned).hostname or ""
    if not cleaned or len(cleaned) > 253 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in cleaned):
        raise ValueError("Enter a valid hostname or public IP address.")
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(cleaned, None)})
    except socket.gaierror as exc:
        raise ValueError("Target could not be resolved.") from exc
    if not addresses:
        raise ValueError("Target could not be resolved.")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("Private, loopback, link-local, and reserved targets are not permitted.")
    return cleaned, addresses


def enforce_target_allowlist(host: str) -> None:
    """Require a configured exact domain or dot-prefixed suffix in production."""
    settings = get_settings()
    if not settings.allowed_targets:
        if settings.environment == "production":
            raise ValueError("No authorized target allowlist is configured.")
        return
    if any(host == item or (item.startswith(".") and host.endswith(item)) for item in settings.allowed_targets):
        return
    raise ValueError("Target is not in the authorized target allowlist.")


def check_ports(host: str, addresses: list[str], ports: list[int]) -> list[int]:
    """Connect only to validated IPs; never resolve the hostname again."""
    del host  # Kept for audit-friendly call sites and future SNI-aware checks.
    open_ports: list[int] = []
    for port in (port for port in ports if port in ALLOWED_PORTS):
        for address in addresses:
            try:
                with socket.create_connection((address, port), timeout=1.5):
                    open_ports.append(port)
                    break
            except OSError:
                pass
    return open_ports


def certificate_finding(host: str, addresses: list[str]) -> dict | None:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((addresses[0], 443), timeout=3) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
        expires = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (expires - datetime.now(timezone.utc)).days
        if days_remaining < 30:
            return finding("high" if days_remaining < 7 else "medium", "TLS certificate expires soon", f"Certificate expires in {days_remaining} days.", "Renew and deploy the certificate before expiration.")
        return None
    except (OSError, ssl.SSLError, KeyError, ValueError):
        return finding("medium", "TLS certificate could not be verified", "A trusted TLS connection on port 443 could not be established.", "Confirm HTTPS is enabled and deploy a valid certificate chain.")


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, **kwargs):
        super().__init__(host, **kwargs)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def header_findings(host: str, addresses: list[str]) -> list[dict]:
    try:
        connection = _PinnedHTTPSConnection(host, addresses[0], port=443, timeout=5, context=ssl.create_default_context())
        connection.request("GET", "/", headers={"Host": host, "User-Agent": "NetSek-IQ/1.1"})
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        response.read()
        connection.close()
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return []
    return [finding("low", f"Missing {name}", "Header was not present on the HTTPS response.", remediation)
            for name, remediation in SECURITY_HEADERS.items() if name not in headers]


def finding(severity: str, title: str, evidence: str, remediation: str) -> dict:
    return {"severity": severity, "title": title, "evidence": evidence, "remediation": remediation}


def assess(target: str, ports: list[int]) -> dict:
    host, addresses = validate_public_target(target)
    enforce_target_allowlist(host)
    open_ports = check_ports(host, addresses, ports)
    findings: list[dict] = []
    risky_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}
    for port in open_ports:
        if port in risky_ports:
            findings.append(finding("high", f"Internet-exposed {risky_ports[port]} service", f"TCP port {port} accepted a connection.", "Restrict access with a VPN, firewall allowlist, and strong authentication."))
    if 443 in open_ports:
        cert = certificate_finding(host, addresses)
        if cert:
            findings.append(cert)
        findings.extend(header_findings(host, addresses))
    score = min(100, sum({"critical": 40, "high": 25, "medium": 10, "low": 3}[item["severity"]] for item in findings))
    assessment = {"id": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"), "target": host, "addresses": addresses, "scanned_at": datetime.now(timezone.utc).isoformat(), "open_ports": open_ports, "findings": findings, "risk_score": score}
    _save_assessment(assessment)
    return assessment


def _database() -> sqlite3.Connection:
    path = get_settings().database_path
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.execute("CREATE TABLE IF NOT EXISTS assessments (id TEXT PRIMARY KEY, scanned_at TEXT NOT NULL, payload TEXT NOT NULL)")
    return connection


def _save_assessment(assessment: dict) -> None:
    with _database() as connection:
        connection.execute("INSERT INTO assessments (id, scanned_at, payload) VALUES (?, ?, ?)", (assessment["id"], assessment["scanned_at"], json.dumps(assessment)))
        connection.execute("DELETE FROM assessments WHERE id NOT IN (SELECT id FROM assessments ORDER BY scanned_at DESC LIMIT 50)")


def history_items() -> list[dict]:
    with _database() as connection:
        rows = connection.execute("SELECT payload FROM assessments ORDER BY scanned_at DESC LIMIT 50").fetchall()
    return [json.loads(row[0]) for row in rows]
