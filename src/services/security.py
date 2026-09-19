"""Safe, dependency-free public asset assessment helpers."""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "assessments.json"
ALLOWED_PORTS = {21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443}
SECURITY_HEADERS = {
    "strict-transport-security": "Enable HSTS to require HTTPS connections.",
    "content-security-policy": "Add a Content-Security-Policy to reduce script injection risk.",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
    "x-frame-options": "Set X-Frame-Options or frame-ancestors to mitigate clickjacking.",
    "referrer-policy": "Set a restrictive Referrer-Policy.",
}


def validate_public_target(target: str) -> tuple[str, list[str]]:
    """Resolve one hostname and reject any non-public address."""
    cleaned = target.strip().lower().rstrip(".")
    if "://" in cleaned:
        cleaned = urlparse(cleaned).hostname or ""
    if not cleaned or len(cleaned) > 253 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in cleaned):
        raise ValueError("Enter a valid hostname or public IP address.")
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(cleaned, None)})
    except socket.gaierror as exc:
        raise ValueError("Target could not be resolved.") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("Private, loopback, link-local, and reserved targets are not permitted.")
    return cleaned, addresses


def check_ports(host: str, ports: list[int]) -> list[int]:
    permitted = [port for port in ports if port in ALLOWED_PORTS]
    open_ports: list[int] = []
    for port in permitted:
        try:
            with socket.create_connection((host, port), timeout=1.5):
                open_ports.append(port)
        except OSError:
            pass
    return open_ports


def certificate_finding(host: str) -> dict | None:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=3) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
        expires = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (expires - datetime.now(timezone.utc)).days
        if days_remaining < 30:
            return finding("high" if days_remaining < 7 else "medium", "TLS certificate expires soon", f"Certificate expires in {days_remaining} days.", "Renew and deploy the certificate before expiration.")
        return None
    except (OSError, ssl.SSLError, KeyError, ValueError):
        return finding("medium", "TLS certificate could not be verified", "A trusted TLS connection on port 443 could not be established.", "Confirm HTTPS is enabled and deploy a valid certificate chain.")


def header_findings(host: str) -> list[dict]:
    try:
        request = Request(f"https://{host}", headers={"User-Agent": "NetSek-IQ/1.0"})
        with urlopen(request, timeout=5) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
    except Exception:
        return []
    return [finding("low", f"Missing {name}", "Header was not present on the HTTPS response.", remediation)
            for name, remediation in SECURITY_HEADERS.items() if name not in headers]


def finding(severity: str, title: str, evidence: str, remediation: str) -> dict:
    return {"severity": severity, "title": title, "evidence": evidence, "remediation": remediation}


def assess(target: str, ports: list[int]) -> dict:
    host, addresses = validate_public_target(target)
    open_ports = check_ports(host, ports)
    findings: list[dict] = []
    risky_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}
    for port in open_ports:
        if port in risky_ports:
            findings.append(finding("high", f"Internet-exposed {risky_ports[port]} service", f"TCP port {port} accepted a connection.", "Restrict access with a VPN, firewall allowlist, and strong authentication."))
    if 443 in open_ports:
        cert = certificate_finding(host)
        if cert:
            findings.append(cert)
        findings.extend(header_findings(host))
    score = min(100, sum({"critical": 40, "high": 25, "medium": 10, "low": 3}[item["severity"]] for item in findings))
    assessment = {"id": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"), "target": host, "addresses": addresses, "scanned_at": datetime.now(timezone.utc).isoformat(), "open_ports": open_ports, "findings": findings, "risk_score": score}
    _save_assessment(assessment)
    return assessment


def _save_assessment(assessment: dict) -> None:
    DATA_FILE.parent.mkdir(exist_ok=True)
    history = history_items()
    history.insert(0, assessment)
    DATA_FILE.write_text(json.dumps(history[:50], indent=2), encoding="utf-8")


def history_items() -> list[dict]:
    if not DATA_FILE.exists():
        return []
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
