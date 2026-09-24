import re
from collections import Counter
from src.services.gemini import enrich_log

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def analyze_log(content: str) -> dict:
    lines = [line for line in content.splitlines() if line.strip()]
    failed_auth = [line for line in lines if any(term in line.lower() for term in ("failed password", "authentication failure", " 401 ", " 403 "))]
    suspicious_paths = [line for line in lines if any(term in line.lower() for term in ("/.env", "/wp-admin", "../", "cmd=", "/phpmyadmin"))]
    ips = Counter(ip for line in failed_auth for ip in IP_PATTERN.findall(line))
    findings = []
    for ip, attempts in ips.most_common(5):
        if attempts >= 5:
            findings.append({"severity": "high", "title": "Potential brute-force activity", "evidence": f"{ip} generated {attempts} failed authentication events.", "remediation": "Block or challenge the source, review affected accounts, and enforce MFA."})
    if suspicious_paths:
        findings.append({"severity": "medium", "title": "Web probing indicators", "evidence": f"{len(suspicious_paths)} requests matched common reconnaissance paths.", "remediation": "Review web-server logs, patch exposed applications, and tune WAF rules."})
    return {"lines_analyzed": len(lines), "failed_auth_events": len(failed_auth), "findings": findings}


async def enrich_with_gemini(content: str, deterministic_result: dict) -> dict:
    return await enrich_log(content, deterministic_result)
