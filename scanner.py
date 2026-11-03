"""
scanner.py - the security analysis logic.

Nothing in this file knows about FastAPI, HTTP, or background tasks.
It only takes plain Python values in and returns plain Python values out,
which makes it easy to read, test, and extend with new checks.

To add a new check later: write a function that returns a list of findings,
then call it inside scan_target() below.
"""

import re
from urllib.parse import urlparse


def analyze_url(url):
    """Look at the URL itself for transport and phishing red flags."""
    findings = []
    parsed = urlparse(str(url))
    hostname = parsed.hostname or ""

    suspicious_terms = [
        "login", "verify", "secure", "account",
        "update", "wallet", "password"
    ]

    if parsed.scheme != "https":
        findings.append({
            "title": "HTTPS not detected",
            "severity": "medium",
            "category": "Transport Security",
            "description": "The submitted URL does not use HTTPS."
        })

    if hostname.count("-") >= 3:
        findings.append({
            "title": "Unusual domain structure",
            "severity": "medium",
            "category": "Phishing Analysis",
            "description": "The hostname contains several hyphens."
        })

    if any(term in hostname.lower() for term in suspicious_terms):
        findings.append({
            "title": "Suspicious URL keyword",
            "severity": "low",
            "category": "Phishing Analysis",
            "description": "The hostname contains a keyword often used in deceptive URLs."
        })

    return findings


def analyze_source(source):
    """Search pasted source code for hardcoded secrets."""
    findings = []

    patterns = {
        "Possible API key": r'(?i)(api[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']',
        "Possible secret token": r'(?i)(secret|access[_-]?token)\s*[:=]\s*["\'][^"\']{8,}["\']',
        "Possible private key": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'
    }

    for title, pattern in patterns.items():
        if re.search(pattern, source):
            findings.append({
                "title": title,
                "severity": "high",
                "category": "Exposed Secrets",
                "description": "A possible hardcoded credential was detected. Review and rotate it if genuine."
            })

    return findings


def analyze_headers(headers):
    """Check supplied response headers for missing API protections."""
    findings = []

    if not headers:
        return findings

    normalized = {
        key.lower(): value for key, value in headers.items()
    }

    if "ratelimit-limit" not in normalized and "x-ratelimit-limit" not in normalized:
        findings.append({
            "title": "Rate-limit policy not evident",
            "severity": "medium",
            "category": "API Protection",
            "description": "No recognized rate-limit limit header was supplied. This does not prove rate limiting is absent."
        })

    return findings


def build_graph(findings):
    """Turn a list of findings into nodes and edges for the frontend graph.

    There is one central "target" node, plus one node per finding,
    each connected back to the target.
    """
    nodes = [{
        "id": "target",
        "label": "Scanned Target",
        "severity": "info"
    }]
    edges = []

    for index, finding in enumerate(findings):
        node_id = f"node-{index + 1}"

        nodes.append({
            "id": node_id,
            "label": finding["title"],
            "severity": finding["severity"],
            "category": finding["category"]
        })

        edges.append({
            "source": "target",
            "target": node_id
        })

    return {"nodes": nodes, "edges": edges}


def scan_target(target_url, source_code=None, response_headers=None):
    """Run every check and return the complete results dictionary."""
    findings = []

    findings.extend(analyze_url(target_url))

    if source_code:
        findings.extend(analyze_source(source_code))

    findings.extend(analyze_headers(response_headers))

    return {
        "total_findings": len(findings),
        "findings": findings,
        "graph": build_graph(findings)
    }
