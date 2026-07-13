"""Response analyzer for detecting vulnerabilities from API test results."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from aegis.tools.api_fuzzing.runner import FuzzResult, HTTPResponse


@dataclass
class Vulnerability:
    title: str
    severity: str  # critical, high, medium, low, info
    category: str
    description: str
    evidence: str
    endpoint: str
    method: str
    cvss_breakdown: dict[str, str] | None = None
    cwe: str = ""


# ── Detection Patterns ────────────────────────────────────────────────────────

_SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"icrosoft.*odbc.*sql server",
    r"postgresql.*error",
    r"ora-\d{5}",
    r"sqlite3?\..*error",
    r"sql command not properly ended",
    r"invalid query",
    r"column .* cannot be null",
    r"table .* doesn't exist",
    r"sqlstate",
]

_AUTH_BYPASS_INDICATORS = [
    (200, r'"token"\s*:'),
    (200, r'"access_token"\s*:'),
    (200, r'"role"\s*:\s*"admin'),
    (200, r'"is_admin"\s*:\s*true'),
    (200, r'"admin"\s*:\s*true'),
]

_INFO_DISCLOSURE_PATTERNS = [
    r"stack trace",
    r"traceback",
    r"at line \d+",
    r"in file .*\.py",
    r"in file .*\.js",
    r"internal server error",
    r"debug",
    r"exception",
    r"sqlstate",
    r"mongodb",
    r"redis",
    r"connection string",
    r"password",
    r"secret",
    r"api[_-]?key",
]

_XSS_REFLECTION_PATTERNS = [
    r"<script>alert",
    r"onerror=alert",
    r"onload=alert",
    r"javascript:alert",
]

_SSTI_PATTERNS = [
    r"49",  # {{7*7}} = 49
    r"Jinja2",
    r"UndefinedError",
    r"TemplateSyntaxError",
]

_COMMAND_INJECTION_EVIDENCE = [
    "AEGIS_TEST_12345",
    "root:",
    "daemon:",
]

_SSRF_INDICATORS = [
    # AWS metadata
    r"ami-id",
    r"instance-id",
    r"iam/security-credentials",
    r"local-ipv4",
    # GCP metadata
    r"computeMetadata",
    # Azure metadata
    r"Metadata",
    # Internal service responses
    r"redis_version",
    r"mysql",
    r"postgres",
    r"mongodb",
    # File read via SSRF
    r"root:.*:0:0:",
    r"www-data:.*:0:0:",
]


def _check_sqli(response: HTTPResponse, test_payload: str) -> str | None:
    """Check for SQL injection indicators."""
    body_lower = response.body.lower()

    for pattern in _SQLI_ERROR_PATTERNS:
        if re.search(pattern, body_lower):
            return f"SQL error detected: {pattern}"

    # Time-based: if response took >4 seconds and payload had SLEEP
    if "sleep" in test_payload.lower() and response.elapsed_ms > 4000:
        return f"Time-based SQLi: response took {response.elapsed_ms:.0f}ms"

    return None


def _check_auth_bypass(response: HTTPResponse, test_name: str) -> str | None:
    """Check for authentication bypass."""
    if response.status_code != 200:
        return None

    # If we sent no token or invalid token and got 200 with token-like response
    if any(
        name in test_name for name in ["no_token", "empty_bearer", "invalid_token", "expired_token"]
    ):
        for status, pattern in _AUTH_BYPASS_INDICATORS:
            if response.status_code == status and re.search(pattern, response.body):
                return f"Auth bypass: got access without valid credentials"

    return None


def _check_info_disclosure(response: HTTPResponse) -> str | None:
    """Check for information disclosure."""
    body_lower = response.body.lower()

    for pattern in _INFO_DISCLOSURE_PATTERNS:
        if re.search(pattern, body_lower):
            return f"Information disclosure: {pattern} found in response"

    return None


def _check_xss(response: HTTPResponse, test_payload: str) -> str | None:
    """Check for XSS reflection."""
    if response.status_code != 200:
        return None

    # Check if payload is reflected without encoding
    if test_payload in response.body:
        return f"XSS: payload reflected in response"

    for pattern in _XSS_REFLECTION_PATTERNS:
        if re.search(pattern, response.body):
            return f"XSS: script execution pattern detected"

    return None


def _check_ssti(response: HTTPResponse, test_payload: str) -> str | None:
    """Check for SSTI."""
    if "{{7*7}}" in test_payload and "49" in response.body:
        return "SSTI: template expression evaluated ({{7*7}} = 49)"

    if "${7*7}" in test_payload and "49" in response.body:
        return "SSTI: template expression evaluated (${{7*7}} = 49)"

    for pattern in _SSTI_PATTERNS:
        if re.search(pattern, response.body):
            return f"SSTI: {pattern} detected"

    return None


def _check_command_injection(response: HTTPResponse) -> str | None:
    """Check for command injection."""
    for evidence in _COMMAND_INJECTION_EVIDENCE:
        if evidence in response.body:
            return f"Command injection: {evidence} found in response"

    return None


def _check_path_traversal(response: HTTPResponse) -> str | None:
    """Check for path traversal."""
    if response.status_code == 200:
        if "root:" in response.body or "daemon:" in response.body:
            return "Path traversal: /etc/passwd content leaked"
        if "[boot loader]" in response.body.lower():
            return "Path traversal: Windows system file leaked"

    return None


def _check_nosqli(response: HTTPResponse, test_payload: str) -> str | None:
    """Check for NoSQL injection."""
    if response.status_code == 200 and "$gt" in test_payload:
        if "token" in response.body.lower() or "admin" in response.body.lower():
            return "NoSQL injection: operator processed, access gained"

    if response.status_code == 500:
        body_lower = response.body.lower()
        if "casterror" in body_lower or "bson" in body_lower:
            return "NoSQL injection: MongoDB error in response"

    return None


def _check_mass_assignment(response: HTTPResponse, test_name: str) -> str | None:
    """Check for mass assignment."""
    if response.status_code in (200, 201) and "TypeFuzz" in test_name:
        if '"admin"' in response.body or '"role"' in response.body:
            return "Mass assignment: unexpected field accepted"

    return None


def _check_ssrf(response: HTTPResponse, test_payload: str) -> str | None:
    """Check for SSRF indicators."""
    if response.status_code not in (200, 500):
        return None

    body_lower = response.body.lower()

    for pattern in _SSRF_INDICATORS:
        if re.search(pattern, body_lower):
            return f"SSRF: internal resource accessed — {pattern}"

    # Check if internal IP was reflected
    if "169.254.169.254" in test_payload and response.status_code == 200:
        if len(response.body) > 10:
            return "SSRF: AWS metadata endpoint responded"

    return None


def _check_idor(response: HTTPResponse, test_name: str) -> str | None:
    """Check for IDOR indicators."""
    if "IDOR" not in test_name:
        return None

    if response.status_code == 200:
        # If we got 200 on an IDOR test, it might be exploitable
        if '"email"' in response.body or '"phone"' in response.body or '"name"' in response.body:
            return "IDOR: cross-user data access possible"

    return None


def _determine_severity(
    category: str, evidence: str, status_code: int
) -> tuple[str, dict[str, str]]:
    """Determine CVSS severity based on finding type."""
    severity_map = {
        "injection": (
            "high",
            {
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "N",
                "user_interaction": "N",
                "scope": "U",
                "confidentiality": "H",
                "integrity": "H",
                "availability": "N",
            },
        ),
        "auth": (
            "critical",
            {
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "N",
                "user_interaction": "N",
                "scope": "C",
                "confidentiality": "H",
                "integrity": "H",
                "availability": "N",
            },
        ),
        "idor": (
            "high",
            {
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "L",
                "user_interaction": "N",
                "scope": "U",
                "confidentiality": "H",
                "integrity": "N",
                "availability": "N",
            },
        ),
        "ssrf": (
            "critical",
            {
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "N",
                "user_interaction": "N",
                "scope": "C",
                "confidentiality": "H",
                "integrity": "H",
                "availability": "N",
            },
        ),
        "csrf": (
            "high",
            {
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "N",
                "user_interaction": "R",
                "scope": "U",
                "confidentiality": "N",
                "integrity": "H",
                "availability": "N",
            },
        ),
        "info_disclosure": (
            "medium",
            {
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "N",
                "user_interaction": "N",
                "scope": "U",
                "confidentiality": "L",
                "integrity": "N",
                "availability": "N",
            },
        ),
        "business_logic": (
            "medium",
            {
                "attack_vector": "N",
                "attack_complexity": "H",
                "privileges_required": "L",
                "user_interaction": "N",
                "scope": "U",
                "confidentiality": "L",
                "integrity": "L",
                "availability": "N",
            },
        ),
    }

    base_sev, cvss = severity_map.get(
        category,
        (
            "medium",
            {
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "N",
                "user_interaction": "N",
                "scope": "U",
                "confidentiality": "L",
                "integrity": "N",
                "availability": "N",
            },
        ),
    )

    # Upgrade severity for critical patterns
    if "SQL error" in evidence or "Command injection" in evidence:
        return "critical", cvss
    if "Auth bypass" in evidence:
        return "critical", cvss
    if "Path traversal" in evidence and "etc/passwd" in evidence:
        return "high", cvss

    return base_sev, cvss


def analyze_result(result: FuzzResult) -> Vulnerability | None:
    """Analyze a fuzz result and return a vulnerability if found."""
    if result.response.status_code == 0:
        return None  # Request failed, not a vulnerability

    response = result.response
    test = result.test
    evidence = None

    # Run all detectors
    payload = str(test.body) if test.body else ""

    if "injection" in test.category or "SQLi" in test.name:
        evidence = _check_sqli(response, payload)
    if not evidence and "NoSQLi" in test.name:
        evidence = _check_nosqli(response, payload)
    if not evidence and ("XSS" in test.name or "xss" in test.category):
        evidence = _check_xss(response, payload)
    if not evidence and "SSTI" in test.name:
        evidence = _check_ssti(response, payload)
    if not evidence and "CMDi" in test.name:
        evidence = _check_command_injection(response)
    if not evidence and "PathTraversal" in test.name:
        evidence = _check_path_traversal(response)
    if not evidence and "auth" in test.category:
        evidence = _check_auth_bypass(response, test.name)
    if not evidence and "BizLogic" in test.name:
        evidence = _check_mass_assignment(response, test.name)
    if not evidence and "SSRF" in test.name:
        evidence = _check_ssrf(response, payload)
    if not evidence and "IDOR" in test.name:
        evidence = _check_idor(response, test.name)
    if not evidence:
        evidence = _check_info_disclosure(response)

    if not evidence:
        return None

    severity, cvss = _determine_severity(test.category, evidence, response.status_code)

    cwe_map = {
        "injection": "CWE-89",
        "auth": "CWE-287",
        "idor": "CWE-639",
        "ssrf": "CWE-918",
        "csrf": "CWE-352",
        "info_disclosure": "CWE-200",
        "business_logic": "CWE-840",
    }

    return Vulnerability(
        title=f"{test.category.upper()} in {test.method} {test.endpoint}",
        severity=severity,
        category=test.category,
        description=evidence,
        evidence=f"Payload: {payload}\nStatus: {response.status_code}\nResponse: {response.body[:500]}",
        endpoint=test.endpoint,
        method=test.method,
        cvss_breakdown=cvss,
        cwe=cwe_map.get(test.category, ""),
    )
