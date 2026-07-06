"""Schema violation testing — send invalid payloads against OpenAPI spec."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import requests

from aegis.tools.api_fuzzing.schema import Endpoint, Parameter, RequestBody


logger = logging.getLogger(__name__)


@dataclass
class ViolationResult:
    endpoint: str
    method: str
    violation_type: str
    description: str
    status_code: int
    response_snippet: str = ""
    severity: str = "low"


def _generate_type_violations(schema: dict[str, Any], field_name: str) -> list[dict[str, Any]]:
    """Generate violations based on expected schema type."""
    expected_type = schema.get("type", "string")
    violations = []

    type_violations = {
        "string": [
            {"value": 12345, "desc": "integer instead of string"},
            {"value": True, "desc": "boolean instead of string"},
            {"value": [1, 2, 3], "desc": "array instead of string"},
            {"value": {}, "desc": "object instead of string"},
            {"value": None, "desc": "null instead of string"},
        ],
        "integer": [
            {"value": "not_a_number", "desc": "string instead of integer"},
            {"value": 1.5, "desc": "float instead of integer"},
            {"value": True, "desc": "boolean instead of integer"},
            {"value": [1], "desc": "array instead of integer"},
            {"value": None, "desc": "null instead of integer"},
        ],
        "number": [
            {"value": "not_a_number", "desc": "string instead of number"},
            {"value": True, "desc": "boolean instead of number"},
            {"value": [1.0], "desc": "array instead of number"},
        ],
        "boolean": [
            {"value": "yes", "desc": "string instead of boolean"},
            {"value": 1, "desc": "integer instead of boolean"},
            {"value": [], "desc": "array instead of boolean"},
        ],
        "array": [
            {"value": "not_an_array", "desc": "string instead of array"},
            {"value": {}, "desc": "object instead of array"},
            {"value": 123, "desc": "integer instead of array"},
        ],
        "object": [
            {"value": "not_an_object", "desc": "string instead of object"},
            {"value": [1, 2, 3], "desc": "array instead of object"},
            {"value": 123, "desc": "integer instead of object"},
        ],
    }

    for v in type_violations.get(expected_type, []):
        violations.append({
            "field": field_name,
            "value": v["value"],
            "description": f"{v['desc']} (expected {expected_type})",
        })

    return violations


def _generate_enum_violations(param: Parameter) -> list[dict[str, Any]]:
    """Generate violations for enum parameters."""
    if not param.enum:
        return []

    return [
        {"field": param.name, "value": "INVALID_ENUM_VALUE", "description": "Invalid enum value"},
        {"field": param.name, "value": "", "description": "Empty string for enum field"},
        {"field": param.name, "value": param.enum[0] + "_typo", "description": "Typo in enum value"},
    ]


def _generate_required_violations(endpoint: Endpoint) -> list[dict[str, Any]]:
    """Generate violations by omitting required fields."""
    violations = []

    if endpoint.request_body and endpoint.request_body.schema:
        required = endpoint.request_body.schema.get("required", [])
        properties = endpoint.request_body.schema.get("properties", {})

        for field_name in required:
            if field_name in properties:
                violations.append({
                    "field": field_name,
                    "value": None,
                    "description": f"Omit required field '{field_name}'",
                    "omit": True,
                })

    # Also omit required query/path params
    for param in endpoint.parameters:
        if param.required:
            violations.append({
                "field": param.name,
                "value": None,
                "description": f"Omit required {param.location} parameter '{param.name}'",
                "omit": True,
            })

    return violations


def _generate_length_violations(param: Parameter) -> list[dict[str, Any]]:
    """Generate violations for string length constraints."""
    violations = []

    if param.schema_type == "string":
        violations.append({
            "field": param.name,
            "value": "",
            "description": "Empty string where non-empty expected",
        })
        violations.append({
            "field": param.name,
            "value": "A" * 10000,
            "description": "Extremely long string (10000 chars)",
        })

    return violations


def test_schema_violations(
    base_url: str,
    endpoints: list[Endpoint],
    auth_headers: dict[str, str] | None,
    max_endpoints: int = 20,
) -> list[ViolationResult]:
    """Test endpoints for schema violation handling."""
    results = []

    for endpoint in endpoints[:max_endpoints]:
        violations = []

        # Type violations on body fields
        if endpoint.request_body and endpoint.request_body.schema:
            properties = endpoint.request_body.schema.get("properties", {})
            for field_name, field_schema in properties.items():
                violations.extend(_generate_type_violations(field_schema, field_name))

            # Enum violations
            for field_name, field_schema in properties.items():
                if "enum" in field_schema:
                    param = Parameter(name=field_name, location="body", enum=field_schema["enum"])
                    violations.extend(_generate_enum_violations(param))

        # Required field omissions
        violations.extend(_generate_required_violations(endpoint))

        # Parameter length violations
        for param in endpoint.parameters:
            violations.extend(_generate_length_violations(param))

        # Test each violation
        for violation in violations[:10]:  # Limit per endpoint
            try:
                url = f"{base_url.rstrip('/')}{endpoint.path}"
                headers = {"Content-Type": "application/json"}
                if auth_headers:
                    headers.update(auth_headers)

                if endpoint.method in ("POST", "PUT", "PATCH"):
                    if violation.get("omit"):
                        # Send empty body
                        body = {}
                    else:
                        body = {violation["field"]: violation["value"]}

                    resp = requests.request(
                        method=endpoint.method,
                        url=url,
                        json=body,
                        headers=headers,
                        timeout=10,
                        verify=False,
                    )
                else:
                    # GET with query param violation
                    params = {}
                    if not violation.get("omit"):
                        params[violation["field"]] = violation["value"]
                    resp = requests.request(
                        method=endpoint.method,
                        url=url,
                        params=params,
                        headers=headers,
                        timeout=10,
                        verify=False,
                    )

                # Check if server leaks info in error response
                severity = "low"
                if resp.status_code == 500:
                    severity = "medium"
                if any(
                    pattern in resp.text.lower()
                    for pattern in ["stack trace", "traceback", "exception", "debug"]
                ):
                    severity = "high"

                results.append(ViolationResult(
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    violation_type=violation["description"],
                    description=f"Sent {violation['description']}",
                    status_code=resp.status_code,
                    response_snippet=resp.text[:200],
                    severity=severity,
                ))

            except Exception as exc:
                logger.debug("Schema violation test failed: %s", exc)

    return results
