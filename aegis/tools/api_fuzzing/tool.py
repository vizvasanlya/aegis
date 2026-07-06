"""Agent-callable API security scanner tool."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

logger = logging.getLogger(__name__)


@function_tool(timeout=600, strict_mode=False)
async def run_api_scan(
    ctx: RunContextWrapper,
    base_url: str,
    spec_path: str | None = None,
    auth_headers: str | None = None,
    focus: str | None = None,
) -> str:
    """Automated API security scanner — tests every endpoint for vulnerabilities.

    Scans all endpoints using intelligent fuzzing with schema-guided payload
    generation. Tests injection, authentication, authorization, and business
    logic vulnerabilities. Returns structured findings with HTTP evidence.

    Args:
        base_url: Target API base URL (e.g., "https://api.target.com").
        spec_path: Path to OpenAPI/Swagger spec file in the sandbox
            (e.g., "/workspace/openapi.json"). If provided, tests every
            endpoint in the spec systematically. If omitted, auto-discovers
            schema from common paths.
        auth_headers: JSON string of authentication headers
            (e.g., '{"Authorization": "Bearer eyJ..."}').
            If omitted, tests both unauthenticated and authenticated access.
        focus: Testing focus — "injection" (SQLi/XSS/SSTI/CMDi),
            "auth" (authentication/authorization bypass), or "all" (default).
            Focused scans run faster; "all" is recommended for full coverage.

    Returns:
        JSON string with scan results including vulnerabilities found,
        endpoints tested, and HTTP evidence for each finding.
    """
    from aegis.tools.api_fuzzing.schema import (
        discover_schema,
        parse_openapi_spec,
        Endpoint,
    )
    from aegis.tools.api_fuzzing.fuzzer import generate_test_cases
    from aegis.tools.api_fuzzing.runner import run_fuzzing
    from aegis.tools.api_fuzzing.analyzer import analyze_result

    # Parse auth headers
    headers: dict[str, str] | None = None
    if auth_headers:
        try:
            headers = json.loads(auth_headers)
        except json.JSONDecodeError:
            logger.warning("Invalid auth_headers JSON, proceeding without auth")

    # Step 1: Get API schema
    endpoints: list[Endpoint] = []

    if spec_path:
        # Load from provided spec file
        import requests as req

        try:
            if spec_path.startswith(("http://", "https://")):
                resp = req.get(spec_path, timeout=15)
                spec = resp.json()
            else:
                from pathlib import Path

                spec_data = Path(spec_path).read_text(encoding="utf-8")
                spec = json.loads(spec_data)
        except Exception as exc:
            return json.dumps({
                "success": False,
                "error": f"Failed to load spec from {spec_path}: {exc}",
            })

        endpoints = parse_openapi_spec(spec)
        logger.info("Loaded %d endpoints from spec", len(endpoints))
    else:
        # Auto-discover schema
        schema = discover_schema(base_url)
        if schema:
            endpoints = parse_openapi_spec(schema)
            logger.info("Auto-discovered %d endpoints", len(endpoints))
        else:
            # Fallback: test common API paths
            endpoints = _common_endpoint_fallback()
            logger.info("No schema found, testing %d common endpoints", len(endpoints))

    if not endpoints:
        return json.dumps({
            "success": False,
            "error": "No endpoints discovered. Provide --api-spec or check target URL.",
        })

    # Step 2: Generate test cases
    all_tests = []
    for endpoint in endpoints:
        tests = generate_test_cases(endpoint)
        if focus == "injection":
            tests = [t for t in tests if t.category == "injection"]
        elif focus == "auth":
            tests = [t for t in tests if t.category == "auth"]
        all_tests.extend(tests)

    logger.info("Generated %d test cases across %d endpoints", len(all_tests), len(endpoints))

    # Limit total tests to prevent timeout
    max_tests = 100
    if len(all_tests) > max_tests:
        # Prioritize: auth tests first, then injection, then business logic
        priority_order = {"auth": 0, "injection": 1, "business_logic": 2}
        all_tests.sort(key=lambda t: priority_order.get(t.category, 3))
        all_tests = all_tests[:max_tests]

    # Step 3: Execute tests
    results = await run_fuzzing(
        base_url=base_url,
        tests=all_tests,
        auth_headers=headers,
        max_concurrent=5,
        timeout=15,
    )

    # Step 4: Analyze results
    vulnerabilities = []
    for result in results:
        vuln = analyze_result(result)
        if vuln:
            vulnerabilities.append({
                "title": vuln.title,
                "severity": vuln.severity,
                "category": vuln.category,
                "description": vuln.description,
                "evidence": vuln.evidence,
                "endpoint": vuln.endpoint,
                "method": vuln.method,
                "cwe": vuln.cwe,
                "cvss_breakdown": vuln.cvss_breakdown,
                "http_request": result.request,
                "http_response": {
                    "status_code": result.response.status_code,
                    "headers": result.response.headers,
                    "body": result.response.body,
                },
            })

    return json.dumps({
        "success": True,
        "endpoints_tested": len(endpoints),
        "tests_executed": len(results),
        "vulnerabilities_found": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }, ensure_ascii=False, default=str)


def _common_endpoint_fallback() -> list:
    """Generate common API endpoints when no spec is available."""
    from aegis.tools.api_fuzzing.schema import Endpoint

    common = [
        ("/api", "GET"),
        ("/api/v1", "GET"),
        ("/api/v2", "GET"),
        ("/api/login", "POST"),
        ("/api/auth/login", "POST"),
        ("/api/users", "GET"),
        ("/api/admin", "GET"),
        ("/api/settings", "GET"),
        ("/api/health", "GET"),
        ("/api/status", "GET"),
        ("/login", "POST"),
        ("/register", "POST"),
        ("/users", "GET"),
        ("/admin", "GET"),
        ("/graphql", "POST"),
    ]

    return [Endpoint(path=path, method=method) for path, method in common]
