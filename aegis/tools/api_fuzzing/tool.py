"""Agent-callable API security scanner tool."""

from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

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
    generation. Tests injection, authentication, authorization, business
    logic, schema violations, GraphQL, gRPC, SSE, HTTP smuggling, OAuth2,
    API versioning, rate limiting, and nuclei templates.
    Returns structured findings with HTTP evidence.

    Args:
        base_url: Target API base URL (e.g., "https://api.target.com").
        spec_path: Path to OpenAPI/Swagger spec file in the sandbox
            (e.g., "/workspace/openapi.json"). If provided, tests every
            endpoint in the spec systematically. If omitted, auto-discovers
            schema from common paths.
        auth_headers: JSON string of authentication headers
            (e.g., '{"Authorization": "Bearer eyJ..."}').
            If omitted, tests both unauthenticated and authenticated access.
        focus: Testing focus — "injection", "auth", "schema", or "all" (default).

    Returns:
        JSON string with scan results including vulnerabilities found,
        endpoints tested, coverage report, and HTTP evidence for each finding.
    """
    from aegis.tools.api_fuzzing.schema import (
        discover_schema,
        parse_openapi_spec,
        Endpoint,
    )
    from aegis.tools.api_fuzzing.fuzzer import generate_test_cases
    from aegis.tools.api_fuzzing.runner import run_fuzzing
    from aegis.tools.api_fuzzing.analyzer import analyze_result
    from aegis.tools.api_fuzzing.coverage import CoverageTracker

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
            return json.dumps(
                {
                    "success": False,
                    "error": f"Failed to load spec from {spec_path}: {exc}",
                }
            )

        endpoints = parse_openapi_spec(spec)
        logger.info("Loaded %d endpoints from spec", len(endpoints))
    else:
        schema = discover_schema(base_url)
        if schema:
            endpoints = parse_openapi_spec(schema)
            logger.info("Auto-discovered %d endpoints", len(endpoints))
        else:
            endpoints = _common_endpoint_fallback()
            logger.info("No schema found, testing %d common endpoints", len(endpoints))

    if not endpoints:
        return json.dumps(
            {
                "success": False,
                "error": "No endpoints discovered. Provide --api-spec or check target URL.",
            }
        )

    # Initialize coverage tracker
    tracker = CoverageTracker(endpoints)

    # Step 2: Generate test cases
    all_tests = []
    for endpoint in endpoints:
        tests = generate_test_cases(endpoint)
        if focus == "injection":
            tests = [t for t in tests if t.category == "injection"]
        elif focus == "auth":
            tests = [t for t in tests if t.category == "auth"]
        elif focus == "schema":
            tests = []  # Schema violations handled separately
        all_tests.extend(tests)

    logger.info("Generated %d test cases across %d endpoints", len(all_tests), len(endpoints))

    # Limit total tests — prioritize auth, injection, SSRF, IDOR over less critical
    max_tests = 300
    if len(all_tests) > max_tests:
        priority_order = {
            "auth": 0,
            "injection": 1,
            "ssrf": 2,
            "idor": 3,
            "csrf": 4,
            "business_logic": 5,
        }
        all_tests.sort(key=lambda t: priority_order.get(t.category, 6))
        all_tests = all_tests[:max_tests]

    # Step 3: Execute fuzzing tests
    results = await run_fuzzing(
        base_url=base_url,
        tests=all_tests,
        auth_headers=headers,
        max_concurrent=5,
        timeout=15,
    )

    # Track coverage
    for result in results:
        tracker.record_test(result.test.endpoint, result.test.method, result.test.category)

    # Step 4: Analyze results
    vulnerabilities = []
    for result in results:
        vuln = analyze_result(result)
        if vuln:
            tracker.record_vulnerability(result.test.endpoint, result.test.method)
            vulnerabilities.append(
                {
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
                }
            )

    # Step 5: Schema violation tests (if enabled)
    if focus != "injection" and focus != "auth":
        try:
            from aegis.tools.api_fuzzing.schema_violation import test_schema_violations

            violations = test_schema_violations(base_url, endpoints, headers, max_endpoints=10)
            for v in violations:
                tracker.record_test(v.endpoint, v.method, "schema_violation")
                if v.severity in ("high", "critical"):
                    tracker.record_vulnerability(v.endpoint, v.method)
                    vulnerabilities.append(
                        {
                            "title": f"Schema Violation: {v.violation_type}",
                            "severity": v.severity,
                            "category": "schema_violation",
                            "description": v.description,
                            "evidence": v.response_snippet,
                            "endpoint": v.endpoint,
                            "method": v.method,
                            "cwe": "CWE-20",
                        }
                    )
        except Exception as exc:
            logger.debug("Schema violation tests failed: %s", exc)

    # Step 6: GraphQL introspection and testing
    if focus in (None, "all", "graphql"):
        try:
            from aegis.tools.api_fuzzing.graphql import test_introspection

            graphql_url = base_url.rstrip("/")
            if not graphql_url.endswith("/graphql"):
                graphql_url += "/graphql"

            gql_result = test_introspection(graphql_url, headers)
            if gql_result.get("success") and gql_result.get("vulnerabilities"):
                for vuln in gql_result["vulnerabilities"]:
                    tracker.record_test("/graphql", "POST", vuln.get("category", "info_disclosure"))
                    if vuln.get("severity") in ("high", "critical"):
                        tracker.record_vulnerability("/graphql", "POST")
                    vulnerabilities.append(
                        {
                            "title": vuln["title"],
                            "severity": vuln["severity"],
                            "category": vuln.get("category", "graphql"),
                            "description": vuln["description"],
                            "evidence": vuln.get("evidence", ""),
                            "endpoint": "/graphql",
                            "method": "POST",
                            "cwe": vuln.get("cwe", "CWE-200"),
                        }
                    )
        except Exception as exc:
            logger.debug("GraphQL tests failed: %s", exc)

    # Step 7: gRPC reflection, auth, injection, DoS tests
    if focus in (None, "all", "grpc"):
        try:
            from aegis.tools.api_fuzzing.grpc import run_all_grpc_tests

            grpc_results = run_all_grpc_tests(base_url, headers)
            for result in grpc_results:
                if result.vulnerable:
                    tracker.record_test(f"gRPC/{result.test_name}", "POST", "grpc")
                    tracker.record_vulnerability(f"gRPC/{result.test_name}", "POST")
                    vulnerabilities.append(
                        {
                            "title": result.test_name,
                            "severity": result.severity,
                            "category": "grpc",
                            "description": result.description,
                            "evidence": result.evidence,
                            "endpoint": f"gRPC/{result.test_name}",
                            "method": "POST",
                            "cwe": "CWE-284" if "Auth" in result.test_name else "CWE-200",
                        }
                    )
        except Exception as exc:
            logger.debug("gRPC tests failed: %s", exc)

    # Step 8: SSE (Server-Sent Events) security tests
    if focus in (None, "all", "sse"):
        try:
            from aegis.tools.api_fuzzing.sse import run_all_sse_tests

            sse_url = base_url.rstrip("/")
            sse_results = run_all_sse_tests(sse_url, sse_url, headers)
            for result in sse_results:
                if result.vulnerable:
                    tracker.record_test(f"/{result.test_name}", "GET", "sse")
                    tracker.record_vulnerability(f"/{result.test_name}", "GET")
                    vulnerabilities.append(
                        {
                            "title": result.test_name,
                            "severity": result.severity,
                            "category": "sse",
                            "description": result.description,
                            "evidence": result.evidence,
                            "endpoint": f"/{result.test_name}",
                            "method": "GET",
                            "cwe": "CWE-79" if "XSS" in result.test_name else "CWE-346",
                        }
                    )
        except Exception as exc:
            logger.debug("SSE tests failed: %s", exc)

    # Step 9: HTTP/2 and HTTP request smuggling tests
    if focus in (None, "all", "smuggling"):
        try:
            from aegis.tools.api_fuzzing.http2 import run_all_smuggling_tests

            smuggling_results = run_all_smuggling_tests(base_url, headers)
            for result in smuggling_results:
                if result.vulnerable:
                    tracker.record_test(f"/{result.test_name}", "POST", "smuggling")
                    tracker.record_vulnerability(f"/{result.test_name}", "POST")
                    vulnerabilities.append(
                        {
                            "title": result.test_name,
                            "severity": result.severity,
                            "category": "http_smuggling",
                            "description": result.description,
                            "evidence": result.evidence,
                            "endpoint": f"/{result.test_name}",
                            "method": "POST",
                            "cwe": "CWE-444",
                        }
                    )
        except Exception as exc:
            logger.debug("HTTP smuggling tests failed: %s", exc)

    # Step 10: OAuth2/JWT security tests
    if focus in (None, "all", "oauth"):
        try:
            from aegis.tools.api_fuzzing.oauth2 import (
                test_client_credentials_flow,
                test_token_introspection,
            )

            parsed = urlparse(base_url)
            token_url = f"{parsed.scheme}://{parsed.netloc}/oauth/token"

            # Test client credentials flow with empty/default creds
            cred_results = test_client_credentials_flow(token_url, "", "", headers)
            for result in cred_results:
                if result.vulnerability:
                    tracker.record_test(f"/oauth/{result.flow_type}", "POST", "oauth")
                    tracker.record_vulnerability(f"/oauth/{result.flow_type}", "POST")
                    vulnerabilities.append(
                        {
                            "title": f"OAuth2: {result.vulnerability}",
                            "severity": result.severity,
                            "category": "oauth2",
                            "description": result.vulnerability,
                            "evidence": result.evidence,
                            "endpoint": f"/oauth/{result.flow_type}",
                            "method": "POST",
                            "cwe": "CWE-287",
                        }
                    )

            # Test JWT token introspection if we can get a token
            jwt_token = _extract_jwt_from_headers(headers)
            if jwt_token:
                jwt_result = test_token_introspection(token_url, jwt_token, headers)
                if jwt_result and jwt_result.vulnerability:
                    tracker.record_test("/oauth/jwt", "POST", "oauth")
                    tracker.record_vulnerability("/oauth/jwt", "POST")
                    vulnerabilities.append(
                        {
                            "title": f"JWT: {jwt_result.vulnerability}",
                            "severity": jwt_result.severity,
                            "category": "jwt",
                            "description": jwt_result.vulnerability,
                            "evidence": jwt_result.evidence,
                            "endpoint": "/oauth/jwt",
                            "method": "POST",
                            "cwe": "CWE-327",
                        }
                    )
        except Exception as exc:
            logger.debug("OAuth2/JWT tests failed: %s", exc)

    # Step 11: API versioning security tests
    if focus in (None, "all", "versioning"):
        try:
            from aegis.tools.api_fuzzing.versioning import run_all_version_tests

            version_results = run_all_version_tests(base_url, headers)
            for result in version_results:
                if result.vulnerable:
                    tracker.record_test(f"/{result.test_name}", "GET", "versioning")
                    tracker.record_vulnerability(f"/{result.test_name}", "GET")
                    vulnerabilities.append(
                        {
                            "title": result.test_name,
                            "severity": result.severity,
                            "category": "versioning",
                            "description": result.description,
                            "evidence": result.evidence,
                            "endpoint": f"/{result.test_name}",
                            "method": "GET",
                            "cwe": "CWE-284",
                        }
                    )
        except Exception as exc:
            logger.debug("API versioning tests failed: %s", exc)

    # Step 12: Rate limit detection and bypass tests
    if focus in (None, "all", "rate_limit"):
        try:
            from aegis.tools.api_fuzzing.rate_limit import detect_rate_limit, test_rate_limit_bypass

            # Test the first write endpoint found
            write_endpoints = [ep for ep in endpoints if ep.method in ("POST", "PUT", "PATCH")]
            if write_endpoints:
                test_ep = write_endpoints[0]
                rate_url = f"{base_url.rstrip('/')}{test_ep.path}"
                rate_result = detect_rate_limit(rate_url, test_ep.method, headers, num_requests=15)
                if not rate_result.detected:
                    # No rate limit detected — try bypass techniques
                    bypass_results = test_rate_limit_bypass(rate_url, test_ep.method, headers)
                    for bypass in bypass_results:
                        if not bypass.detected and bypass.bypass_technique:
                            tracker.record_test(test_ep.path, test_ep.method, "rate_limit")
                            tracker.record_vulnerability(test_ep.path, test_ep.method)
                            vulnerabilities.append(
                                {
                                    "title": f"Rate Limit Bypass: {bypass.bypass_technique}",
                                    "severity": bypass.severity,
                                    "category": "rate_limiting",
                                    "description": (
                                        f"Rate limit bypassed: {bypass.bypass_technique}"
                                    ),
                                    "evidence": bypass.evidence,
                                    "endpoint": test_ep.path,
                                    "method": test_ep.method,
                                    "cwe": "CWE-770",
                                }
                            )
        except Exception as exc:
            logger.debug("Rate limit tests failed: %s", exc)

    # Step 13: Nuclei template scanning (if nuclei available)
    if focus in (None, "all", "nuclei"):
        try:
            from aegis.tools.api_fuzzing.nuclei_auto import auto_run_nuclei

            nuclei_result = await auto_run_nuclei(
                base_url, spec_path, severity="critical,high,medium", timeout=180
            )
            if nuclei_result.get("success") and nuclei_result.get("total_findings", 0) > 0:
                for finding in nuclei_result.get("findings", [])[:30]:
                    sev = finding.get("severity", "info")
                    name = finding.get("name", finding.get("template_id", "Unknown"))
                    matched = finding.get("matched_at", "")
                    tracker.record_test(matched or "/nuclei", "GET", "nuclei")
                    if sev in ("critical", "high"):
                        tracker.record_vulnerability(matched or "/nuclei", "GET")
                    vulnerabilities.append(
                        {
                            "title": f"Nuclei: {name}",
                            "severity": sev,
                            "category": "nuclei",
                            "description": finding.get("description", name),
                            "evidence": finding.get(
                                "curl_command", finding.get("matcher_name", "")
                            ),
                            "endpoint": matched,
                            "method": "GET",
                            "cwe": "CWE-20",
                        }
                    )
        except Exception as exc:
            logger.debug("Nuclei tests failed: %s", exc)

    # Generate coverage report
    coverage = tracker.generate_report()

    return json.dumps(
        {
            "success": True,
            "endpoints_tested": coverage.endpoints_tested,
            "tests_executed": coverage.total_tests,
            "vulnerabilities_found": coverage.total_vulns,
            "coverage_percent": coverage.coverage_percent,
            "untested_endpoints": coverage.untested_endpoints,
            "vulnerabilities": vulnerabilities,
        },
        ensure_ascii=False,
        default=str,
    )


def _extract_jwt_from_headers(headers: dict[str, str] | None) -> str | None:
    """Extract a JWT token from auth headers for JWT analysis."""
    if not headers:
        return None
    for key, value in headers.items():
        if key.lower() == "authorization" and value.lower().startswith("bearer "):
            token = value[7:].strip()
            if "." in token and len(token) > 50:
                return token
    return None


def _common_endpoint_fallback() -> list:
    """Generate common API endpoints when no spec is available."""
    from aegis.tools.api_fuzzing.schema import Endpoint, Parameter, RequestBody

    endpoints = []

    # GET endpoints (no body)
    get_paths = [
        "/api", "/api/v1", "/api/v2", "/api/users", "/api/admin",
        "/api/settings", "/api/health", "/api/status", "/users", "/admin",
        "/health", "/status", "/api/v1/users", "/api/v1/admin",
    ]
    for path in get_paths:
        endpoints.append(Endpoint(path=path, method="GET"))

    # POST endpoints with body schemas for injection testing
    post_endpoints = [
        ("/api/login", {"username": {"type": "string"}, "password": {"type": "string"}}),
        ("/api/auth/login", {"email": {"type": "string"}, "password": {"type": "string"}}),
        ("/api/v1/auth/login", {"phone_number": {"type": "string"}, "pin": {"type": "string"}}),
        ("/api/v1/admin/auth/login", {"email": {"type": "string"}, "password": {"type": "string"}}),
        ("/login", {"username": {"type": "string"}, "password": {"type": "string"}}),
        ("/register", {"email": {"type": "string"}, "password": {"type": "string"}, "name": {"type": "string"}}),
        ("/api/register", {"email": {"type": "string"}, "password": {"type": "string"}}),
        ("/api/users", {"name": {"type": "string"}, "email": {"type": "string"}, "role": {"type": "string"}}),
        ("/api/admin/users", {"username": {"type": "string"}, "action": {"type": "string"}}),
        ("/api/settings", {"key": {"type": "string"}, "value": {"type": "string"}}),
        ("/api/search", {"query": {"type": "string"}, "filter": {"type": "string"}}),
        ("/api/upload", {"file_url": {"type": "string"}, "description": {"type": "string"}}),
        ("/api/webhook", {"url": {"type": "string"}, "event": {"type": "string"}}),
        ("/api/subscribe", {"email": {"type": "string"}, "topic": {"type": "string"}}),
        ("/api/contact", {"name": {"type": "string"}, "email": {"type": "string"}, "message": {"type": "string"}}),
    ]
    for path, props in post_endpoints:
        endpoints.append(Endpoint(
            path=path,
            method="POST",
            request_body=RequestBody(
                content_type="application/json",
                schema={"type": "object", "properties": props, "required": list(props.keys())[:2]},
            ),
        ))

    return endpoints
