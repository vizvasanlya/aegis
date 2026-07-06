"""gRPC server reflection and vulnerability testing."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import requests


logger = logging.getLogger(__name__)


@dataclass
class GrpcService:
    name: str
    methods: list[dict[str, str]] = field(default_factory=list)


@dataclass
class GrpcTestResult:
    test_name: str
    vulnerable: bool
    description: str
    evidence: str = ""
    severity: str = "medium"


# ── gRPC Reflection via HTTP/1.1 (gRPC-Web) ──────────────────────────────────

_REFLECTION_QUERY = {
    "file_containing_symbol": "grpc.reflection.v1alpha.ServerReflection",
}


def _try_grpc_web_reflection(
    base_url: str,
    headers: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Try gRPC-Web reflection via HTTP/1.1."""
    # Try common gRPC-Web endpoints
    grpc_web_paths = [
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.health.v1.Health/Check",
    ]

    for path in grpc_web_paths:
        try:
            url = f"{base_url.rstrip('/')}{path}"
            resp = requests.post(
                url,
                headers={
                    "Content-Type": "application/grpc-web+proto",
                    "Accept": "application/grpc-web+proto",
                    **(headers or {}),
                },
                timeout=10,
                verify=False,
            )

            # gRPC-Web returns specific status codes
            if resp.status_code in (200, 404, 500):
                return {"path": path, "status": resp.status_code, "body": resp.text[:500]}

        except Exception:
            continue

    return None


def _try_grpc_json_transcoding(
    base_url: str,
    headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Try gRPC JSON transcoding (Envoy/gRPC-Gateway style)."""
    services = []

    # Common transcoding patterns
    transcoded_paths = [
        "/v1/reflect",
        "/grpc/reflection/v1alpha/ServerReflection",
        "/server_reflection",
        "/reflection",
        "/grpc.health.v1.Health/Check",
        "/grpc.health.v1/Health",
        "/health",
        "/grpc/health/v1",
    ]

    for path in transcoded_paths:
        try:
            url = f"{base_url.rstrip('/')}{path}"
            resp = requests.get(
                url,
                headers=headers or {},
                timeout=5,
                verify=False,
            )

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    services.append({
                        "path": path,
                        "status": resp.status_code,
                        "data": data,
                    })
                except (json.JSONDecodeError, ValueError):
                    pass

        except Exception:
            continue

    return services


def discover_grpc_services(
    base_url: str,
    headers: dict[str, str] | None = None,
) -> list[GrpcService]:
    """Discover gRPC services via reflection or JSON transcoding."""
    services = []

    # Method 1: Try gRPC-Web reflection
    reflection = _try_grpc_web_reflection(base_url, headers)
    if reflection:
        logger.info("Found gRPC reflection at %s", reflection["path"])
        # Parse reflection response for service names
        # (simplified — real implementation would parse the proto reflection response)

    # Method 2: Try JSON transcoding
    transcoded = _try_grpc_json_transcoding(base_url, headers)
    for entry in transcoded:
        data = entry.get("data", {})
        if isinstance(data, dict):
            service_name = data.get("serviceName", data.get("name", ""))
            if service_name:
                services.append(GrpcService(
                    name=service_name,
                    methods=[{"name": m.get("name", ""), "type": m.get("type", "")}
                            for m in data.get("methods", [])],
                ))

    # Method 3: Brute-force common gRPC service paths
    common_services = [
        ("grpc.health.v1.Health", ["Check", "Watch"]),
        ("grpc.reflection.v1alpha.ServerReflection", ["ServerReflectionInfo"]),
        ("grpc.reflection.v1.ServerReflection", ["ServerReflectionInfo"]),
    ]

    for service_name, method_names in common_services:
        for method in method_names:
            path = f"/{service_name}/{method}"
            try:
                url = f"{base_url.rstrip('/')}{path}"
                resp = requests.post(
                    url,
                    headers={
                        "Content-Type": "application/grpc+proto",
                        **(headers or {}),
                    },
                    timeout=5,
                    verify=False,
                )

                # If we get anything other than 404, service likely exists
                if resp.status_code != 404:
                    existing = next((s for s in services if s.name == service_name), None)
                    if existing:
                        if not any(m["name"] == method for m in existing.methods):
                            existing.methods.append({"name": method, "type": "unary"})
                    else:
                        services.append(GrpcService(
                            name=service_name,
                            methods=[{"name": method, "type": "unary"}],
                        ))

            except Exception:
                continue

    return services


def test_grpc_reflection_abuse(
    base_url: str,
    headers: dict[str, str] | None = None,
) -> GrpcTestResult:
    """Test if gRPC server reflection is enabled (information disclosure)."""
    services = discover_grpc_services(base_url, headers)

    if services:
        service_names = [s.name for s in services]
        method_counts = sum(len(s.methods) for s in services)

        return GrpcTestResult(
            test_name="gRPC Reflection Enabled",
            vulnerable=True,
            description=(
                f"gRPC server reflection is enabled. "
                f"Discovered {len(services)} services with {method_counts} methods. "
                f"Services: {', '.join(service_names)}"
            ),
            evidence=f"Services: {json.dumps(service_names)}",
            severity="medium",
        )

    return GrpcTestResult(
        test_name="gRPC Reflection Enabled",
        vulnerable=False,
        description="gRPC server reflection is disabled or not accessible",
    )


def test_grpc_auth_bypass(
    base_url: str,
    services: list[GrpcService],
    headers: dict[str, str] | None = None,
) -> list[GrpcTestResult]:
    """Test gRPC methods for authentication bypass."""
    results = []

    for service in services:
        for method_info in service.methods:
            method_name = method_info["name"]
            if not method_name or method_name in ("Check", "Watch", "ServerReflectionInfo"):
                continue

            try:
                url = f"{base_url.rstrip('/')}/{service.name}/{method_name}"

                # Try without auth
                resp = requests.post(
                    url,
                    headers={
                        "Content-Type": "application/grpc+proto",
                        **(headers or {}),
                    },
                    data=b"\x00\x00\x00\x00\x00",  # Minimal gRPC frame
                    timeout=5,
                    verify=False,
                )

                # If we get anything other than 401/403, auth may be missing
                if resp.status_code not in (401, 403, 404):
                    results.append(GrpcTestResult(
                        test_name=f"gRPC Auth Bypass: {service.name}/{method_name}",
                        vulnerable=True,
                        description=f"gRPC method {service.name}/{method_name} accessible without authentication",
                        evidence=f"Status: {resp.status_code}",
                        severity="high",
                    ))

            except Exception as exc:
                logger.debug("gRPC auth test failed for %s: %s", method_name, exc)

    return results


def test_grpc_injection(
    base_url: str,
    services: list[GrpcService],
    headers: dict[str, str] | None = None,
) -> list[GrpcTestResult]:
    """Test gRPC methods for injection vulnerabilities."""
    results = []

    injection_payloads = [
        ("SQLi", b'\n\x07" OR 1=1'),
        ("XSS", b'\n\x1c<script>alert(1)</script>'),
        ("Command", b'\n\x15; echo INJECTED_TEST'),
        ("Path Traversal", b'\n\x12../../../etc/passwd'),
        ("Large Payload", b'\x00' * 10000),
    ]

    for service in services:
        for method_info in service.methods:
            method_name = method_info["name"]
            if not method_name or method_name in ("Check", "Watch", "ServerReflectionInfo"):
                continue

            for payload_name, payload in injection_payloads:
                try:
                    url = f"{base_url.rstrip('/')}/{service.name}/{method_name}"

                    resp = requests.post(
                        url,
                        headers={
                            "Content-Type": "application/grpc+proto",
                            **(headers or {}),
                        },
                        data=payload,
                        timeout=10,
                        verify=False,
                    )

                    # Check for error messages that leak info
                    if resp.status_code in (200, 500):
                        body = resp.text
                        if any(pattern in body.lower() for pattern in [
                            "sql", "error", "exception", "stack", "trace",
                            "injected", "test",
                        ]):
                            results.append(GrpcTestResult(
                                test_name=f"gRPC Injection ({payload_name}): {service.name}/{method_name}",
                                vulnerable=True,
                                description=f"{payload_name} injection possible in {service.name}/{method_name}",
                                evidence=f"Payload: {payload[:50]}, Status: {resp.status_code}",
                                severity="critical" if payload_name in ("SQLi", "Command") else "high",
                            ))

                except Exception as exc:
                    logger.debug("gRPC injection test failed: %s", exc)

    return results


def test_grpc_message_size_dos(
    base_url: str,
    services: list[GrpcService],
    headers: dict[str, str] | None = None,
) -> GrpcTestResult:
    """Test if large gRPC messages cause server issues."""
    for service in services:
        for method_info in service.methods:
            method_name = method_info["name"]
            if not method_name or method_name in ("Check", "Watch", "ServerReflectionInfo"):
                continue

            try:
                url = f"{base_url.rstrip('/')}/{service.name}/{method_name}"

                # Send progressively larger messages
                for size_kb in [100, 500, 1000, 5000]:
                    payload = b"\x00" * (size_kb * 1024)

                    resp = requests.post(
                        url,
                        headers={
                            "Content-Type": "application/grpc+proto",
                            **(headers or {}),
                        },
                        data=payload,
                        timeout=15,
                        verify=False,
                    )

                    # If server accepts very large messages without limits
                    if resp.status_code in (200, 500) and size_kb >= 1000:
                        return GrpcTestResult(
                            test_name="gRPC Message Size DoS",
                            vulnerable=True,
                            description=f"Server accepted {size_kb}KB message on {service.name}/{method_name}",
                            evidence=f"Status: {resp.status_code} for {size_kb}KB payload",
                            severity="high",
                        )

            except Exception:
                continue

    return GrpcTestResult(
        test_name="gRPC Message Size DoS",
        vulnerable=False,
        description="Server enforces message size limits",
    )


def run_all_grpc_tests(
    base_url: str,
    headers: dict[str, str] | None = None,
) -> list[GrpcTestResult]:
    """Run all gRPC security tests."""
    results = []

    # Discover services first
    services = discover_grpc_services(base_url, headers)

    # Test reflection
    results.append(test_grpc_reflection_abuse(base_url, headers))

    # Test auth bypass on discovered services
    results.extend(test_grpc_auth_bypass(base_url, services, headers))

    # Test injection
    results.extend(test_grpc_injection(base_url, services, headers))

    # Test message size DoS
    results.append(test_grpc_message_size_dos(base_url, services, headers))

    return results
