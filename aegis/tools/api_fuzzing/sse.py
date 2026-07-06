"""Server-Sent Events (SSE) security testing."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import requests


logger = logging.getLogger(__name__)


@dataclass
class SSETestResult:
    test_name: str
    vulnerable: bool
    description: str
    evidence: str = ""
    severity: str = "medium"


def test_sse_injection(
    url: str,
    headers: dict[str, str] | None = None,
) -> SSETestResult:
    """Test for XSS injection via SSE data field."""
    try:
        # Connect to SSE endpoint
        resp = requests.get(
            url,
            headers={
                "Accept": "text/event-stream",
                **(headers or {}),
            },
            timeout=10,
            stream=True,
            verify=False,
        )

        if resp.status_code != 200:
            return SSETestResult(
                test_name="SSE Injection",
                vulnerable=False,
                description=f"SSE endpoint returned status {resp.status_code}",
            )

        # Read a few events
        events = []
        start = time.monotonic()
        for line in resp.iter_lines(decode_unicode=True):
            if time.monotonic() - start > 5:
                break
            if line:
                events.append(line)

        resp.close()

        # Check if any event data contains unsanitized user input
        for event in events:
            if event.startswith("data:"):
                data = event[5:].strip()
                # Check for XSS patterns
                if any(pattern in data for pattern in [
                    "<script", "onerror=", "onload=", "javascript:",
                    "document.cookie", "innerHTML",
                ]):
                    return SSETestResult(
                        test_name="SSE Injection",
                        vulnerable=True,
                        description="SSE data field contains unsanitized script tags",
                        evidence=f"Event data: {data[:200]}",
                        severity="critical",
                    )

        return SSETestResult(
            test_name="SSE Injection",
            vulnerable=False,
            description="No XSS payloads detected in SSE events",
        )

    except Exception as exc:
        return SSETestResult(
            test_name="SSE Injection",
            vulnerable=False,
            description=f"Test inconclusive: {exc}",
        )


def test_sse_auth_bypass(
    url: str,
    headers: dict[str, str] | None = None,
) -> SSETestResult:
    """Test if SSE endpoint works without authentication."""
    try:
        # Try without auth
        resp = requests.get(
            url,
            headers={"Accept": "text/event-stream"},
            timeout=5,
            stream=True,
            verify=False,
        )

        if resp.status_code == 200:
            # Read first event to confirm it's streaming real data
            start = time.monotonic()
            has_data = False
            for line in resp.iter_lines(decode_unicode=True):
                if time.monotonic() - start > 3:
                    break
                if line and line.startswith("data:"):
                    has_data = True
                    break

            resp.close()

            if has_data:
                return SSETestResult(
                    test_name="SSE Auth Bypass",
                    vulnerable=True,
                    description="SSE endpoint streams data without authentication",
                    evidence="Connected and received events without auth token",
                    severity="high",
                )

        return SSETestResult(
            test_name="SSE Auth Bypass",
            vulnerable=False,
            description="SSE endpoint requires authentication",
        )

    except Exception as exc:
        return SSETestResult(
            test_name="SSE Auth Bypass",
            vulnerable=False,
            description=f"Test inconclusive: {exc}",
        )


def test_sse_origin_validation(
    url: str,
    headers: dict[str, str] | None = None,
) -> SSETestResult:
    """Test if SSE endpoint validates Origin header."""
    try:
        evil_origins = ["https://evil.com", "https://attacker.net", "null"]

        for origin in evil_origins:
            resp = requests.get(
                url,
                headers={
                    "Accept": "text/event-stream",
                    "Origin": origin,
                    **(headers or {}),
                },
                timeout=5,
                stream=True,
                verify=False,
            )

            # Check if server reflects the origin or allows cross-origin
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*" or acao == origin:
                resp.close()
                return SSETestResult(
                    test_name="SSE Origin Validation",
                    vulnerable=True,
                    description=f"SSE endpoint allows cross-origin from {origin}",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    severity="high",
                )

            resp.close()

        return SSETestResult(
            test_name="SSE Origin Validation",
            vulnerable=False,
            description="SSE endpoint validates Origin header",
        )

    except Exception as exc:
        return SSETestResult(
            test_name="SSE Origin Validation",
            vulnerable=False,
            description=f"Test inconclusive: {exc}",
        )


def run_all_sse_tests(url: str, headers: dict[str, str] | None = None) -> list[SSETestResult]:
    """Run all SSE security tests."""
    results = []
    results.append(test_sse_injection(url, headers))
    results.append(test_sse_auth_bypass(url, headers))
    results.append(test_sse_origin_validation(url, headers))
    return results
