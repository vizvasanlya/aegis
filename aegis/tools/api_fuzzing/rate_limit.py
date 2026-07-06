"""Rate limit detection and bypass testing."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import requests


logger = logging.getLogger(__name__)


@dataclass
class RateLimitResult:
    endpoint: str
    detected: bool
    limit: int | None = None
    window_seconds: int | None = None
    bypass_technique: str | None = None
    evidence: str = ""
    severity: str = "medium"


def detect_rate_limit(
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    body: dict | None = None,
    num_requests: int = 20,
    delay: float = 0.1,
) -> RateLimitResult:
    """Detect if an endpoint has rate limiting by sending rapid requests."""
    rate_limited = False
    limit = None

    for i in range(num_requests):
        try:
            start = time.monotonic()
            resp = requests.request(
                method=method,
                url=url,
                json=body,
                headers=headers or {},
                timeout=10,
                verify=False,
            )
            elapsed = time.monotonic() - start

            if resp.status_code == 429:
                rate_limited = True
                limit = i + 1

                # Extract retry-after header
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        limit = int(retry_after)
                    except ValueError:
                        pass

                # Extract rate limit headers
                for header in resp.headers:
                    if "rate" in header.lower() or "limit" in header.lower():
                        try:
                            limit = int(resp.headers[header])
                        except ValueError:
                            pass

                break

            # Check for soft rate limiting (slowdown, captchas)
            if resp.status_code in (503, 529) and i > 5:
                rate_limited = True
                limit = i + 1
                break

            time.sleep(delay)

        except Exception as exc:
            logger.debug("Rate limit detection request %d failed: %s", i, exc)

    return RateLimitResult(
        endpoint=url,
        detected=rate_limited,
        limit=limit,
        evidence=f"Rate limited after {limit} requests" if rate_limited else f"No rate limit detected after {num_requests} requests",
        severity="medium" if rate_limited else "info",
    )


def test_rate_limit_bypass(
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    body: dict | None = None,
) -> list[RateLimitResult]:
    """Test common rate limit bypass techniques."""
    results = []

    # Technique 1: IP rotation via X-Forwarded-For
    for ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "::1"]:
        try:
            bypass_headers = dict(headers or {})
            bypass_headers["X-Forwarded-For"] = ip
            bypass_headers["X-Real-IP"] = ip
            bypass_headers["X-Originating-IP"] = ip

            # Send requests to test if IP-based rate limiting can be bypassed
            rate_limited = False
            for _ in range(15):
                resp = requests.request(
                    method=method,
                    url=url,
                    json=body,
                    headers=bypass_headers,
                    timeout=5,
                    verify=False,
                )
                if resp.status_code == 429:
                    rate_limited = True
                    break
                time.sleep(0.05)

            if not rate_limited:
                results.append(RateLimitResult(
                    endpoint=url,
                    detected=False,
                    bypass_technique=f"X-Forwarded-For: {ip}",
                    evidence=f"Rate limit bypassed by setting X-Forwarded-For to {ip}",
                    severity="high",
                ))
                break

        except Exception as exc:
            logger.debug("Bypass test failed: %s", exc)

    # Technique 2: HTTP method rotation
    for test_method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
        if test_method == method:
            continue
        try:
            rate_limited = False
            for _ in range(15):
                resp = requests.request(
                    method=test_method,
                    url=url,
                    json=body if test_method in ("POST", "PUT", "PATCH") else None,
                    headers=headers or {},
                    timeout=5,
                    verify=False,
                )
                if resp.status_code == 429:
                    rate_limited = True
                    break
                time.sleep(0.05)

            if not rate_limited:
                results.append(RateLimitResult(
                    endpoint=url,
                    detected=False,
                    bypass_technique=f"Method rotation: {test_method}",
                    evidence=f"Rate limit not applied to {test_method} method",
                    severity="medium",
                ))
                break

        except Exception as exc:
            logger.debug("Method rotation test failed: %s", exc)

    # Technique 3: Header variation
    header_variations = [
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        {"User-Agent": "curl/7.68.0"},
        {"Accept": "application/json"},
        {"Accept": "text/html"},
        {"Content-Type": "application/x-www-form-urlencoded"},
    ]

    for var_headers in header_variations:
        try:
            rate_limited = False
            for _ in range(15):
                combined = {**(headers or {}), **var_headers}
                resp = requests.request(
                    method=method,
                    url=url,
                    json=body,
                    headers=combined,
                    timeout=5,
                    verify=False,
                )
                if resp.status_code == 429:
                    rate_limited = True
                    break
                time.sleep(0.05)

            if not rate_limited:
                header_name = list(var_headers.keys())[0]
                results.append(RateLimitResult(
                    endpoint=url,
                    detected=False,
                    bypass_technique=f"Header variation: {header_name}",
                    evidence=f"Rate limit bypassed by changing {header_name}",
                    severity="medium",
                ))
                break

        except Exception as exc:
            logger.debug("Header variation test failed: %s", exc)

    return results
