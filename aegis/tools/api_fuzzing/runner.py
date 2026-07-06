"""Test executor for API fuzzing."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from aegis.tools.api_fuzzing.fuzzer import TestCase


logger = logging.getLogger(__name__)


@dataclass
class HTTPResponse:
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float = 0


@dataclass
class FuzzResult:
    test: TestCase
    request: dict[str, Any]
    response: HTTPResponse
    vulnerability: str | None = None
    severity: str | None = None
    evidence: str = ""


def _build_url(base_url: str, endpoint: str, params: dict[str, str]) -> str:
    """Build full URL with query parameters."""
    url = f"{base_url.rstrip('/')}{endpoint}"
    if params:
        query = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{query}"
    return url


def _execute_request(
    base_url: str,
    test: TestCase,
    auth_headers: dict[str, str] | None,
    timeout: int = 15,
) -> tuple[dict[str, Any], HTTPResponse]:
    """Execute a single HTTP request and return request/response."""
    url = _build_url(base_url, test.endpoint, test.params)

    headers = {"User-Agent": "Aegis-API-Scanner/1.0"}
    if auth_headers:
        headers.update(auth_headers)
    if test.headers:
        headers.update(test.headers)
    if test.body and test.content_type == "application/json":
        headers["Content-Type"] = "application/json"

    request_info = {
        "method": test.method,
        "url": url,
        "headers": dict(headers),
        "body": test.body,
    }

    start = time.monotonic()
    try:
        resp = requests.request(
            method=test.method,
            url=url,
            headers=headers,
            json=test.body if isinstance(test.body, dict) else None,
            data=test.body if isinstance(test.body, str) else None,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        elapsed = (time.monotonic() - start) * 1000

        response = HTTPResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text[:5000],
            elapsed_ms=elapsed,
        )
    except requests.exceptions.Timeout:
        elapsed = (time.monotonic() - start) * 1000
        response = HTTPResponse(
            status_code=0,
            headers={},
            body="Request timed out",
            elapsed_ms=elapsed,
        )
    except requests.exceptions.ConnectionError:
        elapsed = (time.monotonic() - start) * 1000
        response = HTTPResponse(
            status_code=0,
            headers={},
            body="Connection failed",
            elapsed_ms=elapsed,
        )
    except Exception as exc:
        elapsed = (time.monotonic() - start) * 1000
        response = HTTPResponse(
            status_code=0,
            headers={},
            body=f"Request error: {exc}",
            elapsed_ms=elapsed,
        )

    return request_info, response


async def run_single_test(
    base_url: str,
    test: TestCase,
    auth_headers: dict[str, str] | None,
    timeout: int = 15,
) -> FuzzResult:
    """Execute one test case asynchronously."""
    loop = asyncio.get_event_loop()
    request_info, response = await loop.run_in_executor(
        None, _execute_request, base_url, test, auth_headers, timeout
    )

    return FuzzResult(
        test=test,
        request=request_info,
        response=response,
    )


async def run_fuzzing(
    base_url: str,
    tests: list[TestCase],
    auth_headers: dict[str, str] | None,
    max_concurrent: int = 5,
    timeout: int = 15,
) -> list[FuzzResult]:
    """Execute test cases with controlled concurrency."""
    semaphore = asyncio.Semaphore(max_concurrent)
    results: list[FuzzResult] = []

    async def _run_with_semaphore(test: TestCase) -> FuzzResult:
        async with semaphore:
            return await run_single_test(base_url, test, auth_headers, timeout)

    tasks = [_run_with_semaphore(test) for test in tests]
    completed = await asyncio.gather(*tasks, return_exceptions=True)

    for result in completed:
        if isinstance(result, FuzzResult):
            results.append(result)
        elif isinstance(result, Exception):
            logger.debug("Test execution failed: %s", result)

    return results
