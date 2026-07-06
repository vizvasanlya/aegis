"""API versioning security tests."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import requests


logger = logging.getLogger(__name__)


@dataclass
class VersionTestResult:
    test_name: str
    vulnerable: bool
    description: str
    evidence: str = ""
    severity: str = "medium"


def detect_api_versions(base_url: str) -> list[str]:
    """Discover API versions by probing common version patterns."""
    versions = []

    # Check /v1, /v2, /v3, etc.
    for i in range(1, 6):
        for prefix in ["/v", "/api/v", "/api/v"]:
            url = f"{base_url.rstrip('/')}{prefix}{i}"
            try:
                resp = requests.get(url, timeout=5, verify=False)
                if resp.status_code != 404:
                    versions.append(f"{prefix}{i}")
                    break
            except Exception:
                continue

    # Check Accept header versioning
    for version in ["1", "2", "3"]:
        try:
            resp = requests.get(
                base_url,
                headers={"Accept": f"application/vnd.api+json; version={version}"},
                timeout=5,
                verify=False,
            )
            if resp.status_code != 404:
                versions.append(f"header:v{version}")
        except Exception:
            continue

    return versions


def test_old_version_exposure(
    base_url: str,
    auth_headers: dict[str, str] | None = None,
) -> list[VersionTestResult]:
    """Test if old API versions are still accessible."""
    results = []
    versions = detect_api_versions(base_url)

    if len(versions) <= 1:
        return results

    # Check if older versions lack security controls present in newer ones
    for i, older in enumerate(versions[:-1]):
        for newer in versions[i + 1:]:
            try:
                headers = {"Content-Type": "application/json"}
                if auth_headers:
                    headers.update(auth_headers)

                # Try accessing a sensitive endpoint on older version
                for sensitive_path in ["/admin", "/users", "/settings", "/me"]:
                    old_url = f"{base_url.rstrip('/')}{older}{sensitive_path}"
                    new_url = f"{base_url.rstrip('/')}{newer}{sensitive_path}"

                    old_resp = requests.get(old_url, headers=headers, timeout=5, verify=False)
                    new_resp = requests.get(new_url, headers=headers, timeout=5, verify=False)

                    # If old version returns 200 but new returns 401/403
                    if old_resp.status_code == 200 and new_resp.status_code in (401, 403):
                        results.append(VersionTestResult(
                            test_name=f"Old Version Auth Bypass ({older})",
                            vulnerable=True,
                            description=f"API {older} lacks auth controls present in {newer}",
                            evidence=f"{older}{sensitive_path} returned 200, {newer}{sensitive_path} returned {new_resp.status_code}",
                            severity="critical",
                        ))

                    # If old version returns more data
                    if old_resp.status_code == 200 and new_resp.status_code == 200:
                        if len(old_resp.text) > len(new_resp.text) * 1.5:
                            results.append(VersionTestResult(
                                test_name=f"Old Version Data Exposure ({older})",
                                vulnerable=True,
                                description=f"API {older} returns more data than {newer}",
                                evidence=f"{older} response: {len(old_resp.text)} bytes, {newer}: {len(new_resp.text)} bytes",
                                severity="medium",
                            ))

            except Exception as exc:
                logger.debug("Version comparison failed: %s", exc)

    return results


def test_version_header_manipulation(
    base_url: str,
    auth_headers: dict[str, str] | None = None,
) -> list[VersionTestResult]:
    """Test if version can be manipulated via headers."""
    results = []

    version_headers = [
        {"X-API-Version": "1"},
        {"X-Api-Version": "99"},
        {"Api-Version": "1"},
        {"X-Version": "1"},
    ]

    for vh in version_headers:
        try:
            headers = {"Content-Type": "application/json"}
            if auth_headers:
                headers.update(auth_headers)
            headers.update(vh)

            resp = requests.get(base_url, headers=headers, timeout=5, verify=False)

            if resp.status_code == 200:
                # Check if the response differs from normal request
                normal_resp = requests.get(
                    base_url,
                    headers={"Content-Type": "application/json", **(auth_headers or {})},
                    timeout=5,
                    verify=False,
                )

                if resp.text != normal_resp.text:
                    header_name = list(vh.keys())[0]
                    results.append(VersionTestResult(
                        test_name=f"Version Header Manipulation ({header_name})",
                        vulnerable=True,
                        description=f"Setting {header_name} changes API behavior",
                        evidence=f"Different response when {header_name}: {vh[header_name]}",
                        severity="medium",
                    ))

        except Exception as exc:
            logger.debug("Version header test failed: %s", exc)

    return results


def run_all_version_tests(
    base_url: str,
    auth_headers: dict[str, str] | None = None,
) -> list[VersionTestResult]:
    """Run all API versioning tests."""
    results = []
    results.extend(test_old_version_exposure(base_url, auth_headers))
    results.extend(test_version_header_manipulation(base_url, auth_headers))
    return results
