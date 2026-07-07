"""MobSF (Mobile Security Framework) API integration tools.

Provides @function_tool wrappers for the MobSF REST API to automate
mobile application static and dynamic analysis.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx
from agents import RunContextWrapper, function_tool

from aegis.config import load_settings


logger = logging.getLogger(__name__)


def _mobsf_config() -> tuple[str, str | None]:
    settings = load_settings()
    url = settings.mobile.mobsf_url
    api_key = settings.mobile.mobsf_api_key
    return url or "", api_key


def _err(name: str, msg: str) -> str:
    return json.dumps({"success": False, "error": f"{name}: {msg}"}, ensure_ascii=False, default=str)


def _ok(data: Any) -> str:
    return json.dumps({"success": True, "result": data}, ensure_ascii=False, default=str)


def _headers(api_key: str | None) -> dict[str, str]:
    hdrs: dict[str, str] = {}
    if api_key:
        hdrs["Authorization"] = api_key
    return hdrs


@function_tool(timeout=60)
async def mobsf_check_connection(
    ctx: RunContextWrapper,
    mobsf_url: str | None = None,
    api_key: str | None = None,
) -> str:
    """Check connectivity to a MobSF server.

    Sends a GET request to the MobSF API docs endpoint and validates
    the server is reachable and responding.

    Args:
        mobsf_url: MobSF server URL (defaults to AEGIS_MOBSF_URL config).
        api_key: MobSF API key (defaults to AEGIS_MOBSF_API_KEY config). Optional.
    """
    url = mobsf_url or _mobsf_config()[0]
    key = api_key or _mobsf_config()[1]

    if not url:
        return _err("mobsf_check_connection", "MobSF URL not configured. Set AEGIS_MOBSF_URL or pass mobsf_url.")

    base = url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{base}/api/v1/scans", headers=_headers(key))
            if resp.status_code == 200:
                return _ok({"status": "connected", "url": base, "api_configured": bool(key)})
            elif resp.status_code == 401:
                return _err("mobsf_check_connection", "MobSF returned 401 — check API key")
            else:
                return _err("mobsf_check_connection", f"MobSF returned HTTP {resp.status_code}: {resp.text[:200]}")
    except httpx.ConnectError as e:
        return _err("mobsf_check_connection", f"Cannot connect to {base}: {e}")
    except httpx.TimeoutException:
        return _err("mobsf_check_connection", f"Connection to {base} timed out")
    except Exception as e:
        return _err("mobsf_check_connection", str(e))


@function_tool(timeout=300)
async def mobsf_upload_and_scan(
    ctx: RunContextWrapper,
    app_path: str,
    mobsf_url: str | None = None,
    api_key: str | None = None,
) -> str:
    """Upload a mobile app (APK/IPA) to MobSF and trigger a full static analysis scan.

    Performs the full MobSF workflow:
    1. Uploads the file via POST /api/v1/upload
    2. Triggers analysis via POST /api/v1/scan
    3. Polls for completion via GET /api/v1/tasks
    4. Returns the JSON report from POST /api/v1/report_json

    Args:
        app_path: Absolute path to the APK or IPA file in the sandbox.
        mobsf_url: MobSF server URL (defaults to AEGIS_MOBSF_URL config).
        api_key: MobSF API key (defaults to AEGIS_MOBSF_API_KEY config).
    """
    path = Path(app_path)
    if not path.exists():
        return _err("mobsf_upload_and_scan", f"File not found: {app_path}")

    url = mobsf_url or _mobsf_config()[0]
    key = api_key or _mobsf_config()[1]

    if not url:
        return _err("mobsf_upload_and_scan", "MobSF URL not configured. Set AEGIS_MOBSF_URL or pass mobsf_url.")

    base = url.rstrip("/")
    headers = _headers(key)

    try:
        async with httpx.AsyncClient(timeout=300) as client:
            # Step 1: Upload the file
            logger.info("MobSF: uploading %s to %s", path.name, base)
            with open(path, "rb") as f:
                upload_resp = await client.post(
                    f"{base}/api/v1/upload",
                    headers=headers,
                    files={"file": (path.name, f, "application/octet-stream")},
                )

            if upload_resp.status_code != 200:
                return _err("mobsf_upload_and_scan", f"Upload failed (HTTP {upload_resp.status_code}): {upload_resp.text[:300]}")

            upload_data = upload_resp.json()
            file_hash = upload_data.get("hash")
            file_name = upload_data.get("file_name", path.name)
            scan_type = upload_data.get("scan_type", "apk")

            if not file_hash:
                return _err("mobsf_upload_and_scan", f"Upload response missing hash: {upload_data}")

            logger.info("MobSF: uploaded %s (hash=%s, type=%s)", file_name, file_hash, scan_type)

            # Step 2: Trigger scan
            logger.info("MobSF: triggering scan for %s", file_hash)
            scan_resp = await client.post(
                f"{base}/api/v1/scan",
                headers=headers,
                data={"hash": file_hash, "scan_type": scan_type},
            )

            if scan_resp.status_code != 200:
                return _err("mobsf_upload_and_scan", f"Scan trigger failed (HTTP {scan_resp.status_code}): {scan_resp.text[:300]}")

            scan_data = scan_resp.json()
            logger.info("MobSF: scan triggered for %s", file_hash)

            # Step 3: Poll for completion (up to 5 minutes)
            logger.info("MobSF: polling for scan completion...")
            for attempt in range(30):
                await asyncio.sleep(10)
                tasks_resp = await client.get(
                    f"{base}/api/v1/tasks",
                    headers=headers,
                )
                if tasks_resp.status_code == 200:
                    tasks = tasks_resp.json()
                    pending = [t for t in (tasks if isinstance(tasks, list) else []) if t.get("hash") == file_hash]
                    if not pending:
                        logger.info("MobSF: scan task completed for %s", file_hash)
                        break
                    logger.info("MobSF: task still pending (attempt %d/30)", attempt + 1)
                else:
                    logger.info("MobSF: tasks endpoint returned %d (attempt %d/30)", tasks_resp.status_code, attempt + 1)
            else:
                logger.warning("MobSF: scan may still be running after 5min timeout")

            # Step 4: Get JSON report
            logger.info("MobSF: fetching JSON report for %s", file_hash)
            report_resp = await client.post(
                f"{base}/api/v1/report_json",
                headers=headers,
                data={"hash": file_hash},
            )

            if report_resp.status_code != 200:
                return _err("mobsf_upload_and_scan", f"Report fetch failed (HTTP {report_resp.status_code}): {report_resp.text[:300]}")

            report = report_resp.json()

            # Step 5: Get scorecard
            logger.info("MobSF: fetching scorecard for %s", file_hash)
            score_resp = await client.post(
                f"{base}/api/v1/scorecard",
                headers=headers,
                data={"hash": file_hash},
            )
            scorecard = score_resp.json() if score_resp.status_code == 200 else {}

            return _ok({
                "hash": file_hash,
                "file_name": file_name,
                "scan_type": scan_type,
                "package_name": report.get("package_name", ""),
                "app_name": report.get("app_name", ""),
                "version": report.get("version_name", ""),
                "min_sdk": report.get("min_sdk", ""),
                "target_sdk": report.get("target_sdk", ""),
                "permissions": report.get("permissions", []),
                "findings": _extract_findings(report),
                "cvss_score": _extract_cvss(scorecard),
                "security_score": scorecard.get("security_score", ""),
                "total_findings": report.get("total_findings", 0),
                "total_suppressed": report.get("total_suppressed", 0),
            })
    except httpx.ConnectError as e:
        return _err("mobsf_upload_and_scan", f"Cannot connect to MobSF at {base}: {e}")
    except httpx.TimeoutException:
        return _err("mobsf_upload_and_scan", f"MobSF request timed out at {base}")
    except Exception as e:
        return _err("mobsf_upload_and_scan", str(e))


@function_tool(timeout=120)
async def mobsf_get_report(
    ctx: RunContextWrapper,
    scan_hash: str,
    mobsf_url: str | None = None,
    api_key: str | None = None,
) -> str:
    """Retrieve the full JSON report from a completed MobSF scan.

    Args:
        scan_hash: The MD5 hash returned by mobsf_upload_and_scan.
        mobsf_url: MobSF server URL (defaults to AEGIS_MOBSF_URL config).
        api_key: MobSF API key (defaults to AEGIS_MOBSF_API_KEY config).
    """
    url = mobsf_url or _mobsf_config()[0]
    key = api_key or _mobsf_config()[1]

    if not url:
        return _err("mobsf_get_report", "MobSF URL not configured")

    base = url.rstrip("/")
    headers = _headers(key)

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{base}/api/v1/report_json",
                headers=headers,
                data={"hash": scan_hash},
            )
            if resp.status_code != 200:
                return _err("mobsf_get_report", f"HTTP {resp.status_code}: {resp.text[:300]}")
            report = resp.json()
            return _ok({
                "hash": scan_hash,
                "package_name": report.get("package_name", ""),
                "app_name": report.get("app_name", ""),
                "version": report.get("version_name", ""),
                "findings": _extract_findings(report),
                "total_findings": report.get("total_findings", 0),
            })
    except httpx.ConnectError as e:
        return _err("mobsf_get_report", f"Cannot connect to MobSF: {e}")
    except Exception as e:
        return _err("mobsf_get_report", str(e))


@function_tool(timeout=120)
async def mobsf_get_scorecard(
    ctx: RunContextWrapper,
    scan_hash: str,
    mobsf_url: str | None = None,
    api_key: str | None = None,
) -> str:
    """Get the AppSec scorecard for a completed MobSF scan.

    Args:
        scan_hash: The MD5 hash from a MobSF upload.
        mobsf_url: MobSF server URL (defaults to AEGIS_MOBSF_URL config).
        api_key: MobSF API key (defaults to AEGIS_MOBSF_API_KEY config).
    """
    url = mobsf_url or _mobsf_config()[0]
    key = api_key or _mobsf_config()[1]

    if not url:
        return _err("mobsf_get_scorecard", "MobSF URL not configured")

    base = url.rstrip("/")
    headers = _headers(key)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{base}/api/v1/scorecard",
                headers=headers,
                data={"hash": scan_hash},
            )
            if resp.status_code != 200:
                return _err("mobsf_get_scorecard", f"HTTP {resp.status_code}: {resp.text[:300]}")
            return _ok(resp.json())
    except httpx.ConnectError as e:
        return _err("mobsf_get_scorecard", f"Cannot connect to MobSF: {e}")
    except Exception as e:
        return _err("mobsf_get_scorecard", str(e))


@function_tool(timeout=30)
async def mobsf_delete_scan(
    ctx: RunContextWrapper,
    scan_hash: str,
    mobsf_url: str | None = None,
    api_key: str | None = None,
) -> str:
    """Delete a scan and its uploaded file from MobSF.

    Args:
        scan_hash: The MD5 hash of the scan to delete.
        mobsf_url: MobSF server URL (defaults to AEGIS_MOBSF_URL config).
        api_key: MobSF API key (defaults to AEGIS_MOBSF_API_KEY config).
    """
    url = mobsf_url or _mobsf_config()[0]
    key = api_key or _mobsf_config()[1]

    if not url:
        return _err("mobsf_delete_scan", "MobSF URL not configured")

    base = url.rstrip("/")
    headers = _headers(key)

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{base}/api/v1/delete_scan",
                headers=headers,
                data={"hash": scan_hash},
            )
            if resp.status_code == 200:
                return _ok({"deleted": True, "hash": scan_hash})
            return _err("mobsf_delete_scan", f"HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        return _err("mobsf_delete_scan", str(e))


def _extract_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract structured findings from a MobSF JSON report."""
    findings: list[dict[str, Any]] = []

    # Android findings
    for key in ("findings", "malware_findings", "trackers"):
        items = report.get(key, {})
        if isinstance(items, dict):
            for rule_id, details in items.items():
                if isinstance(details, dict):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": details.get("severity", "info"),
                        "title": details.get("title", rule_id),
                        "description": details.get("description", ""),
                        "cwe": details.get("cwe", ""),
                        "cvss": details.get("cvss", 0),
                    })

    # iOS findings
    ios_findings = report.get("ios_findings", {})
    if isinstance(ios_findings, dict):
        for rule_id, details in ios_findings.items():
            if isinstance(details, dict):
                findings.append({
                    "rule_id": rule_id,
                    "severity": details.get("severity", "info"),
                    "title": details.get("title", rule_id),
                    "description": details.get("description", ""),
                    "cwe": details.get("cwe", ""),
                    "cvss": details.get("cvss", 0),
                })

    findings.sort(key=lambda f: {"critical": 0, "high": 1, "warning": 2, "info": 3}.get(f.get("severity", "info"), 4))
    return findings


def _extract_cvss(scorecard: dict[str, Any]) -> float | None:
    try:
        return float(scorecard.get("cvss_score", 0))
    except (TypeError, ValueError):
        return None


import asyncio
