"""Nuclei integration for API vulnerability scanning."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


async def run_nuclei_api_scan(
    base_url: str,
    spec_path: str | None = None,
    severity: str = "critical,high",
    timeout: int = 120,
) -> list[dict[str, Any]]:
    """Run nuclei with API-specific templates.

    If spec_path is provided, uses nuclei's OpenAPI input mode.
    Otherwise runs with standard API-related template tags.
    """
    import asyncio

    findings: list[dict[str, Any]] = []

    # Build nuclei command
    cmd_parts = ["nuclei"]

    if spec_path:
        # OpenAPI/Swagger input mode
        cmd_parts.extend(["-im", "openapi", "-l", spec_path])
    else:
        cmd_parts.extend(["-u", base_url])

    cmd_parts.extend([
        "-tags", "api,cve,xss,sqli,ssrf,auth",
        "-s", severity,
        "-rl", "50",
        "-c", "10",
        "-timeout", "10",
        "-retries", "1",
        "-silent",
        "-jsonl",
    ])

    # Use a temp file for output
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        output_file = f.name

    cmd_parts.extend(["-o", output_file])

    cmd = " ".join(cmd_parts)
    logger.info("Running nuclei API scan: %s", cmd[:200])

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        # Parse JSONL output
        output_path = Path(output_file)
        if output_path.exists():
            for line in output_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    findings.append({
                        "template_id": finding.get("template-id", ""),
                        "name": finding.get("info", {}).get("name", ""),
                        "severity": finding.get("info", {}).get("severity", ""),
                        "matched_at": finding.get("matched-at", ""),
                        "description": finding.get("info", {}).get("description", ""),
                        "reference": finding.get("info", {}).get("reference", []),
                        "matcher_name": finding.get("matcher-name", ""),
                        "curl_command": finding.get("curl-command", ""),
                    })
                except json.JSONDecodeError:
                    continue

            output_path.unlink(missing_ok=True)

    except asyncio.TimeoutError:
        logger.warning("Nuclei scan timed out after %ds", timeout)
    except Exception as exc:
        logger.warning("Nuclei scan failed: %s", exc)

    logger.info("Nuclei found %d API-related findings", len(findings))
    return findings
