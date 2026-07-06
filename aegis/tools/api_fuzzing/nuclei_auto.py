"""Automated nuclei integration — runs nuclei with API templates automatically."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


async def auto_run_nuclei(
    base_url: str,
    spec_path: str | None = None,
    severity: str = "critical,high,medium",
    tags: str = "api,cve,xss,sqli,ssrf,auth,misconfig",
    timeout: int = 180,
) -> dict[str, Any]:
    """Automatically run nuclei with comprehensive API scanning.

    This is called by the agent without needing to construct the command.
    Handles: template selection, output parsing, finding deduplication.
    """
    cmd_parts = ["nuclei"]

    if spec_path:
        cmd_parts.extend(["-im", "openapi"])
        # Use a targets file with the spec URL
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(f"{base_url}\n")
            targets_file = f.name
        cmd_parts.extend(["-l", targets_file])
    else:
        cmd_parts.extend(["-u", base_url])

    cmd_parts.extend([
        "-tags", tags,
        "-s", severity,
        "-rl", "50",
        "-c", "10",
        "-bs", "10",
        "-timeout", "10",
        "-retries", "1",
        "-stats",
        "-silent",
        "-jsonl",
    ])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        output_file = f.name

    cmd_parts.extend(["-o", output_file])
    cmd = " ".join(cmd_parts)

    logger.info("Auto-running nuclei: %s", cmd[:200])

    findings = []
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        output_path = Path(output_file)
        if output_path.exists():
            seen = set()
            for line in output_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    template_id = finding.get("template-id", "")
                    matched = finding.get("matched-at", "")
                    dedup_key = f"{template_id}:{matched}"

                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    info = finding.get("info", {})
                    findings.append({
                        "template_id": template_id,
                        "name": info.get("name", ""),
                        "severity": info.get("severity", ""),
                        "matched_at": matched,
                        "description": info.get("description", ""),
                        "reference": info.get("reference", []),
                        "matcher_name": finding.get("matcher-name", ""),
                        "curl_command": finding.get("curl-command", ""),
                        "tags": info.get("tags", []),
                    })
                except json.JSONDecodeError:
                    continue

            output_path.unlink(missing_ok=True)

    except asyncio.TimeoutError:
        logger.warning("Nuclei scan timed out after %ds", timeout)
    except Exception as exc:
        logger.warning("Nuclei scan failed: %s", exc)

    # Categorize findings
    by_severity = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        by_severity.setdefault(sev, []).append(f)

    return {
        "success": True,
        "total_findings": len(findings),
        "by_severity": {k: len(v) for k, v in by_severity.items()},
        "findings": findings[:50],  # Cap at 50 for agent context
    }
