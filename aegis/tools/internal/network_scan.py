"""Internal network scanning and host discovery."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Host:
    ip: str
    hostname: str = ""
    mac: str = ""
    os: str = ""
    ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)


async def discover_hosts(subnet: str) -> list[Host]:
    """Discover live hosts on a subnet using nmap ping sweep."""
    cmd = f"nmap -sn {subnet} -oX -"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode("utf-8", errors="replace")

        hosts = []
        # Parse nmap XML output for hosts
        for match in re.finditer(r'<address addr="([^"]+)" addrtype="ipv4"', output):
            ip = match.group(1)
            hostname_match = re.search(
                f'<address addr="{re.escape(ip)}".*?<hostname name="([^"]*)"', output
            )
            hostname = hostname_match.group(1) if hostname_match else ""
            hosts.append(Host(ip=ip, hostname=hostname))

        logger.info("Discovered %d hosts on %s", len(hosts), subnet)
        return hosts

    except Exception as exc:
        logger.warning("Host discovery failed: %s", exc)
        return []


async def scan_ports(
    hosts: list[Host],
    ports: str = "1-1000",
    timeout: int = 300,
) -> list[Host]:
    """Scan ports on discovered hosts."""
    if not hosts:
        return hosts

    ip_list = " ".join(h.ip for h in hosts)
    cmd = f"nmap -sV -p {ports} {ip_list} -oX -"

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode("utf-8", errors="replace")

        # Parse results per host
        host_blocks = re.split(r'<host ', output)
        for block in host_blocks[1:]:  # Skip first empty split
            ip_match = re.search(r'addr="([^"]+)" addrtype="ipv4"', block)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            # Find the matching host
            host = next((h for h in hosts if h.ip == ip), None)
            if not host:
                continue

            # Parse ports
            for port_match in re.finditer(
                r'portid="(\d+)".*?state="open".*?service name="([^"]*)"',
                block,
                re.DOTALL,
            ):
                port = int(port_match.group(1))
                service = port_match.group(2)
                host.ports.append(port)
                host.services[port] = service

            # Parse OS detection
            os_match = re.search(r'<osmatch name="([^"]+)"', block)
            if os_match:
                host.os = os_match.group(1)

        logger.info("Port scan complete: %d hosts with open ports", sum(1 for h in hosts if h.ports))
        return hosts

    except Exception as exc:
        logger.warning("Port scan failed: %s", exc)
        return hosts


async def enumerate_services(hosts: list[Host]) -> dict[str, Any]:
    """Enumerate services on discovered hosts."""
    results = {
        "total_hosts": len(hosts),
        "hosts_with_services": 0,
        "web_services": [],
        "database_services": [],
        "admin_services": [],
        "file_services": [],
        "other_services": [],
    }

    web_ports = {80, 443, 8080, 8443, 8000, 3000, 5000, 9090}
    db_ports = {3306, 5432, 1433, 27017, 6379, 9042, 5984}
    admin_ports = {8080, 9090, 3000, 5601, 9093, 9100}
    file_ports = {21, 445, 139, 2049}

    for host in hosts:
        if not host.ports:
            continue
        results["hosts_with_services"] += 1

        for port in host.ports:
            service = host.services.get(port, "unknown")
            entry = {"ip": host.ip, "port": port, "service": service, "hostname": host.hostname}

            if port in web_ports:
                results["web_services"].append(entry)
            elif port in db_ports:
                results["database_services"].append(entry)
            elif port in admin_ports:
                results["admin_services"].append(entry)
            elif port in file_ports:
                results["file_services"].append(entry)
            else:
                results["other_services"].append(entry)

    return results
