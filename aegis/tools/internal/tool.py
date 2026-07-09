"""Agent-callable internal network security scanner tool."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

logger = logging.getLogger(__name__)


@function_tool(timeout=600, strict_mode=False)
async def run_internal_scan(
    ctx: RunContextWrapper,
    target_range: str,
    focus: str | None = None,
    ad_domain: str | None = None,
    credentials: str | None = None,
) -> str:
    """Internal network security scanner — tests from inside the target network.

    Scans network ranges, enumerates Active Directory, tests credentials,
    and discovers internal services. Must be run from inside the target
    network (VPN, jump server, or office workstation).

    Args:
        target_range: Network range or CIDR (e.g., "10.0.0.0/24") or
            single IP (e.g., "10.0.1.50").
        focus: Testing focus — "network" (host/port discovery),
            "ad" (Active Directory enumeration), "credentials" (password
            spraying), "services" (internal service discovery),
            or "all" (default).
        ad_domain: Active Directory domain name (e.g., "corp.local").
            Required for AD enumeration and Kerberos attacks.
        credentials: JSON string with domain credentials for
            authenticated testing. Format:
            '{"username": "admin", "password": "P@ssw0rd", "domain": "corp.local"}'.
            If omitted, performs unauthenticated testing only.

    Returns:
        JSON string with scan results including hosts discovered,
        services found, AD enumeration, credential test results,
        and vulnerabilities.
    """
    from aegis.tools.internal.network_scan import (
        discover_hosts, scan_ports, enumerate_services,
    )
    from aegis.tools.internal.credential_spray import spray_passwords
    from aegis.tools.internal.lateral_movement import (
        smb_exec, smb_shares, winrm_exec, ssh_exec, multi_service_spray,
    )

    # Parse credentials
    creds = None
    if credentials:
        try:
            creds = json.loads(credentials)
        except json.JSONDecodeError:
            logger.warning("Invalid credentials JSON")

    results = {
        "success": True,
        "target_range": target_range,
        "focus": focus or "all",
    }

    # Step 1: Network discovery (always needed)
    if focus in (None, "all", "network", "services"):
        logger.info("Discovering hosts on %s", target_range)
        hosts = await discover_hosts(target_range)

        if hosts:
            # Port scan discovered hosts
            hosts = await scan_ports(hosts, ports="1-1000")

            # Enumerate services
            services = await enumerate_services(hosts)

            results["hosts_discovered"] = len(hosts)
            results["hosts"] = [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "os": h.os,
                    "ports": h.ports,
                    "services": h.services,
                }
                for h in hosts
            ]
            results["services"] = services
        else:
            results["hosts_discovered"] = 0
            results["hosts"] = []
            results["services"] = {"total_hosts": 0}

    # Step 2: Active Directory enumeration
    if focus in (None, "all", "ad") and ad_domain:
        logger.info("Enumerating Active Directory for %s", ad_domain)
        from aegis.tools.internal.ad_enum import (
            ldap_enumerate, kerberoast, asrep_roast,
        )

        dc_ip = target_range.split("/")[0] if "/" not in target_range else target_range
        username = creds.get("username", "") if creds else ""
        password = creds.get("password", "") if creds else ""

        ad_result = await ldap_enumerate(dc_ip, ad_domain, username, password)
        results["ad"] = {
            "domain": ad_result.domain,
            "users_count": len(ad_result.users),
            "users": [
                {"username": u.username, "full_name": u.full_name, "admin": u.admin, "spn": u.spn}
                for u in ad_result.users[:50]  # Cap for context
            ],
            "vulnerabilities": ad_result.vulnerabilities,
        }

        # Kerberoasting
        kerberoast_result = await kerberoast(ad_domain, dc_ip, username, password)
        results["kerberoast"] = kerberoast_result

        # AS-REP Roasting
        asrep_result = await asrep_roast(ad_domain, dc_ip)
        results["asrep_roast"] = asrep_result

    # Step 3: Credential testing
    if focus in (None, "all", "credentials") and creds:
        logger.info("Testing credential reuse")
        hosts_to_test = []
        if "hosts" in results:
            hosts_to_test = [h["ip"] for h in results["hosts"][:20]]

        if hosts_to_test:
            spray_result = await spray_passwords(
                hosts=hosts_to_test,
                usernames=[creds["username"]],
                password=creds["password"],
                service="smb",
            )
            results["credential_spray"] = {
                "tested": len(spray_result),
                "valid": [r.host for r in spray_result if r.success],
                "invalid": [r.host for r in spray_result if not r.success],
            }

    # Step 4: Lateral movement (if credentials available)
    if focus in (None, "all", "lateral") and creds and "hosts" in results:
        logger.info("Testing lateral movement paths")
        hosts_to_test = [h["ip"] for h in results["hosts"][:10]]
        if hosts_to_test:
            lateral_result = await multi_service_spray(
                hosts=hosts_to_test,
                username=creds["username"],
                password=creds["password"],
            )
            results["lateral_movement"] = {
                "tested": len(lateral_result),
                "accessible": [r for r in lateral_result if r["success"]],
            }

            # Get SMB shares on accessible hosts
            for host_ip in [r["host"] for r in lateral_result if r["success"] and r["service"] == "smb"]:
                shares = await smb_shares(host_ip, creds["username"], creds["password"])
                if shares.get("shares"):
                    results.setdefault("shares", {})[host_ip] = shares["shares"]

    # Step 5: Internal service enumeration
    if focus in (None, "all", "services") and "services" in results:
        services = results["services"]
        internal_findings = []

        # Check for exposed admin panels
        for svc in services.get("admin_services", []):
            internal_findings.append({
                "type": "exposed_admin_panel",
                "severity": "high",
                "description": f"Admin service at {svc['ip']}:{svc['port']} ({svc['service']})",
                "host": svc["ip"],
                "port": svc["port"],
            })

        # Check for exposed databases
        for svc in services.get("database_services", []):
            internal_findings.append({
                "type": "exposed_database",
                "severity": "critical",
                "description": f"Database at {svc['ip']}:{svc['port']} ({svc['service']})",
                "host": svc["ip"],
                "port": svc["port"],
            })

        results["internal_findings"] = internal_findings
        results["findings_count"] = len(internal_findings)

    # Summary
    results["summary"] = {
        "hosts_discovered": results.get("hosts_discovered", 0),
        "services_found": results.get("services", {}).get("total_hosts", 0),
        "ad_enumerated": "ad" in results,
        "credentials_tested": "credential_spray" in results,
        "lateral_movement": "lateral_movement" in results,
        "findings": results.get("findings_count", 0),
    }

    return json.dumps(results, ensure_ascii=False, default=str)
