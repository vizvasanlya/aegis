---
name: internal_overview
description: Internal network testing methodology and overview
---

# Internal Network Testing

Testing from inside the target network — simulating a compromised employee, malicious insider, or guest WiFi pivot.

## How Internal Differs from External

| Aspect | External | Internal |
|--------|----------|----------|
| Starting point | Internet | Inside the corporate network |
| Visible targets | Public-facing apps only | Everything behind the firewall |
| Initial access | Must be gained first | Already have network access |
| Threat model | Internet attacker | Malicious insider, compromised account |

## Internal Testing Phases

1. **Network Discovery** — Find all live hosts and services
2. **Service Enumeration** — Identify what's running on each host
3. **AD Enumeration** — Map Active Directory (users, groups, policies)
4. **Credential Attacks** — Password spraying, hash capture
5. **Privilege Escalation** — Kerberoasting, AS-REP roasting
6. **Lateral Movement** — Pivot across the network
7. **Objective Achievement** — Reach target systems/data

## Key Principle

Internal networks are often less defended than external ones. Services that face the internet get patched and monitored, but internal systems (dev environments, admin panels, databases) are frequently forgotten. The goal is to find and exploit these neglected attack surfaces.
