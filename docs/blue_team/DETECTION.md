# Detection — How to Find Attacks

---

## Detection Stack Overview

```
                    ┌─────────────────┐
                    │   SOC Analyst   │
                    │  (Human Layer)  │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │      SIEM       │
                    │ (Correlation)   │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
    ┌─────▼─────┐     ┌─────▼─────┐     ┌─────▼─────┐
    │    EDR    │     │   Firewall │     │    WAF    │
    │ (Endpoints)│     │ (Network) │     │ (Web Apps)│
    └───────────┘     └───────────┘     └───────────┘
```

---

## Detection Layers

### Layer 1: Endpoint Detection (EDR)

What it monitors: Individual computers and servers

| Tool | Cost | What It Catches |
|------|------|-----------------|
| CrowdStrike Falcon | $5-10/endpoint/year | Malware, lateral movement, persistence |
| Microsoft Defender for Endpoint | Included with M365 | Same as above |
| Wazuh | Free (open source) | Same as above |
| SentinelOne | $5-10/endpoint/year | Same as above |

**What EDR detects:**
- Malware execution
- Unusual process behavior
- Credential dumping attempts
- Lateral movement (PsExec, WMI)
- Registry persistence mechanisms
- Suspicious PowerShell commands

### Layer 2: Network Detection (IDS/IPS)

What it monitors: Network traffic

| Tool | Cost | What It Catches |
|------|------|-----------------|
| Snort | Free (open source) | Known attack signatures |
| Suricata | Free (open source) | Network anomalies, protocols |
| Zeek | Free (open source) | Protocol analysis, logging |
| Palo Alto IDS | $$$$ | Enterprise-grade |

**What network detection catches:**
- Known exploit signatures
- Unusual protocol usage
- Port scanning
- Data exfiltration attempts
- C2 communication patterns

### Layer 3: Web Application Detection (WAF)

What it monitors: Web traffic

| Tool | Cost | What It Catches |
|------|------|-----------------|
| Cloudflare WAF | Free (basic) | OWASP Top 10 attacks |
| ModSecurity | Free (open source) | SQLi, XSS, command injection |
| AWS WAF | $0.60/million requests | Same as above |
| Imperva | $$$$ | Enterprise protection |

**What WAF catches:**
- SQL injection attempts
- Cross-site scripting
- Command injection
- Path traversal
- Known vulnerability exploits

### Layer 4: SIEM (Correlation Engine)

What it does: Collects logs from all sources and correlates them into alerts

| Tool | Cost | Capability |
|------|------|-----------|
| Splunk | $$$$ | Enterprise SIEM |
| Elastic SIEM | Free (basic) | Log analysis, detection rules |
| Microsoft Sentinel | $$$$ | Cloud-native SIEM |
| Wazuh | Free | SIEM + EDR combined |
| Graylog | Free (open source) | Log management |

**How SIEM works:**
1. Collect logs from firewalls, servers, applications, EDR
2. Parse and normalize the data
3. Apply detection rules
4. Correlate events across sources
5. Generate alerts for analysts

---

## Detection Rules Examples

### Rule 1: Brute Force Detection

```
WHEN:
  More than 5 failed login attempts
  FROM the same source IP
  TO the same account
  WITHIN 5 minutes

THEN:
  ALERT: Potential brute force attack
  SEVERITY: High
  ACTION: Block IP for 30 minutes
```

### Rule 2: Lateral Movement Detection

```
WHEN:
  A new process (PsExec, WMI, SSH)
  FROM a workstation
  TO another workstation
  OUTSIDE normal working hours

THEN:
  ALERT: Potential lateral movement
  SEVERITY: Critical
  ACTION: Isolate endpoint, investigate
```

### Rule 3: Data Exfiltration Detection

```
WHEN:
  Outbound data transfer > 100MB
  TO an external IP
  NOT in approved cloud services list

THEN:
  ALERT: Potential data exfiltration
  SEVERITY: Critical
  ACTION: Block transfer, investigate
```

### Rule 4: Privilege Escalation Detection

```
WHEN:
  A new administrator account created
  OR
  User added to "Domain Admins" group

THEN:
  ALERT: Potential privilege escalation
  SEVERITY: High
  ACTION: Verify with IT, log for audit
```

---

## Detection Maturity Levels

| Level | Description | Example |
|-------|-------------|---------|
| Level 0 | No detection | Attacks go unnoticed |
| Level 1 | Basic logging | Logs exist but nobody reads them |
| Level 2 | Rule-based detection | Known patterns trigger alerts |
| Level 3 | Behavioral detection | Anomalies from baseline trigger alerts |
| Level 4 | Threat hunting | Proactive search for hidden threats |
| Level 5 | Automated response | Systems auto-block detected threats |

Most organizations are at Level 1-2. The goal is to reach Level 3-4.
