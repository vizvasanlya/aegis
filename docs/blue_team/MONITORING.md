# Monitoring — What to Watch

---

## What to Monitor

### 1. Authentication Events

| Event | Why It Matters |
|-------|---------------|
| Failed logins | Brute force attempts |
| Successful logins from unusual locations | Compromised credentials |
| Password changes | Account takeover indicator |
| MFA bypass attempts | Sophisticated attacks |
| New account creation | Persistence mechanism |

### 2. Network Traffic

| Event | Why It Matters |
|-------|---------------|
| Outbound connections to unusual IPs | C2 communication |
| Large data transfers | Data exfiltration |
| Port scanning activity | Reconnaissance |
| DNS queries to known malicious domains | Malware communication |
| Unusual protocol usage | Tunneling attempts |

### 3. System Events

| Event | Why It Matters |
|-------|---------------|
| New processes spawned | Malware execution |
| Registry modifications | Persistence mechanisms |
| Scheduled task creation | Persistence mechanisms |
| Service installation | Persistence mechanisms |
| Driver installation | Rootkit attempts |

### 4. Application Events

| Event | Why It Matters |
|-------|---------------|
| SQL errors in logs | SQL injection attempts |
| XSS payloads in input | XSS attack attempts |
| Unauthorized API calls | API abuse |
| File upload activity | Webshell deployment |
| Error rate spikes | Attack in progress |

---

## Alert Priority Matrix

| Priority | Criteria | Response Time |
|----------|----------|---------------|
| P1 Critical | Active breach, data exfiltration, ransomware | Immediate |
| P2 High | Confirmed compromise, lateral movement | < 1 hour |
| P3 Medium | Suspicious activity, investigation needed | < 4 hours |
| P4 Low | Policy violation, informational | < 24 hours |
| P5 Info | Normal activity, logged for audit | Review weekly |

---

## Dashboards to Maintain

### Security Operations Dashboard
- Total alerts today
- Open incidents
- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- Top attack types this week

### Vulnerability Dashboard
- Critical vulnerabilities open
- Patch compliance rate
- Systems overdue for patching
- New CVEs affecting our stack

### Threat Intelligence Dashboard
- Latest IOCs (Indicators of Compromise)
- Threats relevant to our industry
- Dark web mentions of our organization
- Phishing campaigns targeting our domain
