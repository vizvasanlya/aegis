# Incident Response

---

## What Is an Incident?

A security incident is any event that:
- Threatens the confidentiality, integrity, or availability of systems
- Involves unauthorized access to data or systems
- Could result in business disruption or financial loss

**Examples:** Malware infection, data breach, ransomware attack, unauthorized access, DDoS attack, phishing compromise.

---

## The 6 Phases of Incident Response

### Phase 1: Preparation

Before anything happens, be ready.

**Checklist:**
- [ ] Incident response plan documented
- [ ] Contact list for key personnel
- [ ] Communication templates ready
- [ ] Tools and access prepared
- [ ] Team trained on procedures
- [ ] Legal counsel identified
- [ ] Insurance policy reviewed

### Phase 2: Detection and Analysis

Identify that an incident has occurred and understand its scope.

**Detection sources:**
- SIEM alerts
- EDR alerts
- User reports
- Threat intelligence feeds
- Anomaly detection

**Analysis steps:**
1. Validate the alert (is it real or false positive?)
2. Determine scope (how many systems affected?)
3. Classify severity (low, medium, high, critical)
4. Document initial findings
5. Escalate if needed

### Phase 3: Containment

Stop the attack from spreading.

**Short-term containment:**
- Isolate affected systems from network
- Block malicious IPs/domains
- Disable compromised accounts
- Preserve evidence (memory dumps, logs)

**Long-term containment:**
- Apply emergency patches
- Change all passwords
- Implement additional monitoring
- Deploy temporary fixes

### Phase 4: Eradication

Remove the attacker from the environment.

**Steps:**
1. Identify root cause (how did they get in?)
2. Remove malware and backdoors
3. Close the attack vector
4. Verify all attacker presence is gone
5. Scan all systems for indicators of compromise

### Phase 5: Recovery

Restore normal operations.

**Steps:**
1. Restore systems from clean backups
2. Reset all credentials
3. Apply permanent patches
4. Verify system integrity
5. Monitor closely for 30 days
6. Gradually restore services

### Phase 6: Post-Incident Activity

Learn from the incident.

**Steps:**
1. Document timeline of events
2. Conduct post-mortem meeting
3. Identify what worked and what didn't
4. Update detection rules
5. Update incident response plan
6. Report to stakeholders

---

## Severity Classification

| Severity | Description | Response Time | Escalation |
|----------|-------------|---------------|------------|
| **Critical** | Active breach, data exfiltration, ransomware | Immediate | CISO, Legal, CEO |
| **High** | Confirmed compromise, limited scope | < 1 hour | SOC Manager, CISO |
| **Medium** | Suspicious activity, investigation needed | < 4 hours | Security Engineer |
| **Low** | Policy violation, minor issue | < 24 hours | Security Analyst |

---

## Incident Response Playbooks

### Playbook 1: Ransomware

1. **Isolate** — Disconnect affected machines from network (do NOT power off)
2. **Preserve** — Image memory for forensic analysis
3. **Identify** — Determine ransomware variant, check nomoreransom.org
4. **Assess** — What data is encrypted? What's the business impact?
5. **Communicate** — Notify stakeholders, legal, insurance
6. **Restore** — Rebuild from clean backups (if available)
7. **Never pay** — (Organization policy dependent)

### Playbook 2: Phishing Compromise

1. **Validate** — Confirm the phishing email and who clicked
2. **Reset** — Change password for affected account immediately
3. **Check** — Review email for additional phishing attempts
4. **Scan** — Run full antivirus scan on affected machine
5. **Monitor** — Watch for suspicious activity from the account
6. **Educate** — Send awareness email to all employees

### Playbook 3: Data Breach

1. **Contain** — Stop ongoing data access
2. **Assess** — What data was accessed? How much? What type?
3. **Legal** — Notify legal counsel immediately
4. **Notify** — Follow regulatory requirements (GDPR: 72 hours)
5. **Investigate** — Full forensic analysis
6. **Remediate** — Fix the vulnerability that allowed access
7. **Document** — Complete incident report for regulators

---

## Incident Response Kit

Every SOC analyst should have:

| Item | Purpose |
|------|---------|
| Forensic workstation | For analyzing evidence |
| Write-blocker | Prevent accidental evidence modification |
| External hard drives | For evidence preservation |
| Network tap | For passive traffic capture |
| Incident response binder | Printed procedures |
| Contact list | Key personnel phone numbers |
| USB with tools | Forensic utilities |
