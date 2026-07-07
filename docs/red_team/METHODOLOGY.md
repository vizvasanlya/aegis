# Red Team Methodology

Based on the MITRE ATT&CK framework — the industry standard for adversary emulation.

---

## The 8 Phases of a Red Team Engagement

### Phase 1: Pre-Engagement (1-2 weeks before start)

Before any technical work begins, the red team and organization agree on everything in writing.

**Key agreements:**
- Which systems are in bounds vs out of bounds
- What the red team is trying to achieve (specific objectives)
- How long the engagement runs
- Who to call if something breaks
- Whether the blue team knows (purple team) or not (unknown red team)
- Legal boundaries — what's allowed, what's not

**Why this matters:** Without clear rules, a red team can accidentally cause real damage, cross legal boundaries, or test systems they shouldn't touch.

### Phase 2: Reconnaissance (Week 1)

Gather intelligence about the target without touching their systems directly.

**Passive recon (no contact with target):**
- Employee names from LinkedIn, GitHub, job postings
- Email addresses, phone numbers
- Technology stack from job descriptions
- Third-party vendor identification
- Social media analysis of key employees

**Active recon (minimal contact):**
- Port scanning from external IP ranges
- Service fingerprinting
- Web application crawling
- Certificate transparency log analysis
- Shodan/Censys searches for exposed services

**Goal:** Build a complete map of the attack surface before launching any attack.

### Phase 3: Initial Access (Week 1-2)

Get the first foothold inside the organization.

**Most common vectors:**

| Vector | Description | Success Rate |
|--------|-------------|-------------|
| Spear phishing | Targeted emails to specific employees | High |
| Credential stuffing | Try leaked passwords on VPN/email | Medium |
| Public vuln exploitation | Exploit known CVEs on internet-facing services | Medium |
| Supply chain | Compromise a vendor or software dependency | Low but high impact |
| Physical access | Tailgating, badge cloning, USB drops | Low |
| Watering hole | Compromise a website employees visit | Low |

**The phishing path is usually most reliable.** A convincing email with a link typically yields initial access within days.

### Phase 4: Execution and Persistence (Week 2)

Establish a durable presence inside the compromised environment.

**Execution:** Running code on the compromised machine
- Malicious document macros
- PowerShell payloads
- Living-off-the-land binaries (LOLBins)

**Persistence:** Surviving reboots and cleanup
- Registry run keys
- Scheduled tasks
- WMI event subscriptions
- DLL search order hijacking
- Golden tickets (domain persistence)

**Defense evasion:** Avoiding detection
- Encrypting C2 traffic to look like normal HTTPS
- Sleeping between check-ins
- Using legitimate services for C2 (Slack, Teams, cloud storage)
- Process injection into trusted processes

### Phase 5: Privilege Escalation (Week 2-3)

Move from standard user to administrator.

**Local privilege escalation:**
- Unquoted service paths
- Weak file permissions
- Kernel exploits
- Token impersonation

**Domain privilege escalation:**
- Kerberoasting (cracking service account hashes)
- AS-REP roasting (accounts without pre-auth)
- DCSync (replicating domain controller data)
- Pass-the-Hash / Pass-the-Ticket
- GPO abuse

### Phase 6: Lateral Movement (Week 3-4)

Spread across the network from the initial compromised machine.

**Techniques:**
- Using stolen credentials for RDP, SSH, WMI, PSExec
- Exploiting trust relationships between systems
- Moving from on-premises to cloud environments
- Accessing database servers, file shares, email
- Pivoting through jump hosts and bastion servers

### Phase 7: Objective Achievement (Week 4-6)

Demonstrate the agreed-upon business impact.

**Common objectives:**

| Objective | What It Proves |
|-----------|---------------|
| Steal customer database | Data breach impact |
| Access financial systems | Fraud potential |
| Disrupt critical services | Business continuity risk |
| Forge CEO email | Social engineering success |
| Access source code | Intellectual property theft |
| Modify production transaction | Financial manipulation |

### Phase 8: Cleanup and Reporting (Week 6-8)

**Cleanup:**
- Remove all backdoors and persistence
- Delete any accounts created
- Restore modified configurations
- Verify no artifacts remain

**Reporting includes:**
1. Executive summary with business impact
2. Day-by-day timeline of the entire attack
3. Technical findings with CVSS scores
4. MITRE ATT&CK technique mapping
5. Detection gaps identified
6. Prioritized remediation recommendations
