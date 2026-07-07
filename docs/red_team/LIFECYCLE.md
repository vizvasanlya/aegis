# Red Team Engagement Lifecycle

Complete end-to-end walkthrough of a real red team engagement with examples.

---

## Scenario: Red Team Engagement for "TechCorp"

TechCorp is a mid-size SaaS company. They hire a red team to test their security.

---

### Pre-Engagement: Rules of Engagement Document

```
RED TEAM ENGAGEMENT — TECHCORP
═══════════════════════════════════════════════

SCOPE:
  IN-SCOPE:
    - All internet-facing assets (*.techcorp.com)
    - Internal network: 10.0.0.0/8
    - Cloud environment: AWS account 123456789
    - GitHub organization: github.com/techcorp
  
  OUT-SCOPE:
    - Personal devices of employees
    - Third-party SaaS (Slack, Google Workspace)
    - Production databases (read-only access only)

OBJECTIVES (in priority order):
  1. Gain domain admin access
  2. Access the customer database
  3. Demonstrate ability to modify billing records

TIMEFRAME:
  - Start: March 1, 2026
  - End: April 15, 2026 (6 weeks)
  - Active testing hours: 6 AM - 10 PM EST only
  - No testing during company-wide maintenance windows

LEGAL:
  - Authorized by: CISO Jane Smith, CEO John Doe
  - Legal approval: Legal team sign-off attached
  - Data handling: No customer PII may be exfiltrated
    (use synthetic/test data for proof only)
  - No destructive actions (no dropping tables, no wiping systems)
  - No social engineering of personal accounts

ESCALATION:
  - Primary: Jane Smith (CISO) — 555-0100
  - Secondary: John Doe (CEO) — 555-0101
  - Emergency (system down): 555-0199 (NOC)

DECONFLICTION:
  - Blue team IS aware (purple team exercise)
  - Blue team can see red team activity in their SIEM
  - Weekly sync calls every Friday at 2 PM

COMMUNICATION:
  - Encrypted channel: Signal group "TechCorp Red Team"
  - Daily status updates via email to CISO
  - Critical findings reported immediately
```

---

### Week 1: Reconnaissance

**Day 1-2: OSINT Collection**

| Source | Intel Gathered |
|--------|---------------|
| LinkedIn | CISO Jane Smith, 3 DevOps engineers, 12 developers |
| GitHub | techcorp org repos, commit patterns, exposed emails |
| Job postings | "Experience with AWS, PostgreSQL, React" — tech stack revealed |
| DNS | 47 subdomains discovered |
| Shodan | VPN server, API endpoints exposed |

**Day 3-4: Infrastructure Mapping**

```
Discovered assets:
  app.techcorp.com     → Cloudflare Pages (React SPA)
  api.techcorp.com     → Railway.app (Node.js API)
  admin.techcorp.com   → Vercel (admin panel)
  vpn.techcorp.com     → OpenVPN server
  mail.techcorp.com    → Google Workspace
  git.techcorp.com     → GitHub Enterprise

Technology stack:
  Frontend: React 18, Next.js 14
  Backend: Node.js, Express, PostgreSQL
  Auth: JWT with RSA-256
  Cloud: AWS (S3, EC2, RDS)
  CI/CD: GitHub Actions
```

**Day 5-7: Vulnerability Discovery**

| Finding | Severity | Location |
|---------|----------|----------|
| Missing rate limiting on login | High | api.techcorp.com/auth/login |
| CORS wildcard on API | Medium | api.techcorp.com |
| GitHub Actions secrets in repo | Critical | github.com/techcorp/app/.github/workflows |
| VPN with weak cipher | Medium | vpn.techcorp.com |

---

### Week 2: Initial Access

**Attack vector: Spear phishing targeting DevOps engineer**

The Phishing Agent generates:
- Email mimicking GitHub security alert
- Landing page cloning GitHub SSO login
- Credential capture on form submission

**Result:** DevOps engineer "Mike Chen" enters GitHub credentials on the fake page.

**What Aegis captures:**
```
Phishing email sent to: mike.chen@techcorp.com
Subject: [GitHub] Security alert: Unusual sign-in activity
Landing page: https://github-security-alert.com/login
Credentials captured: mike.chen@techcorp.com / ********
Time: 2026-03-08 14:32:00 EST
```

---

### Week 3: Execution and Persistence

**Step 1: Access GitHub with stolen credentials**
```
Authenticated as mike.chen@techcorp.com
Accessed repos: techcorp/app, techcorp/infrastructure
Found: AWS access keys in .github/workflows/deploy.yml
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
  AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Step 2: Access AWS environment**
```
AWS Account: 123456789
Region: us-east-1
Accessible services: S3, EC2, RDS, IAM
```

**Step 3: Install persistence**
- Created IAM user "backup-admin" with admin policy
- Added SSH key to existing EC2 instance
- Set up C2 agent on bastion host

---

### Week 4: Privilege Escalation

**Technique: Kerberoasting**

From the compromised EC2 instance, the agent requests service account hashes:
```
Kerberoasting results:
  Service: SQL_svc — Hash cracked: ********
  Service: Backup_svc — Hash cracked: ********
  Service: DomainJoin_svc — Hash not cracked (strong password)
```

**Technique: DCSync**

Using cracked SQL service account:
```
DCSync successful — replicated password hashes for:
  Administrator: ******** (NTLM: 32693b11e6aa90eb43d32c72a07ceea6)
  krbtgt: ******** (enables Golden Ticket creation)
```

---

### Week 5: Objective Achievement

**Objective 1: Domain Admin — ACHIEVED**
```
Domain Admin access confirmed via:
  - Golden Ticket creation
  - Full AD replication
  - Access to all domain resources
```

**Objective 2: Customer Database — ACHIEVED**
```
Connected to RDS instance: techcorp-prod-db.cluster-xxx.us-east-1.rds.amazonaws.com
Database: techcorp_prod
Tables found: users (125,000 rows), orders (890,000 rows), payments (450,000 rows)
Sample data extracted (synthetic, no real PII per ROE):
  users: 10 records with id, email, name, created_at
  orders: 5 records with id, user_id, amount, status
```

**Objective 3: Billing Modification — DEMONSTRATED**
```
Connected to billing microservice via internal API
Modified test record: order #TEST-001 amount changed from $100.00 to $0.01
Reverted change per ROE (no actual data modification allowed)
Evidence: screenshot of before/after + API request/response
```

---

### Week 6: Cleanup and Reporting

**Cleanup checklist:**
- [x] Removed "backup-admin" IAM user
- [x] Removed SSH key from EC2 instance
- [x] Removed C2 agent from bastion host
- [x] Deleted phishing domain and landing page
- [x] Revoked all captured credentials (notified CISO)
- [x] Verified no persistence mechanisms remain

**Report delivered with:**
- Executive summary (1 page for board)
- Technical findings (12 vulnerabilities)
- Attack narrative (timeline)
- MITRE ATT&CK mapping
- Detection gaps
- Remediation recommendations
