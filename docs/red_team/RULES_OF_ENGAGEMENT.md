# Rules of Engagement

How to set up, manage, and document a red team engagement.

---

## What Is a Rules of Engagement (ROE) Document

A legally binding agreement between the red team and the target organization that defines exactly what will happen during the engagement. Without it, red team activities can be illegal.

---

## Required Sections

### 1. Authorization

```
This engagement is authorized by:

Organization: TechCorp Inc.
Authorized by: Jane Smith, CISO
Legal approval: John Doe, General Counsel
Date of authorization: February 15, 2026
Engagement period: March 1 - April 15, 2026
```

### 2. Scope

**In-scope assets:**
```
Network ranges:
  - 10.0.0.0/8 (internal network)
  - 203.0.113.0/24 (DMZ)

Domains:
  - *.techcorp.com
  - *.techcorp.io

Cloud:
  - AWS Account: 123456789
  - GitHub: github.com/techcorp

Applications:
  - https://app.techcorp.com
  - https://api.techcorp.com
  - https://admin.techcorp.com
```

**Out-of-scope assets:**
```
- Personal devices of employees
- Third-party SaaS (Slack, Google Workspace)
- Customer production databases (read-only access)
- Physical security of non-office locations
```

### 3. Objectives

```
Primary objectives (in priority order):
  1. Gain domain administrator access to Active Directory
  2. Access the customer database and extract sample records
  3. Demonstrate ability to modify billing records

Success criteria:
  - Objective 1: Achieved if red team has Domain Admin credentials
  - Objective 2: Achieved if red team can query customer table
  - Objective 3: Achieved if red team can modify a test record
```

### 4. Timeframe

```
Engagement duration: 6 weeks
Start date: March 1, 2026
End date: April 15, 2026

Active testing windows:
  - Weekdays: 6:00 AM - 10:00 PM EST
  - Weekends: 8:00 AM - 6:00 PM EST
  - No testing during: Company all-hands meetings, maintenance windows

Milestones:
  - Week 1: Reconnaissance complete
  - Week 2: Initial access achieved
  - Week 3: Privilege escalation
  - Week 4: Lateral movement
  - Week 5: Objective achievement
  - Week 6: Cleanup and reporting
```

### 5. Communication

```
Primary channel: Signal group "TechCorp Red Team 2026"
  Members: Red team lead, CISO, CTO

Daily updates:
  - Time: 8:00 PM EST
  - Method: Email to CISO
  - Content: Summary of day's activities, findings, plan for tomorrow

Critical findings:
  - Reported immediately via Signal
  - Includes severity, affected systems, recommended action

Weekly sync:
  - Time: Friday 2:00 PM EST
  - Method: Video call
  - Agenda: Progress review, scope adjustments, risk assessment
```

### 6. Escalation Paths

```
Level 1 — Routine issues:
  Contact: Red team lead
  Phone: 555-0200
  When: Questions about scope, technical issues

Level 2 — Significant findings:
  Contact: CISO Jane Smith
  Phone: 555-0100
  When: Critical vulnerabilities discovered, scope questions

Level 3 — Emergency:
  Contact: CTO John Doe
  Phone: 555-0101
  When: System outage, data breach, legal issues

Level 4 — System down:
  Contact: NOC
  Phone: 555-0199
  When: Production system affected by testing
```

### 7. Legal Boundaries

```
PERMITTED:
  - Port scanning and vulnerability scanning
  - Exploitation of discovered vulnerabilities
  - Social engineering (phishing, vishing) of employees
  - Physical access testing (tailgating, badge cloning)
  - Credential harvesting and reuse
  - Data access for proof (read-only)

PROHIBITED:
  - Data destruction or deletion
  - Modifying production data (except test records)
  - Denial of service attacks
  - Social engineering of personal accounts
  - Testing personal devices
  - Accessing out-of-scope systems
  - Sharing findings with third parties
  - Installing cryptocurrency miners or similar

DATA HANDLING:
  - No customer PII may be exfiltrated
  - Use synthetic/test data for proof only
  - All captured credentials must be securely deleted after engagement
  - Screenshots of sensitive data must be encrypted
```

### 8. Deconfliction

```
Blue team awareness:
  - Blue team IS aware of this engagement (purple team exercise)
  - Blue team can see red team activity in their SIEM
  - Blue team may attempt to detect and respond to red team actions

Deconfliction process:
  - If blue team detects red team activity, they contact CISO
  - CISO contacts red team lead to verify it's part of the engagement
  - If not part of engagement, stop immediately and investigate

Safe words:
  - "CHECKPOINT" — Red team pauses all activity for 1 hour
  - "ABORT" — Red team stops all activity immediately
```

### 9. Deliverables

```
The red team will deliver:

1. Executive Summary (1-2 pages)
   - Business impact assessment
   - Risk rating
   - Key recommendations

2. Technical Report (20-50 pages)
   - Full attack narrative with timeline
   - All findings with CVSS scores
   - MITRE ATT&CK technique mapping
   - Evidence (screenshots, HTTP traffic, PoC code)
   - Detection gaps identified

3. Remediation Plan (5-10 pages)
   - Prioritized fix recommendations
   - Quick wins vs long-term improvements
   - Resource estimates for remediation

4. Presentation (30 minutes)
   - Board-level summary
   - Live demo of critical attack paths
   - Q&A session

Delivery date: April 22, 2026 (1 week after engagement ends)
```

---

## Template: Copy and Customize

```markdown
# RULES OF ENGAGEMENT

## Authorization
Organization: [Company Name]
Authorized by: [Name, Title]
Legal approval: [Name, Title]
Engagement period: [Start Date] to [End Date]

## Scope
[Define in-scope and out-of-scope assets]

## Objectives
[Define specific, measurable objectives]

## Timeframe
[Define testing windows and milestones]

## Communication
[Define channels, cadence, and escalation]

## Legal Boundaries
[Define permitted and prohibited activities]

## Deconfliction
[Define blue team awareness and safe words]

## Deliverables
[Define what will be delivered and when]
```
