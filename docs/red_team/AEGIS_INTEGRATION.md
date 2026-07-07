# Aegis Integration with Red Team Operations

How Aegis fits into a red team engagement — what it handles and what requires human operators.

---

## Aegis Role in Red Teaming

Aegis is not a replacement for human red teamers. It's an **force multiplier** that handles the tactical, repetitive, and time-consuming work while humans focus on strategic decisions.

---

## What Aegis Handles (Tactical)

### Reconnaissance — Automated

| Task | Aegis Capability | Time Saved |
|------|-----------------|------------|
| Subdomain enumeration | subfinder, httpx | Hours → Minutes |
| Port scanning | nmap, naabu | Hours → Minutes |
| Technology fingerprinting | httpx, wappalyzer | Hours → Minutes |
| Vulnerability scanning | nuclei, sqlmap | Days → Hours |
| Secret detection | gitleaks, trufflehog | Hours → Minutes |

### Exploitation — Semi-Automated

| Task | Aegis Capability | Human Oversight |
|------|-----------------|-----------------|
| Vulnerability discovery | Automated scanning | Verify findings |
| Exploit development | PoC script generation | Review before execution |
| Credential attacks | Brute force, stuffing, JWT analysis | Choose targets |
| Web app exploitation | SQLi, XSS, SSRF, auth bypass | Approve risky payloads |

### Evidence Collection — Automated

| Task | Aegis Capability |
|------|-----------------|
| HTTP traffic capture | Caido proxy integration |
| Screenshots | agent-browser |
| Finding documentation | Structured vulnerability reports |
| MITRE ATT&CK mapping | Automatic technique classification |

---

## What Requires Human Operators (Strategic)

### Decision Points

| Decision | Why AI Can't Decide Alone |
|----------|--------------------------|
| Which lead to pursue | Requires understanding business priorities |
| When to escalate | Requires judgment about risk vs reward |
| Social engineering targets | Requires reading people, not just data |
| Stealth thresholds | Requires understanding defender capabilities |
| Scope boundaries | Requires legal and ethical judgment |

### Social Engineering

| Task | Who Does It |
|------|------------|
| Phishing email approval | Human reviews before sending |
| Phone calls (vishing) | Human makes the calls |
| Physical access | Human enters buildings |
| Impersonation | Human acts as IT support, vendor, etc. |

### Physical Security

| Task | Who Does It |
|------|------------|
| Badge cloning | Human with physical device |
| Lock picking | Human with tools |
| USB drops | Human places devices |
| Tailgating | Human enters secured areas |

---

## Human-AI Collaboration Model

```
┌─────────────────────────────────────────┐
│           HUMAN OPERATOR                │
│  - Strategic decisions                  │
│  - Social engineering                   │
│  - Physical access                      │
│  - Stealth management                   │
│  - Business context                     │
└──────────────────┬──────────────────────┘
                   │ Commands / Approvals
                   v
┌─────────────────────────────────────────┐
│           AEGIS ROOT AGENT              │
│  - Orchestrates child agents            │
│  - Manages attack timeline              │
│  - Coordinates parallel operations      │
│  - Reports to operator                  │
└──────────────────┬──────────────────────┘
                   │ Delegates
    ┌──────────────┼──────────────┐
    v              v              v
┌─────────┐  ┌─────────┐  ┌─────────┐
│ Recon   │  │ Exploit │  │ Report  │
│ Agent   │  │ Agent   │  │ Agent   │
│         │  │         │  │         │
│ nmap    │  │ sqlmap  │  │ CVE     │
│ subfinder│ │ nuclei  │  │ CVSS    │
│ httpx   │  │ ffuf    │  │ MITRE   │
└─────────┘  └─────────┘  └─────────┘
```

---

## Engagement Workflow with Aegis

### Pre-Engagement

```bash
# Configure Aegis with engagement rules
aegis --target https://techcorp.com \
  --redteam \
  --instruction "
    SCOPE: *.techcorp.com, 10.0.0.0/8
    OBJECTIVES: 1) Domain admin 2) Customer DB 3) Billing mod
    ACTIVE HOURS: 6 AM - 10 PM EST
    NO destructive actions
    ESCALATION: CISO 555-0100
  " \
  --notify signal
```

### During Engagement

**Human operator workflow:**

1. **Morning:** Review overnight recon results from Aegis
2. **Planning:** Choose which attack path to pursue
3. **Delegation:** Tell Aegis "focus on VPN brute force" or "test the admin panel"
4. **Monitoring:** Watch Aegis output, approve risky actions
5. **Social engineering:** Make phishing calls, send emails
6. **Evening:** Review day's progress, update objectives

**Aegis autonomous workflow:**

1. **Recon:** Scans target, maps attack surface
2. **Discovery:** Finds vulnerabilities, documents findings
3. **Reporting:** Reports to operator via notifications
4. **Waiting:** Pauses for operator decisions
5. **Execution:** Runs approved attacks, captures evidence

### Post-Engagement

```bash
# Generate final report
aegis --resume techcorp-engagement \
  --instruction "Generate final red team report with MITRE mapping"
```

---

## Configuration for Red Team Mode

### Required Settings

```bash
# LLM for agent intelligence
export AEGIS_LLM="openai/gpt-4o"
export LLM_API_KEY="your-key"

# C2 integration (optional)
export SLIVER_SERVER="your-vps:8888"
export SLIVER_API_KEY="your-key"

# Notifications (optional)
export SLACK_WEBHOOK="https://hooks.slack.com/..."
export NOTIFY_EMAIL="operator@company.com"
```

### Red Team Specific Flags

```bash
--redteam              # Enable red team mode
--stealth              # Use quiet scanning techniques
--max-duration 6w      # Maximum engagement duration
--notify slack         # Send notifications to Slack
--notify-email ops@co.com  # Send email notifications
--objective "domain admin" # Primary objective
```

---

## What Aegis Cannot Do (Limitations)

| Limitation | Workaround |
|-----------|------------|
| Physical access | Human operator handles |
| Phone calls | Human operator handles |
| Long-term social relationships | Human operator handles |
| Real-time tactical judgment | Operator approves via notifications |
| Legal decisions | Human operator handles |
| Business priority decisions | Human operator handles |

---

## Metrics: How Aegis Improves Red Team Efficiency

| Metric | Without Aegis | With Aegis |
|--------|--------------|------------|
| Recon time | 3-5 days | 2-4 hours |
| Vulnerability discovery | 1-2 weeks | 1-2 days |
| Evidence collection | Manual, inconsistent | Automated, structured |
| Report generation | 2-3 days | 2-4 hours |
| Coverage | Operator knowledge-dependent | Systematic, checklist-driven |
| Cost per engagement | $50K-200K | $10K-50K |

Aegis doesn't replace the red team — it makes each team member 3-5x more productive.
