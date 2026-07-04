---
name: network_testing
description: Network protocol security testing - SMB, SSH, RDP, cloud metadata, port scanning
---

# Network Protocol Security Testing

Test network services for vulnerabilities beyond web applications.

## Services to Test

### 1. SMB (Server Message Block)

Test for common SMB vulnerabilities:

```python
import subprocess
import re

def test_smb(target: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Nmap SMB scripts
    scripts = [
        "smb-enum-shares",
        "smb-enum-users",
        "smb-vuln-ms17-010",  # EternalBlue
        "smb-vuln-ms08-067",
        "smb-security-mode",
    ]
    
    for script in scripts:
        cmd = f"nmap -p 445 --script {script} {target}"
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if "VULNERABLE" in output.stdout:
            results["vulnerable"] = True
            results["evidence"].append(f"{script}: VULNERABLE")
        elif "STATE" in output.stdout and "open" in output.stdout:
            results["evidence"].append(f"{script}: SMB open")
    
    return results
```

### 2. SSH (Secure Shell)

Test SSH configuration weaknesses:

```python
def test_ssh(target: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Nmap SSH scripts
    scripts = [
        "ssh-auth-methods",
        "ssh2-enum-algos",
        "ssh-hostkey",
        "ssh-brute",
    ]
    
    for script in scripts:
        cmd = f"nmap -p 22 --script {script} {target}"
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if "password" in output.stdout.lower():
            results["vulnerable"] = True
            results["evidence"].append("SSH allows password authentication")
        
        if "diffie-hellman-group1-sha1" in output.stdout:
            results["vulnerable"] = True
            results["evidence"].append("Weak key exchange algorithm supported")
    
    return results
```

### 3. RDP (Remote Desktop Protocol)

Test RDP security:

```python
def test_rdp(target: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Nmap RDP scripts
    scripts = [
        "rdp-enum-encryption",
        "rdp-vuln-ms12-020",
        "rdp-ntlm-info",
        "rdp-brute",
    ]
    
    for script in scripts:
        cmd = f"nmap -p 3389 --script {script} {target}"
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if "VULNERABLE" in output.stdout:
            results["vulnerable"] = True
            results["evidence"].append(f"{script}: VULNERABLE")
        
        if "NLA" not in output.stdout and "open" in output.stdout:
            results["vulnerable"] = True
            results["evidence"].append("RDP without NLA (Network Level Authentication)")
    
    return results
```

### 4. Cloud Metadata

Test for cloud metadata endpoint access (SSRF exploitation):

```python
import requests

def test_cloud_metadata(target: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # AWS metadata endpoints
    aws_endpoints = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
    ]
    
    # GCP metadata endpoints
    gcp_endpoints = [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
    ]
    
    # Azure metadata endpoints
    azure_endpoints = [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ]
    
    all_endpoints = aws_endpoints + gcp_endpoints + azure_endpoints
    
    for endpoint in all_endpoints:
        try:
            resp = requests.get(endpoint, timeout=5, headers={"Metadata-Flavor": "Google"})
            if resp.status_code == 200:
                results["vulnerable"] = True
                results["evidence"].append(f"Metadata accessible: {endpoint}")
        except:
            pass
    
    return results
```

### 5. DNS Zone Transfer

Test for DNS zone transfer vulnerability:

```python
def test_dns_zone_transfer(target: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    cmd = f"dig @{target} axfr {target}"
    output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if "XFR size" in output.stdout:
        results["vulnerable"] = True
        results["evidence"].append("DNS zone transfer successful")
    
    return results
```

### 6. SSL/TLS Testing

Test for SSL/TLS vulnerabilities:

```python
def test_ssl_tls(target: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Test for weak ciphers
    cmd = f"nmap --script ssl-enum-ciphers -p 443 {target}"
    output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
    for cipher in weak_ciphers:
        if cipher in output.stdout:
            results["vulnerable"] = True
            results["evidence"].append(f"Weak cipher: {cipher}")
    
    # Test for SSLv3
    if "SSLv3" in output.stdout:
        results["vulnerable"] = True
        results["evidence"].append("SSLv3 supported (POODLE vulnerability)")
    
    return results
```

## Network Testing Checklist

| Service | Port | Key Tests |
|---------|------|-----------|
| SMB | 445 | EternalBlue, null sessions, shares |
| SSH | 22 | Auth methods, weak algorithms |
| RDP | 3389 | NLA, encryption, MS12-020 |
| DNS | 53 | Zone transfer, cache poisoning |
| FTP | 21 | Anonymous access, brute force |
| Telnet | 23 | Cleartext credentials |
| SMTP | 25 | Open relay, enumeration |

## Cloud Metadata Testing

| Provider | Endpoint | Risk |
|----------|----------|------|
| AWS | 169.254.169.254/latest/meta-data/ | IAM credentials |
| GCP | metadata.google.internal | Service account tokens |
| Azure | 169.254.169.254/metadata/instance | Managed identity tokens |

## Integration with Aegis

Add to **Category 4 - Server-Side**:
- [ ] Test SMB for EternalBlue
- [ ] Test SSH for weak algorithms
- [ ] Test RDP for NLA bypass
- [ ] Test cloud metadata access
- [ ] Test DNS zone transfer
- [ ] Test SSL/TLS weaknesses

## Remediation

1. Disable SMBv1 ( EternalBlue mitigation)
2. Disable password authentication for SSH
3. Enable NLA for RDP
4. Block metadata endpoints from application servers
5. Disable DNS zone transfers
6. Use TLS 1.2+ with strong ciphers
