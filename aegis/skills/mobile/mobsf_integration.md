---
name: mobsf_integration
description: MobSF (Mobile Security Framework) integration for automated mobile app security analysis
---

# MobSF Integration

MobSF (Mobile Security Framework) is an automated mobile application security testing
framework capable of static and dynamic analysis for Android, iOS, and Windows apps.

## When to Use MobSF

Use MobSF when you need:
- **Comprehensive static analysis** — deeper and more thorough than manual apktool/jadx inspection
- **OWASP Mobile Top 10 mapping** — MobSF maps findings to OWASP categories
- **Malware detection** — checks APKs against known malware signatures
- **Tracker detection** — identifies analytics and tracking SDKs
- **CVSS scoring** — automated severity assessment for each finding

## Workflow

### 1. Check Connection First
```python
result = mobsf_check_connection()
# Returns {"status": "connected", "api_configured": true}
```

### 2. Upload and Scan
```python
result = mobsf_upload_and_scan(
    app_path="/workspace/target.apk",
    mobsf_url="http://host.docker.internal:8000"
)
# Returns: hash, package_name, permissions, findings, cvss_score, security_score
```

### 3. Get Detailed Report
```python
result = mobsf_get_report(scan_hash="<hash_from_upload>")
# Returns: full JSON report with all findings, code analysis, etc.
```

### 4. Get Security Scorecard
```python
result = mobsf_get_scorecard(scan_hash="<hash>")
# Returns: AppSec scorecard with CVSS score, security score, etc.
```

## Key Findings MobSF Can Detect

### Android
- Insecure WebView (JavaScript enabled, file access)
- Insecure data storage (SQLite, SharedPreferences, internal storage)
- Cleartext traffic (usesCleartextTraffic, ATS bypass)
- Exported components (activities, services, providers)
- Hardcoded secrets (API keys, tokens, passwords)
- Certificate pinning issues
- Root detection bypass
- Debug mode enabled
- Backup flag vulnerabilities
- Deep link hijacking
- Tapjacking vulnerabilities
- Malware signatures
- Third-party trackers

### iOS
- Insecure data storage (NSUserDefaults, CoreData)
- ATS bypass (NSAllowsArbitraryLoads)
- Insecure WebView (UIWebView still in use)
- Pasteboard leakage
- Keychain issues
- URL scheme hijacking
- Binary protections (PIE, ARC, stack canary)
- Insecure random number generation

## Configuration

MobSF must be running as a separate service accessible from the Aegis sandbox.
Either:
1. **Docker**: Run MobSF via `docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest`
2. **Host**: Run MobSF on the host machine, accessible at `http://host.docker.internal:8000`

Set environment variables:
```bash
export AEGIS_MOBSF_URL=http://host.docker.internal:8000
export AEGIS_MOBSF_API_KEY=your_mobsf_api_key
```

The API key is found in MobSF's web UI under `MobSF Menu → API Docs`.
