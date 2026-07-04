---
name: supply_chain
description: Supply chain security analysis - dependency scanning, vulnerability checking, and risk assessment
---

# Supply Chain Analysis

Analyze dependencies for known vulnerabilities, outdated packages, and security risks.

## Capabilities

1. **Dependency Scanning** - Check npm/pip/maven for vulnerabilities
2. **Version Analysis** - Identify outdated packages
3. **License Compliance** - Check for problematic licenses
4. **Risk Assessment** - Evaluate dependency risk
5. **Malware Detection** - Identify suspicious packages

## Dependency Scanning

### Python (pip)

```python
import subprocess
import json

def scan_python_dependencies(project_path: str) -> dict:
    """Scan Python dependencies for vulnerabilities."""
    results = {"vulnerabilities": [], "outdated": [], "evidence": []}
    
    # Method 1: Safety check
    try:
        output = subprocess.run(
            ["pip-audit", "-r", f"{project_path}/requirements.txt", "--json"],
            capture_output=True, text=True, timeout=60
        )
        
        if output.returncode == 0:
            vulns = json.loads(output.stdout)
            for vuln in vulns:
                results["vulnerabilities"].append({
                    "package": vuln["name"],
                    "version": vuln["version"],
                    "vulnerability": vuln["vulnerability_id"],
                    "severity": vuln.get("severity", "unknown"),
                    "fix": vuln.get("fix_versions", [])
                })
    except FileNotFoundError:
        results["evidence"].append("pip-audit not installed")
    
    # Method 2: Check for known vulnerable packages
    known_vulnerable = {
        "django": {"<3.2": "CVE-2021-33203"},
        "flask": {"<2.0": "CVE-2023-30861"},
        "requests": {"<2.31.0": "CVE-2023-32681"},
        "urllib3": {"<1.26.18": "CVE-2023-45803"},
    }
    
    # Parse requirements.txt
    try:
        with open(f"{project_path}/requirements.txt", "r") as f:
            for line in f:
                if "==" in line:
                    pkg, version = line.strip().split("==")
                    pkg = pkg.lower()
                    
                    if pkg in known_vulnerable:
                        for vuln_version, cve in known_vulnerable[pkg].items():
                            if version.startswith(vuln_version.replace("<", "")):
                                results["vulnerabilities"].append({
                                    "package": pkg,
                                    "version": version,
                                    "vulnerability": cve,
                                    "severity": "high"
                                })
    except FileNotFoundError:
        results["evidence"].append("No requirements.txt found")
    
    return results
```

### JavaScript (npm)

```python
def scan_javascript_dependencies(project_path: str) -> dict:
    """Scan JavaScript dependencies for vulnerabilities."""
    results = {"vulnerabilities": [], "outdated": [], "evidence": []}
    
    # Method 1: npm audit
    try:
        output = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=project_path,
            capture_output=True, text=True, timeout=60
        )
        
        if output.stdout:
            audit_data = json.loads(output.stdout)
            for vuln in audit_data.get("vulnerabilities", {}).values():
                results["vulnerabilities"].append({
                    "package": vuln.get("name", "unknown"),
                    "severity": vuln.get("severity", "unknown"),
                    "vulnerability": vuln.get("via", ["unknown"])[0] if vuln.get("via") else "unknown",
                    "fix": vuln.get("fixAvailable", False)
                })
    except FileNotFoundError:
        results["evidence"].append("npm not installed")
    
    # Method 2: Check package.json
    try:
        with open(f"{project_path}/package.json", "r") as f:
            pkg_json = json.load(f)
            
            deps = pkg_json.get("dependencies", {})
            dev_deps = pkg_json.get("devDependencies", {})
            
            all_deps = {**deps, **dev_deps}
            
            # Check for known vulnerable packages
            vulnerable_patterns = {
                "lodash": "Prototype pollution",
                "minimist": "Prototype pollution",
                "node-fetch": "Open redirect",
                "axios": "SSRF",
                "express": "Various",
            }
            
            for pkg in vulnerable_patterns:
                if pkg in all_deps:
                    results["evidence"].append(
                        f"Check {pkg}: {vulnerable_patterns[pkg]}"
                    )
    except FileNotFoundError:
        results["evidence"].append("No package.json found")
    
    return results
```

### Go Modules

```python
def scan_go_dependencies(project_path: str) -> dict:
    """Scan Go dependencies for vulnerabilities."""
    results = {"vulnerabilities": [], "outdated": [], "evidence": []}
    
    # Method 1: govulncheck
    try:
        output = subprocess.run(
            ["govulncheck", "-json", "./..."],
            cwd=project_path,
            capture_output=True, text=True, timeout=120
        )
        
        if output.stdout:
            vulns = json.loads(output.stdout)
            for vuln in vulns.get("vulns", []):
                results["vulnerabilities"].append({
                    "package": vuln.get("osv", {}).get("package", {}).get("name", "unknown"),
                    "vulnerability": vuln.get("osv", {}).get("id", "unknown"),
                    "severity": vuln.get("osv", {}).get("database_specific", {}).get("severity", "unknown"),
                    "affected": vuln.get("affected", [])
                })
    except FileNotFoundError:
        results["evidence"].append("govulncheck not installed")
    
    return results
```

## Version Analysis

### Outdated Package Detection

```python
def check_outdated_packages(project_path: str, ecosystem: str) -> list[dict]:
    """Check for outdated packages."""
    outdated = []
    
    if ecosystem == "python":
        try:
            output = subprocess.run(
                ["pip", "list", "--outdated", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if output.stdout:
                outdated = json.loads(output.stdout)
        except:
            pass
    
    elif ecosystem == "javascript":
        try:
            output = subprocess.run(
                ["npm", "outdated", "--json"],
                cwd=project_path,
                capture_output=True, text=True, timeout=60
            )
            if output.stdout:
                outdated_data = json.loads(output.stdout)
                outdated = [
                    {
                        "package": pkg,
                        "current": info.get("current"),
                        "wanted": info.get("wanted"),
                        "latest": info.get("latest")
                    }
                    for pkg, info in outdated_data.items()
                ]
        except:
            pass
    
    return outdated
```

## License Compliance

### License Scanning

```python
def scan_licenses(project_path: str, ecosystem: str) -> dict:
    """Scan dependencies for license issues."""
    results = {"licenses": [], "issues": [], "evidence": []}
    
    # Problematic licenses
    problematic = [
        "GPL-3.0", "AGPL-3.0", "SSPL",  # Strong copyleft
        "CC-BY-NC-4.0",  # Non-commercial
        "CC-BY-ND-4.0",  # No derivatives
    ]
    
    if ecosystem == "python":
        try:
            output = subprocess.run(
                ["pip-licenses", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if output.stdout:
                licenses = json.loads(output.stdout)
                for pkg in licenses:
                    license_name = pkg.get("License", "Unknown")
                    results["licenses"].append({
                        "package": pkg["Name"],
                        "license": license_name
                    })
                    
                    if any(prob in license_name for prob in problematic):
                        results["issues"].append({
                            "package": pkg["Name"],
                            "license": license_name,
                            "issue": "Potentially problematic license"
                        })
        except:
            pass
    
    return results
```

## Risk Assessment

### Dependency Risk Scoring

```python
def assess_dependency_risk(dependency: dict) -> dict:
    """Assess risk score for a dependency."""
    risk_score = 0
    risk_factors = []
    
    # Factor 1: Vulnerability count
    vuln_count = dependency.get("vulnerability_count", 0)
    if vuln_count > 0:
        risk_score += vuln_count * 10
        risk_factors.append(f"{vuln_count} known vulnerabilities")
    
    # Factor 2: Age of last update
    last_update = dependency.get("last_update_days", 0)
    if last_update > 365:
        risk_score += 20
        risk_factors.append(f"Last updated {last_update} days ago")
    elif last_update > 180:
        risk_score += 10
        risk_factors.append(f"Last updated {last_update} days ago")
    
    # Factor 3: Maintenance status
    if dependency.get("stars", 0) < 100:
        risk_score += 15
        risk_factors.append("Low community adoption")
    
    if dependency.get("open_issues", 0) > 50:
        risk_score += 10
        risk_factors.append("Many open issues")
    
    # Factor 4: License risk
    if dependency.get("license") in ["GPL-3.0", "AGPL-3.0"]:
        risk_score += 25
        risk_factors.append("Copyleft license")
    
    # Factor 5: Supply chain indicators
    if dependency.get("typosquatting_suspect", False):
        risk_score += 50
        risk_factors.append("Possible typosquatting")
    
    return {
        "risk_score": min(risk_score, 100),
        "risk_level": "high" if risk_score > 50 else "medium" if risk_score > 25 else "low",
        "risk_factors": risk_factors
    }
```

## Malware Detection

### Typosquatting Detection

```python
def detect_typosquatting(package_name: str, ecosystem: str) -> dict:
    """Detect potential typosquatting attacks."""
    results = {"suspicious": False, "evidence": []}
    
    # Common typosquatting patterns
    patterns = [
        (r"^(.)\1+$", "Repeated characters"),
        (r".*[-_].*[-_].*", "Multiple separators"),
        (r".*(js|ts|py|go)$", "Suffix adding"),
        (r"^popular-.*$", "Prefix adding"),
    ]
    
    for pattern, description in patterns:
        if re.match(pattern, package_name):
            results["suspicious"] = True
            results["evidence"].append(f"Pattern: {description}")
    
    # Check similarity to popular packages
    popular_packages = [
        "requests", "flask", "django", "express", "react",
        "lodash", "axios", "webpack", "babel", "jest"
    ]
    
    from difflib import SequenceMatcher
    
    for popular in popular_packages:
        similarity = SequenceMatcher(None, package_name.lower(), popular.lower()).ratio()
        if 0.8 < similarity < 1.0:
            results["suspicious"] = True
            results["evidence"].append(
                f"Similar to '{popular}' (similarity: {similarity:.2f})"
            )
    
    return results
```

### Backdoor Detection

```python
def detect_suspicious_patterns(code: str) -> dict:
    """Detect suspicious code patterns that might indicate backdoors."""
    results = {"suspicious": False, "patterns": []}
    
    suspicious_patterns = [
        (r"eval\s*\(", "eval() usage"),
        (r"exec\s*\(", "exec() usage"),
        (r"__import__\s*\(", "Dynamic import"),
        (r"subprocess\.call.*shell\s*=\s*True", "Shell command execution"),
        (r"os\.system\s*\(", "System command execution"),
        (r"requests\.get\s*\(['\"]https?://(?!example\.com)", "External HTTP request"),
        (r"base64\.b64decode", "Base64 decoding (possible obfuscation)"),
    ]
    
    for pattern, description in suspicious_patterns:
        if re.search(pattern, code):
            results["suspicious"] = True
            results["patterns"].append(description)
    
    return results
```

## Integration with Aegis

### Workflow

1. **Identify Ecosystem** - Python, JavaScript, Go, etc.
2. **Scan Dependencies** - Check for vulnerabilities
3. **Check Versions** - Find outdated packages
4. **Analyze Licenses** - Identify compliance issues
5. **Assess Risk** - Score dependency risk
6. **Detect Malware** - Check for typosquatting/backdoors
7. **Report** - Document all findings

### Example Usage

```python
from aegis.tools.supply_chain import (
    scan_python_dependencies,
    detect_typosquatting,
    assess_dependency_risk
)

# Scan Python project
vulns = scan_python_dependencies("/workspace/project")

# Check specific package
typosquat = detect_typosquatting("requets", "python")
if typosquat["suspicious"]:
    print(f"Possible typosquatting: {typosquat['evidence']}")

# Assess risk
risk = assess_dependency_risk({
    "name": "old-package",
    "vulnerability_count": 3,
    "last_update_days": 500,
    "stars": 50
})
print(f"Risk level: {risk['risk_level']}")
```

## Integration with CI/CD

```yaml
# GitHub Actions
- name: Scan dependencies
  run: |
    pip install pip-audit safety
    aegis-scan --supply-chain ./src
    
# Fail on high-severity vulnerabilities
- name: Check for critical vulns
  run: |
    if aegis-scan --severity critical; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

## Best Practices

1. **Scan regularly** - Run supply chain checks in CI/CD
2. **Pin versions** - Use exact version pins in production
3. **Review new dependencies** - Check before adding
4. **Monitor for vulnerabilities** - Subscribe to security advisories
5. **Use lock files** - Ensure reproducible builds
