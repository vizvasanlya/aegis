---
name: api_fuzzing
description: Automated API fuzzing with schema learning, intelligent payload generation, and response analysis
---

# API Fuzzing Engine

Automated API security testing with schema learning and intelligent fuzzing.

## Capabilities

1. **Schema Learning** - Automatically discover API structure from OpenAPI/Swagger
2. **Intelligent Fuzzing** - Context-aware payload generation
3. **Response Analysis** - Detect vulnerabilities from response patterns
4. **Authentication Testing** - Test auth mechanisms systematically
5. **Business Logic Testing** - Test workflow vulnerabilities

## Schema Learning

### OpenAPI/Swagger Discovery

```python
import requests
import yaml

def discover_api_schema(base_url: str) -> dict:
    """Discover API schema from common endpoints."""
    schema_endpoints = [
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/swagger/v1/swagger.json",
        "/v1/api-docs",
        "/v2/api-docs",
        "/docs",
        "/redoc",
    ]
    
    for endpoint in schema_endpoints:
        resp = requests.get(f"{base_url}{endpoint}", timeout=10)
        if resp.status_code == 200:
            try:
                schema = resp.json()
                if "openapi" in schema or "swagger" in schema:
                    return schema
            except:
                try:
                    schema = yaml.safe_load(resp.text)
                    if "openapi" in schema or "swagger" in schema:
                        return schema
                except:
                    continue
    
    return None
```

### Endpoint Discovery

```python
def discover_endpoints(base_url: str) -> list[dict]:
    """Discover API endpoints through various methods."""
    endpoints = []
    
    # Method 1: Common API paths
    common_paths = [
        "/api", "/api/v1", "/api/v2",
        "/users", "/admin", "/login", "/register",
        "/health", "/status", "/version",
    ]
    
    for path in common_paths:
        resp = requests.get(f"{base_url}{path}", timeout=5)
        if resp.status_code != 404:
            endpoints.append({
                "path": path,
                "method": "GET",
                "status": resp.status_code
            })
    
    # Method 2: JavaScript file analysis
    resp = requests.get(f"{base_url}/static/js/main.js", timeout=10)
    if resp.status_code == 200:
        # Extract API paths from JS
        import re
        paths = re.findall(r'["\'](/api/[^"\']+)["\']', resp.text)
        for path in set(paths):
            endpoints.append({
                "path": path,
                "method": "GET",
                "source": "javascript"
            })
    
    return endpoints
```

## Intelligent Fuzzing

### Payload Generation

```python
def generate_fuzz_payloads(endpoint: dict) -> dict:
    """Generate context-aware fuzz payloads based on endpoint."""
    payloads = {
        "injection": [],
        "auth_bypass": [],
        "data_manipulation": [],
        "error_based": [],
    }
    
    # SQL Injection payloads
    payloads["injection"].extend([
        "' OR '1'='1",
        "' OR '1'='1'--",
        "1' UNION SELECT NULL--",
        "1; DROP TABLE users--",
    ])
    
    # XSS payloads
    payloads["injection"].extend([
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ])
    
    # Authentication bypass
    payloads["auth_bypass"].extend([
        "admin:admin",
        "admin:password",
        "test:test",
        "guest:guest",
    ])
    
    # Data manipulation
    payloads["data_manipulation"].extend([
        "-1", "0", "999999",  # Numeric overflow
        "null", "undefined",  # Type confusion
        "../", "..\\",  # Path traversal
    ])
    
    # Error-based detection
    payloads["error_based"].extend([
        "'",
        "\"",
        "`",
        "\\",
        "%00",
    ])
    
    return payloads
```

### Parameter Fuzzing

```python
def fuzz_parameters(url: str, method: str, params: list[dict]) -> list[dict]:
    """Fuzz individual parameters."""
    findings = []
    
    for param in params:
        param_name = param["name"]
        param_type = param.get("type", "string")
        
        # Generate type-specific payloads
        if param_type == "integer":
            payloads = ["-1", "0", "2147483647", "2147483648", "null"]
        elif param_type == "string":
            payloads = ["", "'", "\"", "<script>", "../", "A" * 1000]
        elif param_type == "email":
            payloads = ["test@test.com", "invalid", "a@b", "a" * 100 + "@test.com"]
        else:
            payloads = ["", "null", "undefined", "test"]
        
        for payload in payloads:
            resp = requests.request(
                method, url,
                params={param_name: payload} if method == "GET" else None,
                json={param_name: payload} if method == "POST" else None,
                timeout=10
            )
            
            # Analyze response
            if resp.status_code == 500:
                findings.append({
                    "type": "server_error",
                    "param": param_name,
                    "payload": payload,
                    "evidence": "Server returned 500"
                })
            elif "error" in resp.text.lower() and len(resp.text) > 100:
                findings.append({
                    "type": "verbose_error",
                    "param": param_name,
                    "payload": payload,
                    "evidence": "Detailed error message leaked"
                })
    
    return findings
```

## Response Analysis

### Error Pattern Detection

```python
def analyze_error_patterns(responses: list[dict]) -> dict:
    """Analyze error patterns for vulnerabilities."""
    results = {"vulnerabilities": [], "evidence": []}
    
    # Pattern 1: Verbose error messages
    verbose_patterns = [
        "stack trace",
        "traceback",
        "line number",
        "internal error",
        "database error",
        "sql syntax",
    ]
    
    for resp in responses:
        body = resp.get("body", "").lower()
        for pattern in verbose_patterns:
            if pattern in body:
                results["vulnerabilities"].append({
                    "type": "information_disclosure",
                    "pattern": pattern,
                    "evidence": resp
                })
    
    # Pattern 2: Different responses for valid/invalid
    status_groups = {}
    for resp in responses:
        status = resp.get("status")
        status_groups.setdefault(status, []).append(resp)
    
    if len(status_groups) > 1:
        results["vulnerabilities"].append({
            "type": "enumeration_possible",
            "evidence": f"Different status codes: {list(status_groups.keys())}"
        })
    
    return results
```

### Timing Analysis

```python
import time

def timing_analysis(url: str, payloads: list[str]) -> dict:
    """Analyze response timing for vulnerabilities."""
    results = {"anomalies": [], "evidence": []}
    
    timings = []
    
    for payload in payloads:
        start = time.time()
        requests.post(url, json={"input": payload}, timeout=10)
        elapsed = time.time() - start
        timings.append({"payload": payload, "time": elapsed})
    
    # Detect timing anomalies
    avg_time = sum(t["time"] for t in timings) / len(timings)
    
    for t in timings:
        if t["time"] > avg_time * 2:
            results["anomalies"].append({
                "payload": t["payload"],
                "time": t["time"],
                "avg_time": avg_time
            })
            results["evidence"].append(
                f"Timing anomaly: {t['time']:.2f}s vs avg {avg_time:.2f}s"
            )
    
    return results
```

## Authentication Testing

### Token Manipulation

```python
import jwt
import base64

def fuzz_jwt(token: str) -> dict:
    """Fuzz JWT tokens for vulnerabilities."""
    results = {"vulnerabilities": [], "evidence": []}
    
    # Decode header
    header = jwt.get_unverified_header(token)
    
    # Test 1: Algorithm confusion
    if header.get("alg") == "HS256":
        # Try RS256 to HS256
        results["evidence"].append("Algorithm: HS256 - test RS256 confusion")
    
    # Test 2: None algorithm
    results["vulnerabilities"].append({
        "type": "algorithm_none",
        "test": "Modify alg to 'none' and remove signature",
        "payload": token.replace(header["alg"], "none")
    })
    
    # Test 3: Weak secret
    common_secrets = ["secret", "password", "123456", "key"]
    for secret in common_secrets:
        try:
            jwt.decode(token, secret, algorithms=["HS256"])
            results["vulnerabilities"].append({
                "type": "weak_secret",
                "secret": secret
            })
            break
        except:
            continue
    
    return results
```

### Authorization Testing

```python
def fuzz_authorization(url: str, token: str, endpoints: list[str]) -> dict:
    """Fuzz authorization mechanisms."""
    results = {"vulnerabilities": [], "evidence": []}
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test 1: No token
    for endpoint in endpoints:
        resp = requests.get(f"{url}{endpoint}", timeout=10)
        if resp.status_code == 200:
            results["vulnerabilities"].append({
                "type": "no_auth_required",
                "endpoint": endpoint
            })
    
    # Test 2: Invalid token
    for endpoint in endpoints:
        resp = requests.get(
            f"{url}{endpoint}",
            headers={"Authorization": "Bearer invalid_token"},
            timeout=10
        )
        if resp.status_code == 200:
            results["vulnerabilities"].append({
                "type": "invalid_token_accepted",
                "endpoint": endpoint
            })
    
    # Test 3: Token in different formats
    formats = [
        token,  # Bearer
        f"Basic {base64.b64encode(token.encode()).decode()}",
        token,  # Raw
    ]
    
    for fmt in formats:
        resp = requests.get(
            f"{url}{endpoints[0]}",
            headers={"Authorization": fmt},
            timeout=10
        )
        if resp.status_code == 200:
            results["vulnerabilities"].append({
                "type": "auth_bypass",
                "format": fmt[:50]
            })
    
    return results
```

## Business Logic Testing

### Workflow Bypass

```python
def fuzz_workflow(url: str, workflow_steps: list[dict]) -> dict:
    """Test workflow bypass vulnerabilities."""
    results = {"vulnerabilities": [], "evidence": []}
    
    # Test skipping steps
    for i, step in enumerate(workflow_steps):
        # Skip this step and try the next
        if i + 1 < len(workflow_steps):
            next_step = workflow_steps[i + 1]
            resp = requests.post(
                f"{url}{next_step['endpoint']}",
                json=next_step.get("data", {}),
                timeout=10
            )
            
            if resp.status_code == 200:
                results["vulnerabilities"].append({
                    "type": "workflow_bypass",
                    "skipped": step["name"],
                    "reached": next_step["name"]
                })
    
    # Test out-of-order execution
    for i in range(len(workflow_steps) - 1, 0, -1):
        step = workflow_steps[i]
        resp = requests.post(
            f"{url}{step['endpoint']}",
            json=step.get("data", {}),
            timeout=10
        )
        
        if resp.status_code == 200:
            results["vulnerabilities"].append({
                "type": "out_of_order_execution",
                "step": step["name"]
            })
    
    return results
```

### Race Conditions

```python
import concurrent.futures

def fuzz_race_condition(url: str, endpoint: str, data: dict, 
                        count: int = 10) -> dict:
    """Test for race conditions."""
    results = {"vulnerabilities": [], "evidence": []}
    
    def make_request():
        return requests.post(f"{url}{endpoint}", json=data, timeout=10)
    
    # Send parallel requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(make_request) for _ in range(count)]
        responses = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    # Analyze responses
    status_codes = [r.status_code for r in responses]
    success_count = sum(1 for s in status_codes if s == 200)
    
    if success_count > 1:
        results["vulnerabilities"].append({
            "type": "race_condition",
            "success_count": success_count,
            "evidence": f"{success_count} parallel requests succeeded"
        })
    
    return results
```

## Integration with Aegis

### Workflow

1. **Schema Discovery** - Find OpenAPI/Swagger specs
2. **Endpoint Enumeration** - Map all API endpoints
3. **Parameter Discovery** - Identify all parameters
4. **Fuzzing** - Test each endpoint/parameter
5. **Analysis** - Detect vulnerabilities from responses
6. **Validation** - Confirm findings with PoCs
7. **Report** - Document all findings

### Example Usage

```python
from aegis.tools.api_fuzzing import (
    discover_api_schema,
    fuzz_parameters,
    analyze_error_patterns
)

# Discover schema
schema = discover_api_schema("https://api.target.com")

# Get endpoints
endpoints = schema.get("paths", {})

# Fuzz each endpoint
for path, methods in endpoints.items():
    for method in methods:
        findings = fuzz_parameters(
            f"https://api.target.com{path}",
            method.upper(),
            methods[method].get("parameters", [])
        )
        
        # Analyze
        if findings:
            analysis = analyze_error_patterns(findings)
            print(f"Vulnerabilities at {path}: {analysis}")
```

## Best Practices

1. **Start with schema** - Use OpenAPI specs for efficient testing
2. **Fuzz systematically** - Test all endpoints and parameters
3. **Analyze responses** - Look for patterns in errors and timing
4. **Validate findings** - Confirm with working PoCs
5. **Document everything** - Maintain audit trail
