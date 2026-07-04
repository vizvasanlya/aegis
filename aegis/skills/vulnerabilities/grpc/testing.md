---
name: grpc_testing
description: gRPC security testing - reflection, authentication bypass, injection
---

# gRPC Security Testing

Test gRPC services for vulnerabilities including reflection abuse, authentication bypass, and injection attacks.

## gRPC Attack Vectors

### 1. Server Reflection Abuse

Extract service definitions without authentication:

```python
import grpc
from grpc_reflection.v1alpha import reflection

def test_grpc_reflection(target: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    try:
        channel = grpc.insecure_channel(target)
        stub = reflection.ServerReflectionStub(channel)
        
        # Request service list
        request = reflection.ServerReflectionRequest(
            list_services=reflection.ServiceRequest()
        )
        
        response = stub.ServerReflectionInfo(iter([request]))
        for resp in response:
            if hasattr(resp, 'list_services_response'):
                services = resp.list_services_response.service
                results["vulnerable"] = True
                results["evidence"].append(f"Exposed services: {[s.name for s in services]}")
        
        channel.close()
    except Exception as e:
        results["evidence"].append(f"Reflection error: {str(e)}")
    
    return results
```

### 2. Authentication Bypass

Test gRPC methods without authentication:

```python
def test_grpc_auth_bypass(target: str, service_name: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    try:
        channel = grpc.insecure_channel(target)
        
        # Create dynamic stub
        from grpc_tools import protoc
        import importlib
        
        # Try common methods without auth
        methods = [
            "GetUser",
            "ListUsers",
            "DeleteUser",
            "AdminAction",
        ]
        
        for method in methods:
            try:
                # Generic call without auth metadata
                response = channel.unary_unary(
                    f"/{service_name}/{method}",
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x,
                )
                results["vulnerable"] = True
                results["evidence"].append(f"Method {method} accessible without auth")
            except grpc.RpcError as e:
                if "UNAUTHENTICATED" not in str(e):
                    results["evidence"].append(f"Method {method}: {e.code()}")
        
        channel.close()
    except Exception as e:
        results["evidence"].append(f"Error: {str(e)}")
    
    return results
```

### 3. Injection Attacks

Test gRPC parameters for injection:

```python
def test_grpc_injection(target: str, service_name: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    injection_payloads = [
        # SQL injection
        {"query": "' OR '1'='1"},
        # Command injection
        {"command": "; ls -la"},
        # Path traversal
        {"path": "../../../etc/passwd"},
        # NoSQL injection
        {"filter": '{"$gt": ""}'},
    ]
    
    try:
        channel = grpc.insecure_channel(target)
        
        for payload in injection_payloads:
            try:
                # Test with injection payload
                response = channel.unary_unary(
                    f"/{service_name}/Search",
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x,
                )
                results["evidence"].append(f"Tested: {str(payload)[:50]}")
            except grpc.RpcError as e:
                if "INTERNAL" in str(e.code()):
                    results["vulnerable"] = True
                    results["evidence"].append(f"Internal error with payload: {str(payload)[:50]}")
        
        channel.close()
    except Exception as e:
        results["evidence"].append(f"Error: {str(e)}")
    
    return results
```

### 4. Message Size DoS

Test for denial of service via large messages:

```python
def test_grpc_message_size(target: str, service_name: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    sizes = [1024, 10240, 102400, 1048576, 10485760]  # 1KB to 10MB
    
    try:
        channel = grpc.insecure_channel(target)
        
        for size in sizes:
            try:
                large_message = "A" * size
                response = channel.unary_unary(
                    f"/{service_name}/Process",
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x,
                )
                results["evidence"].append(f"Accepted {size} byte message")
            except grpc.RpcError as e:
                if "RESOURCE_EXHAUSTED" in str(e.code()):
                    results["evidence"].append(f"Rejected at {size} bytes (proper limit)")
                break
        
        channel.close()
    except Exception as e:
        results["evidence"].append(f"Error: {str(e)}")
    
    return results
```

### 5. TLS Downgrade

Test for TLS configuration weaknesses:

```python
def test_grpc_tls(target: str) -> dict:
    results = {"vulnerable": False, "evidence": []}
    
    # Test insecure channel
    try:
        channel = grpc.insecure_channel(target)
        # If this works, TLS is not enforced
        results["vulnerable"] = True
        results["evidence"].append("Insecure channel accepted (no TLS)")
        channel.close()
    except Exception as e:
        results["evidence"].append(f"Insecure channel rejected: {str(e)}")
    
    # Test with weak TLS
    try:
        credentials = grpc.ssl_channel_credentials()
        channel = grpc.secure_channel(target, credentials)
        results["evidence"].append("TLS channel created")
        channel.close()
    except Exception as e:
        results["evidence"].append(f"TLS error: {str(e)}")
    
    return results
```

## gRPC Vulnerability Checklist

| Vulnerability | Risk | Test |
|---------------|------|------|
| Server Reflection | Medium | Query service list |
| Missing Authentication | High | Call methods without auth |
| Injection Attacks | High | Send malicious payloads |
| Message Size DoS | Medium | Send large messages |
| TLS Not Enforced | High | Connect without TLS |
| Weak TLS Configuration | Medium | Test TLS versions |

## Integration with Aegis

Add to **Category 8 - API Security**:
- [ ] Test gRPC reflection
- [ ] Test authentication bypass
- [ ] Test injection vulnerabilities
- [ ] Test message size limits
- [ ] Test TLS configuration

## Remediation

1. Disable server reflection in production
2. Require authentication for all methods
3. Validate and sanitize all inputs
4. Implement message size limits
5. Enforce TLS with strong ciphers
6. Use mutual TLS for service-to-service communication
