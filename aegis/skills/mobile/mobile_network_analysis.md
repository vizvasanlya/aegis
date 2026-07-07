---
name: mobile_network_analysis
description: Mobile network traffic analysis — HTTPS interception, certificate pinning bypass, Caido proxy integration, custom protocol analysis
---

# Mobile Network Traffic Analysis

Analyze mobile application network traffic for security vulnerabilities.

## Traffic Interception Setup

### Android with Caido Proxy

```bash
# Method 1: ADB proxy setting (emulator or rooted device)
adb shell settings put global http_proxy 127.0.0.1:48080

# Method 2: Without ADB (use Frida to proxy)
frida -U -f com.example.app -l /workspace/frida-scripts/proxy.js --no-pause
```

```javascript
// Frida proxy script
Java.perform(function() {
    var SystemProperties = Java.use('java.lang.System');
    SystemProperties.setProperty("http.proxyHost", "127.0.0.1");
    SystemProperties.setProperty("http.proxyPort", "48080");
    SystemProperties.setProperty("https.proxyHost", "127.0.0.1");
    SystemProperties.setProperty("https.proxyPort", "48080");
});
```

### iOS with Caido Proxy

```bash
# Method 1: Set proxy via Wi-Fi settings
# Settings → Wi-Fi → (i) → HTTP Proxy → Manual → 127.0.0.1:48080

# Method 2: Frida proxy hook
frida -U -f com.example.app -l /workspace/frida-scripts/ios-proxy.js --no-pause
```

## Certificate Trust Setup

### Android

```bash
# Push Caido CA cert to device
adb push /app/certs/ca.crt /sdcard/Download/
# On device: Settings → Security → Encryption & credentials → Install from storage

# Or for system-level trust (requires root)
adb root
adb remount
adb push /app/certs/ca.crt /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/ca.crt
adb reboot
```

### iOS

```bash
# Install Caido CA cert via Safari (serve from HTTP)
python3 -m http.server 8080 --directory /app/certs/
# On device: Safari → http://<host>:8080/ca.crt → Install

# Then enable full trust:
# Settings → General → About → Certificate Trust Settings → Enable "Testing Root CA"
```

## SSL Pinning Bypass Techniques

### Android Frida Universal Bypass

```javascript
// Universal Android SSL Pinning Bypass
Java.perform(function() {
    // Bypass TrustManager
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrusted, auth, host, client, untrusted2, untrusted3, ocsp, tls) {
        return untrusted;
    };
    
    // Bypass OkHttp3 CertificatePinner
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.pin.implementation = function(pin) {};
    CertificatePinner.check$okhttp.implementation = function(pinned, hashes) {};
    
    // Bypass onCheckServerTrusted
    try {
        var X509TrustManagerExtended = Java.use('javax.net.ssl.X509TrustManager');
        X509TrustManagerExtended.checkServerTrusted.implementation = function(chain, authType) {};
    } catch(e) {}
});
```

### iOS Frida Universal Bypass

```javascript
// Universal iOS SSL Pinning Bypass
if (ObjC.available) {
    // Bypass NSURLSession/URLSession delegate
    var NSURLSession = ObjC.classes.NSURLSession;
    
    // Bypass AFNetworking
    var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
    if (AFSecurityPolicy) {
        AFSecurityPolicy['- setSSLPinningMode:'] = function(mode) {};
        AFSecurityPolicy['- setValidatesDomainName:'] = function(validates) {};
    }
    
    // Bypass TrustKit
    var TrustKit = ObjC.classes.TSKTrustKit;
    if (TrustKit) {
        TrustKit['+ sharedInstance'] = function() { return null; };
    }
}
```

## Traffic Analysis with Caido

```python
from caido_api import list_requests, view_request, list_sitemap, view_sitemap_entry

# Get all captured traffic from mobile app
sitemap = list_sitemap()

# Analyze each endpoint for security issues
for entry in sitemap:
    for request_id in entry.request_ids:
        req = view_request(request_id, "request")
        resp = view_request(request_id, "response")
        
        # Check for cleartext credentials
        if req.get("body") and "password" in req["body"].lower():
            print(f"CLEARTEXT CREDENTIALS: {req.url}")
        
        # Check for missing security headers
        if resp.get("headers"):
            headers = resp["headers"]
            if "Content-Security-Policy" not in headers:
                print(f"MISSING CSP: {req.url}")
        
        # Check for sensitive data in responses
        if resp.get("body") and len(resp["body"]) < 10000:
            for keyword in ["ssn", "credit_card", "token", "secret", "internal"]:
                if keyword in resp["body"].lower():
                    print(f"DATA LEAKAGE ({keyword}): {req.url}")
```

## Automated Security Checks

```python
import json

def analyze_mobile_traffic(proxy_requests):
    findings = []
    
    for req in proxy_requests:
        url = req.get("url", "")
        method = req.get("method", "GET")
        req_body = req.get("body", "")
        resp_body = req.get("response_body", "")
        resp_status = req.get("status_code", 0)
        
        # Cleartext HTTP
        if url.startswith("http://"):
            findings.append({
                "type": "cleartext_http",
                "url": url,
                "severity": "high"
            })
        
        # Sensitive data in URL params
        for param in ["token", "apikey", "password", "secret"]:
            if param in url.lower() and "=" in url:
                findings.append({
                    "type": "sensitive_param_in_url",
                    "param": param,
                    "url": url,
                    "severity": "medium"
                })
        
        # Large data responses
        if len(resp_body) > 50000:
            findings.append({
                "type": "large_response",
                "url": url,
                "size": len(resp_body),
                "severity": "info"
            })
    
    return findings
```

## Key Checks

1. **Cleartext HTTP**: Any requests made over HTTP (not HTTPS)
2. **Certificate Validation**: Can traffic be intercepted without triggering errors?
3. **Data Exfiltration**: Is sensitive data sent to third-party endpoints?
4. **Endpoint Discovery**: What backend APIs does the app communicate with?
5. **Custom Protocols**: Does the app use custom TCP/UDP protocols (WebSocket, gRPC)?
6. **Analytics/Tracking**: What data is sent to analytics SDKs?
