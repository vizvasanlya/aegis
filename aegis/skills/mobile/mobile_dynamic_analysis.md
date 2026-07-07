---
name: mobile_dynamic_analysis
description: Runtime mobile security analysis — Frida, objection, SSL pinning bypass, runtime manipulation, traffic interception
---

# Mobile Dynamic Analysis

Runtime analysis techniques for mobile applications using Frida, objection, and traffic interception.

## Android Dynamic Analysis

### Prerequisites
- Android emulator or physical device with ADB debugging enabled
- Frida server running on device (`frida-server`)

### Frida Setup

```bash
# Check Frida version matches between host and device
frida --version

# Push frida-server to device
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# List running processes
frida-ps -U
```

### Common Frida Scripts

```javascript
// SSL Pinning Bypass
Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.TrustManager');
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustAllManager = Java.registerClass({
        name: 'com.example.TrustAllManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var sc = SSLContext.getInstance("TLS");
    sc.init(null, [TrustAllManager.$new()], null);
    SSLContext.setDefault(sc);
});

// Root Detection Bypass
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        return false;
    };
});

// Dynamic Class Dump
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf('com.example.app') >= 0) {
                console.log(className);
            }
        },
        onComplete: function() {}
    });
});
```

### Running Frida

```bash
# Bypass SSL pinning + dump all classes
frida -U -l /workspace/frida-scripts/ssl-bypass.js -f com.example.app --no-pause

# Hook a specific method
frida -U -f com.example.app -l /workspace/frida-scripts/hook.js --no-pause
```

### Objection (Frida wrapper)

```bash
# Start objection
objection -g com.example.app explore

# Explore environment
> env
> android hooking list classes
> android hooking list activities

# Bypass
> android sslpinning disable
> android root disable

# Dump data
> android keystore list
> android sqlite dump /data/data/com.example.app/databases/app.db
> android sharedpreferences dump

# Screenshot
> android ui screenshot /workspace/screenshot.png
```

### Traffic Interception (via Caido proxy)

```bash
# Set system proxy on emulator
adb shell settings put global http_proxy host.docker.internal:48080

# Install Caido CA cert on device
adb root
adb remount
adb push /app/certs/ca.crt /system/etc/security/cacerts/  # Or user certs
adb reboot

# Or install user certificate
adb push /app/certs/ca.crt /sdcard/
# On device: Settings → Security → Install from storage
```

## iOS Dynamic Analysis

### Frida on iOS

```bash
# Connect to jailbroken device via SSH
ssh root@<device-ip>

# Start frida-server
./frida-server &

# Back on host
frida -U -f com.example.app -l /workspace/frida-scripts/ios-bypass.js
```

### Objection for iOS

```bash
# Connect to iOS app
objection -g com.example.app explore

# Bypass SSL pinning
> ios sslpinning disable

# Keychain operations
> ios keychain dump
> ios keychain clear

# Info plist
> ios plist cat /var/containers/Bundle/Application/.../Info.plist

# Binary info
> ios info binary
```

## Combined Traffic Analysis

Use Caido proxy for both platforms:

```python
# Python script to intercept and analyze mobile traffic
from caido_api import list_requests, view_request

# Get all captured requests
requests = list_requests(first=100)

# Analyze each for sensitive data leakage
for req in requests:
    req_detail = view_request(req.id, "request")
    resp_detail = view_request(req.id, "response")
    
    # Check for sensitive data in request body
    if req_detail.get("body"):
        body = req_detail["body"]
        if any(kw in body.lower() for kw in ["password", "token", "ssn", "credit"]):
            print(f"ALERT: Sensitive data in request #{req.id}: {req.url}")
    
    # Check response for data leakage
    if resp_detail.get("body"):
        body = resp_detail["body"]
        if "internal" in body.lower() or len(body) > 100000:
            print(f"ALERT: Large response #{req.id}: {len(body)} bytes")
```

## Key Runtime Checks

1. **SSL Pinning**: Can be bypassed?
2. **Root/Jailbreak Detection**: Can be bypassed?
3. **Runtime Integrity**: Is the app tamper-protected?
4. **Debugger Detection**: Does the app detect and respond to debugging?
5. **Emulator Detection**: Does the app block emulator execution?
6. **Screen Capture Protection**: Is `FLAG_SECURE` or equivalent used?
