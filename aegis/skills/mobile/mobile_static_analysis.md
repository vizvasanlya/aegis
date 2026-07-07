---
name: mobile_static_analysis
description: Combined static analysis workflow for mobile applications — manifest/plist review, permission auditing, secret detection
---

# Mobile Static Analysis

Unified static analysis methodology for both Android and iOS applications.

## Automated Analysis Workflow

### Android Static Analysis

```python
from androguard.core.bytecodes.apk import APK
import hashlib
import os

def analyze_apk(apk_path):
    apk = APK(apk_path)
    
    # File hashes
    with open(apk_path, "rb") as f:
        data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
    
    results = {
        "package": apk.get_package(),
        "version": apk.get_androidversion_name(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "sha256": sha256,
        "md5": md5,
        "size": len(data),
        "permissions": list(apk.get_permissions()),
        "activities": list(apk.get_activities()),
        "services": list(apk.get_services()),
        "providers": list(apk.get_providers()),
        "receivers": list(apk.get_receivers()),
        "debuggable": apk.is_debugable(),
        "allow_backup": apk.get_android_manifest_android().get("android:allowBackup", "true"),
    }
    
    # Dangerous permissions
    dangerous = [
        "READ_CONTACTS", "READ_SMS", "ACCESS_FINE_LOCATION", 
        "RECORD_AUDIO", "CAMERA", "READ_EXTERNAL_STORAGE",
    ]
    results["dangerous_permissions"] = [p for p in dangerous if p in str(results["permissions"])]
    
    return results
```

### iOS Static Analysis

```bash
#!/bin/bash
# Analyze IPA
IPA_PATH="$1"
EXTRACT_DIR="/workspace/ipa-analyzed"

unzip -o "$IPA_PATH" -d "$EXTRACT_DIR"
APP_BUNDLE=$(find "$EXTRACT_DIR" -name "*.app" -type d)

# File hashes
sha256sum "$IPA_PATH"
md5sum "$IPA_PATH"

# Read Info.plist
plistutil -i "$APP_BUNDLE/Info.plist" -o /tmp/info.xml
cat /tmp/info.xml

# Check entitlements
codesign -d --entitlements - "$APP_BUNDLE" 2>/dev/null || true

# Search for secrets
strings "$APP_BUNDLE"/* 2>/dev/null | grep -iE "(api.?key|token|secret|password|eyJ[a-Z0-9])" > /tmp/secrets.txt || true
```

## Permission Auditing

### Android Dangerous Permissions
| Permission | Risk |
|------------|------|
| INTERNET | Network access (normal) |
| READ_CONTACTS | Data leakage |
| ACCESS_FINE_LOCATION | Location tracking |
| CAMERA | Privacy violation |
| RECORD_AUDIO | Eavesdropping |
| READ_SMS | Intercept 2FA codes |
| READ_EXTERNAL_STORAGE | File access |

### iOS Permissions (Info.plist keys)
| Key | Risk |
|-----|------|
| NSLocationWhenInUseUsageDescription | Location tracking |
| NSPhotoLibraryUsageDescription | Photo access |
| NSCameraUsageDescription | Camera access |
| NSMicrophoneUsageDescription | Audio recording |
| NSContactsUsageDescription | Contact data |

## Hardcoded Secret Detection

```bash
# General secrets
grep -rE "(?i)(api.?key|api.?secret|access.?token|bearer|jwt|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})" /workspace/decompiled/

# AWS keys
grep -rE "AKIA[0-9A-Z]{16}" /workspace/decompiled/

# Private keys
grep -r "-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----" /workspace/decompiled/
```

## Component Exposure Analysis

### Android — Check exported components
```bash
# Parse AndroidManifest.xml for exported components
grep -E 'android:exported="true"' /workspace/decompiled/AndroidManifest.xml

# Check for intent filters (implicitly exported on some API levels)
grep -A5 '<intent-filter>' /workspace/decompiled/AndroidManifest.xml
```

### iOS — Check URL schemes and app groups
```bash
# Custom URL schemes
/usr/libexec/PlistBuddy -c "Print CFBundleURLTypes" /workspace/info.plist 2>/dev/null

# App groups
/usr/libexec/PlistBuddy -c "Print com.apple.security.application-groups" /workspace/entitlements.plist 2>/dev/null
```
