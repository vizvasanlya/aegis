---
name: android_decompilation
description: APK decompilation tools and techniques — apktool, jadx, dex2jar, androguard
---

# Android APK Decompilation

Tools and techniques for reverse engineering Android APK files.

## Tool Setup

All tools are pre-installed in the sandbox:
- `apktool` — APK decoding and rebuilding
- `jadx` — DEX to Java decompiler with GUI
- `dex2jar` — DEX to JAR converter
- `androguard` — Python-based Android analysis framework

## Decompilation Workflow

### Step 1: Extract APK Metadata

```bash
# Get basic APK info
apktool d target.apk -o /workspace/decompiled/
ls /workspace/decompiled/AndroidManifest.xml

# Get package name and version
aapt dump badging target.apk | grep -E "package:|application-label:"
```

### Step 2: Decompile to Java

```bash
# Using jadx (produces readable Java source)
jadx -d /workspace/java-source/ target.apk

# Using jadx with resources
jadx -d /workspace/java-source/ -r target.apk
```

### Step 3: Analyze with androguard

```python
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis

# Load APK
apk = APK("/workspace/target.apk")

# Get package name
print(f"Package: {apk.get_package()}")

# Get all permissions
for perm in apk.get_permissions():
    print(f"Permission: {perm}")

# Get activities, services, providers, receivers
for activity in apk.get_activities():
    print(f"Activity: {activity}")

# Check for debuggable
print(f"Debuggable: {apk.is_debugable()}")

# Check for backup
print(f"Allow Backup: {apk.get_android_manifest_android()['android:allowBackup']}")
```

### Step 4: Extract Strings and Secrets

```bash
# Extract all hardcoded strings
strings /workspace/decompiled/classes.dex | grep -E "(api|key|token|secret|password|jwt|eyJ)" > /workspace/secrets.txt

# Search for URLs and endpoints
grep -rE "https?://[a-zA-Z0-9./_-]+" /workspace/java-source/ > /workspace/endpoints.txt
```

## Key Analysis Points

1. **ProGuard/R8 Obfuscation**: Check if code is obfuscated (class names like `a.b.c`)
2. **Root Detection**: Search for "su", "Superuser", "magisk" in decompiled code
3. **Certificate Pinning**: Search for "pin", "certificate", "PublicKey" in decompiled code
4. **Hardcoded Credentials**: Search for API keys, tokens, passwords in resources and code
5. **Custom Protocols**: Look for custom URL schemes in intent filters
