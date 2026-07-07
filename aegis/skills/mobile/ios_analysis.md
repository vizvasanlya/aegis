---
name: ios_analysis
description: iOS IPA analysis tools — objection, frida, radare2, binary analysis, and entitlements inspection
---

# iOS IPA Analysis

Tools and techniques for analyzing iOS IPA files.

## Tool Setup

Tools pre-installed or installable in sandbox:
- `frida` — Dynamic instrumentation framework
- `objection` — Runtime mobile exploration toolkit
- `radare2` — Binary analysis framework (pre-installed in Kali)

## Static Analysis Workflow

### Step 1: Extract IPA

```bash
# Rename and extract (IPA is a ZIP)
cp target.ipa target.zip
unzip -d /workspace/ipa-extracted/ target.zip
ls /workspace/ipa-extracted/Payload/*.app/
```

### Step 2: Read Info.plist

```bash
# Convert binary plist to XML and read
plistutil -i /workspace/ipa-extracted/Payload/*.app/Info.plist -o /workspace/info.plist
cat /workspace/info.plist

# Extract specific keys
/usr/libexec/PlistBuddy -c "Print CFBundleURLTypes" Payload/*.app/Info.plist
/usr/libexec/PlistBuddy -c "Print NSAppTransportSecurity" Payload/*.app/Info.plist
```

### Step 3: Check Entitlements

```bash
# Extract entitlements from the binary
codesign -d --entitlements - /workspace/ipa-extracted/Payload/*.app/ 2>&1

# Or from the provisioning profile
security cms -D -i Payload/*.app/embedded.mobileprovision > /workspace/provisioning.plist
/usr/libexec/PlistBuddy -c "Print Entitlements" /workspace/provisioning.plist
```

### Step 4: Binary Analysis

```bash
# Check binary architecture
file Payload/*.app/<executable>
# Typically: Mach-O 64-bit executable arm64

# Search for hardcoded strings
strings Payload/*.app/<executable> | grep -iE "(api.?key|token|secret|password|https?://|eyJ)"

# Search for interesting classes
strings Payload/*.app/<executable> | grep -iE "(keychain|password|certificate|pinning|encrypt)"
```

### Step 5: Class Dump (from decrypted binary)

```bash
# Dump Objective-C class information (requires decrypted binary)
class-dump Payload/*.app/<executable>
# Or with radare2
r2 -q -c 'ic' Payload/*.app/<executable>
```

### Step 6: Check for Third-Party SDKs

```bash
# Search for common SDK frameworks
ls -la Payload/*.app/Frameworks/
strings Payload/*.app/<executable> | grep -iE "(Firebase|Adjust|Branch|Flurry|AppsFlyer)"
```

## Key Analysis Points

1. **App Transport Security (ATS)**: Check `NSAllowsArbitraryLoads` and `NSExceptionDomains`
2. **Certificate Pinning**: Search for pinned certificates or public keys in binary
3. **Hardcoded Secrets**: API keys, tokens, passwords in strings/resources
4. **Jailbreak Detection**: Search for "jailbreak", "cydia", "substrate" bypass code
5. **Insecure Data Storage**: Check for NSUserDefaults, CoreData usage patterns
6. **Background Modes**: Check `UIBackgroundModes` for sensitive background operations
