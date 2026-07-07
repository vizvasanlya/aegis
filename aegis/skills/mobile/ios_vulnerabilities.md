---
name: ios_vulnerabilities
description: iOS-specific vulnerability classes — insecure storage, ATS bypass, keychain issues, pasteboard leakage
---

# iOS Vulnerability Testing

Complete testing methodology for iOS-specific vulnerabilities.

## 1. Insecure Data Storage

### NSUserDefaults
```bash
# Extract NSUserDefaults from device
find /var/mobile/Containers/Data/Application -name "*.plist" 2>/dev/null
```
**Check for:** passwords, tokens, sensitive data stored in plaintext

### CoreData / SQLite
```bash
# Find and extract SQLite databases
find /var/mobile/Containers/Data/Application -name "*.sqlite" 2>/dev/null
find /var/mobile/Containers/Data/Application -name "*.db" 2>/dev/null
```

### Keychain Dumping (with objection)
```bash
# Dump all keychain entries
objection -g com.example.app explore
> ios keychain dump
> ios keychain dump --json /workspace/keychain.json
```

### Pasteboard Leakage
```objective-c
// Insecure — data remains on pasteboard
UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
pasteboard.string = @"sensitive-token-123";
```

## 2. Insecure Communication

### ATS Bypass Check
Info.plist contains:
```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

### Certificate Pinning Bypass
```bash
# Bypass pinning with objection
objection -g com.example.app explore
> ios sslpinning disable

# With Frida script
frida -U -f com.example.app -l frida-script.js --no-pause
```

## 3. Local Authentication Bypass

```objective-c
// Insecure LAContext usage
LAContext *context = [[LAContext alloc] init];
NSError *error = nil;
if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
        localizedReason:@"Authenticate" reply:^(BOOL success, NSError *error) {
        if (success) {
            // Grant access without checking fallback
        }
    }];
}
```

**Test for:**
- Biometric authentication without fallback mechanism
- `LAPolicyDeviceOwnerAuthentication` vs `LAPolicyDeviceOwnerAuthenticationWithBiometrics`
- Keychain accessibility class bypass

## 4. Deep Link Hijacking

### Custom URL Schemes
```xml
<key>CFBundleURLTypes</key>
<array><dict>
    <key>CFBundleURLSchemes</key>
    <array><string>myapp</string></array>
</dict></array>
```

**Test:** Open `myapp://sensitive-action?token=ABC123` from another app

### Universal Links
Check `apple-app-site-association` file on the server:
```bash
curl https://example.com/.well-known/apple-app-site-association
```

## 5. Insecure WebView

```objective-c
// Dangerous configuration
WKWebView *webView = [[WKWebView alloc] init];
[webView.configuration.preferences setJavaScriptEnabled:YES];
[webView loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"https://example.com"]]];
```

**Test for:**
- JavaScript enabled in WebView
- `loadHTMLString` with user-controlled data (XSS)
- `evaluateJavaScript` with untrusted input

## 6. Snapshot Protection

Check for:
- `UIApplicationExitsOnSuspend` (prevents backgrounding entirely)
- `applicationDidEnterBackground` clearing sensitive views
- `ignoreSnapshotOnNextApplicationNotification`
