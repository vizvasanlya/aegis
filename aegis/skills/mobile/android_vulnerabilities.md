---
name: android_vulnerabilities
description: Android-specific vulnerability classes — insecure storage, WebView issues, intent interception, deep links
---

# Android Vulnerability Testing

Complete testing methodology for Android-specific vulnerabilities.

## 1. Insecure Data Storage

### SharedPreferences
```bash
# Extract SharedPreferences from device/emulator
adb shell cat /data/data/<package>/shared_prefs/*.xml
```
**Check for:** passwords, tokens, credit cards, PII in cleartext

### SQLite Databases
```bash
# Extract and inspect databases
adb shell cat /data/data/<package>/databases/*.db
```
**Check for:** sensitive data stored without encryption

### Internal/External Storage
```bash
# List internal storage files
adb shell ls -la /data/data/<package>/files/
adb shell ls -la /data/data/<package>/
```
**Check for:** world-readable files (mode 644/777), sensitive data in cache

### Logcat Leakage
```bash
# Monitor logs for sensitive data
adb logcat | grep -iE "(password|token|apikey|secret|credit)"
```

## 2. Insecure Communication

### Cleartext Traffic
Check `AndroidManifest.xml` for:
```xml
<application android:usesCleartextTraffic="true">
```
Also check `network_security_config.xml` for cleartext traffic permits.

### SSL/TLS Verification
Search decompiled code for:
- Custom `TrustManager` that trusts all certificates
- `HostnameVerifier` that accepts all hosts
- Disabled SSL checking via `setHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER)`

## 3. WebView Security

```xml
<!-- Dangerous WebView configuration in source -->
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccess(true);
webView.getSettings().setAllowContentAccess(true);
webView.addJavascriptInterface(new Bridge(), "bridge");
```

**Test for:**
- XSS via `loadUrl("javascript:...")`
- File access via `file:///` scheme
- JavaScript interface injection
- DOM storage leakage

## 4. Intent Interception

```java
// Dangerous — implicit intent can be intercepted
Intent intent = new Intent("com.example.CUSTOM_ACTION");
intent.putExtra("token", authToken);
startActivity(intent);
```

**Test for:**
- Implicit intents with sensitive data
- Intent redirection via `getIntent()` without validation
- PendingIntent misuse (immutable vs mutable)

## 5. Deep Link Hijacking

```xml
<!-- Deep link definition in manifest -->
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="myapp" android:host="verify"/>
</intent-filter>
```

**Test for:**
- Custom URL schemes without proper validation
- Missing Android App Links verification
- Deep link parameter injection

## 6. Content Provider Leakage

```bash
# Query exposed content providers
adb shell content query --uri content://com.example.provider/users/
adb shell content query --uri content://com.example.provider/files/
```

**Test for:**
- SQL injection in provider queries
- Path traversal in file providers
- Unauthorized data access via exported providers

## 7. Tapjacking Protection

Check manifest for:
```xml
<activity android:filterTouchesWhenObscured="true">
```

## 8. Backup Vulnerabilities

If `android:allowBackup="true"` (default), full app data can be extracted:
```bash
adb backup -f backup.ab -noapk com.example.app
(echo "yes" | abe unpack backup.ab backup.tar) 2>/dev/null
tar xf backup.tar
```
