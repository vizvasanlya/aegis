---
name: android_overview
description: Android security model, APK structure, component analysis, and common attack surfaces
---

# Android Security Overview

Comprehensive guide to Android application security assessment.

## APK Structure

An APK (Android Package Kit) contains:
- `AndroidManifest.xml` — App declaration (binary XML, parsed by apktool)
- `classes.dex` — Dalvik Executable bytecode
- `resources.arsc` — Compiled resources
- `res/` — Raw resources (layouts, drawables, etc.)
- `lib/` — Native libraries (armeabi-v7a, arm64-v8a, x86, x86_64)
- `assets/` — Raw asset files
- `META-INF/` — Signatures and manifest

## AndroidManifest.xml Key Elements

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:allowBackup="true" android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="https" android:host="example.com"/>
            </intent-filter>
        </activity>
        <provider android:name=".FileProvider" android:exported="true"
            android:authorities="com.example.fileprovider"/>
        <service android:name=".BackgroundService" android:exported="true"/>
        <receiver android:name=".BootReceiver" android:exported="true"/>
    </application>
</manifest>
```

## Component Types

1. **Activities** — UI screens. Exported activities can be launched by other apps
2. **Services** — Background processes. Exported services can be bound/started by other apps
3. **Content Providers** — Data storage abstraction. Exported providers allow other apps to read/write data
4. **Broadcast Receivers** — System-wide event listeners. Exported receivers can receive arbitrary broadcasts

## Common Attack Surfaces

- **Exported Components**: Activities, services, providers, receivers with `android:exported="true"`
- **Insecure Data Storage**: SharedPreferences, SQLite databases, internal/external files with world-readable permissions
- **Insecure Communication**: Cleartext HTTP traffic, SSL pinning bypass, WebView with JavaScript enabled
- **Intent Redirection**: Implicit intents that can be intercepted by malicious apps
- **Deep Link Hijacking**: Custom URL schemes and Android App Links without proper verification
- **Tapjacking**: Overlay attacks where malicious apps draw on top of legitimate UI
- **Backup Vulnerabilities**: `android:allowBackup="true"` allows full app data extraction via ADB
- **Debug Mode**: `android:debuggable="true"` exposes debug interfaces
