---
name: ios_overview
description: iOS security model, IPA structure, entitlements, keychain, and common attack surfaces
---

# iOS Security Overview

Guide to iOS application security assessment.

## IPA Structure

An IPA (iOS App Store Package) contains:
- `Payload/<app>.app/` — The application bundle
  - `Info.plist` — App metadata, permissions, configuration
  - `<app>` — Compiled Mach-O executable binary
  - `embedded.mobileprovision` — Provisioning profile
  - `Frameworks/` — Embedded frameworks
  - `PlugIns/` — App extensions
  - `*.lproj/` — Localization resources
  - `Assets.car` — Compiled asset catalog
- `SwiftSupport/` — Swift runtime libraries (App Store distribution only)

## Info.plist Key Elements

```xml
<key>CFBundleURLTypes</key>
<array><dict>
    <key>CFBundleURLSchemes</key>
    <array><string>myapp</string></array>
</dict></array>
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
<key>NSFaceIDUsageDescription</key>
<string>Use Face ID to authenticate</string>
<key>UIBackgroundModes</key>
<array><string>fetch</string></array>
```

## Entitlements

Check embedded entitlements for:
- `com.apple.security.application-groups` — App group access
- `keychain-access-groups` — Keychain sharing
- `com.apple.developer.associated-domains` — Universal links
- `com.apple.developer.nfc.readersession.formats` — NFC access
- `aps-environment` — Push notification environment

## Keychain

- iOS keychain stores sensitive data: passwords, tokens, encryption keys
- Accessible via `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`
- Keychain items have access groups and accessibility classes
- `kSecAttrAccessibleWhenUnlocked` — Accessible when device unlocked
- `kSecAttrAccessibleAfterFirstUnlock` — Accessible after first unlock
- `kSecAttrAccessibleAlways` — Always accessible (most dangerous)

## Common Attack Surfaces

1. **Insecure Data Storage**: NSUserDefaults, CoreData, Plist files, Keychain misconfiguration
2. **Insecure Communication**: ATS bypass, certificate pinning bypass, cleartext HTTP
3. **Insecure Authentication**: Local authentication bypass (LAContext), biometric fallback
4. **Deep Links**: Custom URL schemes, Universal Links without validation
5. **Pasteboard Leakage**: UIPasteboard used for cross-app data sharing
6. **Insecure WebView**: WKWebView with JavaScript enabled, file access
7. **Screenshot Capture**: Application snapshot in app switcher reveals sensitive data
8. **Backgrounding**: Task switching exposes app state
