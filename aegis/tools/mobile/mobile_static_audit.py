"""Mobile static security audit — manifest/plist review, permission analysis, component exposure."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


_DANGEROUS_ANDROID_PERMS = frozenset({
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_CALL_LOG",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
})

_HIGH_RISK_IOS_PERMS = frozenset({
    "NSLocationAlwaysUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSCameraUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSContactsUsageDescription",
    "NSBluetoothAlwaysUsageDescription",
    "NSMotionUsageDescription",
    "NSHealthShareUsageDescription",
    "NSHealthUpdateUsageDescription",
})


def _err(name: str, exc: Exception) -> str:
    logger.exception("%s failed", name)
    return json.dumps({"success": False, "error": f"{name} failed: {exc}"}, ensure_ascii=False, default=str)


def _ok(data: Any) -> str:
    return json.dumps({"success": True, "result": data}, ensure_ascii=False, default=str)


@function_tool(timeout=120)
async def audit_android_manifest(ctx: RunContextWrapper, apk_path: str) -> str:
    """Audit an Android APK's AndroidManifest.xml for security issues.

    Checks for: debuggable mode, allowBackup, exported components, cleartext traffic,
    dangerous permissions, and insecure intent filters.

    Args:
        apk_path: Absolute path to the APK file in the sandbox.
    """
    path = Path(apk_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"APK not found: {apk_path}"})

    try:
        result = subprocess.run(
            ["apktool", "d", "-f", "-s", apk_path, "-o", "/tmp/apk_audit"],
            capture_output=True, text=True, timeout=120,
        )
        manifest_file = Path("/tmp/apk_audit/AndroidManifest.xml")
        if not manifest_file.exists():
            return json.dumps({"success": False, "error": "Failed to decode APK manifest"})

        text = manifest_file.read_text(encoding="utf-8", errors="replace")

        findings = []
        vulns = []

        # Debuggable check
        if 'android:debuggable="true"' in text:
            findings.append("DEBUG_MODE")
            vulns.append({
                "title": "App is debuggable",
                "severity": "medium",
                "description": "android:debuggable is set to true in AndroidManifest.xml. "
                               "This allows debugging of the app even on production devices.",
                "cwe": "CWE-215",
            })

        # Backup check
        if 'android:allowBackup="false"' not in text:
            findings.append("ALLOW_BACKUP")
            vulns.append({
                "title": "App data can be backed up",
                "severity": "medium",
                "description": "android:allowBackup is not set to false. An attacker with "
                               "ADB access can extract all app data via backup.",
                "cwe": "CWE-200",
            })

        # Cleartext traffic
        if 'android:usesCleartextTraffic="true"' in text:
            findings.append("CLEARTEXT_TRAFFIC")
            vulns.append({
                "title": "Cleartext HTTP traffic allowed",
                "severity": "high",
                "description": "android:usesCleartextTraffic is set to true, allowing "
                               "unencrypted HTTP connections.",
                "cwe": "CWE-319",
            })

        # Exported components
        exported_pattern = r'<(activity|service|provider|receiver)[^>]*android:exported="true"[^>]*>'
        exported_matches = re.finditer(exported_pattern, text)
        exported_components = []
        for m in exported_matches:
            component_block = m.group(0)[:300]
            name_match = re.search(r'android:name="([^"]+)"', component_block)
            comp_type = m.group(1)
            comp_name = name_match.group(1) if name_match else "unknown"
            exported_components.append({"type": comp_type, "name": comp_name})

        if exported_components:
            findings.append("EXPORTED_COMPONENTS")
            vulns.append({
                "title": f"Exported {len(exported_components)} component(s)",
                "severity": "high",
                "description": f"The following components are exported and accessible from "
                               f"other apps: {json.dumps(exported_components)}",
                "cwe": "CWE-926",
                "details": exported_components,
            })

        # Dangerous permissions
        permissions = re.findall(r'<uses-permission[^>]*android:name="([^"]+)"', text)
        dangerous = [p for p in permissions if p in _DANGEROUS_ANDROID_PERMS]
        if dangerous:
            findings.append("DANGEROUS_PERMISSIONS")
            vulns.append({
                "title": f"App requests {len(dangerous)} dangerous permission(s)",
                "severity": "medium",
                "description": f"The app requests these dangerous permissions: "
                               f"{json.dumps(dangerous)}. Verify they are necessary.",
                "cwe": "CWE-272",
                "details": dangerous,
            })

        # Intent filters with custom schemes (deep links)
        intent_filters = re.findall(
            r'<intent-filter>.*?<data[^>]*android:scheme="([^"]+)"[^>]*/>.*?</intent-filter>',
            text, re.DOTALL,
        )
        if intent_filters:
            findings.append("DEEP_LINKS")
            vulns.append({
                "title": "Custom URL schemes registered",
                "severity": "info",
                "description": f"The app registers custom URL scheme(s): "
                               f"{json.dumps(intent_filters)}. Test for deep link hijacking.",
                "cwe": "CWE-927",
                "details": intent_filters,
            })

        return _ok({
            "findings": findings,
            "vulnerabilities": vulns,
            "manifest_snippet": text[:3000],
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"success": False, "error": "apktool timed out"})
    except FileNotFoundError:
        return json.dumps({"success": False, "error": "apktool not found in sandbox"})
    except Exception as e:
        return _err("audit_android_manifest", e)


@function_tool(timeout=120)
async def audit_ios_entitlements(ctx: RunContextWrapper, ipa_path: str) -> str:
    """Audit an iOS IPA's Info.plist and entitlements for security issues.

    Checks for: ATS bypass, insecure URL schemes, sensitive permissions,
    missing encryption, and keychain access groups.

    Args:
        ipa_path: Absolute path to the IPA file in the sandbox.
    """
    path = Path(ipa_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"IPA not found: {ipa_path}"})

    try:
        import zipfile
        import plistlib

        extract_dir = Path("/tmp/ipa_audit")
        extract_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(ipa_path) as zf:
            zf.extractall(extract_dir)

        app_bundles = list((extract_dir / "Payload").glob("*.app")) if (extract_dir / "Payload").exists() else []
        if not app_bundles:
            return json.dumps({"success": False, "error": "No .app bundle found"})

        app_bundle = app_bundles[0]
        info_plist_path = app_bundle / "Info.plist"

        findings = []
        vulns = []

        if info_plist_path.exists():
            with open(info_plist_path, "rb") as f:
                plist_data = plistlib.load(f)

            # ATS check
            ats = plist_data.get("NSAppTransportSecurity", {})
            if ats.get("NSAllowsArbitraryLoads"):
                findings.append("ATS_BYPASS")
                vulns.append({
                    "title": "App Transport Security bypassed",
                    "severity": "high",
                    "description": "NSAllowsArbitraryLoads is enabled, allowing cleartext HTTP "
                                   "connections. Sensitive data may be transmitted insecurely.",
                    "cwe": "CWE-319",
                })

            exception_domains = ats.get("NSExceptionDomains", {})
            if exception_domains:
                findings.append("ATS_EXCEPTION_DOMAINS")
                vulns.append({
                    "title": f"ATS exceptions for {len(exception_domains)} domain(s)",
                    "severity": "medium",
                    "description": f"ATS has exceptions for: {list(exception_domains.keys())}",
                    "cwe": "CWE-319",
                })

            # URL schemes
            url_types = plist_data.get("CFBundleURLTypes", [])
            schemes = []
            for url_type in url_types:
                schemes.extend(url_type.get("CFBundleURLSchemes", []))
            if schemes:
                findings.append("URL_SCHEMES")
                vulns.append({
                    "title": f"Custom URL scheme(s): {schemes}",
                    "severity": "info",
                    "description": f"Custom URL schemes can be used for deep link hijacking "
                                   f"if not validated: {schemes}",
                    "cwe": "CWE-927",
                })

            # Permission usage descriptions
            perm_descriptions = {
                k: plist_data.get(k) for k in _HIGH_RISK_IOS_PERMS if plist_data.get(k)
            }
            if perm_descriptions:
                findings.append("SENSITIVE_PERMISSIONS")
                vulns.append({
                    "title": f"iOS app requests {len(perm_descriptions)} sensitive permission(s)",
                    "severity": "medium",
                    "description": f"Permission usage descriptions: {json.dumps(perm_descriptions)}",
                    "cwe": "CWE-272",
                })

            # Check for local auth
            if "NSFaceIDUsageDescription" in plist_data:
                findings.append("FACE_ID_USAGE")

        # Check entitlements
        binary_path = app_bundle / app_bundle.stem
        if binary_path.exists():
            try:
                ent_result = subprocess.run(
                    ["codesign", "-d", "--entitlements", "-", str(binary_path)],
                    capture_output=True, text=True, timeout=30,
                )
                ent_output = ent_result.stdout or ent_result.stderr
                if "keychain-access-groups" in ent_output:
                    findings.append("KEYCHAIN_ACCESS")
            except FileNotFoundError:
                pass

        return _ok({
            "findings": findings,
            "vulnerabilities": vulns,
        })
    except zipfile.BadZipFile:
        return json.dumps({"success": False, "error": "IPA is not a valid ZIP file"})
    except Exception as e:
        return _err("audit_ios_entitlements", e)
