"""iOS IPA analysis tools — extraction, Info.plist parsing, entitlements inspection."""

from __future__ import annotations

import json
import logging
import re
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


def _err(name: str, exc: Exception) -> str:
    logger.exception("%s failed", name)
    return json.dumps({"success": False, "error": f"{name} failed: {exc}"}, ensure_ascii=False, default=str)


def _ok(data: Any) -> str:
    return json.dumps({"success": True, "result": data}, ensure_ascii=False, default=str)


def _find_app_bundle(extract_dir: Path) -> Path | None:
    payload = extract_dir / "Payload"
    if not payload.exists():
        return None
    app_bundles = list(payload.glob("*.app"))
    return app_bundles[0] if app_bundles else None


def _parse_info_plist(plist_path: Path) -> dict[str, Any]:
    """Parse Info.plist using plistutil or plistlib."""
    try:
        result = subprocess.run(
            ["plistutil", "-i", str(plist_path), "-o", "/tmp/info_parsed.plist"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            output = Path("/tmp/info_parsed.plist").read_text(encoding="utf-8", errors="replace")
            return _plist_xml_to_dict(output)
    except FileNotFoundError:
        pass

    try:
        import plistlib
        with open(plist_path, "rb") as f:
            return plistlib.load(f)
    except (ImportError, Exception):
        pass

    return {}


def _plist_xml_to_dict(xml: str) -> dict[str, Any]:
    """Basic XML plist to dict conversion."""
    result: dict[str, Any] = {}

    url_schemes = re.findall(r'<string>([a-zA-Z][a-zA-Z0-9+\-.]*)://?.*?</string>', xml)
    if url_schemes:
        result["url_schemes"] = url_schemes

    ats = re.search(r'<key>NSAppTransportSecurity</key>\s*<dict>(.*?)</dict>', xml, re.DOTALL)
    if ats:
        result["ns_app_transport_security"] = {
            "allows_arbitrary_loads": 'NSAllowsArbitraryLoads' in ats.group(1) and 'true' in ats.group(1),
        }

    if 'NSFaceIDUsageDescription' in xml:
        result["face_id_usage"] = True

    if 'NSPhotoLibraryUsageDescription' in xml:
        result["photo_library_usage"] = True

    background_modes = re.findall(r'<string>(audio|fetch|remote-notification|processing|bluetooth-central|bluetooth-peripheral|external-accessory|location)</string>', xml)
    if background_modes:
        result["background_modes"] = background_modes

    return result


def _check_entitlements(app_bundle: Path) -> dict[str, Any]:
    """Extract entitlements from the app binary."""
    entitlements = {}

    binaries = list(app_bundle.glob(app_bundle.stem))
    for binary in binaries[:1]:
        try:
            result = subprocess.run(
                ["codesign", "-d", "--entitlements", "-", str(binary)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                output = result.stdout or result.stderr
                entitlements["raw"] = output[:2000]
                entitlements["has_keychain_access"] = "keychain-access-groups" in output
                entitlements["has_app_groups"] = "application-groups" in output
                entitlements["has_associated_domains"] = "associated-domains" in output
        except FileNotFoundError:
            pass

    return entitlements


@function_tool(timeout=300)
async def analyze_ipa(ctx: RunContextWrapper, ipa_path: str) -> str:
    """Analyze an iOS IPA file and return its metadata, entitlements, and security configuration.

    Extracts the IPA (ZIP format), reads Info.plist for URL schemes, App Transport Security,
    background modes, and permission usage descriptions. Also checks code signing entitlements.

    Args:
        ipa_path: Absolute path to the IPA file in the sandbox.
    """
    path = Path(ipa_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"IPA not found: {ipa_path}"})
    if not ipa_path.endswith(".ipa"):
        return json.dumps({"success": False, "error": "File must have .ipa extension"})

    try:
        import hashlib
        data = path.read_bytes()

        extract_dir = Path("/tmp/ipa_extracted")
        extract_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(ipa_path) as zf:
            zf.extractall(extract_dir)

        app_bundle = _find_app_bundle(extract_dir)
        if not app_bundle:
            return json.dumps({"success": False, "error": "No .app bundle found in IPA"})

        result: dict[str, Any] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "file_size": len(data),
            "app_bundle": str(app_bundle),
        }

        info_plist = app_bundle / "Info.plist"
        if info_plist.exists():
            plist_data = _parse_info_plist(info_plist)
            result["info_plist"] = plist_data

            bundle_id = _get_plist_value(info_plist, "CFBundleIdentifier")
            if bundle_id:
                result["bundle_id"] = bundle_id
            version = _get_plist_value(info_plist, "CFBundleShortVersionString")
            if version:
                result["version"] = version

        entitlements = _check_entitlements(app_bundle)
        if entitlements:
            result["entitlements"] = entitlements

        # Check for embedded provisioning profile
        mobileprovision = app_bundle / "embedded.mobileprovision"
        result["has_provisioning_profile"] = mobileprovision.exists()

        # Check for frameworks
        frameworks_dir = app_bundle / "Frameworks"
        if frameworks_dir.exists():
            result["frameworks"] = [f.name for f in frameworks_dir.iterdir()]

        return _ok(result)
    except zipfile.BadZipFile:
        return json.dumps({"success": False, "error": "IPA is not a valid ZIP file"})
    except Exception as e:
        return _err("analyze_ipa", e)


def _get_plist_value(plist_path: Path, key: str) -> str | None:
    try:
        import plistlib
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
        return str(data.get(key, "")) or None
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["/usr/libexec/PlistBuddy", "-c", f"Print {key}", str(plist_path)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass

    return None
