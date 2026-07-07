"""Android APK analysis tools — decompilation, manifest parsing, permission audit."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


def _err(name: str, exc: Exception) -> str:
    logger.exception("%s failed", name)
    return json.dumps(
        {"success": False, "error": f"{name} failed: {exc}"},
        ensure_ascii=False,
        default=str,
    )


def _ok(data: Any) -> str:
    return json.dumps({"success": True, "result": data}, ensure_ascii=False, default=str)


def _run(cmd: list[str], timeout: int = 120) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except FileNotFoundError:
        return "NOT_FOUND"


def _extract_manifest_xml(apk_path: str, output_dir: str) -> str | None:
    try:
        result = subprocess.run(
            ["apktool", "d", "-f", "-s", apk_path, "-o", output_dir],
            capture_output=True, text=True, timeout=120,
        )
        manifest_path = Path(output_dir) / "AndroidManifest.xml"
        if manifest_path.exists():
            return manifest_path.read_text(encoding="utf-8", errors="replace")
        return result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return str(e)


def _parse_manifest_quick(apk_path: str) -> dict[str, Any]:
    """Parse key AndroidManifest attributes via aapt/apktool."""
    result = {}
    output = _run(["apktool", "d", "-f", "-s", apk_path, "-o", "/tmp/apktool_out"])
    manifest_file = Path("/tmp/apktool_out/AndroidManifest.xml")
    if manifest_file.exists():
        text = manifest_file.read_text(encoding="utf-8", errors="replace")
        pkg = re.search(r'package="([^"]+)"', text)
        if pkg:
            result["package"] = pkg.group(1)
        version = re.search(r'android:versionName="([^"]+)"', text)
        if version:
            result["version_name"] = version.group(1)
        vcode = re.search(r'android:versionCode="([^"]+)"', text)
        if vcode:
            result["version_code"] = vcode.group(1)
        result["debuggable"] = 'android:debuggable="true"' in text
        result["allow_backup"] = 'android:allowBackup="false"' not in text
        exported = re.findall(r'android:exported="true"', text)
        result["exported_components"] = len(exported)
        activities = re.findall(r'<activity\s+', text)
        services = re.findall(r'<service\s+', text)
        providers = re.findall(r'<provider\s+', text)
        receivers = re.findall(r'<receiver\s+', text)
        result["activities"] = len(activities)
        result["services"] = len(services)
        result["providers"] = len(providers)
        result["receivers"] = len(receivers)
        uses_cleartext = 'android:usesCleartextTraffic="true"' in text
        result["uses_cleartext_traffic"] = uses_cleartext
    return result


def _run_androguard(apk_path: str) -> dict[str, Any]:
    """Use androguard to extract APK metadata if available."""
    try:
        from androguard.core.bytecodes.apk import APK as AndroAPK
        apk = AndroAPK(apk_path)
        return {
            "package": apk.get_package(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": sorted(apk.get_permissions()),
            "activities": sorted(apk.get_activities()),
            "services": sorted(apk.get_services()),
            "providers": sorted(apk.get_providers()),
            "receivers": sorted(apk.get_receivers()),
            "debuggable": apk.is_debugable(),
            "allow_backup": apk.get_android_manifest_android().get("android:allowBackup", "true"),
        }
    except ImportError:
        return {}


@function_tool(timeout=300)
async def analyze_apk(ctx: RunContextWrapper, apk_path: str) -> str:
    """Analyze an Android APK file and return its package metadata, permissions, and component structure.

    Decompiles the APK with apktool and analyzes it with androguard (if available).
    Returns package name, version, permissions, activities, services, providers,
    receivers, debuggable flag, backup flag, and exported component count.

    Args:
        apk_path: Absolute path to the APK file in the sandbox.
    """
    path = Path(apk_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"APK not found: {apk_path}"})
    if not apk_path.endswith(".apk"):
        return json.dumps({"success": False, "error": "File must have .apk extension"})

    try:
        result = _run_androguard(apk_path)
        if not result:
            result = _parse_manifest_quick(apk_path)

        import hashlib
        data = path.read_bytes()
        result["sha256"] = hashlib.sha256(data).hexdigest()
        result["md5"] = hashlib.md5(data).hexdigest()
        result["file_size"] = len(data)

        return _ok(result)
    except Exception as e:
        return _err("analyze_apk", e)


@function_tool(timeout=300)
async def decompile_apk(ctx: RunContextWrapper, apk_path: str, output_dir: str = "/workspace/decompiled") -> str:
    """Decompile an Android APK to Java source code using jadx.

    Extracts Java source code, resources, and AndroidManifest.xml.
    Returns the output directory path and a summary of what was extracted.

    Args:
        apk_path: Absolute path to the APK file in the sandbox.
        output_dir: Directory to write decompiled output (default: /workspace/decompiled).
    """
    path = Path(apk_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"APK not found: {apk_path}"})

    try:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            ["jadx", "-d", str(out), apk_path],
            capture_output=True, text=True, timeout=300,
        )

        java_files = list(out.rglob("*.java"))
        xml_files = list(out.rglob("*.xml"))
        manifest = list(out.rglob("AndroidManifest.xml"))

        return _ok({
            "output_dir": str(out),
            "java_files": len(java_files),
            "xml_files": len(xml_files),
            "has_manifest": len(manifest) > 0,
            "stdout": result.stdout[-2000:] if result.stdout else "",
            "stderr": result.stderr[-2000:] if result.stderr else "",
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"success": False, "error": "Decompilation timed out after 300s"})
    except FileNotFoundError:
        return json.dumps({"success": False, "error": "jadx not found in sandbox"})
    except Exception as e:
        return _err("decompile_apk", e)
