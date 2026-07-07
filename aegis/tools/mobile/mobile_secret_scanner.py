"""Mobile secret scanner — searches decompiled mobile apps for hardcoded secrets, API keys, tokens."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


_SECRET_PATTERNS: dict[str, str] = {
    "jwt_token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "api_key": r"(?i)(api[_-]?key|apikey|api_key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
    "access_token": r"(?i)(access[_-]?token|accesstoken)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
    "bearer_token": r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "private_key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "password": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
    "secret_key": r"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{8,})['\"]",
    "firebase_url": r"https://[a-zA-Z0-9_-]+\.firebaseio\.com",
    "supabase_url": r"https://[a-zA-Z0-9_-]+\.supabase\.co",
    "graphql_endpoint": r"https?://[^/]+/graphql",
}


def _err(name: str, exc: Exception) -> str:
    logger.exception("%s failed", name)
    return json.dumps({"success": False, "error": f"{name} failed: {exc}"}, ensure_ascii=False, default=str)


def _ok(data: Any) -> str:
    return json.dumps({"success": True, "result": data}, ensure_ascii=False, default=str)


def _scan_directory(directory: Path) -> list[dict[str, Any]]:
    """Scan a directory for hardcoded secrets matching known patterns."""
    secrets_found = []
    extensions = (".java", ".kt", ".swift", ".m", ".mm", ".xml", ".plist",
                  ".json", ".txt", ".html", ".js", ".ts", ".py", ".gradle",
                  ".properties", ".yml", ".yaml", ".config", ".env")

    for ext in extensions:
        for file_path in directory.rglob(f"*{ext}"):
            if file_path.stat().st_size > 500_000:  # Skip files > 500KB
                continue
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
                for secret_type, pattern in _SECRET_PATTERNS.items():
                    for match in re.finditer(pattern, text):
                        secrets_found.append({
                            "type": secret_type,
                            "file": str(file_path.relative_to(directory)),
                            "match": match.group(0)[:100],
                            "line": text[:match.start()].count("\n") + 1,
                        })
            except (OSError, ValueError):
                continue

    return secrets_found


@function_tool(timeout=300)
async def scan_mobile_secrets(ctx: RunContextWrapper, app_path: str, platform: str = "auto") -> str:
    """Scan a decompiled mobile app directory for hardcoded secrets, API keys, tokens, and credentials.

    Searches Java, Kotlin, Swift, Objective-C, XML, plist, JSON, JS, TS, and config files
    for JWT tokens, API keys, AWS keys, private keys, passwords, Firebase URLs, etc.

    Args:
        app_path: Path to the decompiled app source directory or the APK/IPA file.
        platform: 'android', 'ios', or 'auto' (default: auto).
    """
    path = Path(app_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"Path not found: {app_path}"})

    try:
        scan_dir = path

        # If it's an APK, auto-decompile first
        if app_path.endswith(".apk") or platform == "android" and not path.is_dir():
            out_dir = Path("/tmp/secret_scan_decompiled")
            out_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["jadx", "-d", str(out_dir), app_path],
                capture_output=True, text=True, timeout=300,
            )
            scan_dir = out_dir

        secrets = _scan_directory(scan_dir)

        # Summarize by type
        by_type: dict[str, list[dict[str, Any]]] = {}
        for s in secrets:
            by_type.setdefault(s["type"], []).append(s)

        stats = {t: len(items) for t, items in by_type.items()}

        return _ok({
            "total_secrets_found": len(secrets),
            "by_type": stats,
            "secrets": secrets[:50],  # Limit to top 50
            "scanned_directory": str(scan_dir),
        })
    except FileNotFoundError:
        return json.dumps({"success": False, "error": "jadx not found; install jadx for APK decompilation"})
    except Exception as e:
        return _err("scan_mobile_secrets", e)
