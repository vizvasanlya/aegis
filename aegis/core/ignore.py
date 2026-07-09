"""File ignore patterns for Aegis scanning (like .gitignore)."""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from typing import Sequence

logger = logging.getLogger(__name__)

# Default patterns to always ignore
DEFAULT_IGNORES = [
    # Version control
    ".git",
    ".git/**",
    # Dependencies
    "node_modules",
    "node_modules/**",
    "vendor",
    "vendor/**",
    ".venv",
    ".venv/**",
    "venv",
    "__pycache__",
    "__pycache__/**",
    # Build artifacts
    "dist",
    "dist/**",
    "build",
    "build/**",
    ".next",
    ".next/**",
    "target",
    "target/**",
    # IDE
    ".idea",
    ".idea/**",
    ".vscode",
    ".vscode/**",
    "*.swp",
    "*.swo",
    # OS
    ".DS_Store",
    "Thumbs.db",
    # Aegis internal
    "aegis_runs",
    "aegis_runs/**",
    ".aegis",
    ".aegis/**",
    # Binary files
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.wasm",
    "*.so",
    "*.dylib",
    "*.dll",
    "*.exe",
    "*.apk",
    "*.ipa",
    "*.aab",
    "*.jar",
    "*.war",
    "*.ear",
    "*.zip",
    "*.tar",
    "*.gz",
    "*.rar",
    "*.7z",
    "*.pdf",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.svg",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
]


def load_ignore_patterns(project_root: Path) -> list[str]:
    """Load ignore patterns from .aegisignore file."""
    patterns = list(DEFAULT_IGNORES)
    ignore_file = project_root / ".aegisignore"

    if ignore_file.exists():
        try:
            content = ignore_file.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
            logger.debug("Loaded %d patterns from .aegisignore", len(patterns) - len(DEFAULT_IGNORES))
        except Exception as exc:
            logger.warning("Failed to read .aegisignore: %s", exc)

    return patterns


def should_ignore(path: Path, project_root: Path, patterns: Sequence[str]) -> bool:
    """Check if a path should be ignored based on patterns."""
    try:
        rel_path = path.relative_to(project_root)
    except ValueError:
        return False

    rel_str = rel_path.as_posix()
    name = path.name

    for pattern in patterns:
        # Match against full relative path
        if fnmatch.fnmatch(rel_str, pattern):
            return True
        # Match against filename
        if fnmatch.fnmatch(name, pattern):
            return True
        # Match against directory name for directory patterns
        if path.is_dir() and fnmatch.fnmatch(name, pattern.rstrip("/")):
            return True

    return False


def filter_ignored(paths: list[Path], project_root: Path, patterns: Sequence[str]) -> list[Path]:
    """Filter out ignored paths from a list."""
    return [p for p in paths if not should_ignore(p, project_root, patterns)]


def get_scannable_files(project_root: Path) -> list[Path]:
    """Get all scannable files in a project, respecting .aegisignore."""
    patterns = load_ignore_patterns(project_root)
    scannable_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb",
        ".php", ".cs", ".swift", ".kt", ".scala", ".clj", ".ex", ".erl",
        ".html", ".css", ".scss", ".less", ".vue", ".svelte",
        ".json", ".yaml", ".yml", ".toml", ".xml", ".env",
        ".sql", ".sh", ".bash", ".ps1", ".bat", ".cmd",
        ".dockerfile", ".tf", ".hcl", ".cfg", ".ini", ".conf",
        ".md", ".txt", ".rst",
    }

    all_files = []
    for ext in scannable_extensions:
        all_files.extend(project_root.rglob(f"*{ext}"))

    # Also include files without extensions that might be config
    for name in ["Dockerfile", "Makefile", "Gemfile", "Rakefile", "Vagrantfile"]:
        all_files.extend(project_root.rglob(name))

    return filter_ignored(all_files, project_root, patterns)
