"""Tool output logging — saves shell command outputs to tool_logs/ directory."""

from __future__ import annotations

import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Maps command prefixes to log file names
_COMMAND_MAP: dict[str, str] = {
    "nmap": "nmap",
    "sqlmap": "sqlmap",
    "nuclei": "nuclei",
    "ffuf": "ffuf",
    "subfinder": "subfinder",
    "httpx": "httpx",
    "katana": "katana",
    "gospider": "gospider",
    "naabu": "naabu",
    "dirsearch": "dirsearch",
    "arjun": "arjun",
    "wafw00f": "wafw00f",
    "hydra": "hydra",
    "crackmapexec": "crackmapexec",
    "enum4linux": "enum4linux",
    "responder": "responder",
    "kerbrute": "kerbrute",
    "impacket-": "impacket",
    "curl": "curl",
    "wget": "wget",
    "python3": "python",
    "pip install": "pip_install",
    "apt-get": "apt",
    "git clone": "git_clone",
    "agent-browser": "agent_browser",
    "semgrep": "semgrep",
    "gitleaks": "gitleaks",
    "trufflehog": "trufflehog",
    "trivy": "trivy",
    "bandit": "bandit",
    "nmap": "nmap",
}

# Counter per tool type to avoid overwriting
_counters: dict[str, int] = {}


def _detect_tool_name(command: str) -> str:
    """Detect which tool is being used from the command string."""
    cmd_lower = command.lower().strip()

    for prefix, tool_name in _COMMAND_MAP.items():
        if cmd_lower.startswith(prefix):
            return tool_name

    # Check for pip install
    if "pip install" in cmd_lower or "pip3 install" in cmd_lower:
        return "pip_install"

    # Check for python scripts
    if cmd_lower.startswith("python") or cmd_lower.startswith("python3"):
        return "python"

    return "other"


def _get_next_filename(tool_logs_dir: Path, tool_name: str) -> str:
    """Get next available filename for a tool type."""
    counter = _counters.get(tool_name, 0) + 1
    _counters[tool_name] = counter
    return f"{tool_name}_{counter:03d}.txt"


def save_tool_output(
    run_dir: str | Path,
    command: str,
    output: str,
    agent_id: str = "",
) -> str | None:
    """Save a tool's command and output to the tool_logs directory.

    Args:
        run_dir: Path to the scan run directory.
        command: The shell command that was executed.
        output: The output returned by the command.
        agent_id: Optional agent identifier.

    Returns:
        Path to the saved log file, or None on failure.
    """
    try:
        run_path = Path(run_dir)
        tool_logs_dir = run_path / "tool_logs"
        tool_logs_dir.mkdir(parents=True, exist_ok=True)

        tool_name = _detect_tool_name(command)
        filename = _get_next_filename(tool_logs_dir, tool_name)
        filepath = tool_logs_dir / filename

        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        content = f"""{'=' * 70}
Tool: {tool_name}
Command: {command}
Timestamp: {timestamp}
Agent: {agent_id or 'root'}
{'=' * 70}

{output}
"""

        filepath.write_text(content, encoding="utf-8")

        # Also save a combined log of all commands
        combined_log = tool_logs_dir / "all_commands.log"
        with combined_log.open("a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{tool_name}] {command[:200]}\n")

        logger.debug("Saved tool output: %s", filepath)
        return str(filepath)

    except Exception as exc:
        logger.debug("Failed to save tool output: %s", exc)
        return None
