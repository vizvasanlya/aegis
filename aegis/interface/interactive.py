"""
Aegis Interactive Mode - Slash command TUI for configuration and guidance.

Run without a target to enter interactive mode:
    aegis --interactive
    aegis -i

Slash commands:
    /help           Show available commands
    /model          Set or view LLM model
    /target         Set scan target
    /scan           Start scan with current settings
    /config         View/edit configuration
    /skills         List available skills
    /history        Show scan history
    /about          About Aegis
    /quit           Exit
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegis.config import load_settings, apply_config_override, persist_current
from aegis.config.models import configure_sdk_model_defaults


console = Console()


COMMANDS = {
    "/help": "Show available commands",
    "/model": "View or set LLM model (e.g., /model openai/gpt-4o)",
    "/target": "Set scan target (e.g., /target https://example.com)",
    "/scan": "Start scan with current settings",
    "/config": "View current configuration",
    "/set": "Set a configuration value (e.g., /set AEGIS_LLM openai/gpt-4o)",
    "/skills": "List available pentesting skills",
    "/history": "Show previous scan results",
    "/about": "About Aegis",
    "/version": "Show version",
    "/quit": "Exit Aegis",
}


def show_help() -> None:
    """Display help menu."""
    table = Table(title="Aegis Commands", show_header=True)
    table.add_column("Command", style="cyan")
    table.add_column("Description")
    
    for cmd, desc in COMMANDS.items():
        table.add_row(cmd, desc)
    
    console.print(table)
    console.print("\n[dim]Type a command or ask a security question.[/dim]\n")


def show_model() -> None:
    """Display current model configuration."""
    settings = load_settings()
    model = settings.llm.model or "Not configured"
    api_key = "Set" if settings.llm.api_key else "Not set"
    
    console.print(f"\n[bold]Current Model:[/bold] {model}")
    console.print(f"[bold]API Key:[/bold] {api_key}")
    console.print(f"[bold]Reasoning Effort:[/bold] {settings.llm.reasoning_effort}")
    console.print()


def set_model(model_name: str) -> None:
    """Set the LLM model."""
    os.environ["AEGIS_LLM"] = model_name
    console.print(f"[green]Model set to: {model_name}[/green]\n")


def show_config() -> None:
    """Display current configuration."""
    settings = load_settings()
    
    table = Table(title="Aegis Configuration", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    
    table.add_row("LLM Model", settings.llm.model or "Not set")
    table.add_row("API Key", "Set" if settings.llm.api_key else "Not set")
    table.add_row("API Base", settings.llm.api_base or "Default")
    table.add_row("Reasoning Effort", settings.llm.reasoning_effort)
    table.add_row("Docker Image", settings.runtime.image)
    table.add_row("Backend", settings.runtime.backend)
    table.add_row("Telemetry", "Enabled" if settings.telemetry.enabled else "Disabled")
    
    console.print(table)
    console.print()


def set_config(key: str, value: str) -> None:
    """Set a configuration value."""
    env_key = f"AEGIS_{key.upper()}" if not key.startswith("AEGIS_") else key
    os.environ[env_key] = value
    console.print(f"[green]{env_key} = {value}[/green]\n")


def show_skills() -> None:
    """List available skills."""
    from aegis.skills import get_available_skills
    
    skills = get_available_skills()
    
    table = Table(title="Available Skills", show_header=True)
    table.add_column("Category", style="cyan")
    table.add_column("Skills")
    
    for category, skill_list in skills.items():
        table.add_row(category, ", ".join(skill_list))
    
    console.print(table)
    console.print("[dim]Use /scan --skills skill1,skill2 to load specific skills[/dim]\n")


def show_history() -> None:
    """Show scan history."""
    runs_dir = Path("aegis_runs")
    if not runs_dir.exists():
        console.print("[yellow]No scan history found.[/yellow]\n")
        return
    
    table = Table(title="Scan History", show_header=True)
    table.add_column("Run", style="cyan")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Vulns")
    
    for run_dir in sorted(runs_dir.iterdir(), reverse=True):
        if not run_dir.is_dir():
            continue
        
        run_json = run_dir / "run.json"
        if not run_json.exists():
            continue
        
        try:
            data = json.loads(run_json.read_text())
            target = data.get("targets_info", [{}])[0].get("original", "Unknown")
            status = data.get("status", "unknown")
            vuln_count = len(data.get("vulnerability_reports", []))
            
            status_style = "green" if status == "completed" else "yellow"
            table.add_row(
                run_dir.name,
                target[:40] + "..." if len(target) > 40 else target,
                f"[{status_style}]{status}[/{status_style}]",
                str(vuln_count)
            )
        except:
            continue
    
    console.print(table)
    console.print()


def show_about() -> None:
    """Show about information."""
    from aegis.interface.main import get_version
    
    version = get_version()
    
    about = f"""
[bold cyan]Aegis[/bold cyan] v{version}

Open-source AI pentesting tool that autonomously finds and 
validates security vulnerabilities with working proof-of-concepts.

[bold]Features:[/bold]
- Mandatory 8-category testing checklist (OWASP/PortSwigger)
- Multi-agent orchestration for parallel testing
- Browser automation with Playwright
- HTTP interception with Caido
- Exploit validation engine
- Vulnerability chaining

[bold]GitHub:[/bold] https://github.com/vizvasanlya/aegis
"""
    console.print(Panel(about, title="About Aegis", border_style="cyan"))
    console.print()


def show_version() -> None:
    """Show version."""
    from aegis.interface.main import get_version
    console.print(f"aegis {get_version()}\n")


def handle_command(cmd: str) -> bool:
    """Handle a slash command. Returns True if should exit."""
    parts = cmd.strip().split(maxsplit=1)
    command = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    
    if command == "/help":
        show_help()
    elif command == "/model":
        if args:
            set_model(args)
        else:
            show_model()
    elif command == "/target":
        if args:
            console.print(f"[green]Target set to: {args}[/green]")
            console.print("[dim]Use /scan to start the scan[/dim]\n")
        else:
            console.print("[yellow]Usage: /target <url-or-path>[/yellow]\n")
    elif command == "/scan":
        console.print("[yellow]Starting scan... (use --target to specify target)[/yellow]\n")
    elif command == "/config":
        show_config()
    elif command == "/set":
        if args:
            parts = args.split(maxsplit=1)
            if len(parts) == 2:
                set_config(parts[0], parts[1])
            else:
                console.print("[yellow]Usage: /set KEY VALUE[/yellow]\n")
        else:
            show_config()
    elif command == "/skills":
        show_skills()
    elif command == "/history":
        show_history()
    elif command == "/about":
        show_about()
    elif command == "/version":
        show_version()
    elif command in ("/quit", "/exit", "/q"):
        console.print("[yellow]Goodbye![/yellow]")
        return True
    else:
        console.print(f"[red]Unknown command: {command}[/red]")
        console.print("[dim]Type /help for available commands[/dim]\n")
    
    return False


def run_interactive_mode() -> None:
    """Run Aegis in interactive configuration mode."""
    # Show welcome banner
    banner = """
[bold cyan]   ___             
  / __ \__   _____  __
 / / / / | / / _ \/_ /
/ /_/ / /|  /  __/ / /
\____/_/ |_/\\___/_/ v1.0

[/bold cyan]"""
    console.print(banner)
    console.print("[bold]Aegis Interactive Mode[/bold]")
    console.print("[dim]Type /help for commands, or ask a security question.[/dim]\n")
    
    # Check if model is configured
    settings = load_settings()
    if not settings.llm.model:
        console.print("[yellow]No LLM model configured.[/yellow]")
        console.print("[dim]Use: /model openai/gpt-4o[/dim]")
        console.print("[dim]Or set: export AEGIS_LLM=openai/gpt-4o[/dim]\n")
    
    # Main loop
    while True:
        try:
            cmd = console.input("[bold green]> [/bold green]")
            
            if not cmd.strip():
                continue
            
            if cmd.strip().startswith("/"):
                if handle_command(cmd):
                    break
            else:
                # Treat as a question/command
                console.print(f"[dim]Processing: {cmd}[/dim]")
                console.print("[yellow]To run a scan, use: /target <url> then /scan[/yellow]\n")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Use /quit to exit[/yellow]")
        except EOFError:
            break


def main() -> None:
    """Entry point for interactive mode."""
    run_interactive_mode()


if __name__ == "__main__":
    main()
