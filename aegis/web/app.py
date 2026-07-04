"""
Aegis Web Application - Full-featured web interface for Aegis pentesting platform.

Run:
    aegis-web
    aegis-web --port 8000
    aegis-web --host 0.0.0.0 --port 8000

Features:
- Create and manage security scans
- View vulnerabilities with details
- GitHub integration for repository scanning
- Model/API key configuration
- Live scan monitoring via WebSocket
- Scan history and comparison
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from aegis.config import load_settings, apply_config_override, persist_current


# ─── App Setup ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Aegis Web API",
    description="Full-featured web interface for Aegis pentesting platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Models ──────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    scan_mode: str = "standard"
    instruction: Optional[str] = None
    model: Optional[str] = None
    skills: Optional[list[str]] = None

class SettingsUpdate(BaseModel):
    model: Optional[str] = None
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    image: Optional[str] = None

class GitRepoRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = "main"
    scan_mode: str = "standard"
    instruction: Optional[str] = None

# ─── Active Scans ────────────────────────────────────────────────────────────

active_scans: dict[str, dict[str, Any]] = {}
scan_processes: dict[str, subprocess.Popen] = {}

# ─── Scan Management ─────────────────────────────────────────────────────────

@app.post("/api/scans")
async def create_scan(request: ScanRequest) -> dict:
    """Create and start a new security scan."""
    import uuid
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    
    # Build command
    cmd = ["aegis", "-n", "--target", request.target, "--scan-mode", request.scan_mode]
    if request.instruction:
        cmd.extend(["--instruction", request.instruction])
    if request.model:
        os.environ["AEGIS_LLM"] = request.model
    
    # Store scan info
    active_scans[scan_id] = {
        "id": scan_id,
        "target": request.target,
        "scan_mode": request.scan_mode,
        "status": "starting",
        "started_at": datetime.now().isoformat(),
        "command": cmd,
    }
    
    # Start scan process
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        scan_processes[scan_id] = process
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["pid"] = process.pid
    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
    
    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/scans")
async def list_scans() -> list[dict]:
    """List all scans (active + historical)."""
    scans = []
    
    # Add active scans
    for scan_id, info in active_scans.items():
        scans.append({
            "id": scan_id,
            "target": info["target"],
            "status": info["status"],
            "started_at": info["started_at"],
            "scan_mode": info["scan_mode"],
        })
    
    # Add historical scans from aegis_runs/
    runs_dir = Path("aegis_runs")
    if runs_dir.exists():
        for run_dir in runs_dir.iterdir():
            if not run_dir.is_dir():
                continue
            run_json = run_dir / "run.json"
            if run_json.exists():
                try:
                    data = json.loads(run_json.read_text())
                    scans.append({
                        "id": run_dir.name,
                        "target": data.get("targets_info", [{}])[0].get("original", "Unknown"),
                        "status": data.get("status", "unknown"),
                        "started_at": data.get("start_time"),
                        "scan_mode": data.get("scan_mode", "unknown"),
                    })
                except:
                    pass
    
    return scans


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    """Get detailed scan information."""
    # Check active scans first
    if scan_id in active_scans:
        return active_scans[scan_id]
    
    # Check historical scans
    run_dir = Path("aegis_runs") / scan_id
    if run_dir.exists():
        run_json = run_dir / "run.json"
        if run_json.exists():
            return json.loads(run_json.read_text())
    
    raise HTTPException(status_code=404, detail="Scan not found")


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    """Delete a scan and its results."""
    # Stop active scan if running
    if scan_id in scan_processes:
        process = scan_processes[scan_id]
        process.terminate()
        del scan_processes[scan_id]
    
    # Remove from active scans
    if scan_id in active_scans:
        del active_scans[scan_id]
    
    # Remove from disk
    run_dir = Path("aegis_runs") / scan_id
    if run_dir.exists():
        import shutil
        shutil.rmtree(run_dir)
    
    return {"status": "deleted"}


# ─── Vulnerabilities ─────────────────────────────────────────────────────────

@app.get("/api/scans/{scan_id}/vulnerabilities")
async def get_vulnerabilities(scan_id: str) -> list[dict]:
    """Get all vulnerabilities for a scan."""
    run_dir = Path("aegis_runs") / scan_id
    vuln_file = run_dir / "vulnerabilities.json"
    
    if vuln_file.exists():
        return json.loads(vuln_file.read_text())
    
    return []


@app.get("/api/vulnerabilities")
async def list_all_vulnerabilities() -> list[dict]:
    """List vulnerabilities across all scans."""
    all_vulns = []
    
    runs_dir = Path("aegis_runs")
    if runs_dir.exists():
        for run_dir in runs_dir.iterdir():
            if not run_dir.is_dir():
                continue
            vuln_file = run_dir / "vulnerabilities.json"
            if vuln_file.exists():
                try:
                    vulns = json.loads(vuln_file.read_text())
                    for vuln in vulns:
                        vuln["scan_id"] = run_dir.name
                    all_vulns.extend(vulns)
                except:
                    pass
    
    return all_vulns


# ─── Git Integration ─────────────────────────────────────────────────────────

@app.post("/api/git/scan")
async def scan_git_repo(request: GitRepoRequest) -> dict:
    """Scan a GitHub repository."""
    import uuid
    scan_id = f"git-{uuid.uuid4().hex[:8]}"
    
    cmd = ["aegis", "-n", "--target", request.repo_url, "--scan-mode", request.scan_mode]
    if request.instruction:
        cmd.extend(["--instruction", request.instruction])
    
    active_scans[scan_id] = {
        "id": scan_id,
        "target": request.repo_url,
        "scan_mode": request.scan_mode,
        "status": "starting",
        "started_at": datetime.now().isoformat(),
        "type": "git",
        "branch": request.branch,
    }
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        scan_processes[scan_id] = process
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["pid"] = process.pid
    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
    
    return {"scan_id": scan_id, "status": "started"}


# ─── Repos ────────────────────────────────────────────────────────────────────

repos_store: list[dict] = []

@app.get("/api/repos")
async def list_repos() -> list[dict]:
    """List all connected repositories."""
    return repos_store


@app.post("/api/repos")
async def add_repo(data: dict) -> dict:
    """Add a new repository."""
    repo_url = data.get("url", "")
    if not repo_url:
        raise HTTPException(status_code=400, detail="URL required")
    
    # Determine provider
    provider = "gitlab" if "gitlab" in repo_url else "github"
    name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    
    repo = {
        "id": len(repos_store) + 1,
        "name": name,
        "url": repo_url,
        "provider": provider,
        "status": "connected",
        "last_scan": None,
        "findings": 0,
    }
    repos_store.append(repo)
    return repo


@app.delete("/api/repos/{repo_id}")
async def delete_repo(repo_id: int) -> dict:
    """Remove a repository."""
    global repos_store
    repos_store = [r for r in repos_store if r["id"] != repo_id]
    return {"status": "deleted"}


@app.post("/api/repos/{repo_id}/scan")
async def scan_repo(repo_id: int) -> dict:
    """Trigger a scan for a repository."""
    repo = next((r for r in repos_store if r["id"] == repo_id), None)
    if not repo:
        raise HTTPException(status_code=404, detail="Repo not found")
    
    # Trigger scan using the same logic as git scan
    import uuid
    scan_id = f"repo-{uuid.uuid4().hex[:8]}"
    
    cmd = ["aegis", "-n", "--target", repo["url"], "--scan-mode", "standard"]
    
    active_scans[scan_id] = {
        "id": scan_id,
        "target": repo["url"],
        "scan_mode": "standard",
        "status": "starting",
        "started_at": datetime.now().isoformat(),
        "type": "repository",
    }
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        scan_processes[scan_id] = process
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["pid"] = process.pid
        
        # Update repo last scan
        repo["last_scan"] = datetime.now().isoformat()
    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
    
    return {"scan_id": scan_id, "status": "started"}


# ─── Settings ────────────────────────────────────────────────────────────────

@app.get("/api/settings")
async def get_settings() -> dict:
    """Get current settings."""
    settings = load_settings()
    return {
        "model": settings.llm.model or "",
        "api_key": "***" if settings.llm.api_key else "",
        "api_base": settings.llm.api_base or "",
        "image": settings.runtime.image,
        "backend": settings.runtime.backend,
        "telemetry": settings.telemetry.enabled,
    }


@app.put("/api/settings")
async def update_settings(update: SettingsUpdate) -> dict:
    """Update settings."""
    if update.model:
        os.environ["AEGIS_LLM"] = update.model
    if update.api_key:
        os.environ["LLM_API_KEY"] = update.api_key
    if update.api_base:
        os.environ["LLM_API_BASE"] = update.api_base
    if update.image:
        os.environ["AEGIS_IMAGE"] = update.image
    
    # Invalidate cache
    import aegis.config.loader as loader
    loader._cached = None
    
    return {"status": "updated"}


@app.get("/api/models")
async def list_models() -> list[dict]:
    """List available LLM models."""
    return [
        {"id": "openai/gpt-4o", "name": "GPT-4o", "provider": "OpenAI"},
        {"id": "openai/gpt-4o-mini", "name": "GPT-4o Mini", "provider": "OpenAI"},
        {"id": "anthropic/claude-sonnet-4-6", "name": "Claude Sonnet 4.6", "provider": "Anthropic"},
        {"id": "opencode/deepseek-v4", "name": "DeepSeek V4", "provider": "DeepSeek"},
        {"id": "opencode/mimo-v2.5-free", "name": "MiMo V2.5", "provider": "OpenCode"},
        {"id": "vertex_ai/gemini-2.5-pro", "name": "Gemini 2.5 Pro", "provider": "Google"},
    ]


# ─── Skills ──────────────────────────────────────────────────────────────────

@app.get("/api/skills")
async def list_skills() -> dict:
    """List available skills by category."""
    from aegis.skills import get_available_skills
    return get_available_skills()


# ─── Logs ────────────────────────────────────────────────────────────────────

@app.get("/api/scans/{scan_id}/logs")
async def get_logs(scan_id: str, lines: int = 100) -> dict:
    """Get scan logs."""
    log_file = Path("aegis_runs") / scan_id / "aegis.log"
    
    if log_file.exists():
        content = log_file.read_text(encoding="utf-8", errors="replace")
        all_lines = content.splitlines()
        return {
            "logs": "\n".join(all_lines[-lines:]),
            "total_lines": len(all_lines),
        }
    
    return {"logs": "", "total_lines": 0}


@app.get("/api/scans/{scan_id}/logs/stream")
async def stream_logs(scan_id: str):
    """Stream scan logs in real-time."""
    log_file = Path("aegis_runs") / scan_id / "aegis.log"
    
    async def generate():
        last_pos = 0
        while True:
            if log_file.exists():
                content = log_file.read_text(encoding="utf-8", errors="replace")
                if len(content) > last_pos:
                    new_content = content[last_pos:]
                    last_pos = len(content)
                    yield f"data: {json.dumps({'log': new_content})}\n\n"
            await asyncio.sleep(1)
    
    return StreamingResponse(generate(), media_type="text/event-stream")


# ─── Statistics ──────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats() -> dict:
    """Get overall statistics."""
    total_scans = 0
    total_vulns = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    runs_dir = Path("aegis_runs")
    if runs_dir.exists():
        for run_dir in runs_dir.iterdir():
            if not run_dir.is_dir():
                continue
            total_scans += 1
            
            vuln_file = run_dir / "vulnerabilities.json"
            if vuln_file.exists():
                try:
                    vulns = json.loads(vuln_file.read_text())
                    total_vulns += len(vulns)
                    for v in vulns:
                        sev = v.get("severity", "").lower()
                        if sev in severity_counts:
                            severity_counts[sev] += 1
                except:
                    pass
    
    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "severity_breakdown": severity_counts,
    }


# ─── Health ──────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check() -> dict:
    """Health check endpoint."""
    return {"status": "ok", "version": "1.0.0"}


# ─── Run ─────────────────────────────────────────────────────────────────────

def main():
    """Run the Aegis web server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Aegis Web Interface")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    args = parser.parse_args()
    
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
