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

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
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
    credential_id: Optional[int] = None
    internal_mode: bool = False

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

class InternalScanRequest(BaseModel):
    target: str
    scan_mode: str = "standard"
    instruction: Optional[str] = None
    credential_id: Optional[int] = None
    scope: str = "network"  # network, ad, full

class CredentialCreate(BaseModel):
    name: str
    site_url: str
    credential_type: str  # "credentials", "api_key", "token", "cookie"
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    token: Optional[str] = None
    cookies: Optional[str] = None
    notes: Optional[str] = None

class ApiScanRequest(BaseModel):
    endpoint: str
    method: str = "GET"
    api_type: str = "rest"  # rest, graphql, grpc, websocket
    scan_mode: str = "standard"
    instruction: Optional[str] = None
    credential_id: Optional[int] = None
    openapi_url: Optional[str] = None
    headers: Optional[dict[str, str]] = None
    body: Optional[str] = None

class MobileScanRequest(BaseModel):
    app_name: str
    platform: str  # android, ios
    source: str  # upload, url
    app_url: Optional[str] = None
    scan_mode: str = "standard"
    instruction: Optional[str] = None
    app_id: Optional[int] = None

class MobileAppUpdate(BaseModel):
    name: Optional[str] = None
    notes: Optional[str] = None

class ApiEndpointCreate(BaseModel):
    name: str
    base_url: str
    api_type: str = "rest"  # rest, graphql, grpc, websocket
    auth_type: Optional[str] = None  # none, api_key, bearer, basic, oauth2
    auth_config: Optional[dict[str, str]] = None
    openapi_url: Optional[str] = None
    headers: Optional[dict[str, str]] = None
    notes: Optional[str] = None

class ApiEndpointUpdate(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    api_type: Optional[str] = None
    auth_type: Optional[str] = None
    auth_config: Optional[dict[str, str]] = None
    openapi_url: Optional[str] = None
    headers: Optional[dict[str, str]] = None
    notes: Optional[str] = None

class ApiRequestTest(BaseModel):
    endpoint_id: int
    method: str = "GET"
    path: str = "/"
    headers: Optional[dict[str, str]] = None
    body: Optional[str] = None
    content_type: str = "application/json"

# ─── Active Scans ────────────────────────────────────────────────────────────

active_scans: dict[str, dict[str, Any]] = {}
scan_processes: dict[str, subprocess.Popen] = {}

# ─── Credentials Storage ─────────────────────────────────────────────────────

import base64
import hashlib

# Persistent storage paths (in project folder)
AEGIS_DIR = Path(__file__).resolve().parent.parent.parent / ".aegis"
CREDENTIALS_FILE = AEGIS_DIR / "credentials.json"
SETTINGS_FILE = AEGIS_DIR / "web-settings.json"
API_ENDPOINTS_FILE = AEGIS_DIR / "api-endpoints.json"
API_HISTORY_FILE = AEGIS_DIR / "api-history.json"

def _ensure_aegis_dir():
    """Ensure .aegis directory exists."""
    AEGIS_DIR.mkdir(parents=True, exist_ok=True)

def _load_credentials() -> list[dict[str, Any]]:
    """Load credentials from disk."""
    _ensure_aegis_dir()
    if CREDENTIALS_FILE.exists():
        try:
            return json.loads(CREDENTIALS_FILE.read_text())
        except:
            return []
    return []

def _save_credentials(credentials: list[dict[str, Any]]):
    """Save credentials to disk."""
    _ensure_aegis_dir()
    CREDENTIALS_FILE.write_text(json.dumps(credentials, indent=2))

def _load_web_settings() -> dict[str, Any]:
    """Load web app settings from disk."""
    _ensure_aegis_dir()
    if SETTINGS_FILE.exists():
        try:
            return json.loads(SETTINGS_FILE.read_text())
        except:
            return {}
    return {}

def _save_web_settings(settings: dict[str, Any]):
    """Save web app settings to disk."""
    _ensure_aegis_dir()
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2))

# Initialize from disk
credentials_store: list[dict[str, Any]] = _load_credentials()

# ─── API Endpoints Storage ───────────────────────────────────────────────────

def _load_api_endpoints() -> list[dict[str, Any]]:
    """Load API endpoints from disk."""
    _ensure_aegis_dir()
    if API_ENDPOINTS_FILE.exists():
        try:
            return json.loads(API_ENDPOINTS_FILE.read_text())
        except:
            return []
    return []

def _save_api_endpoints(endpoints: list[dict[str, Any]]):
    """Save API endpoints to disk."""
    _ensure_aegis_dir()
    API_ENDPOINTS_FILE.write_text(json.dumps(endpoints, indent=2))

def _load_api_history() -> list[dict[str, Any]]:
    """Load API request history from disk."""
    _ensure_aegis_dir()
    if API_HISTORY_FILE.exists():
        try:
            data = json.loads(API_HISTORY_FILE.read_text())
            return data[-500:]  # Keep last 500 entries
        except:
            return []
    return []

def _save_api_history(history: list[dict[str, Any]]):
    """Save API request history to disk."""
    _ensure_aegis_dir()
    API_HISTORY_FILE.write_text(json.dumps(history[-500:], indent=2))

api_endpoints_store: list[dict[str, Any]] = _load_api_endpoints()
api_history_store: list[dict[str, Any]] = _load_api_history()

def _encrypt_value(value: str) -> str:
    """Simple obfuscation for demo. In production, use proper encryption."""
    return base64.b64encode(value.encode()).decode()

def _decrypt_value(value: str) -> str:
    """Simple deobfuscation for demo."""
    try:
        return base64.b64decode(value.encode()).decode()
    except:
        return value

# ─── Scan Management ─────────────────────────────────────────────────────────

def generate_run_name(target_url: str) -> str:
    """Generate a run name from target URL (matches CLI behavior)."""
    import re
    import secrets
    
    # Extract domain/path from URL
    parsed = target_url.replace("https://", "").replace("http://", "")
    parsed = re.sub(r'[:/]', '-', parsed)
    parsed = re.sub(r'[^a-zA-Z0-9-]', '', parsed)
    parsed = parsed.rstrip('-')
    
    # Add random suffix
    suffix = secrets.token_hex(2)
    return f"{parsed}_{suffix}"


@app.post("/api/scans")
async def create_scan(request: ScanRequest) -> dict:
    """Create and start a new security scan."""
    import sys

    # Generate run name like CLI does
    run_name = generate_run_name(request.target)
    project_root = str(Path(__file__).resolve().parent.parent.parent)

    # Build command: use `uv run aegis` to ensure correct environment
    cmd = ["uv", "run", "aegis", "-n", "--target", request.target, "--scan-mode", request.scan_mode]
    if request.instruction:
        cmd.extend(["--instruction", request.instruction])
    if request.model:
        os.environ["AEGIS_LLM"] = request.model
    if request.internal_mode:
        cmd.append("--internal")

    # Store scan info
    active_scans[run_name] = {
        "id": run_name,
        "target": request.target,
        "scan_mode": request.scan_mode,
        "status": "starting",
        "started_at": datetime.now().isoformat(),
        "command": cmd,
        "pid": None,
        "type": "internal" if request.internal_mode else "webapp",
    }

    # Start scan process asynchronously
    async def run_scan():
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=project_root,
            )
            scan_processes[run_name] = process
            active_scans[run_name]["status"] = "running"
            active_scans[run_name]["pid"] = process.pid

            # Wait for process to complete
            stdout, _ = await process.communicate()

            # Check if scan created output — CLI generates its own run_name
            runs_dir = Path("aegis_runs")
            if runs_dir.exists():
                latest_run = None
                latest_time = 0
                for d in runs_dir.iterdir():
                    if d.is_dir() and (d / "run.json").exists():
                        mtime = d.stat().st_mtime
                        if mtime > latest_time:
                            latest_time = mtime
                            latest_run = d
                if latest_run:
                    active_scans[run_name]["status"] = "completed"
                    active_scans[run_name]["actual_run_id"] = latest_run.name
                else:
                    active_scans[run_name]["status"] = "failed"
            else:
                active_scans[run_name]["status"] = "failed"
                active_scans[run_name]["error"] = "No output directory created"
                
        except Exception as e:
            active_scans[run_name]["status"] = "failed"
            active_scans[run_name]["error"] = str(e)
    
    # Start the scan in background
    asyncio.create_task(run_scan())
    
    return {"scan_id": run_name, "status": "started"}


@app.get("/api/scans")
async def list_scans() -> list[dict]:
    """List all scans (active + historical)."""
    scans = []
    
    # Add active scans
    for scan_id, info in list(active_scans.items()):
        # Check if scan has completed by looking for output directory
        run_name = scan_id.replace("scan-", "")
        run_dir = Path("aegis_runs") / run_name
        
        if run_dir.exists() and (run_dir / "run.json").exists():
            # Scan completed - update status
            active_scans[scan_id]["status"] = "completed"
        
        # Check if process is still running
        process = scan_processes.get(scan_id)
        if process and process.returncode is not None:
            # Process has finished
            if active_scans[scan_id]["status"] == "running":
                active_scans[scan_id]["status"] = "completed" if run_dir.exists() else "failed"
        
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
            # Skip if already in active scans
            if f"scan-{run_dir.name}" in active_scans:
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


@app.get("/api/scans/{scan_id}/report")
async def download_report(scan_id: str):
    """Generate and download a pentest report as HTML (printable to PDF)."""
    run_dir = Path("aegis_runs") / scan_id
    vuln_file = run_dir / "vulnerabilities.json"
    run_json = run_dir / "run.json"

    vulns = []
    if vuln_file.exists():
        vulns = json.loads(vuln_file.read_text())

    scan_info = {}
    if run_json.exists():
        scan_info = json.loads(run_json.read_text())

    target = scan_info.get("targets_info", [{}])[0].get("original", scan_id) if scan_info.get("targets_info") else scan_id
    scan_mode = scan_info.get("scan_mode", "unknown")
    start_time = scan_info.get("start_time", "")

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = v.get("severity", "").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    def sev_color(sev: str) -> str:
        return {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6"}.get(sev, "#6b7280")

    vuln_rows = ""
    for i, v in enumerate(vulns, 1):
        sev = v.get("severity", "unknown")
        color = sev_color(sev)
        poc_raw = v.get("poc_script_code") or (v.get("poc", {}) or {}).get("script_code") or ""
        poc = str(poc_raw)[:2000] if poc_raw else ""
        poc_desc_raw = (v.get("poc", {}) or {}).get("description") or ""
        poc_desc = str(poc_desc_raw) if poc_desc_raw else ""
        remediation_raw = v.get("remediation_steps") or ""
        remediation = str(remediation_raw) if remediation_raw else ""
        endpoint_raw = v.get("endpoint") or ""
        endpoint = str(endpoint_raw) if endpoint_raw else ""
        http_req = ""
        http_resp = ""
        if v.get("http_requests"):
            for req in v["http_requests"][:1]:
                raw_req = req.get("request", "")
                raw_resp = req.get("response", "")
                http_req = str(raw_req)[:500] if raw_req else ""
                http_resp = str(raw_resp)[:500] if raw_resp else ""

        vuln_rows += f"""
        <div class="vuln-card" style="border-left: 4px solid {color};">
          <div class="vuln-header">
            <span class="vuln-num">#{i}</span>
            <span class="vuln-title">{str(v.get('title', 'Untitled'))}</span>
            <span class="sev-badge" style="background: {color}20; color: {color};">{sev.upper()}</span>
            {f'<span class="cvss">CVSS {str(v.get("cvss", ""))}</span>' if v.get('cvss') else ''}
          </div>
          {f'<div class="endpoint"><strong>Endpoint:</strong> <code>{str(endpoint)}</code></div>' if endpoint else ''}
          <div class="vuln-desc">{str(v.get('description', ''))}</div>
          {f'<div class="vuln-section"><strong>PoC Description:</strong><p>{poc_desc}</p></div>' if poc_desc else ''}
          {f'<div class="vuln-section"><strong>PoC Script:</strong><pre>{poc}</pre></div>' if poc else ''}
          {f'<div class="vuln-section"><strong>HTTP Request:</strong><pre>{http_req}</pre></div>' if http_req else ''}
          {f'<div class="vuln-section"><strong>HTTP Response:</strong><pre>{http_resp}</pre></div>' if http_resp else ''}
          {f'<div class="vuln-section"><strong>Remediation:</strong><p>{remediation}</p></div>' if remediation else ''}
        </div>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Pentest Report — {target}</title>
<style>
  @media print {{ body {{ font-size: 11pt; }} .no-print {{ display: none; }} }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #1f2937; padding: 40px; max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 24px; margin-bottom: 4px; }}
  .subtitle {{ color: #6b7280; margin-bottom: 24px; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 24px; }}
  .stat {{ flex: 1; padding: 16px; border: 1px solid #e5e7eb; border-radius: 8px; text-align: center; }}
  .stat .num {{ font-size: 28px; font-weight: bold; }}
  .stat .label {{ font-size: 12px; color: #6b7280; }}
  .vuln-card {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 16px; page-break-inside: avoid; }}
  .vuln-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }}
  .vuln-num {{ font-weight: bold; color: #6b7280; }}
  .vuln-title {{ font-weight: 600; font-size: 15px; flex: 1; }}
  .sev-badge {{ padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }}
  .cvss {{ font-size: 12px; color: #6b7280; }}
  .endpoint {{ font-size: 13px; margin-bottom: 8px; }}
  .endpoint code {{ background: #e5e7eb; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
  .vuln-desc {{ font-size: 14px; color: #374151; margin-bottom: 8px; }}
  .vuln-section {{ margin-top: 8px; font-size: 13px; }}
  .vuln-section pre {{ background: #1f2937; color: #e5e7eb; padding: 12px; border-radius: 6px; font-size: 11px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin-top: 4px; }}
  .footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #9ca3af; text-align: center; }}
  .print-btn {{ position: fixed; top: 20px; right: 20px; background: #0891b2; color: white; padding: 10px 20px; border-radius: 8px; border: none; cursor: pointer; font-weight: 600; font-size: 14px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }}
  .print-btn:hover {{ background: #0e7490; }}
</style></head><body>
<button class="print-btn no-print" onclick="window.print()">Download PDF</button>
<h1>Aegis Penetration Test Report</h1>
<p class="subtitle">Target: {target} | Mode: {scan_mode} | Date: {start_time[:10] if start_time else 'N/A'}</p>

<div class="summary">
  <div class="stat"><div class="num" style="color:#111827">{len(vulns)}</div><div class="label">Total Findings</div></div>
  <div class="stat"><div class="num" style="color:#ef4444">{severity_counts['critical']}</div><div class="label">Critical</div></div>
  <div class="stat"><div class="num" style="color:#f97316">{severity_counts['high']}</div><div class="label">High</div></div>
  <div class="stat"><div class="num" style="color:#eab308">{severity_counts['medium']}</div><div class="label">Medium</div></div>
  <div class="stat"><div class="num" style="color:#3b82f6">{severity_counts['low']}</div><div class="label">Low</div></div>
</div>

<h2 style="font-size:18px; margin-bottom:16px;">Findings</h2>
{vuln_rows if vuln_rows else '<p style="color:#6b7280; text-align:center; padding:40px;">No vulnerabilities found</p>'}

<div class="footer">Generated by Aegis Security Platform | {len(vulns)} findings</div>
</body></html>"""

    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html)


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


@app.get("/api/evidence/{scan_id}/evidence/{path:path}")
async def serve_evidence_file(scan_id: str, path: str):
    """Serve evidence files (screenshots, request logs) for a scan."""
    # Sanitize path to prevent directory traversal
    if ".." in path or path.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid path")
    
    file_path = Path("aegis_runs") / scan_id / "evidence" / path
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Evidence file not found")
    
    # Determine content type
    suffix = file_path.suffix.lower()
    content_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".txt": "text/plain",
        ".json": "application/json",
        ".py": "text/x-python",
        ".sh": "application/x-sh",
    }
    content_type = content_types.get(suffix, "application/octet-stream")
    
    return FileResponse(file_path, media_type=content_type)


# ─── API Testing ─────────────────────────────────────────────────────────────

@app.post("/api/api-scan")
async def create_api_scan(request: ApiScanRequest) -> dict:
    """Create and start an API security scan."""
    import uuid

    scan_id = f"api-{uuid.uuid4().hex[:8]}"

    # Build instruction based on API type
    api_instructions = {
        "rest": f"Perform REST API security testing on {request.endpoint}. Test for OWASP API Security Top 10 vulnerabilities.",
        "graphql": f"Perform GraphQL API security testing on {request.endpoint}. Test introspection, injection, authorization bypass.",
        "grpc": f"Perform gRPC service security testing on {request.endpoint}. Test reflection, authorization, injection.",
        "websocket": f"Perform WebSocket security testing on {request.endpoint}. Test authentication, message injection, DoS.",
    }

    instruction = api_instructions.get(request.api_type, api_instructions["rest"])
    if request.instruction:
        instruction += "\n" + request.instruction

    # Add OpenAPI spec if provided
    if request.openapi_url:
        instruction += f"\nOpenAPI specification available at: {request.openapi_url}"

    # Build scan command
    project_root = str(Path(__file__).resolve().parent.parent.parent)
    cmd = ["uv", "run", "aegis", "-n", "--target", request.endpoint, "--scan-mode", request.scan_mode]
    cmd.extend(["--instruction", instruction])

    active_scans[scan_id] = {
        "id": scan_id,
        "target": request.endpoint,
        "scan_mode": request.scan_mode,
        "status": "starting",
        "started_at": datetime.now().isoformat(),
        "type": "api",
        "api_type": request.api_type,
        "method": request.method,
    }

    async def run_scan():
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=project_root,
            )
            scan_processes[scan_id] = process
            active_scans[scan_id]["status"] = "running"
            active_scans[scan_id]["pid"] = process.pid
            stdout, _ = await process.communicate()
            runs_dir = Path("aegis_runs")
            if runs_dir.exists():
                latest_run = None
                latest_time = 0
                for d in runs_dir.iterdir():
                    if d.is_dir() and (d / "run.json").exists():
                        mtime = d.stat().st_mtime
                        if mtime > latest_time:
                            latest_time = mtime
                            latest_run = d
                if latest_run:
                    active_scans[scan_id]["status"] = "completed"
                    active_scans[scan_id]["actual_run_id"] = latest_run.name
                else:
                    active_scans[scan_id]["status"] = "failed"
                    active_scans[scan_id]["error"] = "No output directory created"
        except Exception as e:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)

    asyncio.create_task(run_scan())
    return {"scan_id": scan_id, "status": "started"}


# ─── Mobile App Testing ──────────────────────────────────────────────────────

UPLOAD_DIR = AEGIS_DIR / "uploads"

@app.post("/api/mobile-scan")
async def create_mobile_scan(request: MobileScanRequest) -> dict:
    """Create and start a mobile app security scan."""
    import uuid
    import sys
    import shutil

    scan_id = f"mobile-{uuid.uuid4().hex[:8]}"

    instruction = f"Perform {request.platform} mobile application security testing on {request.app_name}."
    if request.instruction:
        instruction += "\n" + request.instruction

    # Determine the app file path for --apk or --ipa flag
    app_file_path = None
    if request.app_url:
        # Resolve to absolute path
        candidate = Path(request.app_url)
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        if candidate.exists():
            app_file_path = str(candidate)
        else:
            # URL download — need to download first
            try:
                import httpx
                UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                ext = ".apk" if request.platform == "android" else ".ipa"
                saved_name = f"{uuid.uuid4().hex[:12]}{ext}"
                save_path = UPLOAD_DIR / saved_name
                async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
                    resp = await client.get(request.app_url)
                    resp.raise_for_status()
                    save_path.write_bytes(resp.content)
                app_file_path = str(save_path.resolve())
            except Exception as e:
                return {"scan_id": scan_id, "status": "failed", "error": f"Failed to download app: {str(e)}"}

    # Find the correct Python executable to run aegis via `uv run`
    # This ensures the subprocess uses the same venv as the web server
    python_exe = sys.executable
    project_root = str(Path(__file__).resolve().parent.parent.parent)

    # Build command: use `uv run aegis` to ensure correct environment
    cmd = ["uv", "run", "aegis", "-n", "--scan-mode", request.scan_mode]
    cmd.extend(["--instruction", instruction])

    if app_file_path:
        if request.platform == "android":
            cmd.extend(["--apk", app_file_path])
        else:
            cmd.extend(["--ipa", app_file_path])
        target = app_file_path
    else:
        # Fallback: use target URL
        target = request.app_url or request.app_name
        cmd.extend(["--target", target])

    active_scans[scan_id] = {
        "id": scan_id,
        "target": target,
        "scan_mode": request.scan_mode,
        "status": "starting",
        "started_at": datetime.now().isoformat(),
        "type": "mobile",
        "platform": request.platform,
        "app_name": request.app_name,
        "app_id": request.app_id,
    }

    # Update app stats
    if request.app_id:
        app = next((a for a in mobile_apps_store if a["id"] == request.app_id), None)
        if app:
            app["last_scanned"] = datetime.now().isoformat()
            app["total_scans"] = app.get("total_scans", 0) + 1
            _save_mobile_apps(mobile_apps_store)

    async def run_scan():
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=project_root,
            )
            scan_processes[scan_id] = process
            active_scans[scan_id]["status"] = "running"
            active_scans[scan_id]["pid"] = process.pid
            stdout, stderr = await process.communicate()
            output = stdout.decode(errors="replace") if stdout else ""

            # Check if scan created output — the CLI generates its own run_name from target
            runs_dir = Path("aegis_runs")
            if runs_dir.exists():
                # Find the most recently created run directory
                latest_run = None
                latest_time = 0
                for d in runs_dir.iterdir():
                    if d.is_dir() and (d / "run.json").exists():
                        mtime = d.stat().st_mtime
                        if mtime > latest_time:
                            latest_time = mtime
                            latest_run = d
                if latest_run:
                    active_scans[scan_id]["status"] = "completed"
                    active_scans[scan_id]["actual_run_id"] = latest_run.name
                else:
                    active_scans[scan_id]["status"] = "failed"
                    active_scans[scan_id]["error"] = f"No output. Process exit: {process.returncode}. Output: {output[-500:]}"
            else:
                active_scans[scan_id]["status"] = "failed"
                active_scans[scan_id]["error"] = f"No runs directory. Output: {output[-500:]}"
        except Exception as e:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)

    asyncio.create_task(run_scan())
    return {"scan_id": scan_id, "status": "started"}


@app.post("/api/mobile-scan/upload")
async def upload_mobile_app(file: UploadFile) -> dict:
    """Upload an APK or IPA file for mobile scanning."""
    import uuid

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in (".apk", ".ipa", ".aab"):
        raise HTTPException(status_code=400, detail="Only .apk, .ipa, and .aab files are supported")

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    saved_name = f"{uuid.uuid4().hex[:12]}{ext}"
    save_path = UPLOAD_DIR / saved_name

    content = await file.read()
    save_path.write_bytes(content)

    return {
        "filename": file.filename,
        "saved_as": saved_name,
        "path": str(save_path),
        "size": len(content),
        "platform": "android" if ext in (".apk", ".aab") else "ios",
    }


# ─── Internal Network Testing ───────────────────────────────────────────────

@app.post("/api/internal-scan")
async def create_internal_scan(request: InternalScanRequest) -> dict:
    """Create and start an internal network security scan."""
    import uuid

    scan_id = f"internal-{uuid.uuid4().hex[:8]}"
    project_root = str(Path(__file__).resolve().parent.parent.parent)

    instruction = f"Perform internal network security testing on {request.target}."
    scope_desc = {
        "network": "network discovery, host enumeration, port scanning, service fingerprinting",
        "ad": "Active Directory enumeration, Kerberos attacks, GPO analysis, trust relationships",
        "full": "comprehensive internal testing including network, AD, credential attacks, lateral movement",
    }
    instruction += f" Focus on: {scope_desc.get(request.scope, scope_desc['full'])}."
    if request.instruction:
        instruction += "\n" + request.instruction

    cmd = ["uv", "run", "aegis", "-n", "--target", request.target, "--scan-mode", request.scan_mode]
    cmd.extend(["--instruction", instruction])
    cmd.append("--internal")

    active_scans[scan_id] = {
        "id": scan_id,
        "target": request.target,
        "scan_mode": request.scan_mode,
        "status": "starting",
        "started_at": datetime.now().isoformat(),
        "type": "internal",
        "scope": request.scope,
    }

    async def run_scan():
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=project_root,
            )
            scan_processes[scan_id] = process
            active_scans[scan_id]["status"] = "running"
            active_scans[scan_id]["pid"] = process.pid
            stdout, _ = await process.communicate()
            runs_dir = Path("aegis_runs")
            if runs_dir.exists():
                latest_run = None
                latest_time = 0
                for d in runs_dir.iterdir():
                    if d.is_dir() and (d / "run.json").exists():
                        mtime = d.stat().st_mtime
                        if mtime > latest_time:
                            latest_time = mtime
                            latest_run = d
                if latest_run:
                    active_scans[scan_id]["status"] = "completed"
                    active_scans[scan_id]["actual_run_id"] = latest_run.name
                else:
                    active_scans[scan_id]["status"] = "failed"
                    active_scans[scan_id]["error"] = "No output directory created"
        except Exception as e:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)

    asyncio.create_task(run_scan())
    return {"scan_id": scan_id, "status": "started"}


# ─── Mobile Apps Management ─────────────────────────────────────────────────

MOBILE_APPS_FILE = AEGIS_DIR / "mobile-apps.json"

def _load_mobile_apps() -> list[dict[str, Any]]:
    """Load mobile apps from disk."""
    _ensure_aegis_dir()
    if MOBILE_APPS_FILE.exists():
        try:
            return json.loads(MOBILE_APPS_FILE.read_text())
        except:
            return []
    return []

def _save_mobile_apps(apps: list[dict[str, Any]]):
    """Save mobile apps to disk."""
    _ensure_aegis_dir()
    MOBILE_APPS_FILE.write_text(json.dumps(apps, indent=2))

mobile_apps_store: list[dict[str, Any]] = _load_mobile_apps()


@app.get("/api/mobile-apps")
async def list_mobile_apps() -> list[dict]:
    """List all uploaded mobile apps."""
    return mobile_apps_store


@app.post("/api/mobile-apps")
async def create_mobile_app(data: dict) -> dict:
    """Register a mobile app (after upload or URL)."""
    import uuid

    app_id = max((a["id"] for a in mobile_apps_store), default=0) + 1
    app = {
        "id": app_id,
        "name": data.get("name", "Unknown App"),
        "platform": data.get("platform", "android"),
        "filename": data.get("filename", ""),
        "file_path": data.get("file_path", ""),
        "file_size": data.get("file_size", 0),
        "source": data.get("source", "upload"),
        "app_url": data.get("app_url"),
        "notes": data.get("notes", ""),
        "created_at": datetime.now().isoformat(),
        "last_scanned": None,
        "total_scans": 0,
        "vulnerabilities_found": 0,
    }
    mobile_apps_store.append(app)
    _save_mobile_apps(mobile_apps_store)
    return app


@app.get("/api/mobile-apps/{app_id}")
async def get_mobile_app(app_id: int) -> dict:
    """Get mobile app details."""
    app = next((a for a in mobile_apps_store if a["id"] == app_id), None)
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    return app


@app.put("/api/mobile-apps/{app_id}")
async def update_mobile_app(app_id: int, data: MobileAppUpdate) -> dict:
    """Update mobile app details."""
    app = next((a for a in mobile_apps_store if a["id"] == app_id), None)
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    for key, val in data.model_dump(exclude_unset=True).items():
        if val is not None:
            app[key] = val
    _save_mobile_apps(mobile_apps_store)
    return app


@app.delete("/api/mobile-apps/{app_id}")
async def delete_mobile_app(app_id: int) -> dict:
    """Delete a mobile app and its file."""
    global mobile_apps_store
    app = next((a for a in mobile_apps_store if a["id"] == app_id), None)
    if app and app.get("file_path"):
        file_path = Path(app["file_path"])
        if file_path.exists():
            file_path.unlink()
    mobile_apps_store = [a for a in mobile_apps_store if a["id"] != app_id]
    _save_mobile_apps(mobile_apps_store)
    return {"status": "deleted"}


@app.get("/api/mobile-apps/{app_id}/scans")
async def list_mobile_app_scans(app_id: int) -> list[dict]:
    """List all scans for a mobile app."""
    scans = []
    for scan_id, info in active_scans.items():
        if info.get("type") == "mobile" and info.get("app_id") == app_id:
            scans.append({
                "id": scan_id,
                "status": info["status"],
                "started_at": info.get("started_at"),
                "scan_mode": info.get("scan_mode"),
            })
    # Also check historical scans
    runs_dir = Path("aegis_runs")
    if runs_dir.exists():
        for run_dir in runs_dir.iterdir():
            if not run_dir.is_dir():
                continue
            run_json = run_dir / "run.json"
            if run_json.exists():
                try:
                    data = json.loads(run_json.read_text())
                    if data.get("app_id") == app_id:
                        scans.append({
                            "id": run_dir.name,
                            "status": data.get("status", "unknown"),
                            "started_at": data.get("start_time"),
                            "scan_mode": data.get("scan_mode"),
                        })
                except:
                    pass
    return sorted(scans, key=lambda x: x.get("started_at") or "", reverse=True)


# ─── Git Integration ─────────────────────────────────────────────────────────

@app.post("/api/git/scan")
async def scan_git_repo(request: GitRepoRequest) -> dict:
    """Scan a GitHub repository."""
    import uuid
    scan_id = f"git-{uuid.uuid4().hex[:8]}"
    project_root = str(Path(__file__).resolve().parent.parent.parent)

    cmd = ["uv", "run", "aegis", "-n", "--target", request.repo_url, "--scan-mode", request.scan_mode]
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

    async def run_scan():
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=project_root,
            )
            scan_processes[scan_id] = process
            active_scans[scan_id]["status"] = "running"
            active_scans[scan_id]["pid"] = process.pid
            stdout, _ = await process.communicate()
            runs_dir = Path("aegis_runs")
            if runs_dir.exists():
                latest_run = None
                latest_time = 0
                for d in runs_dir.iterdir():
                    if d.is_dir() and (d / "run.json").exists():
                        mtime = d.stat().st_mtime
                        if mtime > latest_time:
                            latest_time = mtime
                            latest_run = d
                if latest_run:
                    active_scans[scan_id]["status"] = "completed"
                    active_scans[scan_id]["actual_run_id"] = latest_run.name
                else:
                    active_scans[scan_id]["status"] = "failed"
        except Exception as e:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)

    asyncio.create_task(run_scan())
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

    import uuid
    scan_id = f"repo-{uuid.uuid4().hex[:8]}"
    project_root = str(Path(__file__).resolve().parent.parent.parent)

    cmd = ["uv", "run", "aegis", "-n", "--target", repo["url"], "--scan-mode", "standard"]

    active_scans[scan_id] = {
        "id": scan_id,
        "target": repo["url"],
        "scan_mode": "standard",
        "status": "starting",
        "started_at": datetime.now().isoformat(),
        "type": "repository",
    }

    async def run_scan():
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=project_root,
            )
            scan_processes[scan_id] = process
            active_scans[scan_id]["status"] = "running"
            active_scans[scan_id]["pid"] = process.pid
            stdout, _ = await process.communicate()
            repo["last_scan"] = datetime.now().isoformat()
            runs_dir = Path("aegis_runs")
            if runs_dir.exists():
                latest_run = None
                latest_time = 0
                for d in runs_dir.iterdir():
                    if d.is_dir() and (d / "run.json").exists():
                        mtime = d.stat().st_mtime
                        if mtime > latest_time:
                            latest_time = mtime
                            latest_run = d
                if latest_run:
                    active_scans[scan_id]["status"] = "completed"
                    active_scans[scan_id]["actual_run_id"] = latest_run.name
                else:
                    active_scans[scan_id]["status"] = "failed"
        except Exception as e:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)

    asyncio.create_task(run_scan())
    return {"scan_id": scan_id, "status": "started"}


# ─── Git OAuth Integration ───────────────────────────────────────────────────

# OAuth configuration storage (in production, use database)
oauth_configs: dict[str, dict[str, str]] = {}
oauth_tokens: dict[str, dict[str, Any]] = {}

class OAuthConfig(BaseModel):
    provider: str  # "github" or "gitlab"
    client_id: str
    client_secret: str
    redirect_uri: str = "http://localhost:8000/api/auth/callback"

class OAuthCallback(BaseModel):
    code: str
    state: str

@app.get("/api/auth/{provider}/config")
async def get_oauth_config(provider: str) -> dict:
    """Get OAuth configuration status for a provider."""
    config = oauth_configs.get(provider)
    if config:
        return {
            "provider": provider,
            "configured": True,
            "client_id": config["client_id"][:8] + "...",  # Masked
        }
    return {"provider": provider, "configured": False}

@app.post("/api/auth/{provider}/config")
async def set_oauth_config(provider: str, config: OAuthConfig) -> dict:
    """Set OAuth configuration for a provider."""
    oauth_configs[provider] = {
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "redirect_uri": config.redirect_uri,
    }
    return {"status": "configured", "provider": provider}

@app.get("/api/auth/{provider}/authorize")
async def authorize_provider(provider: str) -> dict:
    """Get authorization URL for OAuth flow."""
    config = oauth_configs.get(provider)
    if not config:
        raise HTTPException(status_code=400, detail=f"{provider} not configured")
    
    import secrets
    state = secrets.token_urlsafe(32)
    
    if provider == "github":
        auth_url = (
            f"https://github.com/login/oauth/authorize"
            f"?client_id={config['client_id']}"
            f"&redirect_uri={config['redirect_uri']}"
            f"&scope=repo,user"
            f"&state={state}"
        )
    elif provider == "gitlab":
        auth_url = (
            f"https://gitlab.com/oauth/authorize"
            f"?client_id={config['client_id']}"
            f"&redirect_uri={config['redirect_uri']}"
            f"&response_type=code"
            f"&scope=api+read_repository"
            f"&state={state}"
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
    
    # Store state for validation
    oauth_tokens[f"state:{state}"] = {"provider": provider}
    
    return {"auth_url": auth_url, "state": state}

@app.get("/api/auth/callback")
async def oauth_callback(code: str, state: str) -> dict:
    """Handle OAuth callback and exchange code for token."""
    # Validate state
    state_data = oauth_tokens.get(f"state:{state}")
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    provider = state_data["provider"]
    config = oauth_configs.get(provider)
    if not config:
        raise HTTPException(status_code=400, detail=f"{provider} not configured")
    
    # Exchange code for token
    import httpx
    
    if provider == "github":
        token_url = "https://github.com/login/oauth/access_token"
        token_data = {
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "code": code,
            "redirect_uri": config["redirect_uri"],
        }
        headers = {"Accept": "application/json"}
    elif provider == "gitlab":
        token_url = "https://gitlab.com/oauth/token"
        token_data = {
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": config["redirect_uri"],
        }
        headers = {}
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=token_data, headers=headers)
        token_response = response.json()
    
    if "access_token" not in token_response:
        raise HTTPException(status_code=400, detail="Failed to get access token")
    
    # Store token
    oauth_tokens[provider] = {
        "access_token": token_response["access_token"],
        "token_type": token_response.get("token_type", "bearer"),
        "scope": token_response.get("scope", ""),
    }
    
    # Clean up state
    del oauth_tokens[f"state:{state}"]
    
    return {"status": "connected", "provider": provider}

@app.get("/api/auth/{provider}/status")
async def get_auth_status(provider: str) -> dict:
    """Check if provider is connected."""
    token = oauth_tokens.get(provider)
    if token:
        return {"provider": provider, "connected": True, "scope": token.get("scope", "")}
    return {"provider": provider, "connected": False}

@app.delete("/api/auth/{provider}")
async def disconnect_provider(provider: str) -> dict:
    """Disconnect a provider."""
    if provider in oauth_tokens:
        del oauth_tokens[provider]
    return {"status": "disconnected", "provider": provider}

@app.get("/api/auth/{provider}/repos")
async def list_provider_repos(provider: str) -> list[dict]:
    """List repositories from connected provider."""
    token = oauth_tokens.get(provider)
    if not token:
        raise HTTPException(status_code=401, detail=f"{provider} not connected")
    
    import httpx
    
    access_token = token["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    if provider == "github":
        url = "https://api.github.com/user/repos?sort=updated&per_page=30"
    elif provider == "gitlab":
        url = "https://gitlab.com/api/v4/projects?membership=true&order_by=last_activity_at&per_page=30"
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        repos = response.json()
    
    # Normalize response
    normalized = []
    for repo in repos:
        if provider == "github":
            normalized.append({
                "id": repo["id"],
                "name": repo["name"],
                "full_name": repo["full_name"],
                "url": repo["html_url"],
                "clone_url": repo["clone_url"],
                "private": repo["private"],
                "description": repo.get("description", ""),
                "language": repo.get("language"),
                "updated_at": repo.get("updated_at"),
            })
        elif provider == "gitlab":
            normalized.append({
                "id": repo["id"],
                "name": repo["name"],
                "full_name": repo["path_with_namespace"],
                "url": repo["web_url"],
                "clone_url": repo["http_url_to_repo"],
                "private": repo["visibility"] == "private",
                "description": repo.get("description", ""),
                "language": repo.get("language"),
                "updated_at": repo.get("last_activity_at"),
            })
    
    return normalized


# ─── Settings ────────────────────────────────────────────────────────────────

@app.get("/api/settings")
async def get_settings() -> dict:
    """Get current settings, loading from disk if needed."""
    # First try to load from web settings file
    web_settings = _load_web_settings()
    
    # Then merge with main config
    settings = load_settings()
    
    model = web_settings.get("model") or settings.llm.model or ""
    api_key = web_settings.get("api_key") or settings.llm.api_key or ""
    api_base = web_settings.get("api_base") or settings.llm.api_base or ""
    image = web_settings.get("image") or settings.runtime.image
    
    # Apply to env if loaded from disk
    if web_settings.get("model"):
        os.environ["AEGIS_LLM"] = web_settings["model"]
    if web_settings.get("api_key"):
        os.environ["LLM_API_KEY"] = web_settings["api_key"]
    if web_settings.get("api_base"):
        os.environ["LLM_API_BASE"] = web_settings["api_base"]
    
    return {
        "model": model,
        "api_key": "***" if api_key else "",
        "api_base": api_base,
        "image": image,
        "backend": settings.runtime.backend,
        "telemetry": settings.telemetry.enabled,
    }


@app.put("/api/settings")
async def update_settings(update: SettingsUpdate) -> dict:
    """Update settings and persist to disk."""
    if update.model:
        os.environ["AEGIS_LLM"] = update.model
    if update.api_key:
        os.environ["LLM_API_KEY"] = update.api_key
    if update.api_base:
        os.environ["LLM_API_BASE"] = update.api_base
    if update.image:
        os.environ["AEGIS_IMAGE"] = update.image
    
    # Persist to disk
    settings_to_save = {}
    if update.model:
        settings_to_save["model"] = update.model
    if update.api_key:
        settings_to_save["api_key"] = update.api_key
    if update.api_base:
        settings_to_save["api_base"] = update.api_base
    if update.image:
        settings_to_save["image"] = update.image
    
    if settings_to_save:
        current = _load_web_settings()
        current.update(settings_to_save)
        _save_web_settings(current)
    
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


# ─── Credentials ─────────────────────────────────────────────────────────────

@app.get("/api/credentials")
async def list_credentials() -> list[dict]:
    """List all stored credentials (without sensitive values)."""
    return [
        {
            "id": cred["id"],
            "name": cred["name"],
            "site_url": cred["site_url"],
            "credential_type": cred["credential_type"],
            "has_username": bool(cred.get("username")),
            "has_password": bool(cred.get("password")),
            "has_api_key": bool(cred.get("api_key")),
            "has_token": bool(cred.get("token")),
            "notes": cred.get("notes", ""),
            "created_at": cred.get("created_at"),
        }
        for cred in credentials_store
    ]


@app.post("/api/credentials")
async def create_credential(data: CredentialCreate) -> dict:
    """Create a new credential entry."""
    import uuid
    
    cred_id = len(credentials_store) + 1
    credential = {
        "id": cred_id,
        "name": data.name,
        "site_url": data.site_url,
        "credential_type": data.credential_type,
        "username": _encrypt_value(data.username) if data.username else None,
        "password": _encrypt_value(data.password) if data.password else None,
        "api_key": _encrypt_value(data.api_key) if data.api_key else None,
        "token": _encrypt_value(data.token) if data.token else None,
        "cookies": _encrypt_value(data.cookies) if data.cookies else None,
        "notes": data.notes,
        "created_at": datetime.now().isoformat(),
    }
    credentials_store.append(credential)
    _save_credentials(credentials_store)  # Persist to disk
    
    return {
        "id": cred_id,
        "name": data.name,
        "status": "created"
    }


@app.get("/api/credentials/{cred_id}")
async def get_credential(cred_id: int) -> dict:
    """Get credential details (with decrypted values)."""
    cred = next((c for c in credentials_store if c["id"] == cred_id), None)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    return {
        "id": cred["id"],
        "name": cred["name"],
        "site_url": cred["site_url"],
        "credential_type": cred["credential_type"],
        "username": _decrypt_value(cred["username"]) if cred.get("username") else None,
        "password": _decrypt_value(cred["password"]) if cred.get("password") else None,
        "api_key": _decrypt_value(cred["api_key"]) if cred.get("api_key") else None,
        "token": _decrypt_value(cred["token"]) if cred.get("token") else None,
        "cookies": _decrypt_value(cred["cookies"]) if cred.get("cookies") else None,
        "notes": cred.get("notes", ""),
    }


@app.put("/api/credentials/{cred_id}")
async def update_credential(cred_id: int, data: CredentialCreate) -> dict:
    """Update an existing credential."""
    cred = next((c for c in credentials_store if c["id"] == cred_id), None)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    cred["name"] = data.name
    cred["site_url"] = data.site_url
    cred["credential_type"] = data.credential_type
    cred["username"] = _encrypt_value(data.username) if data.username else None
    cred["password"] = _encrypt_value(data.password) if data.password else None
    cred["api_key"] = _encrypt_value(data.api_key) if data.api_key else None
    cred["token"] = _encrypt_value(data.token) if data.token else None
    cred["cookies"] = _encrypt_value(data.cookies) if data.cookies else None
    cred["notes"] = data.notes
    
    return {"status": "updated"}


@app.delete("/api/credentials/{cred_id}")
async def delete_credential(cred_id: int) -> dict:
    """Delete a credential."""
    global credentials_store
    credentials_store = [c for c in credentials_store if c["id"] != cred_id]
    _save_credentials(credentials_store)  # Persist to disk
    return {"status": "deleted"}


@app.get("/api/credentials/{cred_id}/for-scan")
async def get_credential_for_scan(cred_id: int) -> dict:
    """Get credential formatted for use in a scan."""
    cred = next((c for c in credentials_store if c["id"] == cred_id), None)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    # Format for scan instruction
    cred_type = cred["credential_type"]
    username = _decrypt_value(cred["username"]) if cred.get("username") else None
    password = _decrypt_value(cred["password"]) if cred.get("password") else None
    token = _decrypt_value(cred["token"]) if cred.get("token") else None
    
    if cred_type == "credentials" and username and password:
        instruction = f"Login to {cred['site_url']} with username: {username} and password: {password}"
    elif cred_type == "api_key" and cred.get("api_key"):
        api_key = _decrypt_value(cred["api_key"])
        instruction = f"Use API key for {cred['site_url']}: {api_key}"
    elif cred_type == "token" and token:
        instruction = f"Use bearer token for {cred['site_url']}: {token}"
    else:
        instruction = f"Use credentials for {cred['site_url']}"
    
    return {
        "credential_id": cred_id,
        "site_url": cred["site_url"],
        "instruction": instruction,
    }


# ─── API Endpoint Management ────────────────────────────────────────────────

@app.get("/api/api-endpoints")
async def list_api_endpoints() -> list[dict]:
    """List all saved API endpoints."""
    return [
        {
            "id": ep["id"],
            "name": ep["name"],
            "base_url": ep["base_url"],
            "api_type": ep.get("api_type", "rest"),
            "auth_type": ep.get("auth_type"),
            "openapi_url": ep.get("openapi_url"),
            "headers": ep.get("headers"),
            "notes": ep.get("notes"),
            "created_at": ep.get("created_at"),
            "last_tested": ep.get("last_tested"),
            "total_requests": ep.get("total_requests", 0),
        }
        for ep in api_endpoints_store
    ]


@app.post("/api/api-endpoints")
async def create_api_endpoint(data: ApiEndpointCreate) -> dict:
    """Create a new API endpoint."""
    ep_id = max((ep["id"] for ep in api_endpoints_store), default=0) + 1
    endpoint = {
        "id": ep_id,
        "name": data.name,
        "base_url": data.base_url.rstrip("/"),
        "api_type": data.api_type,
        "auth_type": data.auth_type,
        "auth_config": data.auth_config,
        "openapi_url": data.openapi_url,
        "headers": data.headers or {},
        "notes": data.notes,
        "created_at": datetime.now().isoformat(),
        "last_tested": None,
        "total_requests": 0,
    }
    api_endpoints_store.append(endpoint)
    _save_api_endpoints(api_endpoints_store)
    return endpoint


@app.get("/api/api-endpoints/{ep_id}")
async def get_api_endpoint(ep_id: int) -> dict:
    """Get API endpoint details."""
    ep = next((e for e in api_endpoints_store if e["id"] == ep_id), None)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return ep


@app.put("/api/api-endpoints/{ep_id}")
async def update_api_endpoint(ep_id: int, data: ApiEndpointUpdate) -> dict:
    """Update an API endpoint."""
    ep = next((e for e in api_endpoints_store if e["id"] == ep_id), None)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    for key, val in data.model_dump(exclude_unset=True).items():
        if val is not None:
            ep[key] = val
    if ep.get("base_url"):
        ep["base_url"] = ep["base_url"].rstrip("/")
    _save_api_endpoints(api_endpoints_store)
    return ep


@app.delete("/api/api-endpoints/{ep_id}")
async def delete_api_endpoint(ep_id: int) -> dict:
    """Delete an API endpoint."""
    global api_endpoints_store
    api_endpoints_store = [e for e in api_endpoints_store if e["id"] != ep_id]
    _save_api_endpoints(api_endpoints_store)
    return {"status": "deleted"}


@app.post("/api/api-endpoints/{ep_id}/test")
async def test_api_endpoint(ep_id: int, request: ApiRequestTest) -> dict:
    """Send a test request to an API endpoint and record the result."""
    import httpx
    import time

    ep = next((e for e in api_endpoints_store if e["id"] == ep_id), None)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Build full URL
    base = ep["base_url"].rstrip("/")
    path = request.path if request.path.startswith("/") else f"/{request.path}"
    full_url = f"{base}{path}"

    # Merge headers
    headers = {**(ep.get("headers") or {}), **(request.headers or {})}

    # Add auth
    auth_type = ep.get("auth_type")
    auth_config = ep.get("auth_config") or {}
    if auth_type == "api_key" and auth_config.get("key"):
        key_name = auth_config.get("key_name", "X-API-Key")
        key_in = auth_config.get("key_in", "header")
        if key_in == "header":
            headers[key_name] = auth_config["key"]
        elif key_in == "query":
            sep = "&" if "?" in full_url else "?"
            full_url = f"{full_url}{sep}{key_name}={auth_config['key']}"
    elif auth_type == "bearer" and auth_config.get("token"):
        headers["Authorization"] = f"Bearer {auth_config['token']}"
    elif auth_type == "basic" and auth_config.get("username"):
        import base64
        cred = base64.b64encode(f"{auth_config['username']}:{auth_config.get('password', '')}".encode()).decode()
        headers["Authorization"] = f"Basic {cred}"

    # Set content type for body requests
    if request.body and request.method in ("POST", "PUT", "PATCH"):
        headers.setdefault("Content-Type", request.content_type)

    # Execute request
    start_time = time.time()
    try:
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            response = await client.request(
                method=request.method,
                url=full_url,
                headers=headers,
                content=request.body if request.body else None,
            )
            elapsed_ms = round((time.time() - start_time) * 1000)

            # Try to parse response body
            try:
                body = response.json()
                body_str = json.dumps(body, indent=2)
            except:
                body_str = response.text[:10000]

            result = {
                "status_code": response.status_code,
                "status_text": response.reason_phrase,
                "headers": dict(response.headers),
                "body": body_str,
                "elapsed_ms": elapsed_ms,
                "size_bytes": len(response.content),
            }
    except httpx.TimeoutException:
        elapsed_ms = round((time.time() - start_time) * 1000)
        result = {
            "status_code": 0,
            "status_text": "Timeout",
            "headers": {},
            "body": "Request timed out after 30 seconds",
            "elapsed_ms": elapsed_ms,
            "size_bytes": 0,
        }
    except Exception as e:
        elapsed_ms = round((time.time() - start_time) * 1000)
        result = {
            "status_code": 0,
            "status_text": "Error",
            "headers": {},
            "body": str(e),
            "elapsed_ms": elapsed_ms,
            "size_bytes": 0,
        }

    # Record in history
    history_entry = {
        "id": len(api_history_store) + 1,
        "endpoint_id": ep_id,
        "endpoint_name": ep["name"],
        "method": request.method,
        "path": request.path,
        "url": full_url,
        "status_code": result["status_code"],
        "elapsed_ms": result["elapsed_ms"],
        "size_bytes": result["size_bytes"],
        "timestamp": datetime.now().isoformat(),
        "request_headers": headers,
        "request_body": request.body,
        "response_headers": result["headers"],
        "response_body": result["body"],
    }
    api_history_store.append(history_entry)
    _save_api_history(api_history_store)

    # Update endpoint stats
    ep["last_tested"] = datetime.now().isoformat()
    ep["total_requests"] = ep.get("total_requests", 0) + 1
    _save_api_endpoints(api_endpoints_store)

    return {"request_id": history_entry["id"], **result}


@app.get("/api/api-history")
async def list_api_history(endpoint_id: Optional[int] = None, limit: int = 100) -> list[dict]:
    """List API request history, optionally filtered by endpoint."""
    history = api_history_store
    if endpoint_id is not None:
        history = [h for h in history if h["endpoint_id"] == endpoint_id]
    return history[-limit:]


@app.delete("/api/api-history")
async def clear_api_history() -> dict:
    """Clear all API request history."""
    global api_history_store
    api_history_store = []
    _save_api_history(api_history_store)
    return {"status": "cleared"}


@app.post("/api/openapi/parse")
async def parse_openapi_schema(data: dict) -> dict:
    """Parse an OpenAPI/Swagger schema and extract endpoints."""
    import httpx

    url = data.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(url)
            schema = response.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch schema: {str(e)}")

    # Parse OpenAPI 3.x
    if "openapi" in schema or "swagger" in schema:
        paths = schema.get("paths", {})
        info = schema.get("info", {})
        endpoints = []

        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ("get", "post", "put", "delete", "patch", "head", "options"):
                    endpoints.append({
                        "method": method.upper(),
                        "path": path,
                        "summary": details.get("summary", ""),
                        "operationId": details.get("operationId", ""),
                        "tags": details.get("tags", []),
                        "parameters": [
                            {
                                "name": p.get("name"),
                                "in": p.get("in"),
                                "required": p.get("required", False),
                                "schema": p.get("schema", {}),
                            }
                            for p in details.get("parameters", [])
                        ],
                        "requestBody": details.get("requestBody"),
                    })

        return {
            "title": info.get("title", "Unknown API"),
            "version": info.get("version", ""),
            "description": info.get("description", ""),
            "total_endpoints": len(endpoints),
            "endpoints": endpoints,
        }

    raise HTTPException(status_code=400, detail="Not a valid OpenAPI/Swagger schema")


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
    """Get overall statistics with test type breakdown, trends, and active scans."""
    total_scans = 0
    total_vulns = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    type_counts = {"webapp": 0, "api": 0, "git": 0, "mobile": 0, "other": 0}
    status_counts = {"completed": 0, "running": 0, "failed": 0, "pending": 0}
    trend_data = {}  # date -> { scans, vulns }
    recent_scans = []

    runs_dir = Path("aegis_runs")
    if runs_dir.exists():
        for run_dir in runs_dir.iterdir():
            if not run_dir.is_dir():
                continue
            total_scans += 1

            run_json = run_dir / "run.json"
            scan_type = "other"
            scan_status = "unknown"
            scan_start = None
            scan_target = run_dir.name

            if run_json.exists():
                try:
                    data = json.loads(run_json.read_text())
                    scan_status = data.get("status", "unknown")
                    scan_start = data.get("start_time")
                    scan_target = data.get("targets_info", [{}])[0].get("original", run_dir.name) if data.get("targets_info") else run_dir.name

                    # Detect scan type from run data or directory name
                    if data.get("type") == "api":
                        scan_type = "api"
                    elif data.get("type") == "mobile":
                        scan_type = "mobile"
                    elif data.get("type") == "git":
                        scan_type = "git"
                    elif data.get("scan_mode"):
                        scan_type = "webapp"
                    elif run_dir.name.startswith("api-"):
                        scan_type = "api"
                    elif run_dir.name.startswith("mobile-"):
                        scan_type = "mobile"
                    elif run_dir.name.startswith("git-"):
                        scan_type = "git"
                    else:
                        scan_type = "webapp"
                except:
                    pass

            # Count by type
            if scan_type in type_counts:
                type_counts[scan_type] += 1
            else:
                type_counts["other"] += 1

            # Count by status
            if scan_status in status_counts:
                status_counts[scan_status] += 1

            # Trend data (last 30 days)
            if scan_start:
                try:
                    date_str = scan_start[:10]  # YYYY-MM-DD
                    if date_str not in trend_data:
                        trend_data[date_str] = {"scans": 0, "vulns": 0}
                    trend_data[date_str]["scans"] += 1
                except:
                    pass

            vuln_file = run_dir / "vulnerabilities.json"
            if vuln_file.exists():
                try:
                    vulns = json.loads(vuln_file.read_text())
                    total_vulns += len(vulns)
                    for v in vulns:
                        sev = v.get("severity", "").lower()
                        if sev in severity_counts:
                            severity_counts[sev] += 1
                    # Add vulns to trend
                    if scan_start:
                        date_str = scan_start[:10]
                        if date_str in trend_data:
                            trend_data[date_str]["vulns"] += len(vulns)
                except:
                    pass

            # Recent scans (last 5)
            recent_scans.append({
                "id": run_dir.name,
                "target": scan_target,
                "type": scan_type,
                "status": scan_status,
                "started_at": scan_start,
            })

    # Sort recent scans by date
    recent_scans.sort(key=lambda x: x.get("started_at") or "", reverse=True)
    recent_scans = recent_scans[:5]

    # Build trend array for last 30 days
    from datetime import datetime, timedelta
    today = datetime.now().date()
    trend_array = []
    for i in range(29, -1, -1):
        date = (today - timedelta(days=i)).isoformat()
        entry = trend_data.get(date, {"scans": 0, "vulns": 0})
        trend_array.append({
            "date": date,
            "scans": entry["scans"],
            "vulns": entry["vulns"],
        })

    # Active scans
    active = []
    for scan_id, info in active_scans.items():
        if info.get("status") in ("running", "starting"):
            active.append({
                "id": scan_id,
                "target": info.get("target", ""),
                "type": info.get("type", "webapp"),
                "status": info["status"],
                "started_at": info.get("started_at"),
                "scan_mode": info.get("scan_mode", "standard"),
            })

    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "severity_breakdown": severity_counts,
        "type_breakdown": type_counts,
        "status_breakdown": status_counts,
        "trend": trend_array,
        "recent_scans": recent_scans,
        "active_scans": active,
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
