"""Strix Web Dashboard Backend — FastAPI server for scan results."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import re
import secrets
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Strix Dashboard API",
    description="API server for Strix scan results and vulnerability data",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Resolve runs dir from env or default to <project>/strix_runs
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RUNS_DIR = Path(os.environ.get("STRIX_RUNS_DIR", str(_PROJECT_ROOT / "strix_runs")))
UPLOADS_DIR = _PROJECT_ROOT / "uploads"


def _get_runs_dir() -> Path:
    if RUNS_DIR.exists():
        return RUNS_DIR
    raise HTTPException(status_code=404, detail="strix_runs directory not found")


# Allowed scan ID pattern: alphanumeric, hyphens, underscores only
_SAFE_SCAN_ID = re.compile(r'^[a-zA-Z0-9_-]+$')


def _validate_scan_id(scan_id: str) -> str:
    """Validate scan_id to prevent path traversal."""
    if not _SAFE_SCAN_ID.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID")
    return scan_id


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read {path.name}: {exc}") from exc


def _safe_read_json(path: Path) -> dict[str, Any] | None:
    """Read JSON without raising — returns None on failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


# ── Health ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "runs_dir": str(RUNS_DIR)}


# ── Scans ────────────────────────────────────────────────────────────────────

@app.get("/api/scans")
async def list_scans(
    search: str | None = Query(None, description="Search in run name, targets, or status"),
    status: str | None = Query(None, description="Filter by status"),
    sort: str = Query("newest", description="Sort order: newest, oldest, vulns"),
) -> list[dict[str, Any]]:
    """List all scan runs with summary info, supporting search, filter, sort."""
    runs_dir = _get_runs_dir()
    scans: list[dict[str, Any]] = []

    for run_dir in runs_dir.iterdir():
        if not run_dir.is_dir():
            continue
        run_data = _safe_read_json(run_dir / "run.json")
        if run_data is None:
            continue

        # Count vulns from vulnerabilities.json
        vulns = _load_vulnerabilities(run_dir)
        severity_breakdown = _severity_breakdown(vulns)

        scan_entry = {
            "id": run_dir.name,
            "run_name": run_data.get("run_name", run_dir.name),
            "status": run_data.get("status", "unknown"),
            "start_time": run_data.get("start_time"),
            "end_time": run_data.get("end_time"),
            "scan_mode": run_data.get("scan_mode", "deep"),
            "targets": _format_targets(run_data.get("targets_info", [])),
            "targets_info": run_data.get("targets_info", []),
            "instruction": run_data.get("instruction", ""),
            "non_interactive": run_data.get("non_interactive", False),
            "vulnerability_count": len(vulns),
            "severity_breakdown": severity_breakdown,
            "llm_usage": run_data.get("llm_usage", {}),
        }

        # Compute duration
        if scan_entry["start_time"] and scan_entry["end_time"]:
            try:
                from datetime import datetime, timezone

                t1 = datetime.fromisoformat(scan_entry["start_time"].replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(scan_entry["end_time"].replace("Z", "+00:00"))
                scan_entry["duration_seconds"] = int((t2 - t1).total_seconds())
            except (ValueError, TypeError):
                scan_entry["duration_seconds"] = None
        else:
            scan_entry["duration_seconds"] = None

        scans.append(scan_entry)

    # Filter by status
    if status:
        scans = [s for s in scans if s["status"] == status]

    # Search
    if search:
        q = search.lower()
        scans = [
            s for s in scans
            if q in s["run_name"].lower()
            or q in s["status"].lower()
            or any(q in t.get("value", "").lower() for t in s["targets"])
            or q in (s.get("instruction") or "").lower()
        ]

    # Sort
    if sort == "oldest":
        scans.sort(key=lambda s: s.get("start_time") or "")
    elif sort == "vulns":
        scans.sort(key=lambda s: s["vulnerability_count"], reverse=True)
    else:  # newest (default)
        scans.sort(key=lambda s: s.get("start_time") or "", reverse=True)

    return scans


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    """Get detailed info for a specific scan."""
    scan_id = _validate_scan_id(scan_id)
    runs_dir = _get_runs_dir()
    scan_dir = runs_dir / scan_id

    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    run_data = _safe_read_json(scan_dir / "run.json")
    if run_data is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' has no run.json")

    vulnerabilities = _load_vulnerabilities(scan_dir)

    # Get scan log (last 500 lines for detail view)
    log_content = ""
    log_file = scan_dir / "strix.log"
    if log_file.exists():
        try:
            lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
            log_content = "\n".join(lines[-500:])
        except OSError:
            pass

    # Duration
    duration_seconds = None
    if run_data.get("start_time") and run_data.get("end_time"):
        try:
            from datetime import datetime, timezone

            t1 = datetime.fromisoformat(run_data["start_time"].replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(run_data["end_time"].replace("Z", "+00:00"))
            duration_seconds = int((t2 - t1).total_seconds())
        except (ValueError, TypeError):
            pass

    return {
        "id": scan_dir.name,
        "run_name": run_data.get("run_name", scan_dir.name),
        "status": run_data.get("status", "unknown"),
        "start_time": run_data.get("start_time"),
        "end_time": run_data.get("end_time"),
        "duration_seconds": duration_seconds,
        "scan_mode": run_data.get("scan_mode", "deep"),
        "targets": _format_targets(run_data.get("targets_info", [])),
        "targets_info": run_data.get("targets_info", []),
        "instruction": run_data.get("instruction", ""),
        "non_interactive": run_data.get("non_interactive", False),
        "llm_usage": run_data.get("llm_usage", {}),
        "vulnerabilities": vulnerabilities,
        "vulnerability_count": len(vulnerabilities),
        "severity_breakdown": _severity_breakdown(vulnerabilities),
        "log": log_content,
    }


# ── Vulnerabilities ──────────────────────────────────────────────────────────

@app.get("/api/scans/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: str | None = Query(None, description="Filter by severity: critical, high, medium, low"),
) -> list[dict[str, Any]]:
    """Get all vulnerability reports for a scan, optionally filtered by severity."""
    scan_id = _validate_scan_id(scan_id)
    runs_dir = _get_runs_dir()
    scan_dir = runs_dir / scan_id

    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    vulns = _load_vulnerabilities(scan_dir)

    if severity:
        vulns = [v for v in vulns if (v.get("severity") or "").lower() == severity.lower()]

    return vulns


@app.get("/api/scans/{scan_id}/vulnerabilities/{vuln_id}")
async def get_vulnerability_detail(scan_id: str, vuln_id: str) -> dict[str, Any]:
    """Get full detail for a single vulnerability."""
    scan_id = _validate_scan_id(scan_id)
    runs_dir = _get_runs_dir()
    scan_dir = runs_dir / scan_id

    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    vulns = _load_vulnerabilities(scan_dir)

    # Try matching by id field or filename
    for v in vulns:
        vid = v.get("id", "")
        if vid == vuln_id or vuln_id in v.get("_file", ""):
            # Also try to load the markdown file for full content
            md_path = scan_dir / v.get("_md_file", "")
            if md_path.exists():
                try:
                    v["markdown_content"] = md_path.read_text(encoding="utf-8")
                except OSError:
                    pass
            return v

    raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found")


# ── Log ──────────────────────────────────────────────────────────────────────

@app.get("/api/scans/{scan_id}/log")
async def get_scan_log(
    scan_id: str,
    lines: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Get scan log with pagination support."""
    scan_id = _validate_scan_id(scan_id)
    runs_dir = _get_runs_dir()
    scan_dir = runs_dir / scan_id
    log_file = scan_dir / "strix.log"

    if not log_file.exists():
        raise HTTPException(status_code=404, detail=f"No log file for scan '{scan_id}'")

    try:
        all_lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(all_lines)
        sliced = all_lines[offset : offset + lines]
        return {
            "log": "\n".join(sliced),
            "total_lines": total,
            "offset": offset,
            "limit": lines,
        }
    except OSError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Stats ────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats() -> dict[str, Any]:
    """Get overall statistics across all scans."""
    runs_dir = _get_runs_dir()
    total_scans = 0
    total_vulns = 0
    statuses: dict[str, int] = {}
    severity_totals: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_cost = 0.0
    total_tokens = 0
    scan_durations: list[int] = []

    for run_dir in runs_dir.iterdir():
        if not run_dir.is_dir():
            continue
        run_data = _safe_read_json(run_dir / "run.json")
        if run_data is None:
            continue

        total_scans += 1
        status = run_data.get("status", "unknown")
        statuses[status] = statuses.get(status, 0) + 1

        # Vulnerabilities
        vulns = _load_vulnerabilities(run_dir)
        total_vulns += len(vulns)
        for v in vulns:
            sev = (v.get("severity") or "unknown").lower()
            if sev in severity_totals:
                severity_totals[sev] += 1

        # LLM usage
        usage = run_data.get("llm_usage", {})
        total_cost += usage.get("cost", 0) or 0
        total_tokens += usage.get("total_tokens", 0) or 0

        # Duration
        if run_data.get("start_time") and run_data.get("end_time"):
            try:
                from datetime import datetime, timezone

                t1 = datetime.fromisoformat(run_data["start_time"].replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(run_data["end_time"].replace("Z", "+00:00"))
                scan_durations.append(int((t2 - t1).total_seconds()))
            except (ValueError, TypeError):
                pass

    avg_duration = int(sum(scan_durations) / len(scan_durations)) if scan_durations else 0

    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "statuses": statuses,
        "severity_breakdown": severity_totals,
        "total_cost": round(total_cost, 4),
        "total_tokens": total_tokens,
        "average_duration_seconds": avg_duration,
    }


# ── Export ───────────────────────────────────────────────────────────────────

@app.get("/api/scans/{scan_id}/export")
async def export_scan(
    scan_id: str,
    format: str = Query("json", description="Export format: json, csv"),
) -> StreamingResponse:
    """Export scan results as JSON or CSV."""
    scan_id = _validate_scan_id(scan_id)
    runs_dir = _get_runs_dir()
    scan_dir = runs_dir / scan_id

    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    vulns = _load_vulnerabilities(scan_dir)
    run_data = _safe_read_json(scan_dir / "run.json") or {}

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "title", "severity", "cvss", "cwe", "endpoint", "method", "timestamp"])
        for v in vulns:
            writer.writerow([
                v.get("id", ""),
                v.get("title", ""),
                v.get("severity", ""),
                v.get("cvss", ""),
                v.get("cwe", ""),
                v.get("endpoint", ""),
                v.get("method", ""),
                v.get("timestamp", ""),
            ])
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={scan_id}_vulnerabilities.csv"},
        )

    # JSON export
    export_data = {
        "scan": {
            "id": scan_dir.name,
            "run_name": run_data.get("run_name"),
            "status": run_data.get("status"),
            "start_time": run_data.get("start_time"),
            "end_time": run_data.get("end_time"),
            "scan_mode": run_data.get("scan_mode"),
            "targets": _format_targets(run_data.get("targets_info", [])),
        },
        "vulnerabilities": vulns,
        "summary": {
            "total": len(vulns),
            "severity_breakdown": _severity_breakdown(vulns),
        },
    }
    return StreamingResponse(
        iter([json.dumps(export_data, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={scan_id}_report.json"},
    )


# ── SSE: Live scan status ───────────────────────────────────────────────────

@app.get("/api/scans/{scan_id}/stream")
async def stream_scan_status(scan_id: str):
    """Server-Sent Events endpoint for live scan status updates."""
    scan_id = _validate_scan_id(scan_id)

    async def event_generator():
        runs_dir = _get_runs_dir()
        scan_dir = runs_dir / scan_id
        last_vuln_count = 0

        while True:
            run_data = _safe_read_json(scan_dir / "run.json")
            if run_data is None:
                yield f"data: {json.dumps({'error': 'Scan not found'})}\n\n"
                break

            vulns = _load_vulnerabilities(scan_dir)
            current_count = len(vulns)

            # Only send update if something changed
            if current_count != last_vuln_count or last_vuln_count == 0:
                usage = run_data.get("llm_usage", {})
                payload = {
                    "status": run_data.get("status", "unknown"),
                    "vulnerability_count": current_count,
                    "severity_breakdown": _severity_breakdown(vulns),
                    "total_tokens": usage.get("total_tokens", 0),
                    "cost": usage.get("cost", 0),
                }
                yield f"data: {json.dumps(payload)}\n\n"
                last_vuln_count = current_count

            # Stop streaming if scan is done
            if run_data.get("status") in ("completed", "failed", "stopped"):
                break

            await asyncio.sleep(3)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _format_targets(targets_info: list[dict[str, Any]]) -> list[dict[str, str]]:
    result = []
    for target in targets_info:
        ttype = target.get("type", "unknown")
        details = target.get("details") or {}
        if ttype == "web_application":
            value = details.get("target_url", "")
        elif ttype == "repository":
            value = details.get("target_repo", "")
        elif ttype == "local_code":
            value = details.get("target_path", "")
        elif ttype == "ip_address":
            value = details.get("target_ip", "")
        else:
            value = target.get("original", "")
        result.append({"type": ttype, "value": value})
    return result


def _load_vulnerabilities(scan_dir: Path) -> list[dict[str, Any]]:
    """Load vulnerabilities, preferring vulnerabilities.json, falling back to individual files."""
    vulns: list[dict[str, Any]] = []

    # Try vulnerabilities.json first (structured data)
    vuln_json = scan_dir / "vulnerabilities.json"
    if vuln_json.exists():
        try:
            data = json.loads(vuln_json.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        vulns.append(item)
                return vulns
        except (json.JSONDecodeError, OSError):
            pass

    # Fallback: load individual vulnerability files from multiple locations
    for subpath in ("vulnerabilities", "reports", "."):
        report_dir = scan_dir / subpath
        if not report_dir.exists():
            continue

        # Try .json files
        for json_file in sorted(report_dir.glob("*.json")):
            data = _safe_read_json(json_file)
            if data and isinstance(data, dict) and (
                data.get("vulnerability_name") or data.get("title") or data.get("id")
            ):
                data["_file"] = json_file.name
                vulns.append(data)

        # Try .md files — extract key fields from markdown
        for md_file in sorted(report_dir.glob("*.md")):
            if md_file.name.startswith("vuln-"):
                try:
                    content = md_file.read_text(encoding="utf-8")
                    parsed = _parse_vuln_markdown(content)
                    if parsed:
                        parsed["_file"] = md_file.name
                        parsed["_md_file"] = str(md_file.relative_to(scan_dir))
                        parsed.setdefault("id", md_file.stem)
                        vulns.append(parsed)
                except OSError:
                    continue

    return vulns


def _parse_vuln_markdown(content: str) -> dict[str, Any] | None:
    """Extract key fields from a vulnerability markdown file."""
    result: dict[str, Any] = {}
    lines = content.split("\n")

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("# ") and not result.get("title"):
            result["title"] = stripped[2:].strip()
        elif stripped.lower().startswith("**severity:**"):
            result["severity"] = stripped.split(":", 1)[1].strip().upper()
        elif stripped.lower().startswith("**cwe:**"):
            result["cwe"] = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("**cvss:**"):
            result["cvss"] = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("**target:**"):
            result["target"] = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("**endpoint:**"):
            result["endpoint"] = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("**method:**"):
            result["method"] = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("**found:**"):
            result["timestamp"] = stripped.split(":", 1)[1].strip()

    # Try to extract description from the first paragraph after heading
    in_description = False
    desc_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## Description"):
            in_description = True
            continue
        if in_description:
            if stripped.startswith("##"):
                break
            if stripped:
                desc_lines.append(stripped)
    if desc_lines:
        result["description"] = " ".join(desc_lines)

    return result if result.get("title") else None


def _severity_breakdown(vulns: list[dict[str, Any]]) -> dict[str, int]:
    breakdown: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for v in vulns:
        sev = (v.get("severity") or "unknown").lower()
        if sev in breakdown:
            breakdown[sev] += 1
        else:
            breakdown["unknown"] += 1
    return breakdown


# ── Mobile App Scan ───────────────────────────────────────────────────────────

UPLOADS_DIR.mkdir(exist_ok=True)

ALLOWED_MOBILE_EXTENSIONS = {".apk", ".ipa"}

_ACTIVE_SCANS: dict[str, dict[str, Any]] = {}


@app.post("/api/mobile/scan")
async def start_mobile_scan(
    file: UploadFile = File(...),
    scan_mode: str = Form("standard"),
    instruction: str = Form(""),
):
    """Upload APK/IPA and start a mobile security scan."""
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_MOBILE_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(ALLOWED_MOBILE_EXTENSIONS)}",
        )

    # Save uploaded file
    safe_name = f"{uuid.uuid4().hex}{ext}"
    dest = UPLOADS_DIR / safe_name
    try:
        content = await file.read()
        dest.write_bytes(content)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {exc}") from exc

    # Build the CLI command
    flag = "--apk" if ext == ".apk" else "--ipa"
    project_root = str(_PROJECT_ROOT)
    run_name = f"mobile-{Path(file.filename or 'app').stem}-{secrets.token_hex(2)}"

    cmd = [
        "uv", "run", "python", "-m", "aegis",
        flag, str(dest),
        "--scan-mode", scan_mode,
        "--name", run_name,
        "-n",
    ]
    if instruction:
        cmd += ["--instruction", instruction]

    scan_id = run_name

    _ACTIVE_SCANS[scan_id] = {
        "scan_id": scan_id,
        "run_name": run_name,
        "status": "starting",
        "target": file.filename,
        "target_type": ext.lstrip("."),
        "scan_mode": scan_mode,
        "instruction": instruction,
    }

    # Launch scan in background
    async def _run_scan():
        try:
            _ACTIVE_SCANS[scan_id]["status"] = "running"
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=project_root,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                _ACTIVE_SCANS[scan_id]["status"] = "completed"
            else:
                _ACTIVE_SCANS[scan_id]["status"] = "failed"
                _ACTIVE_SCANS[scan_id]["error"] = stderr.decode(errors="replace")[:2000]
        except Exception as exc:
            _ACTIVE_SCANS[scan_id]["status"] = "failed"
            _ACTIVE_SCANS[scan_id]["error"] = str(exc)

    asyncio.create_task(_run_scan())

    return {
        "scan_id": scan_id,
        "status": "started",
        "target": file.filename,
        "target_type": ext.lstrip("."),
        "message": f"Mobile scan started for {file.filename}",
    }


@app.get("/api/mobile/scans")
async def list_mobile_scans():
    """List active and historical mobile scans."""
    return list(_ACTIVE_SCANS.values())


@app.get("/api/mobile/scans/{scan_id}")
async def get_mobile_scan(scan_id: str):
    """Get status of a mobile scan."""
    scan = _ACTIVE_SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Mobile scan not found")
    return scan


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn  # noqa: PLC0415

    uvicorn.run(app, host="0.0.0.0", port=8000)
