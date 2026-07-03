# Strix Web Dashboard

A full-featured web dashboard for viewing Strix penetration test results.

## Features

- **Dashboard** — Overview of all scans with severity breakdown, cost tracking, and auto-refresh
- **All Scans** — Table view with search, filter by status, and sort options
- **Scan Detail** — Deep dive into individual scans with expandable vulnerabilities, live log tailing, and LLM usage tracking
- **Vulnerabilities** — Aggregated view across all scans with severity filtering
- **Vulnerability Detail** — Full vulnerability deep-dive with PoC, technical analysis, and code locations
- **Dark/Light Theme** — Toggle between themes, persisted in localStorage
- **Export** — Download scan results as JSON or CSV
- **Live Updates** — SSE-powered real-time scan status monitoring

## Quick Start

### Windows (PowerShell)

```powershell
cd web
.\start.ps1
```

### Linux/macOS

```bash
cd web
chmod +x start.sh
./start.sh
```

### Manual Start

**Terminal 1 — Backend:**
```bash
cd D:\strix
uv run python -m uvicorn web.backend.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Frontend:**
```bash
cd web/frontend
npm install
npm run dev
```

Then open **http://localhost:5173** in your browser.

## Architecture

```
web/
├── backend/
│   ├── main.py              # FastAPI server
│   └── requirements.txt     # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Layout.jsx   # Header, nav, theme provider
│   │   │   └── ui.jsx       # Shared UI components
│   │   ├── lib/
│   │   │   └── api.js       # API client utilities
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx        # Main dashboard
│   │   │   ├── AllScans.jsx         # Scan table view
│   │   │   ├── ScanDetail.jsx       # Individual scan view
│   │   │   ├── AllVulnerabilities.jsx  # All vulns view
│   │   │   └── VulnerabilityDetail.jsx # Single vuln view
│   │   ├── App.jsx          # Router
│   │   ├── index.css        # Tailwind CSS
│   │   └── main.jsx         # Entry point
│   └── package.json
├── start.sh                 # Linux/macOS start script
├── start.ps1                # Windows start script
└── README.md
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/scans` | List all scans (supports `?search=`, `?status=`, `?sort=`) |
| GET | `/api/scans/{id}` | Get scan detail |
| GET | `/api/scans/{id}/vulnerabilities` | Get vulns (supports `?severity=`) |
| GET | `/api/scans/{id}/vulnerabilities/{vuln_id}` | Get single vuln detail |
| GET | `/api/scans/{id}/log` | Get scan log (supports `?lines=`, `?offset=`) |
| GET | `/api/scans/{id}/export` | Export as JSON or CSV (`?format=json\|csv`) |
| GET | `/api/scans/{id}/stream` | SSE live status updates |
| GET | `/api/stats` | Aggregated statistics |

## Tech Stack

- **Backend:** Python, FastAPI, Uvicorn
- **Frontend:** React 19, Vite 8, Tailwind CSS 4
- **Icons:** Lucide React
- **Routing:** React Router v7
