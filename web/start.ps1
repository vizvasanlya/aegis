$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "╔══════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║       STRIX DASHBOARD                ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

if (-not (Test-Path "$ProjectRoot\strix_runs")) {
  Write-Host "⚠  No strix_runs directory found at $ProjectRoot\strix_runs" -ForegroundColor Yellow
  Write-Host "   Run a scan first: strix --target https://example.com" -ForegroundColor Yellow
  Write-Host ""
}

# Start backend
Write-Host "Starting backend on http://localhost:8000 ..." -ForegroundColor Cyan
$backend = Start-Process -NoNewWindow -FilePath "python" -ArgumentList "-m uvicorn web.backend.main:app --host 0.0.0.0 --port 8000 --reload" -WorkingDirectory $ProjectRoot -PassThru

Start-Sleep -Seconds 2

# Start frontend
Write-Host "Starting frontend on http://localhost:5173 ..." -ForegroundColor Cyan
$frontend = Start-Process -NoNewWindow -FilePath "npm" -ArgumentList "run dev" -WorkingDirectory "$PSScriptRoot\frontend" -PassThru

Write-Host ""
Write-Host "╔══════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  Dashboard:  http://localhost:5173   ║" -ForegroundColor Green
Write-Host "║  API:        http://localhost:8000   ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop both servers" -ForegroundColor Gray

try {
  Wait-Process -Id $backend.Id, $frontend.Id
} finally {
  Stop-Process -Id $backend.Id -ErrorAction SilentlyContinue
  Stop-Process -Id $frontend.Id -ErrorAction SilentlyContinue
  Write-Host "Done." -ForegroundColor Gray
}
