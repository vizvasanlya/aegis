#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "╔══════════════════════════════════════╗"
echo "║       STRIX DASHBOARD                ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check if strix_runs directory exists
if [ ! -d "$PROJECT_ROOT/strix_runs" ]; then
  echo "⚠  No strix_runs directory found at $PROJECT_ROOT/strix_runs"
  echo "   Run a scan first: strix --target https://example.com"
  echo ""
fi

# Start backend
echo "Starting backend on http://localhost:8000 ..."
cd "$PROJECT_ROOT"
python -m uvicorn web.backend.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# Wait for backend to be ready
sleep 2

# Start frontend
echo "Starting frontend on http://localhost:5173 ..."
cd "$SCRIPT_DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "╔══════════════════════════════════════╗"
echo "║  Dashboard:  http://localhost:5173   ║"
echo "║  API:        http://localhost:8000   ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "Press Ctrl+C to stop both servers"

# Cleanup on exit
cleanup() {
  echo ""
  echo "Shutting down..."
  kill $BACKEND_PID 2>/dev/null || true
  kill $FRONTEND_PID 2>/dev/null || true
  wait $BACKEND_PID 2>/dev/null || true
  wait $FRONTEND_PID 2>/dev/null || true
  echo "Done."
}
trap cleanup EXIT INT TERM

wait
