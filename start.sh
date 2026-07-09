#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ShieldScan — Quick Start (Backend + Frontend)
# Opens two background processes + launches the browser.
# For Ollama (AI), see Terminal 2 instructions below.
#
# Usage: ./start.sh
# Stop:  ./stop.sh
# ─────────────────────────────────────────────────────────────

PROJ_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$PROJ_DIR/venv"
PYTHON="$VENV/bin/python3.11"
UVICORN="$VENV/bin/uvicorn"

cd "$PROJ_DIR"

echo ""
echo "🛡  Starting ShieldScan..."
echo "────────────────────────────────────────"

# ── Sanity checks ─────────────────────────────────────────
if [ ! -f "$UVICORN" ]; then
  echo "ERROR: venv not found. Run: python3.11 -m venv venv && venv/bin/pip install -r app/backend/requirements.txt"
  exit 1
fi

if [ ! -f ".env" ]; then
  echo "ERROR: .env file not found. Run setup.sh first."
  exit 1
fi

# ── Kill any stale processes ───────────────────────────────
pkill -f "uvicorn backend.main" 2>/dev/null
pkill -f "http.server 3000" 2>/dev/null
sleep 1

# ── Backend ────────────────────────────────────────────────
echo "Starting backend on http://localhost:8000 ..."
cd "$PROJ_DIR/app"
"$UVICORN" backend.main:app --port 8000 --host 0.0.0.0 > "$PROJ_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo "  Backend PID: $BACKEND_PID"

# Wait for backend to be ready
sleep 3
if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
  echo "  WARNING: Backend may not be ready yet. Check backend.log if you see errors."
fi

# ── Frontend ───────────────────────────────────────────────
cd "$PROJ_DIR/app/frontend"
echo "Starting frontend on http://localhost:3000 ..."
"$PYTHON" -m http.server 3000 > "$PROJ_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
echo "  Frontend PID: $FRONTEND_PID"

# Save PIDs for stop.sh
echo "$BACKEND_PID" > "$PROJ_DIR/.pids"
echo "$FRONTEND_PID" >> "$PROJ_DIR/.pids"

sleep 1
echo ""
echo "────────────────────────────────────────"
echo "✅  ShieldScan is running!"
echo ""
echo "  Open: http://localhost:3000"
echo ""
echo "  ⚠  For AI chat, also run in a separate terminal:"
echo "      ollama serve"
echo ""
echo "  Logs: backend.log / frontend.log"
echo "  Stop: ./stop.sh"
echo "────────────────────────────────────────"
echo ""

# Open browser (macOS)
sleep 1
open "http://localhost:3000" 2>/dev/null || true
