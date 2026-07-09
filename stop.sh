#!/bin/bash
# ShieldScan — Stop all services

PROJ_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Stopping ShieldScan..."

pkill -f "uvicorn backend.main" 2>/dev/null && echo "  ✓ Backend stopped"
pkill -f "http.server 3000" 2>/dev/null && echo "  ✓ Frontend stopped"

if [ -f "$PROJ_DIR/.pids" ]; then
  while read pid; do
    kill "$pid" 2>/dev/null
  done < "$PROJ_DIR/.pids"
  rm "$PROJ_DIR/.pids"
fi

echo "Done."
