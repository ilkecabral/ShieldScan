#!/bin/bash
# =============================================================
# ShieldScan API — Container Entrypoint
# Runs on every container start:
#   1. Waits for PostgreSQL to be ready
#   2. Runs Alembic migrations (idempotent — safe to run every start)
#   3. Starts uvicorn
# =============================================================
set -e

echo "=== ShieldScan API starting ==="
echo "ENV=${ENV:-development}"
echo "AI_PROVIDER=${AI_PROVIDER:-ollama}"

# ── Wait for PostgreSQL ────────────────────────────────────────
# docker-compose healthcheck handles ordering for compose deployments,
# but we double-check here for standalone / Oracle Cloud bare-Docker runs.
if [[ "${DATABASE_URL:-}" == postgresql* ]]; then
    DB_HOST=$(python3 -c "
from urllib.parse import urlparse; import os
u = urlparse(os.environ['DATABASE_URL'])
print(u.hostname)
" 2>/dev/null || echo "db")

    DB_PORT=$(python3 -c "
from urllib.parse import urlparse; import os
u = urlparse(os.environ['DATABASE_URL'])
print(u.port or 5432)
" 2>/dev/null || echo "5432")

    echo "Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}..."
    RETRIES=30
    until pg_isready -h "${DB_HOST}" -p "${DB_PORT}" -q 2>/dev/null; do
        RETRIES=$((RETRIES - 1))
        if [ "$RETRIES" -le 0 ]; then
            echo "ERROR: PostgreSQL not ready after 30 seconds. Check DB_HOST and credentials."
            exit 1
        fi
        sleep 1
    done
    echo "PostgreSQL is ready"
fi

# ── Run Alembic migrations ─────────────────────────────────────
# 'alembic upgrade head' is idempotent — it's safe to run on every start.
# It detects the current DB state and only applies missing migrations.
echo "Running database migrations..."
cd /app
alembic upgrade head
echo "Migrations complete"

# ── Start the API ──────────────────────────────────────────────
echo "Starting uvicorn with ${UVICORN_WORKERS:-2} workers..."
exec uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers "${UVICORN_WORKERS:-2}" \
    --access-log \
    --log-level info
