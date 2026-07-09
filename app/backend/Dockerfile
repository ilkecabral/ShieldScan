# ============================================================
# ShieldScan API — Production Dockerfile
# Build context: ./app  (run: docker build -f backend/Dockerfile ./app)
# Multi-stage build: keeps the final image lean (~250MB)
#
# What changed from v1:
#   - Build context expanded to ./app so alembic/ is included
#   - Added postgresql-client for pg_isready in entrypoint
#   - Switched from CMD to ENTRYPOINT (entrypoint.sh runs migrations then uvicorn)
# ============================================================

# ── Stage 1: builder ───────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build deps (needed for some Python packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Build context is ./app — requirements.txt lives in backend/
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ───────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Install runtime deps:
#   - postgresql-client: provides pg_isready (used in entrypoint.sh)
#   - Trivy: CWPP container scanner (USE_MOCK_CWPP=False to activate)
# Note: apt-key is removed in Debian trixie — use gpg keyring method instead.
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl libpq5 postgresql-client gpg gpg-agent \
    && mkdir -p /etc/apt/keyrings \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
       | gpg --dearmor > /etc/apt/keyrings/trivy.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
       > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source (build context is ./app)
COPY backend/ ./backend/
COPY alembic/  ./alembic/
COPY alembic.ini ./

# Copy + make entrypoint executable before switching to non-root
COPY backend/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Non-root user (security best practice — never run as root in prod)
RUN useradd -m -u 1001 -s /bin/bash shieldscan \
    && chown -R shieldscan:shieldscan /app
USER shieldscan

# Pre-download Trivy vulnerability DB so first scan doesn't block
RUN trivy image --download-db-only --no-progress 2>/dev/null || true

EXPOSE 8000

# Health check — used by docker-compose, ALB, and Oracle Cloud load balancer
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# entrypoint.sh: waits for DB → runs alembic upgrade head → starts uvicorn
ENTRYPOINT ["/app/entrypoint.sh"]
