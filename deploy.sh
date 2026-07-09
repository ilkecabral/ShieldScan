#!/bin/bash
# ============================================================
# ShieldScan — Oracle Cloud / Hetzner / Any Ubuntu VPS
# One-command deploy script
#
# Run this on a fresh Ubuntu 22.04 ARM or x86 server:
#   curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/shieldscan/main/deploy.sh | bash
#
# Or clone the repo first and run locally:
#   git clone https://github.com/YOUR_ORG/shieldscan.git
#   cd shieldscan
#   bash deploy.sh
#
# What this script does:
#   1. Installs Docker + Docker Compose v2
#   2. Clones/updates the ShieldScan repo
#   3. Walks you through creating .env (or uses existing)
#   4. Starts the full stack with docker compose
#   5. Runs Alembic migrations (via entrypoint.sh on container start)
#   6. Prints the URL and next steps
#
# After this, run setup-ssl.sh to add HTTPS with Let's Encrypt.
# ============================================================

set -e

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC}   $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Config ───────────────────────────────────────────────────
REPO_URL="${REPO_URL:-https://github.com/YOUR_ORG/shieldscan.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/shieldscan}"
BRANCH="${BRANCH:-main}"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         ShieldScan — Production Deployment           ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: System requirements ──────────────────────────────
info "Checking system..."

# Must run as root or with sudo
if [ "$EUID" -ne 0 ]; then
    error "Please run as root: sudo bash deploy.sh"
fi

OS=$(lsb_release -si 2>/dev/null || echo "Unknown")
if [[ "$OS" != "Ubuntu" && "$OS" != "Debian" ]]; then
    warn "This script is tested on Ubuntu 22.04. Proceeding anyway..."
fi

# ── Step 2: Install Docker ────────────────────────────────────
if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release

    # Docker official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Docker apt repo
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    success "Docker installed"
else
    success "Docker already installed ($(docker --version | cut -d' ' -f3 | tr -d ','))"
fi

# Add current non-root user to docker group if exists
if [ -n "$SUDO_USER" ]; then
    usermod -aG docker "$SUDO_USER" || true
fi

# ── Step 3: Install Python (for key generation) ───────────────
if ! command -v python3 &>/dev/null; then
    info "Installing Python 3..."
    apt-get install -y python3 python3-pip
fi

# ── Step 4: Open firewall ports ───────────────────────────────
info "Opening firewall ports 80 and 443..."
if command -v ufw &>/dev/null; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    success "ufw rules added (80, 443)"
fi
# Note: Also open these in Oracle Cloud console → VCN → Security Lists

# ── Step 5: Clone or update repo ─────────────────────────────
if [ -d "$INSTALL_DIR/.git" ]; then
    info "Updating existing repo at $INSTALL_DIR..."
    cd "$INSTALL_DIR"
    git fetch origin
    git reset --hard "origin/$BRANCH"
    success "Repo updated to $(git rev-parse --short HEAD)"
else
    info "Cloning repo to $INSTALL_DIR..."
    git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    success "Repo cloned"
fi

cd "$INSTALL_DIR"

# ── Step 6: Create .env if it doesn't exist ──────────────────
ENV_FILE="$INSTALL_DIR/app/backend/.env"

if [ ! -f "$ENV_FILE" ]; then
    info "Creating .env from template..."
    cp "$INSTALL_DIR/app/backend/.env.example" "$ENV_FILE"

    # Generate secrets automatically
    JWT_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null \
        || python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
    DB_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
    ADMIN_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")

    # Write to .env
    sed -i "s|JWT_SECRET_KEY=.*|JWT_SECRET_KEY=${JWT_KEY}|" "$ENV_FILE"
    sed -i "s|AWS_ENCRYPTION_KEY=.*|AWS_ENCRYPTION_KEY=${FERNET_KEY}|" "$ENV_FILE"
    sed -i "s|ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${ADMIN_PASS}|" "$ENV_FILE"

    # Write DB password to root .env for docker-compose
    echo "DB_PASSWORD=${DB_PASS}" > "$INSTALL_DIR/.env"

    echo ""
    echo "┌─────────────────────────────────────────────────┐"
    echo "│           SAVE THESE CREDENTIALS NOW!           │"
    echo "├─────────────────────────────────────────────────┤"
    echo "│  Admin password:  ${ADMIN_PASS}"
    echo "│  DB password:     ${DB_PASS}"
    echo "│  JWT key:         (saved to .env)"
    echo "└─────────────────────────────────────────────────┘"
    echo ""

    # Prompt for required values
    echo "━━━━ Required configuration ━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    read -rp "Groq API key (free at console.groq.com, press Enter to skip): " GROQ_KEY
    if [ -n "$GROQ_KEY" ]; then
        sed -i "s|AI_PROVIDER=.*|AI_PROVIDER=groq|" "$ENV_FILE"
        sed -i "s|# GROQ_API_KEY=.*|GROQ_API_KEY=${GROQ_KEY}|" "$ENV_FILE"
        sed -i "s|GROQ_API_KEY=.*|GROQ_API_KEY=${GROQ_KEY}|" "$ENV_FILE"
    fi

    read -rp "Your domain / DuckDNS address (e.g. shieldscan.duckdns.org): " DOMAIN
    if [ -n "$DOMAIN" ]; then
        sed -i "s|APP_URL=.*|APP_URL=https://${DOMAIN}|" "$ENV_FILE"
        sed -i "s|CORS_ALLOWED_ORIGINS=.*|CORS_ALLOWED_ORIGINS=[\"https://${DOMAIN}\"]|" "$ENV_FILE"
        echo "DOMAIN=${DOMAIN}" >> "$INSTALL_DIR/.env"
    fi

    sed -i "s|ENV=.*|ENV=production|" "$ENV_FILE"
    success ".env created"
else
    success ".env already exists — skipping"
fi

# ── Step 7: Create ssl/ directory (certbot will populate it) ──
mkdir -p "$INSTALL_DIR/ssl"
# Nginx needs cert files to start. Use self-signed for now if no certs yet.
if [ ! -f "$INSTALL_DIR/ssl/cert.pem" ]; then
    info "Generating temporary self-signed SSL cert (replace with Let's Encrypt)..."
    DOMAIN_VAL=$(grep "^DOMAIN=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2 || echo "localhost")
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$INSTALL_DIR/ssl/key.pem" \
        -out "$INSTALL_DIR/ssl/cert.pem" \
        -subj "/CN=${DOMAIN_VAL}" 2>/dev/null
    success "Self-signed cert created (run setup-ssl.sh to replace with Let's Encrypt)"
fi

# ── Step 8: Start the stack ───────────────────────────────────
info "Starting ShieldScan stack..."
cd "$INSTALL_DIR"

# Pull latest images
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull --quiet 2>/dev/null || true

# Build API image
info "Building API Docker image (this takes 3-5 minutes on first run)..."
docker compose -f docker-compose.yml -f docker-compose.prod.yml build api

# Start everything
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# ── Step 9: Wait for health check ─────────────────────────────
info "Waiting for API to become healthy..."
ATTEMPTS=0
MAX=60
until curl -sf http://localhost:8000/health >/dev/null 2>&1 || [ "$ATTEMPTS" -ge "$MAX" ]; do
    sleep 2
    ATTEMPTS=$((ATTEMPTS + 1))
    printf "."
done
echo ""

if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    success "API is healthy!"
else
    warn "API health check failed after ${MAX} attempts. Check logs:"
    echo "  docker compose logs api --tail=50"
fi

# ── Done ──────────────────────────────────────────────────────
DOMAIN_VAL=$(grep "^DOMAIN=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2 || echo "YOUR_SERVER_IP")

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║                 Deploy Complete!                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  App URL:     http://${DOMAIN_VAL}  (HTTP only for now)"
echo "  Health:      http://${DOMAIN_VAL}/health"
echo "  API docs:    http://${DOMAIN_VAL}/docs"
echo ""
echo "  ── Next steps ─────────────────────────────────────"
echo "  1. Open Oracle VCN Security List → add ports 80 + 443"
echo "  2. Point your DuckDNS domain to this server's IP"
echo "  3. Run: bash setup-ssl.sh   (adds HTTPS + auto-renew)"
echo ""
echo "  ── Useful commands ─────────────────────────────────"
echo "  Logs:     docker compose logs -f api"
echo "  Status:   docker compose ps"
echo "  Restart:  docker compose restart api"
echo "  Update:   git pull && bash deploy.sh"
echo ""
