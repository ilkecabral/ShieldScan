#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ShieldScan — One-Time Setup Script
# Run this ONCE before starting the app for the first time,
# or after pulling new code that adds dependencies.
# ─────────────────────────────────────────────────────────────

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "🛡  ShieldScan Setup"
echo "──────────────────────────────────────────"

# ── 1. Check venv ──────────────────────────────────────────
if [ ! -d "venv" ]; then
  echo "Creating virtual environment..."
  python3.11 -m venv venv
  echo "✓ venv created"
else
  echo "✓ venv exists"
fi

PYTHON="$SCRIPT_DIR/venv/bin/python3.11"
PIP="$SCRIPT_DIR/venv/bin/pip3"

# ── 2. Install / update all dependencies ──────────────────
echo ""
echo "Installing dependencies from requirements.txt..."
"$PIP" install -r app/backend/requirements.txt --quiet
echo "✓ All packages installed"

# ── 3. Check .env ──────────────────────────────────────────
if [ ! -f ".env" ]; then
  echo ""
  echo "ERROR: .env file not found. It should have been created by Claude."
  echo "Create it manually or re-run the Claude setup task."
  exit 1
else
  echo "✓ .env found"
fi

# ── 4. Migrate DB (adds new columns/tables to existing DB) ─
echo ""
echo "Running DB migration..."
"$PYTHON" - <<'PYEOF'
import sqlite3, os, sys

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shieldscan.db")

if not os.path.exists(db_path):
    print(f"  DB not found at {db_path} — will be created on first run.")
    sys.exit(0)

conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Add aws_account_id column if missing
cur.execute("PRAGMA table_info(users)")
existing_cols = [row[1] for row in cur.fetchall()]

if "aws_account_id" not in existing_cols:
    cur.execute("ALTER TABLE users ADD COLUMN aws_account_id VARCHAR(20)")
    print("  Added aws_account_id column to users")
else:
    print("  aws_account_id already exists — skipping")

# Create passkey_credentials table if missing
cur.execute("""
    CREATE TABLE IF NOT EXISTS passkey_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        credential_id TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        device_type VARCHAR(32),
        aaguid VARCHAR(36),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
""")
print("  passkey_credentials table ready")

conn.commit()
conn.close()
print("  DB migration complete.")
PYEOF

echo ""
echo "──────────────────────────────────────────"
echo "✅  Setup complete! Now run: ./start.sh"
echo ""
