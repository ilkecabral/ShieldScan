# ShieldScan — Start Guide

---

## First Time Only (run once)

Open Terminal and paste:

```bash
cd "/Users/kiranreddy55/Documents/shield scan/shield scan"
venv/bin/pip install boto3==1.34.131 webauthn==2.1.0
```

Installs the two packages added after the venv was originally created.

---

## Every Time — Start the App

### Option A: Single command (easiest)

```bash
cd "/Users/kiranreddy55/Documents/shield scan/shield scan"
./start.sh
```

Starts backend + frontend in the background and opens the browser.
Then in a **separate terminal**, start Ollama for AI chat:

```bash
ollama serve
```

---

### Option B: Manual (3 terminals)

**Terminal 1 — Backend**
```bash
cd "/Users/kiranreddy55/Documents/shield scan/shield scan/app"
../venv/bin/uvicorn backend.main:app --port 8000 --reload
```

**Terminal 2 — Ollama (AI)**
```bash
ollama serve
```
> First time only: `ollama pull llama3.2` (~2 GB download, needed once)

**Terminal 3 — Frontend**
```bash
cd "/Users/kiranreddy55/Documents/shield scan/shield scan/app/frontend"
python3 -m http.server 3000
```

---

## Open the App

→ **http://localhost:3000**

---

## Stop Everything

```bash
cd "/Users/kiranreddy55/Documents/shield scan/shield scan"
./stop.sh
```

Or manually: `Ctrl+C` in each terminal.

---

## Health Checks

```bash
# Is the backend alive?
curl http://localhost:8000/health
# Expected: {"status":"ok","service":"shieldscan-api"}

# Is the AI ready?
curl http://localhost:8000/api/ai/status
# Expected: {"provider":"ollama","model":"llama3.2","status":"ready",...}
```

---

## Logs (when using start.sh)

```bash
tail -f "/Users/kiranreddy55/Documents/shield scan/shield scan/backend.log"
tail -f "/Users/kiranreddy55/Documents/shield scan/shield scan/frontend.log"
```

---

## Database

```bash
sqlite3 "/Users/kiranreddy55/Documents/shield scan/shield scan/shieldscan.db"
# Inside sqlite3: .tables   .schema users   SELECT * FROM users;   .quit
```

---

## Full Reset (if something is broken)

```bash
cd "/Users/kiranreddy55/Documents/shield scan/shield scan"
./stop.sh
pkill -f ollama
find app/backend -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
./start.sh
```

---

## Port already in use?

```bash
lsof -ti:8000 | xargs kill -9   # free backend port
lsof -ti:3000 | xargs kill -9   # free frontend port
```
