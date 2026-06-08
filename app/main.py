from fastapi import FastAPI

app = FastAPI(title="ShieldScan API", version="0.1.0")

@app.get("/")
def root():
    return {"service": "shieldscan", "status": "ok"}

@app.get("/health")
def health():
    return {"status": "healthy"}
