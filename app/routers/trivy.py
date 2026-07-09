import uuid
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from app.services.trivy_scanner import run_trivy_scan, ScanType, TrivyScanError

router = APIRouter(prefix="/scans/trivy", tags=["trivy"])

# Simple in-memory store -- swap for ChromaDB in production
scan_jobs: dict[str, dict] = {}


class ScanRequest(BaseModel):
    target: str
    scan_type: ScanType
    severity: str = "HIGH,CRITICAL"


def _execute_scan(job_id: str, target: str, scan_type: ScanType, severity: str):
    try:
        result = run_trivy_scan(target, scan_type, severity)
        scan_jobs[job_id] = {"status": "completed", **result}
    except TrivyScanError as e:
        scan_jobs[job_id] = {"status": "failed", "error": str(e)}


@router.post("/")
def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Trigger an async Trivy scan. Returns a job_id to poll for results."""
    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {"status": "running"}
    background_tasks.add_task(
        _execute_scan, job_id, request.target, request.scan_type, request.severity
    )
    return {"job_id": job_id, "status": "running"}


@router.get("/{job_id}")
def get_scan_result(job_id: str):
    """Poll scan status and retrieve results."""
    job = scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return job


@router.post("/ingest")
def ingest_scan_results(payload: dict):
    """
    Receives results pushed from the daily rescan GitHub Action
    and stores them for the dashboard / findings store.
    """
    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "status": "ingested",
        "source": "daily-rescan",
        "results": payload,
    }
    # TODO: persist into ChromaDB findings store instead of in-memory dict
    return {"job_id": job_id, "status": "ingested"}
