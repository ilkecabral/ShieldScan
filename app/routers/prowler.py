import uuid
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from app.services.prowler_scanner import run_prowler_scan, ScanCategory, ProwlerScanError

router = APIRouter(prefix="/scans/prowler", tags=["prowler"])

# Simple in-memory store -- swap for ChromaDB in production
scan_jobs: dict[str, dict] = {}


class ProwlerScanRequest(BaseModel):
    role_arn: str
    category: ScanCategory = ScanCategory.ALL
    severity: str = "critical high"
    region: str = "us-east-1"


def _execute_scan(job_id: str, role_arn: str, category: ScanCategory, severity: str, region: str):
    try:
        result = run_prowler_scan(role_arn, category, severity, region)
        scan_jobs[job_id] = {"status": "completed", **result}
    except ProwlerScanError as e:
        scan_jobs[job_id] = {"status": "failed", "error": str(e)}


@router.post("/")
def trigger_posture_scan(request: ProwlerScanRequest, background_tasks: BackgroundTasks):
    """Trigger an async Prowler CSPM scan. Returns a job_id to poll for results."""
    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {"status": "running"}
    background_tasks.add_task(
        _execute_scan, job_id, request.role_arn, request.category, request.severity, request.region
    )
    return {"job_id": job_id, "status": "running"}


@router.get("/{job_id}")
def get_posture_scan_result(job_id: str):
    """Poll scan status and retrieve results."""
    job = scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return job


@router.get("/{job_id}/summary")
def get_posture_summary(job_id: str):
    """Get just the summary counts for a completed scan."""
    job = scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    if job.get("status") != "completed":
        return {"status": job.get("status")}
    return {"status": "completed", "summary": job.get("summary", {})}


@router.post("/ingest")
def ingest_posture_results(payload: dict):
    """
    Receives results pushed from the daily Prowler GitHub Action
    and stores them for the dashboard / findings store.
    """
    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "status": "ingested",
        "source": "daily-posture-scan",
        "results": payload,
    }
    # TODO: persist into ChromaDB findings store instead of in-memory dict
    return {"job_id": job_id, "status": "ingested"}
