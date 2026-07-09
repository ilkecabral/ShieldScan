"""
cnappgoat_routes_fastapi.py
─────────────────────────────────────────────────────────────────────────────
FastAPI router that adds CNAPPgoat testing endpoints to your EXISTING
ShieldScan FastAPI app, under the /cnappgoat prefix (so it won't collide
with your existing routes like /scans/image).

INTEGRATION — in your existing main.py / app.py:

    from fastapi import FastAPI
    from cnappgoat_routes_fastapi import router as cnappgoat_router

    app = FastAPI()
    app.include_router(cnappgoat_router)

    # ... your existing /scans/image routes etc. stay untouched ...

That's it. Then visit:  http://<your-host>:<port>/cnappgoat/
"""

import os
import threading
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import cnappgoat_core as core

router = APIRouter(prefix='/cnappgoat', tags=['cnappgoat'])

_HERE = os.path.dirname(os.path.abspath(__file__))
_DASHBOARD_PATH = os.path.join(_HERE, '..', 'frontend', 'cnappgoat_dashboard.html')


class ScenarioRequest(BaseModel):
    scenario_id: str


@router.get('/', response_class=HTMLResponse)
def dashboard():
    """Serves the dashboard UI. It calls /cnappgoat/api/... under the hood."""
    with open(_DASHBOARD_PATH, 'r', encoding='utf-8') as f:
        return f.read()


@router.get('/api/system-status')
def system_status():
    return core.get_system_status()


@router.get('/api/scenario-status/{scenario_id}')
def scenario_status(scenario_id: str):
    return core.get_state(scenario_id)


@router.post('/api/deploy')
def deploy(req: ScenarioRequest):
    core.get_state(req.scenario_id)  # init
    threading.Thread(target=core.worker_deploy, args=(req.scenario_id,), daemon=True).start()
    return {'status': 'deploying'}


@router.post('/api/scan')
def scan(req: ScenarioRequest):
    threading.Thread(target=core.worker_scan, args=(req.scenario_id,), daemon=True).start()
    return {'status': 'scanning'}


@router.post('/api/destroy')
def destroy(req: ScenarioRequest):
    threading.Thread(target=core.worker_destroy, args=(req.scenario_id,), daemon=True).start()
    return {'status': 'destroying'}
