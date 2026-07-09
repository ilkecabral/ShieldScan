"""
cnappgoat_core.py
─────────────────────────────────────────────────────────────────────────────
Framework-agnostic core for CNAPPgoat CWPP/CSPM testing integration.

This module has NO dependency on Flask or FastAPI — it just runs
cnappgoat / aws / trivy as subprocesses and keeps in-memory state.
Import this from either a Flask blueprint or a FastAPI router.

Drop this file into your existing ShieldScan backend, e.g.:
    shieldscan-backend/
        app.py                (your existing Flask/FastAPI app)
        cnappgoat_core.py      <- this file
        cnappgoat_routes.py    <- Flask blueprint OR FastAPI router (see other files)
        static/cnappgoat_dashboard.html
"""

import json
import re
import subprocess
import threading

STATE = {}
STATE_LOCK = threading.Lock()

DEFAULT_STATE = lambda: {
    'status': 'not_deployed',   # not_deployed|deploying|deployed|scanning|scanned|destroying|error
    'progress': 0,
    'log': '',
    'vulnerabilities': None,
    'cves': [],
    'repo_url': None,
    'error': None,
}


def get_state(scenario_id: str) -> dict:
    with STATE_LOCK:
        if scenario_id not in STATE:
            STATE[scenario_id] = DEFAULT_STATE()
        return dict(STATE[scenario_id])


def update_state(scenario_id: str, **kwargs):
    with STATE_LOCK:
        if scenario_id not in STATE:
            STATE[scenario_id] = DEFAULT_STATE()
        STATE[scenario_id].update(kwargs)


def append_log(scenario_id: str, text: str):
    if not text:
        return
    with STATE_LOCK:
        if scenario_id not in STATE:
            STATE[scenario_id] = DEFAULT_STATE()
        STATE[scenario_id]['log'] = (STATE[scenario_id]['log'] + text)[-8000:]


def remove_state(scenario_id: str):
    with STATE_LOCK:
        STATE.pop(scenario_id, None)


def run_cmd(cmd, timeout=900):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, '', 'Command timed out'
    except FileNotFoundError as e:
        return -1, '', f'Command not found: {e}'


# ─────────────────────────────────────────────────────────────────────────────
# Background workers (run in a thread, kicked off by the route handlers)
# ─────────────────────────────────────────────────────────────────────────────

def worker_deploy(scenario_id: str):
    update_state(scenario_id, status='deploying', progress=5, error=None, log='')
    append_log(scenario_id, f'$ cnappgoat provision {scenario_id}\n')

    code, out, err = run_cmd(['cnappgoat', 'provision', scenario_id], timeout=900)
    append_log(scenario_id, out)
    if err:
        append_log(scenario_id, err)

    if code != 0:
        append_log(scenario_id, f'\n$ Retrying: cnappgoat provision --scenario-name {scenario_id}\n')
        code, out, err = run_cmd(['cnappgoat', 'provision', '--scenario-name', scenario_id], timeout=900)
        append_log(scenario_id, out)
        if err:
            append_log(scenario_id, err)

    if code != 0:
        update_state(scenario_id, status='error', progress=0, error=(err or out or 'Deployment failed'))
        return

    update_state(scenario_id, status='deployed', progress=100)
    worker_fetch_output(scenario_id)


def worker_fetch_output(scenario_id: str):
    code, out, err = run_cmd(['cnappgoat', 'output', scenario_id], timeout=30)
    if code != 0:
        code, out, err = run_cmd(['cnappgoat', 'output', '--scenario-name', scenario_id], timeout=30)

    append_log(scenario_id, f'\n$ cnappgoat output {scenario_id}\n{out}\n')

    repo_url = None
    for line in out.split('\n'):
        if 'dkr.ecr' in line:
            parts = [p.strip() for p in line.split('│') if p.strip()]
            for p in parts:
                if 'dkr.ecr' in p:
                    repo_url = p
                    break
    if repo_url:
        update_state(scenario_id, repo_url=repo_url)


def worker_scan(scenario_id: str):
    """
    Scans the deployed image. Tries Trivy first (using an ECR token),
    falls back to native AWS ECR scan findings if Trivy can't parse/reach it.
    """
    update_state(scenario_id, status='scanning', error=None)
    append_log(scenario_id, '\n$ Starting vulnerability scan...\n')

    st = get_state(scenario_id)
    repo_url = st.get('repo_url')

    if not repo_url:
        worker_fetch_output(scenario_id)
        st = get_state(scenario_id)
        repo_url = st.get('repo_url')

    if not repo_url:
        update_state(scenario_id, status='error',
                     error='No ECR repository found in scenario output (this scenario may target EC2 instead of ECR).')
        return

    m = re.search(r'dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com', repo_url)
    region = m.group(1) if m else 'eu-west-3'
    repo_name = repo_url.split('/')[-1]

    code, out, err = run_cmd(['aws', 'ecr', 'list-images', '--repository-name', repo_name,
                               '--region', region, '--output', 'json'], timeout=30)
    append_log(scenario_id, f'\n$ aws ecr list-images --repository-name {repo_name} --region {region}\n{out}\n')

    image_tag = None
    try:
        images = json.loads(out).get('imageIds', [])
        for img in images:
            if 'imageTag' in img:
                image_tag = img['imageTag']
                break
    except Exception:
        pass

    full_image = f'{repo_url}:{image_tag}' if image_tag else repo_url

    code, token, err = run_cmd(['aws', 'ecr', 'get-login-password', '--region', region], timeout=30)
    token = token.strip()
    if code != 0 or not token:
        update_state(scenario_id, status='error', error=f'Could not get ECR login token: {err}')
        return

    append_log(scenario_id, f'\n$ trivy image --registry-token **** {full_image}\n')
    code, out, err = run_cmd(
        ['trivy', 'image', '--registry-token', token, '--format', 'json', '--quiet', full_image],
        timeout=300
    )
    if err:
        append_log(scenario_id, err[-2000:])

    vulns = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    cve_list = []
    parsed_ok = False

    if code == 0 and out:
        try:
            trivy_data = json.loads(out)
            for result in trivy_data.get('Results', []) or []:
                for vuln in result.get('Vulnerabilities', []) or []:
                    sev = vuln.get('Severity', 'UNKNOWN')
                    if sev in vulns:
                        vulns[sev] += 1
                    if len(cve_list) < 15:
                        cve_list.append(vuln.get('VulnerabilityID', 'N/A'))
            parsed_ok = True
        except json.JSONDecodeError:
            append_log(scenario_id, '\n[warn] Could not parse Trivy JSON output.\n')

    if not parsed_ok or sum(vulns.values()) == 0:
        append_log(scenario_id, '\n$ Falling back to AWS ECR native scan findings...\n')
        if image_tag:
            code3, out3, err3 = run_cmd(
                ['aws', 'ecr', 'describe-image-scan-findings',
                 '--repository-name', repo_name,
                 '--image-id', f'imageTag={image_tag}',
                 '--region', region, '--output', 'json'],
                timeout=60
            )
            append_log(scenario_id, (out3[-3000:] if out3 else '') + (err3[-1000:] if err3 else ''))
            try:
                findings = json.loads(out3).get('imageScanFindings', {}).get('findings', [])
                for f in findings:
                    sev = f.get('severity', 'UNKNOWN')
                    if sev in vulns:
                        vulns[sev] += 1
                    if len(cve_list) < 15:
                        cve_list.append(f.get('name', 'N/A'))
            except Exception as e:
                append_log(scenario_id, f'\n[error] Could not parse ECR findings: {e}\n')

    update_state(scenario_id, status='scanned', vulnerabilities=vulns, cves=cve_list)
    append_log(scenario_id, f'\n✅ Scan complete: {vulns}\n')


def worker_destroy(scenario_id: str):
    update_state(scenario_id, status='destroying', error=None)
    append_log(scenario_id, f'\n$ cnappgoat destroy {scenario_id}\n')

    code, out, err = run_cmd(['cnappgoat', 'destroy', scenario_id], timeout=600)
    append_log(scenario_id, out)
    if code != 0:
        append_log(scenario_id, f'\n$ Retrying: cnappgoat destroy --scenario-name {scenario_id}\n')
        code, out, err = run_cmd(['cnappgoat', 'destroy', '--scenario-name', scenario_id], timeout=600)
        append_log(scenario_id, out)
    if err:
        append_log(scenario_id, err)

    if code != 0:
        update_state(scenario_id, status='error', error=(err or 'Destroy failed'))
        return

    remove_state(scenario_id)


def get_system_status() -> dict:
    aws_code, aws_out, _ = run_cmd(['aws', 'sts', 'get-caller-identity'], timeout=8)
    cg_code, _, _ = run_cmd(['cnappgoat', '--version'], timeout=8)
    trivy_code, _, _ = run_cmd(['trivy', '--version'], timeout=8)
    account = None
    if aws_code == 0:
        try:
            account = json.loads(aws_out).get('Account')
        except Exception:
            pass
    return {
        'aws_connected': aws_code == 0,
        'aws_account': account,
        'cnappgoat_ok': cg_code == 0,
        'trivy_ok': trivy_code == 0,
    }
