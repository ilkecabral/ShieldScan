"""
cnappgoat_routes_flask.py
─────────────────────────────────────────────────────────────────────────────
Flask Blueprint that adds CNAPPgoat testing endpoints to your EXISTING
ShieldScan Flask app, under the /cnappgoat prefix (so it won't collide
with your existing routes like /scans/image).

INTEGRATION — in your existing app.py:

    from flask import Flask
    from cnappgoat_routes_flask import cnappgoat_bp

    app = Flask(__name__)
    app.register_blueprint(cnappgoat_bp)

    # ... your existing /scans/image routes etc. stay untouched ...

That's it. Then visit:  http://<your-host>:<port>/cnappgoat/
"""

import os
import threading
from flask import Blueprint, jsonify, request, Response

import cnappgoat_core as core

cnappgoat_bp = Blueprint(
    'cnappgoat',
    __name__,
    url_prefix='/cnappgoat',
)

_HERE = os.path.dirname(os.path.abspath(__file__))
_DASHBOARD_PATH = os.path.join(_HERE, 'cnappgoat_dashboard.html')


@cnappgoat_bp.route('/', methods=['GET'])
def dashboard():
    """Serves the dashboard UI. It calls /cnappgoat/api/... under the hood."""
    with open(_DASHBOARD_PATH, 'r', encoding='utf-8') as f:
        html = f.read()
    return Response(html, mimetype='text/html')


@cnappgoat_bp.route('/api/system-status', methods=['GET'])
def system_status():
    return jsonify(core.get_system_status())


@cnappgoat_bp.route('/api/scenario-status/<scenario_id>', methods=['GET'])
def scenario_status(scenario_id):
    return jsonify(core.get_state(scenario_id))


@cnappgoat_bp.route('/api/deploy', methods=['POST'])
def deploy():
    data = request.get_json(force=True, silent=True) or {}
    scenario_id = data.get('scenario_id')
    if not scenario_id:
        return jsonify({'error': 'scenario_id required'}), 400

    core.get_state(scenario_id)  # init
    threading.Thread(target=core.worker_deploy, args=(scenario_id,), daemon=True).start()
    return jsonify({'status': 'deploying'})


@cnappgoat_bp.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json(force=True, silent=True) or {}
    scenario_id = data.get('scenario_id')
    if not scenario_id:
        return jsonify({'error': 'scenario_id required'}), 400

    threading.Thread(target=core.worker_scan, args=(scenario_id,), daemon=True).start()
    return jsonify({'status': 'scanning'})


@cnappgoat_bp.route('/api/destroy', methods=['POST'])
def destroy():
    data = request.get_json(force=True, silent=True) or {}
    scenario_id = data.get('scenario_id')
    if not scenario_id:
        return jsonify({'error': 'scenario_id required'}), 400

    threading.Thread(target=core.worker_destroy, args=(scenario_id,), daemon=True).start()
    return jsonify({'status': 'destroying'})
