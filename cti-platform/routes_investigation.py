"""
Investigation workspace routes - session hub, deliverables, TTP coverage.
"""

import logging
from datetime import datetime
from pathlib import Path
from flask import Blueprint, render_template, request, g
from modules.api_helpers import api_success, api_error
from modules.auth import require_auth
from config import OUTPUT_FOLDER

logger = logging.getLogger(__name__)

investigation_bp = Blueprint('investigation', __name__, url_prefix='/investigation')


def _db():
    return g.db


def _scan_deliverables(limit: int = 50):
    from modules.storage_monitor import format_bytes

    files = []
    subfolders = ('iocs', 'stix', 'reports')
    for subfolder in subfolders:
        folder = OUTPUT_FOLDER / subfolder
        if not folder.exists():
            continue
        for file_path in folder.iterdir():
            if not file_path.is_file():
                continue
            try:
                stat = file_path.stat()
                files.append({
                    'path': str(file_path),
                    'name': file_path.name,
                    'folder': subfolder,
                    'size': stat.st_size,
                    'size_formatted': format_bytes(stat.st_size),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'modified_timestamp': stat.st_mtime,
                })
            except OSError:
                continue

    files.sort(key=lambda x: x['modified_timestamp'], reverse=True)
    return files[:limit]


@investigation_bp.route('/')
@require_auth
def investigation_home():
    """Investigation workspace hub."""
    active = _db().get_active_investigation_session()
    groups = _db().get_all_groups()
    group_id = active.get('group_id') if active else None
    stats = _db().get_investigation_session_stats(group_id)
    return render_template(
        'investigation/index.html',
        active_session=active,
        groups=groups,
        stats=stats,
    )


@investigation_bp.route('/api/session', methods=['GET'])
@require_auth
def api_get_session():
    try:
        active = _db().get_active_investigation_session()
        stats = _db().get_investigation_session_stats(
            active.get('group_id') if active else None
        )
        return api_success({'session': active, 'stats': stats})
    except Exception as e:
        logger.error(f"api_get_session error: {e}", exc_info=True)
        return api_error(str(e), 500)


@investigation_bp.route('/api/session', methods=['POST'])
@require_auth
def api_save_session():
    try:
        data = request.get_json() or {}
        name = (data.get('name') or '').strip()
        if not name:
            return api_error('Session name is required', 400)

        notes = (data.get('notes') or '').strip()
        group_id = data.get('group_id')
        if group_id in ('', None):
            group_id = None
        else:
            group_id = int(group_id)

        session_id = data.get('id')
        if session_id:
            session_id = int(session_id)

        saved_id = _db().save_investigation_session(
            name=name,
            notes=notes,
            group_id=group_id,
            session_id=session_id,
        )
        active = _db().get_active_investigation_session()
        stats = _db().get_investigation_session_stats(
            active.get('group_id') if active else None
        )

        try:
            from modules import zettelforge_bridge as zf
            group_name = ''
            if group_id:
                groups = _db().get_all_groups()
                match = next((g for g in groups if g.get('id') == group_id), None)
                group_name = (match or {}).get('name', '')
            zf.remember_investigation_session(saved_id, name, notes, group_name=group_name)
        except Exception as mem_err:
            logger.debug('CTI memory investigation session skipped: %s', mem_err)

        return api_success({'id': saved_id, 'session': active, 'stats': stats})
    except Exception as e:
        logger.error(f"api_save_session error: {e}", exc_info=True)
        return api_error(str(e), 500)


@investigation_bp.route('/api/session/close', methods=['POST'])
@require_auth
def api_close_session():
    try:
        data = request.get_json() or {}
        session_id = data.get('id')
        if not session_id:
            active = _db().get_active_investigation_session()
            session_id = active.get('id') if active else None
        if not session_id:
            return api_error('No active session to close', 400)

        closed = _db().close_investigation_session(int(session_id))
        if not closed:
            return api_error('Session not found or already closed', 404)
        return api_success({'message': 'Session closed'})
    except Exception as e:
        logger.error(f"api_close_session error: {e}", exc_info=True)
        return api_error(str(e), 500)


@investigation_bp.route('/api/deliverables', methods=['GET'])
@require_auth
def api_deliverables():
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        outputs = _scan_deliverables(limit=limit)
        return api_success({'outputs': outputs, 'count': len(outputs)})
    except Exception as e:
        logger.error(f"api_deliverables error: {e}", exc_info=True)
        return api_error(str(e), 500)


@investigation_bp.route('/api/ttp-coverage', methods=['GET'])
@require_auth
def api_ttp_coverage():
    try:
        group_id = request.args.get('group_id')
        if group_id in ('', None, 'all'):
            group_id = None
        else:
            group_id = int(group_id)

        coverage = _db().get_ttp_coverage(group_id=group_id)
        return api_success(coverage)
    except Exception as e:
        logger.error(f"api_ttp_coverage error: {e}", exc_info=True)
        return api_error(str(e), 500)
