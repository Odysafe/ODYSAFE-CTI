"""
CTI Memory routes · ZettelForge integration (no LLM).
"""

import logging
import tempfile
from pathlib import Path

from flask import Blueprint, render_template, request, g
from werkzeug.utils import secure_filename

from modules.api_helpers import api_success, api_error
from modules.auth import require_auth
from modules.cross_index import parse_ref
from modules import zettelforge_bridge as zf

logger = logging.getLogger(__name__)

memory_bp = Blueprint('memory', __name__, url_prefix='/memory')

ALLOWED_SIGMA = {'.yml', '.yaml'}
ALLOWED_YARA = {'.yar', '.yara'}


def _combined_note_text(title: str, content: str) -> str:
    """Return the canonical SQLite representation of one titled IOC note."""
    return '\n\n'.join(
        part for part in ((title or '').strip(), (content or '').strip()) if part
    )


def _linked_ioc_id(note: dict) -> int | None:
    parsed = parse_ref((note or {}).get('source_ref', ''))
    if not parsed or parsed.get('ref_type') != 'ioc':
        return None
    try:
        return int(parsed['entity_id'])
    except (TypeError, ValueError):
        return None


@memory_bp.route('/')
@require_auth
def memory_home():
    status = zf.get_status()
    return render_template('memory/index.html', memory_status=status)


@memory_bp.route('/api/status', methods=['GET'])
@require_auth
def api_memory_status():
    return api_success(zf.get_status())


@memory_bp.route('/api/stats', methods=['GET'])
@require_auth
def api_memory_stats():
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    return api_success(zf.get_memory_stats())


@memory_bp.route('/api/recent', methods=['GET'])
@require_auth
def api_memory_recent():
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    k = min(int(request.args.get('k', 12)), 30)
    notes = zf.list_recent_notes(k=k)
    return api_success({'notes': notes, 'count': len(notes)})


@memory_bp.route('/api/recall', methods=['GET'])
@require_auth
def api_memory_recall():
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    q = request.args.get('q', '').strip()
    if not q or len(q) < 2:
        return api_error('Query must be at least 2 characters', 400)
    k = min(int(request.args.get('k', 10)), 25)
    notes = zf.recall_query(q, k=k)
    return api_success({'query': q, 'notes': notes, 'count': len(notes)})


@memory_bp.route('/api/remember', methods=['POST'])
@require_auth
def api_memory_remember():
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    data = request.get_json() or {}
    content = (data.get('content') or '').strip()
    title = (data.get('title') or '').strip()
    if not content and not title:
        return api_error('content or title is required', 400)
    attach = data.get('attach')
    source_ref = (data.get('source_ref') or '').strip()

    if isinstance(attach, dict) and attach.get('kind') == 'ioc' and attach.get('id'):
        try:
            ioc_id = int(attach['id'])
        except (TypeError, ValueError):
            return api_error('Invalid IOC id', 400)
        ioc = g.db.get_ioc(ioc_id)
        if not ioc or ioc.get('is_deleted'):
            return api_error('IOC not found', 404)

        canonical_notes = _combined_note_text(title, content)
        g.db.update_ioc_notes(ioc_id, canonical_notes)
        memory_status = zf.remember_ioc_note(
            ioc_id,
            ioc.get('ioc_value', ''),
            ioc.get('ioc_type', ''),
            content or title,
            title=title if content else '',
        )
        return api_success({
            'source_ref': f'odysafe:ioc:{ioc_id}',
            'status': memory_status,
            'memory_indexed': memory_status == 'indexed',
            'memory_index_status': memory_status,
        })

    result = zf.remember_text(
        content,
        title=title,
        source_ref=source_ref,
        domain=data.get('domain', 'cti'),
        source_type='odysafe_manual',
        attach=attach if isinstance(attach, dict) else None,
        force=bool(attach),
    )
    if not result:
        return api_error('Failed to store memory entry', 500)
    return api_success(result)


@memory_bp.route('/api/note/<note_id>', methods=['GET'])
@require_auth
def api_memory_get_note(note_id):
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    note = zf.get_note(note_id)
    if not note:
        return api_error('Note not found', 404)
    return api_success({'note': note})


@memory_bp.route('/api/note/<note_id>', methods=['PATCH'])
@require_auth
def api_memory_update_note(note_id):
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    data = request.get_json() or {}
    content = (data.get('content') or '').strip()
    title = data.get('title')
    if title is not None:
        title = str(title).strip()
    if content is None and title is None:
        return api_error('content is required', 400)
    existing_note = zf.get_note(note_id)
    if not existing_note:
        return api_error('Note not found', 404)
    note = zf.update_note(note_id, content, title=title)
    if not note:
        return api_error('Note not found or update failed', 404)
    ioc_id = _linked_ioc_id(note)
    if ioc_id is not None:
        g.db.update_ioc_notes(
            ioc_id,
            _combined_note_text(note.get('title', ''), note.get('content', '')),
        )
    return api_success({'note': note})


@memory_bp.route('/api/note/<note_id>', methods=['DELETE'])
@require_auth
def api_memory_delete_note(note_id):
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    note = zf.get_note(note_id)
    if not note:
        return api_error('Note not found', 404)
    ioc_id = _linked_ioc_id(note)
    if not zf.delete_note(note_id):
        return api_error('Note not found', 404)
    if ioc_id is not None:
        g.db.update_ioc_notes(ioc_id, '')
    return api_success({'deleted': True, 'id': note_id})


@memory_bp.route('/api/entity', methods=['GET'])
@require_auth
def api_memory_entity():
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    entity_type = request.args.get('type', '').strip()
    entity_value = request.args.get('value', '').strip()
    if not entity_type or not entity_value:
        return api_error('type and value are required', 400)
    k = min(int(request.args.get('k', 10)), 25)
    notes = zf.recall_entity(entity_type, entity_value, k=k)
    relationships = zf.get_entity_relationships(entity_type, entity_value)
    return api_success({
        'type': entity_type,
        'value': entity_value,
        'notes': notes,
        'relationships': relationships,
    })


@memory_bp.route('/api/graph', methods=['GET'])
@require_auth
def api_memory_graph():
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    entity_type = request.args.get('type', 'ipv4').strip()
    entity_value = request.args.get('value', '').strip()
    if not entity_value:
        return api_error('value is required', 400)
    max_depth = min(int(request.args.get('depth', 2)), 4)
    edges = zf.traverse_graph(entity_type, entity_value, max_depth=max_depth)
    return api_success({
        'type': entity_type,
        'value': entity_value,
        'depth': max_depth,
        'edges': edges,
    })


@memory_bp.route('/api/ingest/sigma', methods=['POST'])
@require_auth
def api_memory_ingest_sigma():
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    if 'file' not in request.files:
        return api_error('No file provided', 400)
    file = request.files['file']
    if not file.filename:
        return api_error('No file selected', 400)
    suffix = Path(file.filename).suffix.lower()
    if suffix not in ALLOWED_SIGMA:
        return api_error('Unsupported file type. Use .yml or .yaml', 400)
    tmp = None
    try:
        tmp = Path(tempfile.mkstemp(suffix=suffix)[1])
        file.save(str(tmp))
        result = zf.ingest_sigma_rule(tmp, source_ref=secure_filename(file.filename))
        return api_success(result, message='Sigma rule ingested')
    except Exception as exc:
        logger.error('Sigma ingest error: %s', exc, exc_info=True)
        return api_error(str(exc), 500)
    finally:
        if tmp and tmp.exists():
            tmp.unlink(missing_ok=True)


@memory_bp.route('/api/ingest/yara', methods=['POST'])
@require_auth
def api_memory_ingest_yara():
    if not zf.is_available():
        return api_error(zf.get_status().get('error') or 'CTI Memory unavailable', 503)
    if 'file' not in request.files:
        return api_error('No file provided', 400)
    file = request.files['file']
    if not file.filename:
        return api_error('No file selected', 400)
    suffix = Path(file.filename).suffix.lower()
    if suffix not in ALLOWED_YARA:
        return api_error('Unsupported file type. Use .yar or .yara', 400)
    tier = request.form.get('tier', 'warn')
    tmp = None
    try:
        tmp = Path(tempfile.mkstemp(suffix=suffix)[1])
        file.save(str(tmp))
        result = zf.ingest_yara_rule(tmp, tier=tier)
        return api_success(result, message='YARA rule ingested')
    except Exception as exc:
        logger.error('YARA ingest error: %s', exc, exc_info=True)
        return api_error(str(exc), 500)
    finally:
        if tmp and tmp.exists():
            tmp.unlink(missing_ok=True)
