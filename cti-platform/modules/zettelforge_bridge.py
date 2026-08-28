"""
Bridge to ZettelForge CTI memory (regex extraction, vector recall, knowledge graph).
No LLM: background NER and synthesis are disabled via environment variables.

Indexing uses cross_refs (content hash + status) to avoid redundant re-indexing and
to track lifecycle on update/delete without duplicating SQLite IOC rows.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import warnings
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Tuple

from config import ZETTELFORGE_MEMORY_DIR, ZETTELFORGE_MEMORY_MAX_TEXT
from modules.cross_index import (
    content_hash,
    enrich_note_dict,
    make_ref,
    memory_note_url,
    parse_ref,
    resolve_ref_navigation,
)

logger = logging.getLogger(__name__)

warnings.filterwarnings(
    'ignore',
    message=r'.*has been updated on HuggingFace.*',
    category=UserWarning,
)

# Bridge operations may initialize the lazy manager while already holding this
# lock, so it must support re-entrant acquisition in the same worker thread.
_lock = threading.RLock()
_manager = None
_import_error: Optional[str] = None
_env_configured = False
_db = None
MEMORY_LOCK_TIMEOUT_SECONDS = max(
    5,
    int(os.getenv('ZETTELFORGE_LOCK_TIMEOUT_SECONDS', '60')),
)


@contextmanager
def _memory_lock():
    """Bound how long callers can wait behind a stalled Memory operation."""
    acquired = _lock.acquire(timeout=MEMORY_LOCK_TIMEOUT_SECONDS)
    if not acquired:
        raise TimeoutError(
            f'CTI Memory lock acquisition timed out after '
            f'{MEMORY_LOCK_TIMEOUT_SECONDS} seconds'
        )
    try:
        yield
    finally:
        _lock.release()

STIX_ENTITY_TYPES = {
    'ipv4': 'ipv4',
    'ipv6': 'ipv6',
    'domain': 'domain',
    'url': 'url',
    'md5': 'md5',
    'sha1': 'sha1',
    'sha256': 'sha256',
    'email': 'email',
    'cve': 'cve',
    'attack-pattern': 'attack_pattern',
    'attack_pattern': 'attack_pattern',
    'intrusion-set': 'intrusion_set',
    'intrusion_set': 'intrusion_set',
    'tool': 'tool',
    'malware': 'malware',
    'campaign': 'campaign',
    'actor': 'actor',
}


def _get_db():
    global _db
    if _db is None:
        from database import Database
        _db = Database()
    return _db


def _configure_env() -> None:
    global _env_configured
    if _env_configured:
        return
    ZETTELFORGE_MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault('ZETTELFORGE_DATA_DIR', str(ZETTELFORGE_MEMORY_DIR))
    os.environ['ZETTELFORGE_LLM_NER_ENABLED'] = 'false'
    os.environ.setdefault('AMEM_DATA_DIR', str(ZETTELFORGE_MEMORY_DIR))
    _env_configured = True


def _disable_llm_enrichment(mm) -> None:
    """Skip ZettelForge background LLM jobs (Ollama/local). ODYSAFE uses regex + vectors only."""

    def _skip(job) -> None:
        note_id = getattr(job, 'note_id', None)
        if note_id:
            mm._pending_enrichment.discard(note_id)

    mm._run_enrichment = _skip
    mm._run_llm_ner = _skip
    mm._run_evolution = _skip


def is_available() -> bool:
    """Return True if zettelforge is installed and MemoryManager loads."""
    _configure_env()
    try:
        get_manager()
        return True
    except Exception as exc:
        global _import_error
        _import_error = str(exc)
        return False


def get_status() -> Dict[str, Any]:
    """Status for UI and APIs."""
    ok = is_available()
    return {
        'available': ok,
        'data_dir': str(ZETTELFORGE_MEMORY_DIR),
        'llm_enabled': False,
        'llm_note': 'Regex extraction and vector search only. No Ollama or cloud LLM.',
        'error': None if ok else (_import_error or 'ZettelForge not available'),
    }


def get_manager():
    """Lazy singleton MemoryManager (thread-safe)."""
    global _manager, _import_error
    if _manager is not None:
        return _manager
    _configure_env()
    with _memory_lock():
        if _manager is not None:
            return _manager
        try:
            from zettelforge import MemoryManager
            _manager = MemoryManager()
            _disable_llm_enrichment(_manager)
            _import_error = None
            return _manager
        except ImportError as exc:
            _import_error = f'Install zettelforge: pip install zettelforge ({exc})'
            raise RuntimeError(_import_error) from exc
        except Exception as exc:
            _import_error = str(exc)
            raise


def _extract_source_ref(note) -> str:
    content = getattr(note, 'content', None)
    if content:
        ref = getattr(content, 'source_ref', None) or ''
        if ref:
            return ref
    meta = getattr(note, 'metadata', None)
    if not meta:
        return ''
    return (
        getattr(meta, 'source_ref', None)
        or getattr(meta, 'sourceRef', None)
        or ''
    )


ENTITY_LABELS = {
    'ipv4': 'IPv4',
    'ipv6': 'IPv6',
    'domain': 'Domain',
    'url': 'URL',
    'md5': 'MD5',
    'sha1': 'SHA1',
    'sha256': 'SHA256',
    'email': 'Email',
    'cve': 'CVE',
    'attack_pattern': 'TTP',
    'intrusion_set': 'Actor',
    'actor': 'Actor',
    'tool': 'Tool',
    'campaign': 'Campaign',
    'organization': 'Org',
    'person': 'Person',
    'location': 'Location',
}

ENTITY_KIND = {
    'ipv4': 'ioc', 'ipv6': 'ioc', 'domain': 'ioc', 'url': 'ioc',
    'md5': 'ioc', 'sha1': 'ioc', 'sha256': 'ioc', 'email': 'ioc',
    'cve': 'cve',
    'attack_pattern': 'ttp',
    'intrusion_set': 'actor', 'actor': 'actor',
    'tool': 'tool', 'campaign': 'campaign',
}

_TTP_RE = re.compile(r'^T\d{4}(?:\.\d{3})?$', re.I)
_CVE_RE = re.compile(r'^CVE-\d{4}-\d+$', re.I)


def _entity_label(entity_type: str) -> str:
    return ENTITY_LABELS.get((entity_type or '').lower(), (entity_type or 'Entity').replace('_', ' ').title())


def _entity_kind(entity_type: str, value: str = '') -> str:
    et = (entity_type or '').lower()
    if et in ENTITY_KIND:
        return ENTITY_KIND[et]
    v = (value or '').strip().upper()
    if _TTP_RE.match(v):
        return 'ttp'
    if _CVE_RE.match(v):
        return 'cve'
    return 'other'


def _infer_entity_type(value: str) -> str:
    v = (value or '').strip()
    if not v:
        return 'other'
    vu = v.upper()
    if _TTP_RE.match(vu):
        return 'attack_pattern'
    if _CVE_RE.match(vu):
        return 'cve'
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', v):
        return 'ipv4'
    if re.match(r'^[a-fA-F0-9]{32}$', v):
        return 'md5'
    if re.match(r'^[a-fA-F0-9]{64}$', v):
        return 'sha256'
    if '.' in v and ' ' not in v and not v.startswith('http'):
        return 'domain'
    return 'other'


def _entities_for_note(note) -> List[Dict[str, Any]]:
    """Typed entities extracted from a note (entity_index first, semantic fallback)."""
    note_id = getattr(note, 'id', '') or ''
    typed: List[Dict[str, Any]] = []
    seen = set()
    try:
        mm = get_manager()
        with mm.store._write_lock:
            mm.store._check_open()
            rows = mm.store._conn.execute(
                'SELECT entity_type, entity_value FROM entity_index WHERE note_id = ? '
                'ORDER BY entity_type, entity_value',
                (note_id,),
            ).fetchall()
        for row in rows:
            et = row['entity_type']
            ev = row['entity_value']
            key = (et, ev)
            if key in seen:
                continue
            seen.add(key)
            typed.append(_entity_dict(et, ev))
    except Exception as exc:
        logger.debug('entity_index lookup failed: %s', exc)

    if not typed:
        semantic = getattr(note, 'semantic', None)
        for val in (getattr(semantic, 'entities', None) or []):
            ev = str(val).strip()
            if not ev:
                continue
            et = _infer_entity_type(ev)
            key = (et, ev)
            if key in seen:
                continue
            seen.add(key)
            typed.append(_entity_dict(et, ev))
    return typed


def _entity_dict(entity_type: str, value: str) -> Dict[str, Any]:
    from urllib.parse import urlencode
    et = (entity_type or 'other').lower()
    ev = (value or '').strip()
    kind = _entity_kind(et, ev)
    q = urlencode({'q': ev})
    eq = urlencode({'entity_type': et, 'entity_value': ev})
    return {
        'type': et,
        'value': ev,
        'label': _entity_label(et),
        'kind': kind,
        'search_url': f'/memory?{q}',
        'entity_url': f'/memory?{eq}',
    }


_CVE_RE = re.compile(r'^CVE-\d{4}-\d+$', re.I)

TITLE_START = '[TITLE]'
TITLE_END = '[/TITLE]\n'
NOTE_PREVIEW_CHARS = 320


def format_note_storage(title: str, body: str) -> str:
    body = (body or '').strip()
    title = (title or '').strip()
    if title:
        return f'{TITLE_START}{title}{TITLE_END}{body}'
    return body


def parse_note_storage(raw: str) -> Tuple[str, str]:
    raw = raw or ''
    if raw.startswith(TITLE_START):
        end = raw.find(TITLE_END)
        if end > 0:
            title = raw[len(TITLE_START):end].strip()
            body = raw[end + len(TITLE_END):].strip()
            return title, body
    return '', raw.strip()


def _lookup_ioc_by_value(value: str, ioc_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    v = (value or '').strip()
    normalized_type = (ioc_type or '').strip()
    if not v:
        return None
    try:
        with _get_db().connection() as conn:
            if normalized_type:
                row = conn.execute(
                    'SELECT id, ioc_value, ioc_type FROM iocs '
                    'WHERE is_deleted = 0 AND LOWER(ioc_type) = LOWER(?) AND ioc_value = ? LIMIT 1',
                    (normalized_type, v),
                ).fetchone()
            else:
                # Without a known type, the selected row remains arbitrary across
                # identical values originating from different sources.
                row = conn.execute(
                    'SELECT id, ioc_value, ioc_type FROM iocs WHERE is_deleted = 0 AND ioc_value = ? LIMIT 1',
                    (v,),
                ).fetchone()
            if not row:
                if normalized_type:
                    row = conn.execute(
                        'SELECT id, ioc_value, ioc_type FROM iocs '
                        'WHERE is_deleted = 0 AND LOWER(ioc_type) = LOWER(?) '
                        'AND LOWER(ioc_value) = LOWER(?) LIMIT 1',
                        (normalized_type, v),
                    ).fetchone()
                else:
                    row = conn.execute(
                        'SELECT id, ioc_value, ioc_type FROM iocs WHERE is_deleted = 0 '
                        'AND LOWER(ioc_value) = LOWER(?) LIMIT 1',
                        (v,),
                    ).fetchone()
            return dict(row) if row else None
    except Exception as exc:
        logger.debug('ioc lookup by value failed: %s', exc)
        return None


def _normalize_attach(attach: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not attach:
        return {}
    a = dict(attach)
    kind = (a.get('kind') or 'entity').lower()
    value = (a.get('value') or a.get('ioc_value') or '').strip()
    etype = (a.get('entity_type') or a.get('type') or a.get('ioc_type') or '').lower()

    if kind == 'ioc' and a.get('id'):
        if not value and a.get('value'):
            a['value'] = a['value']
        return a

    if kind in ('entity', 'value', 'ioc') and value:
        if _TTP_RE.match(value.upper()) or etype in ('ttp', 'attack_pattern', 'attack-pattern', 'mitre'):
            return {
                'kind': 'ttp',
                'id': value.upper(),
                'value': value.upper(),
                'name': a.get('name') or '',
            }
        ioc = _lookup_ioc_by_value(value, etype or None)
        if ioc:
            return {
                'kind': 'ioc',
                'id': ioc['id'],
                'value': ioc['ioc_value'],
                'ioc_type': ioc['ioc_type'],
                'type': ioc['ioc_type'],
            }
        inferred = etype or _infer_entity_type(value)
        return {'kind': 'entity', 'entity_type': inferred, 'type': inferred, 'value': value}

    if kind == 'ttp':
        tid = (a.get('id') or a.get('value') or '').strip().upper()
        return {'kind': 'ttp', 'id': tid, 'value': tid, 'name': a.get('name') or ''}

    if kind == 'log' and a.get('id'):
        return {'kind': 'log', 'id': a.get('id'), 'name': a.get('name') or a.get('id')}

    return a


def _apply_attach_header(text: str, attach: Dict[str, Any]) -> str:
    if not attach:
        return text
    kind = attach.get('kind')
    if kind == 'ioc' and attach.get('id'):
        ioc_type = attach.get('ioc_type') or attach.get('type') or 'ioc'
        ioc_value = (attach.get('value') or '').strip()
        header = f'Note linked to IOC ({ioc_type}: {ioc_value})' if ioc_value else f'Note linked to IOC #{attach.get("id")}'
        if header.lower() not in text.lower()[:140]:
            return f'{header}\n{text}'
    if kind == 'ttp':
        tid = (attach.get('id') or attach.get('value') or '').strip().upper()
        name = (attach.get('name') or '').strip()
        if tid:
            header = f'ATT&CK {tid}' + (f' · {name}' if name else '')
            if tid not in text.upper()[:80]:
                return f'{header}\n{text}'
    if kind == 'entity':
        et = attach.get('entity_type') or attach.get('type') or 'indicator'
        val = (attach.get('value') or '').strip()
        if val:
            header = f'Note on {_entity_label(et)}: {val}'
            if val not in text[:140]:
                return f'{header}\n{text}'
    if kind == 'log':
        lid = attach.get('id') or ''
        name = attach.get('name') or lid
        header = f'Note on log incident: {name}'
        if header.lower() not in text.lower()[:140]:
            return f'{header}\n{text}'
    return text


def note_to_dict(note, cross_ref_row: Optional[Dict] = None, enrich_db: bool = True) -> Dict[str, Any]:
    raw = getattr(getattr(note, 'content', None), 'raw', '') or ''
    title, body = parse_note_storage(raw)
    meta = getattr(note, 'metadata', None)
    semantic = getattr(note, 'semantic', None)
    source_ref = _extract_source_ref(note)
    entities = _entities_for_note(note)
    d = {
        'id': getattr(note, 'id', ''),
        'title': title,
        'content': body,
        'content_preview': body[:NOTE_PREVIEW_CHARS] + ('…' if len(body) > NOTE_PREVIEW_CHARS else ''),
        'is_long': len(body) > NOTE_PREVIEW_CHARS,
        'context': getattr(semantic, 'context', '') if semantic else '',
        'keywords': list(getattr(semantic, 'keywords', []) or [])[:7],
        'entities': entities,
        'domain': getattr(meta, 'domain', '') if meta else '',
        'tier': getattr(meta, 'tier', '') if meta else '',
        'source_ref': source_ref,
        'source_type': getattr(meta, 'source_type', '') if meta else '',
        'created_at': getattr(note, 'created_at', None),
        'updated_at': getattr(note, 'updated_at', None),
    }
    if enrich_db and not cross_ref_row and source_ref:
        try:
            cross_ref_row = _get_db().get_cross_ref(source_ref)
        except Exception:
            cross_ref_row = None
    enriched = enrich_note_dict(d, cross_ref_row)
    if entities:
        from urllib.parse import urlencode
        vals = [e['value'] for e in entities if e.get('value')][:8]
        if vals:
            enriched['entities_search_url'] = f"/memory?{urlencode({'q': ' '.join(vals)})}"
    return enriched


def _should_skip_index(source_ref: str, text: str) -> bool:
    if not source_ref:
        return False
    h = content_hash(text)
    try:
        row = _get_db().get_cross_ref(source_ref)
        if row and row.get('status') == 'active' and row.get('content_hash') == h:
            return True
    except Exception as exc:
        logger.debug('cross_ref lookup skipped: %s', exc)
    return False


def _register_index(source_ref: str, ref_type: str, entity_id: str, text: str, status: str = 'active') -> bool:
    if not source_ref:
        return False
    try:
        _get_db().upsert_cross_ref(
            source_ref, ref_type, str(entity_id), content_hash(text), status=status,
        )
        return True
    except Exception as exc:
        logger.warning('cross_ref register failed for %s: %s', source_ref, exc)
        return False


def mark_ref_deleted(source_ref: str) -> None:
    """Mark cross_ref deleted so recall filters skip stale memory entries."""
    if not source_ref:
        return
    try:
        _get_db().mark_cross_ref_status(source_ref, 'deleted')
    except Exception as exc:
        logger.debug('mark_ref_deleted failed: %s', exc)


def mark_ref_active(source_ref: str, ref_type: str, entity_id: str) -> None:
    try:
        _get_db().upsert_cross_ref(source_ref, ref_type, str(entity_id), '', status='active')
    except Exception as exc:
        logger.debug('mark_ref_active failed: %s', exc)


def remember_text(
    content: str,
    *,
    title: str = '',
    source_ref: str = '',
    domain: str = 'cti',
    source_type: str = 'odysafe',
    ref_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    force: bool = False,
    attach: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Store text in CTI memory (regex entities + vector + co-occurrence graph)."""
    body = (content or '').strip()
    if not body and not (title or '').strip():
        return None

    attach = _normalize_attach(attach)
    if attach.get('kind') == 'ioc' and attach.get('id'):
        ioc_id = attach['id']
        source_ref = make_ref('ioc', ioc_id)
        ref_type = 'ioc'
        entity_id = str(ioc_id)
        source_type = 'odysafe_ioc_note'
    elif attach.get('kind') == 'ttp' and attach.get('id'):
        tid = attach['id']
        source_ref = source_ref or f'odysafe:manual:ttp:{tid}'
        source_type = 'odysafe_manual'
    elif attach.get('kind') == 'log' and attach.get('id'):
        source_ref = make_ref('log', attach['id'])
        ref_type = 'log'
        entity_id = str(attach['id'])
        source_type = 'odysafe_log_note'

    body = _apply_attach_header(body, attach)
    text = format_note_storage(title, body)
    if not text.strip():
        return None

    if len(text) > ZETTELFORGE_MEMORY_MAX_TEXT:
        text = text[:ZETTELFORGE_MEMORY_MAX_TEXT] + '\n...[truncated]'

    parsed = parse_ref(source_ref)
    if parsed:
        ref_type = ref_type or parsed['ref_type']
        entity_id = entity_id or parsed['entity_id']

    if source_ref:
        try:
            with _memory_lock():
                mm = get_manager()
                existing = mm.store.get_note_by_source_ref(source_ref)
                if existing:
                    existing_title, _ = parse_note_storage(existing.content.raw)
                    use_title = (title or '').strip() or existing_title
                    updated = update_note(existing.id, body, title=use_title)
                    if updated:
                        merged = format_note_storage(use_title, body)
                        if ref_type and entity_id is not None:
                            registered = _register_index(
                                source_ref, ref_type, str(entity_id), merged, status='active'
                            )
                        elif parsed:
                            registered = _register_index(
                                source_ref, parsed['ref_type'], parsed['entity_id'], merged
                            )
                        else:
                            registered = True
                        if not registered:
                            return None
                        return {'note': updated, 'status': 'updated', 'source_ref': source_ref}
                    return None

                if not force and _should_skip_index(source_ref, text):
                    return {'note': None, 'status': 'skipped_unchanged', 'source_ref': source_ref}

                note, status = mm.remember(
                    text,
                    source_type=source_type,
                    source_ref=source_ref,
                    domain=domain,
                    evolve=False,
                )
                if ref_type and entity_id is not None:
                    if not _register_index(
                        source_ref, ref_type, str(entity_id), text, status='active'
                    ):
                        return None
                return {'note': note_to_dict(note), 'status': status, 'source_ref': source_ref}
        except Exception as exc:
            logger.warning('ZettelForge remember failed for %s: %s', source_ref, exc)
            if ref_type and entity_id is not None:
                _register_index(source_ref, ref_type, str(entity_id), text, status='failed')
            return None

    try:
        with _memory_lock():
            mm = get_manager()
            note, status = mm.remember(
                text,
                source_type=source_type,
                source_ref=source_ref,
                domain=domain,
                evolve=False,
            )
        if source_ref and ref_type and entity_id is not None:
            if not _register_index(source_ref, ref_type, str(entity_id), text, status='active'):
                return None
        return {'note': note_to_dict(note), 'status': status, 'source_ref': source_ref}
    except Exception as exc:
        logger.warning('ZettelForge remember failed: %s', exc)
        if source_ref and ref_type and entity_id is not None:
            _register_index(source_ref, ref_type, str(entity_id), text, status='failed')
        return None


def _filter_active_notes(notes: List) -> List:
    out = []
    db = _get_db()
    for note in notes:
        ref = _extract_source_ref(note)
        if ref:
            try:
                row = db.get_cross_ref(ref)
                if row and row.get('status') == 'deleted':
                    continue
            except Exception:
                pass
        out.append(note)
    return out


def list_recent_notes(k: int = 12) -> List[Dict[str, Any]]:
    """Return the most recently created memory notes."""
    try:
        with _memory_lock():
            mm = get_manager()
            notes = mm.store.get_recent_notes(limit=max(1, min(k, 30)))
        notes = _filter_active_notes(notes)
        return [note_to_dict(n, enrich_db=False) for n in notes]
    except Exception as exc:
        logger.warning('ZettelForge list_recent_notes failed: %s', exc)
        return []


def get_note(note_id: str) -> Optional[Dict[str, Any]]:
    if not note_id:
        return None
    try:
        with _memory_lock():
            note = get_manager().store.get_note_by_id(note_id)
        if not note:
            return None
        return note_to_dict(note)
    except Exception as exc:
        logger.warning('get_note failed: %s', exc)
        return None


def get_note_by_ref(source_ref: str) -> Optional[Dict[str, Any]]:
    """Return the single Memory note attached to an active ODYSAFE reference."""
    if not source_ref:
        return None
    try:
        cross_ref = _get_db().get_cross_ref(source_ref)
        if cross_ref and cross_ref.get('status') == 'deleted':
            return None
        with _memory_lock():
            note = get_manager().store.get_note_by_source_ref(source_ref)
        return note_to_dict(note, cross_ref_row=cross_ref) if note else None
    except Exception as exc:
        logger.warning('get_note_by_ref failed for %s: %s', source_ref, exc)
        return None


def update_note(note_id: str, content: str, title: Optional[str] = None) -> Optional[Dict[str, Any]]:
    body = (content or '').strip()
    if not note_id:
        return None
    try:
        with _memory_lock():
            mm = get_manager()
            note = mm.store.get_note_by_id(note_id)
            if not note:
                return None
            source_ref = note.content.source_ref or ''
            existing_title, _ = parse_note_storage(note.content.raw)
            use_title = existing_title if title is None else (title or '').strip()
            if not body and not use_title:
                return None
            text = format_note_storage(use_title, body)
            if len(text) > ZETTELFORGE_MEMORY_MAX_TEXT:
                text = text[:ZETTELFORGE_MEMORY_MAX_TEXT] + '\n...[truncated]'

            mm.store.remove_entity_mappings_for_note(note_id)
            try:
                mm.indexer.remove_note(note_id)
            except Exception:
                pass

            note.content.raw = text
            from zettelforge.vector_memory import get_embedding
            note.embedding.vector = get_embedding(text[:1000])
            _, body_only = parse_note_storage(text)
            note.semantic.context = mm.constructor._generate_context(body_only or text)
            note.semantic.keywords = mm.constructor._extract_keywords(body_only or text)[:7]

            raw_entities = mm.indexer.extractor.extract_all(body_only or text, use_llm=False)
            resolved_entities: Dict[str, List[str]] = {}
            for etype, elist in raw_entities.items():
                resolved_entities[etype] = [mm.resolver.resolve(etype, e) for e in elist]

            flat: List[str] = []
            for elist in resolved_entities.values():
                flat.extend(elist)
            note.semantic.entities = flat

            mm.indexer.add_note(note.id, resolved_entities)
            for etype, elist in resolved_entities.items():
                for evalue in elist:
                    mm.store.add_entity_mapping(etype, evalue, note.id)

            mm.store.rewrite_note(note)
            if mm._lance_store.lancedb is not None:
                try:
                    mm._lance_store._index_in_lance(note)
                except Exception:
                    pass

        if source_ref:
            parsed = parse_ref(source_ref)
            if parsed:
                if not _register_index(source_ref, parsed['ref_type'], parsed['entity_id'], text):
                    return None
        return note_to_dict(note)
    except Exception as exc:
        logger.warning('update_note failed: %s', exc)
        return None


def delete_note(note_id: str) -> bool:
    if not note_id:
        return False
    try:
        with _memory_lock():
            mm = get_manager()
            note = mm.store.get_note_by_id(note_id)
            if not note:
                return False
            source_ref = note.content.source_ref or ''
            mm.store.remove_entity_mappings_for_note(note_id)
            try:
                mm.indexer.remove_note(note_id)
            except Exception:
                pass
            deleted = mm.store.delete_note(note_id)
            if deleted and source_ref:
                remaining = mm.store.get_note_by_source_ref(source_ref)
                if not remaining and parse_ref(source_ref):
                    mark_ref_deleted(source_ref)
        return deleted
    except Exception as exc:
        logger.warning('delete_note failed: %s', exc)
        return False


def recall_query(query: str, k: int = 10, domain: str = 'cti', enrich_db: bool = True) -> List[Dict[str, Any]]:
    query = (query or '').strip()
    if not query:
        return []
    try:
        with _memory_lock():
            mm = get_manager()
            notes = mm.recall(query, domain=domain, k=k * 2)
        notes = _filter_active_notes(notes)[:k]
        return [note_to_dict(n, enrich_db=enrich_db) for n in notes]
    except Exception as exc:
        logger.warning('ZettelForge recall failed: %s', exc)
        return []


def recall_entity(entity_type: str, entity_value: str, k: int = 10) -> List[Dict[str, Any]]:
    stix_type = STIX_ENTITY_TYPES.get((entity_type or '').lower(), entity_type)
    try:
        with _memory_lock():
            mm = get_manager()
            if stix_type == 'intrusion_set' or entity_type.lower() in ('actor', 'group'):
                notes = mm.recall_actor(entity_value, k=k * 2)
            elif stix_type == 'attack_pattern' or (entity_value or '').upper().startswith('T'):
                notes = mm.recall_technique(entity_value.upper(), k=k * 2)
            elif stix_type == 'cve' or (entity_value or '').upper().startswith('CVE-'):
                notes = mm.recall_cve(entity_value.upper(), k=k * 2)
            else:
                notes = mm.recall_entity(stix_type, entity_value, k=k * 2)
        notes = _filter_active_notes(notes)[:k]
        return [note_to_dict(n) for n in notes]
    except Exception as exc:
        logger.warning('ZettelForge recall_entity failed: %s', exc)
        return []


def recall_by_ref(source_ref: str, k: int = 5) -> List[Dict[str, Any]]:
    """Recall memory entries tied to a stable odysafe:* ref (via entity search on id)."""
    parsed = parse_ref(source_ref)
    if not parsed:
        return []
    try:
        row = _get_db().get_cross_ref(source_ref)
        if row and row.get('status') == 'deleted':
            return []
    except Exception:
        pass
    query = parsed['entity_id']
    notes = recall_query(query, k=k)
    return [n for n in notes if n.get('source_ref') == source_ref] or notes[:1]


def traverse_graph(entity_type: str, entity_value: str, max_depth: int = 2) -> List[Dict[str, Any]]:
    stix_type = STIX_ENTITY_TYPES.get((entity_type or '').lower(), entity_type)
    try:
        with _memory_lock():
            mm = get_manager()
            paths = mm.traverse_graph(stix_type, entity_value, max_depth=max_depth)
        flat: List[Dict[str, Any]] = []
        for hop_list in paths or []:
            for edge in hop_list or []:
                if isinstance(edge, dict):
                    flat.append(edge)
        return flat
    except Exception as exc:
        logger.warning('ZettelForge traverse_graph failed: %s', exc)
        return []


def get_entity_relationships(entity_type: str, entity_value: str) -> List[Dict[str, Any]]:
    stix_type = STIX_ENTITY_TYPES.get((entity_type or '').lower(), entity_type)
    try:
        with _memory_lock():
            mm = get_manager()
            return mm.get_entity_relationships(stix_type, entity_value) or []
    except Exception as exc:
        logger.warning('ZettelForge get_entity_relationships failed: %s', exc)
        return []


def get_memory_stats() -> Dict[str, Any]:
    try:
        with _memory_lock():
            mm = get_manager()
            stats = mm.get_stats()
        top_entities = []
        index = stats.get('entity_index') or {}
        for etype, data in index.items():
            if not isinstance(data, dict):
                continue
            top_entities.append({
                'type': etype,
                'unique_entities': data.get('unique_entities', 0),
                'total_mappings': data.get('total_mappings', 0),
            })
        top_entities.sort(key=lambda x: x['total_mappings'], reverse=True)
        stats['top_entities'] = top_entities[:15]
        return stats
    except Exception as exc:
        logger.warning('ZettelForge get_stats failed: %s', exc)
        return {}


def ingest_sigma_rule(file_path: Path, source_ref: str = '') -> Optional[Dict[str, Any]]:
    try:
        from zettelforge.sigma import ingest_rule as ingest_sigma
        with _memory_lock():
            mm = get_manager()
            note, entities = ingest_sigma(
                str(file_path),
                mm,
                domain='detection',
                source_ref=source_ref or str(file_path.name),
            )
        return {
            'note': note_to_dict(note) if note else None,
            'entities': entities,
        }
    except Exception as exc:
        logger.warning('Sigma ingest failed: %s', exc)
        raise


def ingest_yara_rule(file_path: Path, tier: str = 'warn') -> Optional[Dict[str, Any]]:
    try:
        from zettelforge.yara import ingest_rule as ingest_yara
        with _memory_lock():
            mm = get_manager()
            note, entities = ingest_yara(
                str(file_path),
                mm,
                domain='detection',
                tier=tier,
            )
        return {
            'note': note_to_dict(note) if note else None,
            'entities': entities,
        }
    except Exception as exc:
        logger.warning('YARA ingest failed: %s', exc)
        raise


def build_source_memory_text(
    source_info: Optional[Dict],
    iocs_list: List[Dict],
    raw_text: Optional[str] = None,
) -> str:
    parts: List[str] = []
    if source_info:
        name = source_info.get('name') or ''
        if name:
            parts.append(f'Source: {name}')
        ctx = source_info.get('context') or ''
        if ctx:
            parts.append(f'Context: {ctx}')
        stype = source_info.get('source_type') or ''
        if stype:
            parts.append(f'Source type: {stype}')
    if raw_text and raw_text.strip():
        parts.append('\n--- Content ---\n')
        parts.append(raw_text.strip())
    elif iocs_list:
        parts.append(f'\nExtracted IOCs ({len(iocs_list)}):')
        for ioc in iocs_list[:200]:
            parts.append(f"- {ioc.get('ioc_type', 'unknown')}: {ioc.get('ioc_value', '')}")
    return '\n'.join(parts)


def extract_text_from_file(file_path: str) -> str:
    """Best-effort text extraction for memory indexing (reuse iocsearcher when available)."""
    try:
        from modules.iocsearcher_wrapper import IOCSEARCHER_AVAILABLE
        if IOCSEARCHER_AVAILABLE:
            from iocsearcher.document import open_document
            doc = open_document(file_path)
            if doc:
                text, _ = doc.get_text()
                return text or ''
    except Exception as exc:
        logger.debug('extract_text_from_file via iocsearcher failed: %s', exc)
    try:
        path = Path(file_path)
        if path.suffix.lower() in {'.txt', '.log', '.md', '.csv', '.json', '.xml', '.html', '.htm'}:
            return path.read_text(encoding='utf-8', errors='replace')
    except Exception as exc:
        logger.debug('extract_text_from_file plain read failed: %s', exc)
    return ''


def remember_source_import(
    source_id: int,
    source_info: Optional[Dict],
    iocs_list: List[Dict],
    raw_text: Optional[str] = None,
) -> str:
    text = build_source_memory_text(source_info, iocs_list, raw_text=raw_text)
    ref = make_ref('source', source_id)
    result = remember_text(
        text,
        source_ref=ref,
        domain='cti',
        source_type='odysafe_source',
        ref_type='source',
        entity_id=source_id,
    )
    return 'indexed' if result else 'failed'


def remember_ioc_note(ioc_id: int, ioc_value: str, ioc_type: str, notes: str,
                      title: str = '') -> str:
    ref = make_ref('ioc', ioc_id)
    if not notes or not notes.strip():
        mark_ref_deleted(ref)
        return 'not_indexed'
    result = remember_text(
        notes.strip(),
        title=(title or '').strip(),
        source_ref=ref,
        domain='cti',
        source_type='odysafe_ioc_note',
        ref_type='ioc',
        entity_id=ioc_id,
    )
    return 'indexed' if result else 'failed'


def remember_flash_report(data: Dict[str, Any]) -> str:
    ref_id = data.get('reference') or 'flash-report'
    fields = [
        ('Reference', data.get('reference')),
        ('Title', data.get('title') or data.get('subject')),
        ('Product type', data.get('product_type')),
        ('Intelligence requirement', data.get('pir')),
        ('Trigger', data.get('trigger_details')),
        ('Decision to investigate', data.get('investigation_decision')),
        ('Threat actor or cluster', data.get('entity_name') or data.get('threat_actor')),
        ('CVEs', data.get('cves')),
        ('Threat / Activity Type', data.get('threat_type') or data.get('incident_type')),
        ('Why it matters', data.get('why_it_matters')),
        ('Required action', data.get('required_action')),
        ('Anchor', data.get('anchor')),
        ('Observed activity', data.get('observed_activity')),
        ('Reported activity', data.get('reported_activity')),
        ('Assessed activity', data.get('assessed_activity')),
        ('Unknown activity', data.get('unknown_activity')),
        ('Next best pivot', data.get('next_best_pivot')),
        ('Diamond adversary', data.get('diamond_adversary')),
        ('Diamond capability', data.get('diamond_capability')),
        ('Diamond infrastructure', data.get('diamond_infrastructure')),
        ('Diamond victim', data.get('diamond_victim')),
        ('Assessment', data.get('overall_assessment')),
    ]
    lines = [f'Flash Report: {ref_id}']
    for label, val in fields:
        if val and str(val).strip():
            lines.append(f'{label}: {str(val).strip()}')
    iocs = data.get('iocs') or []
    if iocs:
        lines.append(f'\nIOCs in report ({len(iocs)}):')
        for ioc in iocs[:100]:
            if isinstance(ioc, dict):
                lines.append(f"- {ioc.get('type') or ioc.get('ioc_type', '?')}: {ioc.get('value') or ioc.get('ioc_value', '')}")
                notes = str(ioc.get('notes') or '').strip()
                if notes:
                    lines.append(f'  Notes: {notes}')
    ttps = data.get('ttps') or data.get('mitre_ttps') or []
    ttps = data.get('techniques') or ttps
    if ttps:
        lines.append('\nTTPs in report:')
        for t in ttps[:30]:
            if isinstance(t, dict):
                lines.append(f"- {t.get('id', t.get('technique_id', ''))} {t.get('name', '')}".strip())
                procedure = str(t.get('procedure') or '').strip()
                if procedure:
                    lines.append(f'  Procedure: {procedure}')
            else:
                lines.append(f'- {t}')
    ref = make_ref('flash', ref_id)
    result = remember_text(
        '\n'.join(lines),
        source_ref=ref,
        domain='cti',
        source_type='odysafe_flash_report',
        ref_type='flash',
        entity_id=ref_id,
    )
    return 'indexed' if result else 'failed'


def get_ioc_correlations(ioc_id: int, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Aggregate cross-module pointers for an IOC (read-only, no re-index)."""
    db = _get_db()
    ref = make_ref('ioc', ioc_id)
    cross = db.get_cross_ref(ref)
    memory_notes = []
    if is_available():
        try:
            memory_notes = recall_by_ref(ref, k=3)
        except Exception:
            memory_notes = []
    ttp_links = db.get_ioc_ttp_links(ioc_id)
    same_value = db.find_active_iocs_by_value(ioc_type, ioc_value, limit=5)
    same_value = [r for r in same_value if r['id'] != ioc_id]
    nav = resolve_ref_navigation(ref, (cross or {}).get('status', 'active'))
    return {
        'source_ref': ref,
        'index': cross,
        'memory_notes': memory_notes,
        'mitre_links': ttp_links,
        'duplicate_instances': same_value,
        'links': nav,
    }
