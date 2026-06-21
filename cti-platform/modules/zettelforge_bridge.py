"""
Bridge to ZettelForge CTI memory (regex extraction, vector recall, knowledge graph).
No LLM: background NER and synthesis are disabled via environment variables.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import ZETTELFORGE_MEMORY_DIR, ZETTELFORGE_MEMORY_MAX_TEXT

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_manager = None
_import_error: Optional[str] = None
_env_configured = False

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


def _configure_env() -> None:
    global _env_configured
    if _env_configured:
        return
    ZETTELFORGE_MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault('ZETTELFORGE_DATA_DIR', str(ZETTELFORGE_MEMORY_DIR))
    os.environ.setdefault('ZETTELFORGE_LLM_NER_ENABLED', 'false')
    os.environ.setdefault('AMEM_DATA_DIR', str(ZETTELFORGE_MEMORY_DIR))
    _env_configured = True


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
        'error': None if ok else (_import_error or 'ZettelForge not available'),
    }


def get_manager():
    """Lazy singleton MemoryManager (thread-safe)."""
    global _manager, _import_error
    if _manager is not None:
        return _manager
    _configure_env()
    with _lock:
        if _manager is not None:
            return _manager
        try:
            from zettelforge import MemoryManager
            _manager = MemoryManager()
            _import_error = None
            return _manager
        except ImportError as exc:
            _import_error = f'Install zettelforge: pip install zettelforge ({exc})'
            raise RuntimeError(_import_error) from exc
        except Exception as exc:
            _import_error = str(exc)
            raise


def note_to_dict(note) -> Dict[str, Any]:
    content = getattr(getattr(note, 'content', None), 'raw', '') or ''
    meta = getattr(note, 'metadata', None)
    return {
        'id': getattr(note, 'id', ''),
        'content': content,
        'domain': getattr(meta, 'domain', '') if meta else '',
        'tier': getattr(meta, 'tier', '') if meta else '',
        'created_at': getattr(note, 'created_at', None),
        'updated_at': getattr(note, 'updated_at', None),
    }


def remember_text(
    content: str,
    *,
    source_ref: str = '',
    domain: str = 'cti',
    source_type: str = 'odysafe',
) -> Optional[Dict[str, Any]]:
    """Store text in CTI memory (regex entities + vector + co-occurrence graph)."""
    text = (content or '').strip()
    if not text:
        return None
    if len(text) > ZETTELFORGE_MEMORY_MAX_TEXT:
        text = text[:ZETTELFORGE_MEMORY_MAX_TEXT] + '\n...[truncated]'
    try:
        with _lock:
            mm = get_manager()
            note, status = mm.remember(
                text,
                source_type=source_type,
                source_ref=source_ref,
                domain=domain,
                evolve=False,
            )
        return {'note': note_to_dict(note), 'status': status}
    except Exception as exc:
        logger.warning('ZettelForge remember failed: %s', exc)
        return None


def recall_query(query: str, k: int = 10, domain: str = 'cti') -> List[Dict[str, Any]]:
    query = (query or '').strip()
    if not query:
        return []
    try:
        with _lock:
            mm = get_manager()
            notes = mm.recall(query, domain=domain, k=k)
        return [note_to_dict(n) for n in notes]
    except Exception as exc:
        logger.warning('ZettelForge recall failed: %s', exc)
        return []


def recall_entity(entity_type: str, entity_value: str, k: int = 10) -> List[Dict[str, Any]]:
    stix_type = STIX_ENTITY_TYPES.get((entity_type or '').lower(), entity_type)
    try:
        with _lock:
            mm = get_manager()
            if stix_type == 'intrusion_set' or entity_type.lower() in ('actor', 'group'):
                notes = mm.recall_actor(entity_value, k=k)
            elif stix_type == 'attack_pattern' or (entity_value or '').upper().startswith('T'):
                notes = mm.recall_technique(entity_value.upper(), k=k)
            elif stix_type == 'cve' or (entity_value or '').upper().startswith('CVE-'):
                notes = mm.recall_cve(entity_value.upper(), k=k)
            else:
                notes = mm.recall_entity(stix_type, entity_value, k=k)
        return [note_to_dict(n) for n in notes]
    except Exception as exc:
        logger.warning('ZettelForge recall_entity failed: %s', exc)
        return []


def traverse_graph(entity_type: str, entity_value: str, max_depth: int = 2) -> List[Dict[str, Any]]:
    stix_type = STIX_ENTITY_TYPES.get((entity_type or '').lower(), entity_type)
    try:
        with _lock:
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
        with _lock:
            mm = get_manager()
            return mm.get_entity_relationships(stix_type, entity_value) or []
    except Exception as exc:
        logger.warning('ZettelForge get_entity_relationships failed: %s', exc)
        return []


def get_memory_stats() -> Dict[str, Any]:
    try:
        with _lock:
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
        with _lock:
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
        with _lock:
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
) -> None:
    text = build_source_memory_text(source_info, iocs_list, raw_text=raw_text)
    remember_text(
        text,
        source_ref=f'odysafe:source:{source_id}',
        domain='cti',
        source_type='odysafe_source',
    )


def remember_ioc_note(ioc_id: int, ioc_value: str, ioc_type: str, notes: str) -> None:
    if not notes or not notes.strip():
        return
    content = (
        f'IOC note ({ioc_type}: {ioc_value})\n'
        f'{notes.strip()}'
    )
    remember_text(
        content,
        source_ref=f'odysafe:ioc:{ioc_id}',
        domain='cti',
        source_type='odysafe_ioc_note',
    )


def remember_investigation_session(session_id: int, name: str, notes: str, group_name: str = '') -> None:
    parts = [f'Investigation session: {name}']
    if group_name:
        parts.append(f'Scope group: {group_name}')
    if notes and notes.strip():
        parts.append(notes.strip())
    remember_text(
        '\n'.join(parts),
        source_ref=f'odysafe:investigation:{session_id}',
        domain='cti',
        source_type='odysafe_investigation',
    )


def remember_log_incident(incident_id: str, filename: str, technique_summary: List[str]) -> None:
    lines = [f'Log analysis incident: {filename}', f'Incident ID: {incident_id}']
    if technique_summary:
        lines.append('Detected techniques:')
        lines.extend(f'- {t}' for t in technique_summary[:50])
    remember_text(
        '\n'.join(lines),
        source_ref=f'odysafe:log:{incident_id}',
        domain='cti',
        source_type='odysafe_log',
    )


def remember_flash_report(data: Dict[str, Any]) -> None:
    ref = data.get('reference') or 'flash-report'
    fields = [
        ('Reference', data.get('reference')),
        ('Subject', data.get('subject')),
        ('Threat actor', data.get('threat_actor')),
        ('CVEs', data.get('cves')),
        ('Incident type', data.get('incident_type')),
        ('Affected entities', data.get('affected_entities')),
        ('Threat nature', data.get('threat_nature')),
        ('Diamond adversary', data.get('diamond_adversary')),
        ('Diamond capability', data.get('diamond_capability')),
        ('Diamond infrastructure', data.get('diamond_infrastructure')),
        ('Diamond victim', data.get('diamond_victim')),
        ('Assessment', data.get('overall_assessment')),
    ]
    lines = [f'Flash Report: {ref}']
    for label, val in fields:
        if val and str(val).strip():
            lines.append(f'{label}: {str(val).strip()}')
    remember_text(
        '\n'.join(lines),
        source_ref=f'odysafe:flash:{ref}',
        domain='cti',
        source_type='odysafe_flash_report',
    )
