"""
Cross-module index registry for ODYSAFE CTI.

Tracks stable source_ref keys (odysafe:*) with content hashes so CTI Memory
is only re-indexed when data actually changes. Supports active/deleted status
for logical lifecycle without duplicating IOC rows.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Optional
from urllib.parse import urlencode

REF_PREFIX = 'odysafe'
REF_PATTERN = re.compile(r'^odysafe:(ioc|source|log|flash):(.+)$')
TTP_ID_PATTERN = re.compile(r'^T\d{4}(?:\.\d{3})?$', re.IGNORECASE)


def content_hash(text: str) -> str:
    """Short stable hash for skip-if-unchanged indexing."""
    if not text:
        return ''
    return hashlib.sha256(text.encode('utf-8')).hexdigest()[:24]


def make_ref(ref_type: str, entity_id) -> str:
    return f'{REF_PREFIX}:{ref_type}:{entity_id}'


def parse_ref(source_ref: str) -> Optional[Dict[str, str]]:
    m = REF_PATTERN.match((source_ref or '').strip())
    if not m:
        return None
    return {'ref_type': m.group(1), 'entity_id': m.group(2)}


def normalize_ttp_id(value: str) -> Optional[str]:
    v = (value or '').strip().upper()
    if TTP_ID_PATTERN.match(v):
        return v
    return None


def memory_note_url(note_id: str, query: str = '') -> str:
    """Deep link to CTI Memory: open Search tab, run recall, highlight one note."""
    params: Dict[str, str] = {}
    nid = (note_id or '').strip()
    q = (query or '').strip()
    if q:
        params['q'] = q
    if nid:
        params['note'] = nid
    return f'/memory?{urlencode(params)}' if params else '/memory'


def memory_attach_url(**kwargs) -> str:
    """Build /memory URL to compose a note linked to an IOC, TTP, entity, or log."""
    params: Dict[str, str] = {}
    kind = (kwargs.get('kind') or 'entity').strip().lower()
    params['attach'] = kind

    for key in ('id', 'ioc_id', 'value', 'name', 'entity_type', 'type', 'ioc_type', 'technique'):
        val = kwargs.get(key)
        if val is None or val == '':
            continue
        if key in ('ioc_id',):
            params['id'] = str(val)
        elif key == 'technique':
            params['id'] = str(val).upper()
        elif key == 'ioc_type':
            params['type'] = str(val)
        elif key not in params or key in ('value', 'name', 'entity_type', 'type'):
            if key == 'type' and 'type' not in params:
                params['type'] = str(val)
            elif key == 'entity_type':
                params['entity_type'] = str(val)
            elif key == 'value':
                params['value'] = str(val)
            elif key == 'name':
                params['name'] = str(val)
            elif key == 'id':
                params['id'] = str(val)

    if kind == 'ioc' and 'id' not in params and kwargs.get('id'):
        params['id'] = str(kwargs['id'])
    return f'/memory?{urlencode(params)}'


def resolve_ref_navigation(source_ref: str, status: str = 'active') -> Dict[str, Any]:
    """Build UI navigation from a source_ref (no DB lookup)."""
    parsed = parse_ref(source_ref)
    if not parsed:
        return {}
    rt = parsed['ref_type']
    eid = parsed['entity_id']
    nav: Dict[str, Any] = {
        'source_ref': source_ref,
        'ref_type': rt,
        'entity_id': eid,
        'status': status,
    }
    if rt == 'ioc':
        nav['url'] = f'/ioc/{eid}'
        nav['label'] = f'IOC #{eid}'
    elif rt == 'source':
        nav['url'] = f'/sources?highlight={eid}'
        nav['label'] = f'Source #{eid}'
    elif rt == 'flash':
        nav['url'] = f'/flash-report?ref={eid}'
        nav['label'] = f'Report {eid}'
    return nav


def enrich_note_dict(note_dict: Dict[str, Any], cross_ref_row: Optional[Dict] = None) -> Dict[str, Any]:
    """Attach source_ref and navigation links to a memory note dict."""
    source_ref = note_dict.get('source_ref') or ''
    status = 'active'
    if cross_ref_row:
        source_ref = source_ref or cross_ref_row.get('ref_key', '')
        status = cross_ref_row.get('status') or 'active'
    links: Dict[str, Any] = dict(note_dict.get('links') or {})
    if source_ref:
        note_dict['source_ref'] = source_ref
        nav = resolve_ref_navigation(source_ref, status)
        if nav:
            links.update(nav)
    note_id = (note_dict.get('id') or '').strip()
    if note_id:
        links['memory_url'] = memory_note_url(note_id)
    if links:
        note_dict['links'] = links
    note_dict['index_status'] = status
    return note_dict
