"""Extract source metadata and IOC records from STIX 2.0 and STIX 2.1 content."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Tuple


SCO_VALUE_TYPES = {
    'ipv4-addr': 'ipv4',
    'ipv6-addr': 'ipv6',
    'domain-name': 'domain',
    'url': 'url',
    'email-addr': 'email',
    'mac-addr': 'mac',
    'mutex': 'mutex',
}

HASH_TYPES = {
    'MD5': 'md5',
    'SHA-1': 'sha1',
    'SHA-256': 'sha256',
    'SHA-512': 'sha512',
}

STANDARD_TLP_MARKINGS = {
    'marking-definition--5e57c739-391a-4eb3-b6c8-b55b8d663e2e': 'RED',
    'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9': 'AMBER',
    'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da': 'GREEN',
    'marking-definition--7aebcb1e-5e22-46fa-8c15-0aa02e4dcd3d': 'WHITE',
    'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487': 'WHITE',
}

PATTERN_VALUE_RE = re.compile(
    r"(?P<type>[a-z0-9-]+):(?P<property>[a-zA-Z0-9_.\-']+)\s*=\s*'(?P<value>(?:\\.|[^'])*)'",
    re.IGNORECASE,
)


def parse_bundle(content: str | Dict[str, Any] | List[Any]) -> Dict[str, Any]:
    data = json.loads(content) if isinstance(content, str) else content
    if isinstance(data, list):
        return {'type': 'bundle', 'objects': data}
    if not isinstance(data, dict):
        raise ValueError('STIX content must be a JSON object or array')
    if data.get('type') == 'bundle' and isinstance(data.get('objects'), list):
        return data
    if data.get('type') and data.get('id'):
        return {'type': 'bundle', 'objects': [data]}
    raise ValueError('Invalid STIX content')


def _all_objects(bundle: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for obj in bundle.get('objects', []):
        if not isinstance(obj, dict):
            continue
        yield obj
        if obj.get('type') == 'observed-data' and isinstance(obj.get('objects'), dict):
            for local_key, sco in obj['objects'].items():
                if isinstance(sco, dict):
                    embedded = dict(sco)
                    embedded['_parent_id'] = obj.get('id', '')
                    embedded['_local_key'] = str(local_key)
                    embedded['_parent_markings'] = obj.get('object_marking_refs', [])
                    embedded['_parent_first_observed'] = obj.get('first_observed')
                    embedded['_parent_last_observed'] = obj.get('last_observed')
                    yield embedded


def _tlp_map(bundle: Dict[str, Any]) -> Dict[str, str]:
    result = dict(STANDARD_TLP_MARKINGS)
    for obj in bundle.get('objects', []):
        if not isinstance(obj, dict) or obj.get('type') != 'marking-definition':
            continue
        definition = obj.get('definition') or {}
        color = str(definition.get('tlp') or '').upper()
        if color in {'RED', 'AMBER', 'GREEN', 'WHITE', 'CLEAR'} and obj.get('id'):
            result[obj['id']] = 'WHITE' if color == 'CLEAR' else color
    return result


def _confidence(value: Any) -> str:
    try:
        score = int(value)
    except (TypeError, ValueError):
        return 'Unknown'
    if score >= 70:
        return 'High'
    if score >= 40:
        return 'Medium'
    return 'Low'


def _object_tlp(obj: Dict[str, Any], markings: Dict[str, str]) -> str:
    refs = obj.get('object_marking_refs') or obj.get('_parent_markings') or []
    colors = [markings[ref] for ref in refs if ref in markings]
    for color in ('RED', 'AMBER', 'GREEN', 'WHITE'):
        if color in colors:
            return color
    return 'WHITE'


def _notes(obj: Dict[str, Any]) -> str:
    parts = []
    if obj.get('id'):
        parts.append(f"STIX ID: {obj['id']}")
    elif obj.get('_parent_id'):
        parts.append(f"STIX 2.0 object: {obj['_parent_id']} / {obj.get('_local_key', '')}")
    if obj.get('name'):
        parts.append(f"Name: {obj['name']}")
    if obj.get('description'):
        parts.append(f"Description: {obj['description']}")
    if obj.get('labels'):
        parts.append('Labels: ' + ', '.join(str(label) for label in obj['labels']))
    first_seen = obj.get('first_observed') or obj.get('first_seen') or obj.get('_parent_first_observed')
    last_seen = obj.get('last_observed') or obj.get('last_seen') or obj.get('_parent_last_observed')
    if first_seen:
        parts.append(f"First seen: {first_seen}")
    if last_seen:
        parts.append(f"Last seen: {last_seen}")
    return '\n'.join(parts)


def _records_from_object(obj: Dict[str, Any], markings: Dict[str, str]) -> Iterable[Dict[str, str]]:
    first_seen = obj.get('first_observed') or obj.get('first_seen') or obj.get('valid_from') or obj.get('_parent_first_observed') or ''
    last_seen = obj.get('last_observed') or obj.get('last_seen') or obj.get('valid_until') or obj.get('_parent_last_observed') or ''
    common = {
        'tlp': _object_tlp(obj, markings),
        'confidence': _confidence(obj.get('confidence')),
        'notes': _notes(obj),
        'first_seen': str(first_seen),
        'last_seen': str(last_seen),
    }
    stix_type = str(obj.get('type') or '').lower()
    if stix_type in SCO_VALUE_TYPES and obj.get('value'):
        yield {**common, 'ioc_type': SCO_VALUE_TYPES[stix_type], 'value': str(obj['value'])}

    if stix_type in {'file', 'x509-certificate'}:
        for algorithm, value in (obj.get('hashes') or {}).items():
            ioc_type = HASH_TYPES.get(str(algorithm).upper())
            if ioc_type and value:
                yield {**common, 'ioc_type': ioc_type, 'value': str(value)}

    if stix_type == 'indicator' and obj.get('pattern'):
        for match in PATTERN_VALUE_RE.finditer(str(obj['pattern'])):
            pattern_type = match.group('type').lower()
            prop = match.group('property').replace("'", '').lower()
            value = match.group('value').replace("\\'", "'").replace('\\\\', '\\')
            ioc_type = SCO_VALUE_TYPES.get(pattern_type)
            if pattern_type in {'file', 'x509-certificate'} and prop.startswith('hashes.'):
                ioc_type = HASH_TYPES.get(prop.split('.', 1)[1].upper())
            if ioc_type and value:
                yield {**common, 'ioc_type': ioc_type, 'value': value}


def extract_stix_iocs(content: str | Dict[str, Any] | List[Any]) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    bundle = parse_bundle(content)
    markings = _tlp_map(bundle)
    records = []
    seen = set()
    for obj in _all_objects(bundle):
        for record in _records_from_object(obj, markings):
            key = (record['ioc_type'].lower(), record['value'])
            if key not in seen:
                seen.add(key)
                records.append(record)
    return bundle, records


def source_metadata(bundle: Dict[str, Any], filename: str) -> Dict[str, str]:
    reports = [obj for obj in bundle.get('objects', []) if isinstance(obj, dict) and obj.get('type') == 'report']
    report = reports[0] if reports else {}
    name = str(report.get('name') or bundle.get('id') or filename).strip()
    details = ['Imported from STIX Graph Analyzer.']
    if bundle.get('id'):
        details.append(f"Bundle ID: {bundle['id']}")
    if report.get('published'):
        details.append(f"Published: {report['published']}")
    creators = {
        obj.get('id'): obj.get('name')
        for obj in bundle.get('objects', [])
        if isinstance(obj, dict) and obj.get('type') == 'identity' and obj.get('id') and obj.get('name')
    }
    creator = creators.get(report.get('created_by_ref'))
    if creator:
        details.append(f"Created by: {creator}")
    details.append(f"STIX objects: {len(bundle.get('objects', []))}")
    if report.get('description'):
        details.append(str(report['description']))
    return {'name': name[:255], 'context': '\n'.join(details)}
