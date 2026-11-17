"""
Full-platform backup export/import (Settings → Backup & Restore).
Covers IOC lifecycle fields, tags, MITRE IOC links, cross_refs, source templates,
group exclusions, saved STIX models, CTI favorites, and CTI Memory.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

from config import ZETTELFORGE_MEMORY_DIR

logger = logging.getLogger(__name__)

BACKUP_VERSION = '2.1'
SUPPORTED_BACKUP_VERSIONS = frozenset({'1.0', '2.0', BACKUP_VERSION})
MAX_BACKUP_MEMBERS = 10_000
MAX_BACKUP_UNCOMPRESSED_SIZE = 1024 * 1024 * 1024
SETTINGS_SKIP_ON_IMPORT = frozenset({'secret_key'})

_BACKUP_JSON_TYPES = {
    'metadata.json': dict,
    'config.json': dict,
    'sources.json': list,
    'iocs.json': list,
    'tags.json': list,
    'ioc_ttp_links.json': list,
    'investigation_sessions.json': list,
    'cross_refs.json': list,
    'source_templates.json': list,
    'ioc_source_group_exclusions.json': list,
    'saved_stix_models.json': list,
}

_REQUIRED_BACKUP_FILES = {
    '1.0': frozenset({'config.json', 'sources.json', 'iocs.json'}),
    '2.0': frozenset({
        'metadata.json', 'config.json', 'sources.json', 'iocs.json', 'tags.json',
        'ioc_ttp_links.json', 'investigation_sessions.json', 'saved_stix_models.json',
    }),
    BACKUP_VERSION: frozenset({
        'metadata.json', 'config.json', 'sources.json', 'iocs.json', 'tags.json',
        'ioc_ttp_links.json', 'cross_refs.json', 'source_templates.json',
        'ioc_source_group_exclusions.json', 'saved_stix_models.json',
    }),
}

_IOC_BACKUP_COLUMNS = (
    'notes', 'first_seen', 'last_seen', 'tlp', 'validation_status', 'confidence',
    'expiry_date', 'lifecycle_status', 'kill_chain_phase', 'mitre_technique',
    'context', 'is_whitelisted', 'raw_value',
)


def _json_dump(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _read_json_zip(zipf: zipfile.ZipFile, name: str) -> Any:
    if name not in zipf.namelist():
        return None
    return json.loads(zipf.read(name).decode('utf-8'))


def _validate_backup_zip(zipf: zipfile.ZipFile) -> Dict[str, Any]:
    """Validate archive safety and backup structure before any restore writes."""
    members = zipf.infolist()
    if not members:
        raise ValueError('Backup ZIP is empty')
    if len(members) > MAX_BACKUP_MEMBERS:
        raise ValueError(
            f'Backup ZIP contains too many entries ({len(members)}; maximum {MAX_BACKUP_MEMBERS})'
        )

    normalized_names = set()
    total_uncompressed_size = 0
    for member in members:
        normalized_name = member.filename.replace('\\', '/')
        member_path = PurePosixPath(normalized_name)
        if member_path.is_absolute() or '..' in member_path.parts:
            raise ValueError(f'Unsafe path in backup ZIP: {member.filename}')
        if normalized_name.startswith('zettelforge/'):
            memory_path = PurePosixPath(normalized_name[len('zettelforge/'):])
            if memory_path.is_absolute() or '..' in memory_path.parts:
                raise ValueError(f'Unsafe CTI Memory path in backup ZIP: {member.filename}')
        if normalized_name in normalized_names:
            raise ValueError(f'Duplicate entry in backup ZIP: {member.filename}')
        normalized_names.add(normalized_name)

        total_uncompressed_size += member.file_size
        if total_uncompressed_size > MAX_BACKUP_UNCOMPRESSED_SIZE:
            max_size_mb = MAX_BACKUP_UNCOMPRESSED_SIZE // (1024 * 1024)
            raise ValueError(
                f'Backup ZIP exceeds the {max_size_mb} MB uncompressed size limit'
            )

    try:
        corrupt_member = zipf.testzip()
    except RuntimeError as exc:
        raise ValueError(f'Backup ZIP cannot be validated: {exc}') from exc
    if corrupt_member:
        raise ValueError(f'Corrupt entry in backup ZIP: {corrupt_member}')

    if 'metadata.json' in normalized_names:
        metadata = _read_json_zip(zipf, 'metadata.json')
        if not isinstance(metadata, dict):
            raise ValueError('metadata.json must contain a JSON object')
        version = str(metadata.get('version') or '').strip()
        if not version:
            raise ValueError('metadata.json is missing the backup version')
    else:
        # Legacy v1.0 backups did not necessarily include a manifest.
        metadata = {}
        version = '1.0'

    if version not in SUPPORTED_BACKUP_VERSIONS:
        supported = ', '.join(sorted(SUPPORTED_BACKUP_VERSIONS))
        raise ValueError(
            f'Unsupported backup version {version!r}; supported versions: {supported}'
        )

    missing_files = sorted(_REQUIRED_BACKUP_FILES[version] - normalized_names)
    if missing_files:
        raise ValueError(
            f'Backup version {version} is missing required files: {", ".join(missing_files)}'
        )

    for name, expected_type in _BACKUP_JSON_TYPES.items():
        if name not in normalized_names:
            continue
        payload = _read_json_zip(zipf, name)
        if not isinstance(payload, expected_type):
            expected_name = 'object' if expected_type is dict else 'array'
            raise ValueError(f'{name} must contain a JSON {expected_name}')
        if expected_type is list and any(not isinstance(item, dict) for item in payload):
            raise ValueError(f'{name} must contain only JSON objects')

    config = _read_json_zip(zipf, 'config.json')
    if not isinstance(config.get('settings', {}), dict):
        raise ValueError('config.json field "settings" must be a JSON object')
    for field in ('groups', 'cti_favorites', 'rtm_favorites'):
        value = config.get(field, [])
        if not isinstance(value, list):
            raise ValueError(f'config.json field "{field}" must be a JSON array')
    if any(not isinstance(group, dict) for group in config.get('groups', [])):
        raise ValueError('config.json field "groups" must contain only JSON objects')

    for name, nested_fields in (
        ('sources.json', ('groups',)),
        ('iocs.json', ('groups', 'tags')),
    ):
        records = _read_json_zip(zipf, name)
        for index, record in enumerate(records):
            for field in nested_fields:
                value = record.get(field, [])
                if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
                    raise ValueError(
                        f'{name} item {index} field "{field}" must be an array of JSON objects'
                    )

    return {**metadata, 'version': version}


def _format_ioc_export(ioc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'id': ioc.get('id'),
        'source_id': ioc.get('source_id'),
        'source_name': ioc.get('source_name'),
        'ioc_type': ioc.get('ioc_type'),
        'ioc_value': ioc.get('ioc_value'),
        'raw_value': ioc.get('raw_value'),
        'first_seen': ioc.get('first_seen'),
        'last_seen': ioc.get('last_seen'),
        'notes': ioc.get('notes'),
        'created_at': ioc.get('created_at'),
        'tlp': ioc.get('tlp'),
        'validation_status': ioc.get('validation_status'),
        'confidence': ioc.get('confidence'),
        'expiry_date': ioc.get('expiry_date'),
        'lifecycle_status': ioc.get('lifecycle_status'),
        'kill_chain_phase': ioc.get('kill_chain_phase'),
        'mitre_technique': ioc.get('mitre_technique'),
        'context': ioc.get('context'),
        'is_whitelisted': ioc.get('is_whitelisted'),
        'groups': [
            {'id': g.get('id'), 'name': g.get('name'), 'color': g.get('color')}
            for g in ioc.get('groups', [])
        ],
        'tags': [
            {'id': t.get('id'), 'name': t.get('name'), 'category': t.get('category'), 'color': t.get('color')}
            for t in ioc.get('tags', [])
        ],
    }


def _export_ioc_ttp_links(db) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with db.connection() as conn:
        cursor = conn.execute("""
            SELECT s.name AS source_name, i.ioc_type, i.ioc_value,
                   itt.technique_id, itt.confidence, itt.notes, itt.created_at
            FROM ioc_ttp_links itt
            JOIN iocs i ON i.id = itt.ioc_id
            JOIN sources s ON s.id = i.source_id
            WHERE i.is_deleted = 0 AND s.is_deleted = 0
        """)
        for row in cursor.fetchall():
            rows.append(dict(row))
    return rows


def _export_tags(db) -> List[Dict[str, Any]]:
    return db.get_all_tags(only_with_iocs=False, include_stats=False)


def _export_source_templates(db) -> List[Dict[str, Any]]:
    try:
        return db.get_all_source_templates()
    except Exception as exc:
        logger.debug('source_templates export skipped: %s', exc)
        return []


def _export_ioc_group_exclusions(db) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with db.connection() as conn:
        cursor = conn.execute("""
            SELECT s.name AS source_name, i.ioc_type, i.ioc_value, g.name AS group_name
            FROM ioc_source_group_exclusions ex
            JOIN iocs i ON i.id = ex.ioc_id
            JOIN sources s ON s.id = i.source_id
            JOIN groups g ON g.id = ex.group_id
            WHERE i.is_deleted = 0 AND s.is_deleted = 0
        """)
        for row in cursor.fetchall():
            rows.append(dict(row))
    return rows


def build_export_zip(
    zipf: zipfile.ZipFile,
    db,
    github_repo_manager,
    rtm_repo_manager,
) -> Dict[str, int]:
    """Write all backup payloads into an open ZipFile. Returns metadata counts."""
    iocs: List[Dict[str, Any]] = []
    for batch in db.get_all_iocs_streaming(limit=None):
        iocs.extend(batch)

    iocs_export = [_format_ioc_export(ioc) for ioc in iocs]
    zipf.writestr('iocs.json', _json_dump(iocs_export))

    all_sources = db.get_all_sources(limit=100000)
    sources_export = []
    for source in all_sources:
        sources_export.append({
            'id': source.get('id'),
            'name': source.get('name'),
            'context': source.get('context'),
            'source_type': source.get('source_type'),
            'file_path': source.get('file_path'),
            'original_filename': source.get('original_filename'),
            'created_at': source.get('created_at'),
            'status': source.get('status'),
            'groups': [
                {'id': g.get('id'), 'name': g.get('name'), 'color': g.get('color')}
                for g in source.get('groups', [])
            ],
        })
    zipf.writestr('sources.json', _json_dump(sources_export))

    tags_export = _export_tags(db)
    zipf.writestr('tags.json', _json_dump(tags_export))

    ttp_links = _export_ioc_ttp_links(db)
    zipf.writestr('ioc_ttp_links.json', _json_dump(ttp_links))

    cross_refs = []
    with db.connection() as conn:
        for row in conn.execute("SELECT * FROM cross_refs ORDER BY ref_key"):
            cross_refs.append(dict(row))
    zipf.writestr('cross_refs.json', _json_dump(cross_refs))

    source_templates = _export_source_templates(db)
    zipf.writestr('source_templates.json', _json_dump(source_templates))

    group_exclusions = _export_ioc_group_exclusions(db)
    zipf.writestr('ioc_source_group_exclusions.json', _json_dump(group_exclusions))

    saved_stix = []
    with db.connection() as conn:
        for row in conn.execute("SELECT * FROM saved_stix_models ORDER BY updated_at DESC, created_at DESC"):
            saved_stix.append(dict(row))
    zipf.writestr('saved_stix_models.json', _json_dump(saved_stix))

    all_settings = db.get_all_settings()
    all_groups = db.get_all_groups()
    config_export = {
        'settings': all_settings,
        'groups': [
            {
                'id': g.get('id'),
                'name': g.get('name'),
                'description': g.get('description'),
                'color': g.get('color'),
                'created_at': g.get('created_at'),
            }
            for g in all_groups
        ],
        'cti_favorites': list(github_repo_manager.favorites) if hasattr(github_repo_manager, 'favorites') else [],
        'rtm_favorites': list(rtm_repo_manager.favorites) if hasattr(rtm_repo_manager, 'favorites') else [],
    }
    zipf.writestr('config.json', _json_dump(config_export))

    zf_file_count = 0
    if ZETTELFORGE_MEMORY_DIR.exists():
        for path in ZETTELFORGE_MEMORY_DIR.rglob('*'):
            if path.is_file():
                arcname = Path('zettelforge') / path.relative_to(ZETTELFORGE_MEMORY_DIR)
                zipf.write(path, arcname.as_posix())
                zf_file_count += 1

    metadata = {
        'export_date': datetime.now().isoformat(),
        'version': BACKUP_VERSION,
        'total_iocs': len(iocs_export),
        'total_sources': len(sources_export),
        'total_groups': len(all_groups),
        'total_tags': len(tags_export),
        'total_ioc_ttp_links': len(ttp_links),
        'total_cross_refs': len(cross_refs),
        'total_source_templates': len(source_templates),
        'total_ioc_group_exclusions': len(group_exclusions),
        'total_saved_stix_models': len(saved_stix),
        'total_cti_favorites': len(config_export['cti_favorites']),
        'total_rtm_favorites': len(config_export['rtm_favorites']),
        'zettelforge_files': zf_file_count,
        'includes': [
            'iocs.json (lifecycle, tags, groups)',
            'sources.json',
            'tags.json (tag catalog)',
            'ioc_ttp_links.json (MITRE IOC links)',
            'cross_refs.json (Memory index registry)',
            'source_templates.json (extraction templates)',
            'ioc_source_group_exclusions.json',
            'saved_stix_models.json',
            'config.json (settings, groups, DeepDarkCTI + Ransomware favorites)',
            'zettelforge/ (CTI Memory data, when present)',
        ],
        'excludes': [
            'users (password hashes)',
            'flash_report browser drafts (localStorage)',
            'uploaded files and output files on disk',
            'local MITRE ATT&CK JSON (re-download from Analysis)',
            'audit_log',
        ],
        'components': [
            'metadata.json',
            'iocs.json',
            'sources.json',
            'tags.json',
            'ioc_ttp_links.json',
            'cross_refs.json',
            'source_templates.json',
            'ioc_source_group_exclusions.json',
            'saved_stix_models.json',
            'config.json',
            'zettelforge/',
        ],
    }
    zipf.writestr('metadata.json', _json_dump(metadata))
    return metadata


def _apply_ioc_backup_fields(db, ioc_id: int, ioc_data: Dict[str, Any]) -> None:
    values = {col: ioc_data.get(col) for col in _IOC_BACKUP_COLUMNS if col in ioc_data}
    if not values:
        return
    assignments = ', '.join(f'{col} = ?' for col in values)
    params = list(values.values()) + [ioc_id]
    with db.connection() as conn:
        conn.execute(f"UPDATE iocs SET {assignments} WHERE id = ?", params)
        conn.commit()


def _resolve_ioc_id(db, source_name: str, ioc_type: str, ioc_value: str) -> Optional[int]:
    with db.connection() as conn:
        row = conn.execute("""
            SELECT i.id FROM iocs i
            JOIN sources s ON s.id = i.source_id
            WHERE s.name = ? AND i.ioc_type = ? AND i.ioc_value = ?
              AND i.is_deleted = 0 AND s.is_deleted = 0
            LIMIT 1
        """, (source_name, ioc_type, ioc_value)).fetchone()
    return row['id'] if row else None


def _import_tags_on_ioc(db, ioc_id: int, tags: List[Dict[str, Any]], stats: Dict[str, int]) -> None:
    for tag_data in tags or []:
        tag_name = tag_data.get('name')
        if not tag_name:
            continue
        tag_id = db.create_tag(
            tag_name,
            category=tag_data.get('category') or 'custom',
            color=tag_data.get('color'),
        )
        db.add_tag_to_ioc(ioc_id, tag_id)
        stats['tags_imported'] = stats.get('tags_imported', 0) + 1


def _import_config(zipf: zipfile.ZipFile, db, github_repo_manager, rtm_repo_manager, stats: Dict[str, int]) -> Dict[int, int]:
    group_id_map: Dict[int, int] = {}
    config = _read_json_zip(zipf, 'config.json')
    if not config:
        return group_id_map

    for group_data in config.get('groups', []):
        old_group_id = group_data.get('id')
        group_name = group_data.get('name')
        if not group_name:
            continue
        existing_group = db.get_group_by_name(group_name)
        if existing_group:
            new_group_id = existing_group['id']
        else:
            new_group_id = db.create_group(
                name=group_name,
                color=group_data.get('color', '#8B5CF6'),
                description=group_data.get('description', ''),
            )
            stats['groups_imported'] += 1
        if old_group_id:
            group_id_map[old_group_id] = new_group_id

    for key, value in (config.get('settings') or {}).items():
        if key in SETTINGS_SKIP_ON_IMPORT or value is None:
            continue
        db.set_setting(key, str(value))

    if isinstance(config.get('cti_favorites'), list):
        github_repo_manager.favorites = set(config['cti_favorites'])
        github_repo_manager._save_favorites()

    if isinstance(config.get('rtm_favorites'), list):
        rtm_repo_manager.favorites = set(config['rtm_favorites'])
        rtm_repo_manager._save_favorites()
        stats['rtm_favorites_imported'] = len(config['rtm_favorites'])

    stats['config_imported'] = True
    return group_id_map


def _import_tag_catalog(db, zipf: zipfile.ZipFile, stats: Dict[str, int]) -> None:
    tags_data = _read_json_zip(zipf, 'tags.json')
    if not isinstance(tags_data, list):
        return
    for tag in tags_data:
        name = tag.get('name')
        if not name:
            continue
        db.create_tag(name, category=tag.get('category') or 'custom', color=tag.get('color'))
        stats['tags_imported'] = stats.get('tags_imported', 0) + 1


def _import_sources_file(db, zipf: zipfile.ZipFile, stats: Dict[str, int]) -> Dict[str, int]:
    """Returns map source_name -> source_id for sources created/found."""
    source_name_map: Dict[str, int] = {}
    sources_data = _read_json_zip(zipf, 'sources.json')
    if not isinstance(sources_data, list):
        return source_name_map

    for src in sources_data:
        name = src.get('name')
        if not name:
            continue
        existing = None
        with db.connection() as conn:
            row = conn.execute(
                "SELECT id FROM sources WHERE name = ? AND is_deleted = 0 LIMIT 1",
                (name,),
            ).fetchone()
            if row:
                existing = {'id': row['id']}

        if existing:
            source_id = existing['id']
        else:
            source_id = db.create_source(
                name=name,
                context=src.get('context') or f"Imported - {name}",
                source_type=src.get('source_type') or 'import',
                file_path=src.get('file_path'),
                original_filename=src.get('original_filename'),
            )
            stats['sources_imported'] += 1

        source_name_map[name] = source_id
        for group_ref in src.get('groups', []):
            group_name = group_ref.get('name')
            if not group_name:
                continue
            group = db.get_group_by_name(group_name)
            if group:
                db.add_source_to_group(source_id, group['id'])

    return source_name_map


def _import_iocs_file(db, zipf: zipfile.ZipFile, source_name_map: Dict[str, int], stats: Dict[str, int]) -> None:
    iocs_data = _read_json_zip(zipf, 'iocs.json')
    if not isinstance(iocs_data, list):
        return

    sources_dict: Dict[str, Dict[str, Any]] = {}

    for ioc_data in iocs_data:
        source_name = ioc_data.get('source_name')
        if not source_name:
            continue

        if source_name not in sources_dict:
            sources_dict[source_name] = {
                'iocs': [],
                'source_groups_set': set(),
                'ioc_groups_map': {},
            }

        ioc_index = len(sources_dict[source_name]['iocs'])
        sources_dict[source_name]['iocs'].append(ioc_data)
        ioc_groups = [g.get('name') for g in ioc_data.get('groups', []) if g.get('name')]
        sources_dict[source_name]['ioc_groups_map'][ioc_index] = ioc_groups
        for group_name in ioc_groups:
            sources_dict[source_name]['source_groups_set'].add(group_name)

    for source_name, source_info in sources_dict.items():
        if source_name in source_name_map:
            source_id = source_name_map[source_name]
        else:
            source_id = db.create_source(
                name=source_name,
                context=f"Imported - {source_name}",
                source_type='import',
                file_path=None,
                original_filename=None,
            )
            stats['sources_imported'] += 1
            source_name_map[source_name] = source_id

        source_groups = []
        ioc_groups_final: Dict[int, List[str]] = {}
        for group_name in source_info['source_groups_set']:
            appears_on_all = all(
                group_name in source_info['ioc_groups_map'].get(i, [])
                for i in range(len(source_info['iocs']))
            )
            if appears_on_all and source_info['iocs']:
                source_groups.append(group_name)
            else:
                for ioc_idx, groups in source_info['ioc_groups_map'].items():
                    if group_name in groups:
                        ioc_groups_final.setdefault(ioc_idx, []).append(group_name)

        for group_name in source_groups:
            group = db.get_group_by_name(group_name)
            if group:
                db.add_source_to_group(source_id, group['id'])

        for ioc_idx, ioc_data in enumerate(source_info['iocs']):
            ioc_type = ioc_data.get('ioc_type')
            ioc_value = ioc_data.get('ioc_value')
            if not ioc_type or not ioc_value:
                continue
            raw_value = ioc_data.get('raw_value') or ioc_value
            ioc_id = db.create_ioc(source_id, ioc_type, ioc_value, raw_value)
            stats['iocs_imported'] += 1
            _apply_ioc_backup_fields(db, ioc_id, ioc_data)
            _import_tags_on_ioc(db, ioc_id, ioc_data.get('tags', []), stats)

            for group_name in ioc_groups_final.get(ioc_idx, []):
                group_obj = db.get_group_by_name(group_name)
                if group_obj:
                    db.add_ioc_to_group(ioc_id, group_obj['id'])


def _import_ioc_ttp_links(db, zipf: zipfile.ZipFile, stats: Dict[str, int]) -> None:
    links = _read_json_zip(zipf, 'ioc_ttp_links.json')
    if not isinstance(links, list):
        return
    with db.connection() as conn:
        for link in links:
            ioc_id = _resolve_ioc_id(
                db,
                link.get('source_name', ''),
                link.get('ioc_type', ''),
                link.get('ioc_value', ''),
            )
            if not ioc_id:
                continue
            conn.execute("""
                INSERT OR REPLACE INTO ioc_ttp_links
                (ioc_id, technique_id, confidence, notes, created_at)
                VALUES (?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
            """, (
                ioc_id,
                (link.get('technique_id') or '').upper(),
                link.get('confidence') or 'medium',
                link.get('notes'),
                link.get('created_at'),
            ))
            stats['ioc_ttp_links_imported'] = stats.get('ioc_ttp_links_imported', 0) + 1
        conn.commit()


def _import_cross_refs(db, zipf: zipfile.ZipFile, stats: Dict[str, int]) -> None:
    refs = _read_json_zip(zipf, 'cross_refs.json')
    if not isinstance(refs, list):
        return
    with db.connection() as conn:
        for ref in refs:
            ref_key = ref.get('ref_key')
            if not ref_key:
                continue
            conn.execute("""
                INSERT OR REPLACE INTO cross_refs
                (ref_key, ref_type, entity_id, content_hash, status, indexed_at, updated_at)
                VALUES (?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), COALESCE(?, CURRENT_TIMESTAMP))
            """, (
                ref_key,
                ref.get('ref_type', ''),
                str(ref.get('entity_id', '')),
                ref.get('content_hash') or '',
                ref.get('status') or 'active',
                ref.get('indexed_at'),
                ref.get('updated_at'),
            ))
            stats['cross_refs_imported'] = stats.get('cross_refs_imported', 0) + 1
        conn.commit()


def _import_saved_stix_models(db, zipf: zipfile.ZipFile, stats: Dict[str, int]) -> None:
    models = _read_json_zip(zipf, 'saved_stix_models.json')
    if not isinstance(models, list):
        return
    for model in models:
        name = model.get('name')
        content = model.get('stix_content')
        if not name or not content:
            continue
        db.create_saved_stix_model(
            name=name,
            stix_content=content,
            description=model.get('description'),
            node_count=model.get('node_count') or 0,
            edge_count=model.get('edge_count') or 0,
        )
        stats['saved_stix_models_imported'] = stats.get('saved_stix_models_imported', 0) + 1


def _import_source_templates(db, zipf: zipfile.ZipFile, stats: Dict[str, int]) -> None:
    templates = _read_json_zip(zipf, 'source_templates.json')
    if not isinstance(templates, list):
        return
    with db.connection() as conn:
        for tpl in templates:
            name = (tpl.get('name') or '').strip()
            source_type = (tpl.get('source_type') or 'import').strip()
            if not name:
                continue
            existing = conn.execute(
                "SELECT id FROM source_templates WHERE name = ? AND source_type = ? LIMIT 1",
                (name, source_type),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE source_templates SET context = ?, tags = ? WHERE id = ?",
                    (tpl.get('context'), tpl.get('tags'), existing['id']),
                )
            else:
                conn.execute(
                    "INSERT INTO source_templates (name, context, source_type, tags) VALUES (?, ?, ?, ?)",
                    (name, tpl.get('context'), source_type, tpl.get('tags')),
                )
            stats['source_templates_imported'] = stats.get('source_templates_imported', 0) + 1
        conn.commit()


def _import_ioc_group_exclusions(db, zipf: zipfile.ZipFile, stats: Dict[str, int]) -> None:
    rows = _read_json_zip(zipf, 'ioc_source_group_exclusions.json')
    if not isinstance(rows, list):
        return
    for row in rows:
        ioc_id = _resolve_ioc_id(
            db,
            row.get('source_name', ''),
            row.get('ioc_type', ''),
            row.get('ioc_value', ''),
        )
        group_name = row.get('group_name')
        if not ioc_id or not group_name:
            continue
        group = db.get_group_by_name(group_name)
        if group and db.exclude_ioc_from_source_group(ioc_id, group['id']):
            stats['group_exclusions_imported'] = stats.get('group_exclusions_imported', 0) + 1


def _import_zettelforge(zipf: zipfile.ZipFile, stats: Dict[str, int]) -> None:
    prefix = 'zettelforge/'
    names = [n for n in zipf.namelist() if n.startswith(prefix) and not n.endswith('/')]
    if not names:
        return
    ZETTELFORGE_MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    memory_root = ZETTELFORGE_MEMORY_DIR.resolve()
    for name in names:
        rel = name[len(prefix):]
        target = (memory_root / rel).resolve()
        if target == memory_root or memory_root not in target.parents:
            raise ValueError(f'Unsafe CTI Memory path in backup ZIP: {name}')
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipf.open(name) as src, open(target, 'wb') as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
        stats['zettelforge_files_imported'] = stats.get('zettelforge_files_imported', 0) + 1


def import_from_zip_path(
    zip_path: str,
    db,
    github_repo_manager,
    rtm_repo_manager,
) -> Dict[str, Any]:
    stats = {
        'groups_imported': 0,
        'sources_imported': 0,
        'iocs_imported': 0,
        'tags_imported': 0,
        'ioc_ttp_links_imported': 0,
        'cross_refs_imported': 0,
        'source_templates_imported': 0,
        'group_exclusions_imported': 0,
        'saved_stix_models_imported': 0,
        'rtm_favorites_imported': 0,
        'zettelforge_files_imported': 0,
        'config_imported': False,
        'backup_version': None,
    }

    with zipfile.ZipFile(zip_path, 'r') as zipf:
        metadata = _validate_backup_zip(zipf)
        stats['backup_version'] = metadata['version']

        def import_step(category: str, importer, *args):
            try:
                return importer(*args)
            except Exception as exc:
                raise RuntimeError(
                    f'Backup restore failed while importing {category}: {exc}'
                ) from exc

        import_step(
            'configuration and groups',
            _import_config,
            zipf,
            db,
            github_repo_manager,
            rtm_repo_manager,
            stats,
        )
        import_step('tag catalog', _import_tag_catalog, db, zipf, stats)
        source_name_map = import_step('sources', _import_sources_file, db, zipf, stats)
        import_step('IOCs', _import_iocs_file, db, zipf, source_name_map, stats)
        import_step('MITRE IOC links', _import_ioc_ttp_links, db, zipf, stats)
        import_step('Memory index registry', _import_cross_refs, db, zipf, stats)
        import_step('source templates', _import_source_templates, db, zipf, stats)
        import_step('IOC group exclusions', _import_ioc_group_exclusions, db, zipf, stats)
        import_step('saved STIX models', _import_saved_stix_models, db, zipf, stats)
        import_step('CTI Memory files', _import_zettelforge, zipf, stats)

    return stats
