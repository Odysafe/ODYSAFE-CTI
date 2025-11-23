"""
Odysafe CTI Platform
Copyright (C) 2025 Bastien GUIDONE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Helper functions for IOC exports to eliminate code duplication
"""
import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Iterator, Tuple
from flask import send_file

logger = logging.getLogger(__name__)


def get_iocs_for_export(db, data: Dict) -> Tuple[List[Dict], Optional[str]]:
    """
    Unified function to retrieve IOCs for export based on filters.
    Returns (iocs_list, source_context)
    """
    source_ids = data.get('source_ids', [])
    group_ids = data.get('group_ids', [])
    ioc_ids = data.get('ioc_ids', [])
    
    source_context = ""
    iocs = []
    
    # If group_ids is provided, retrieve corresponding source_ids
    if group_ids:
        all_source_ids = []
        for group_id in group_ids:
            group_source_ids = db.get_sources_by_group(group_id)
            all_source_ids.extend(group_source_ids)
        source_ids = list(set(all_source_ids))  # Remove duplicates
    
    # Retrieve IOCs
    if source_ids:
        contexts = []
        for source_id in source_ids:
            source = db.get_source(source_id)
            if source and source.get('context'):
                contexts.append(source['context'])
            source_iocs = db.get_iocs_by_source(source_id)
            iocs.extend(source_iocs)
        
        # Combine contexts if multiple sources
        if contexts:
            source_context = "\n\n---\n\n".join(contexts)
    elif ioc_ids:
        for ioc_id in ioc_ids:
            ioc = db.get_ioc(ioc_id)
            if ioc:
                iocs.append(ioc)
                # Get source context from first IOC
                if not source_context:
                    source_info = db.get_source(ioc.get('source_id'))
                    if source_info:
                        source_context = source_info.get('context', '')
    else:
        # Get all IOCs with streaming for large datasets
        # Collect all IOCs from streaming iterator
        iocs = []
        for batch in db.get_all_iocs_streaming(filters=None, limit=None):
            iocs.extend(batch)
    
    return iocs, source_context


def export_txt(db, data: Dict, output_folder: Path) -> Path:
    """Export IOCs to TXT format"""
    iocs, _ = get_iocs_for_export(db, data)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_folder / "iocs" / f"export_{timestamp}.txt"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for ioc in iocs:
            f.write(f"{ioc['ioc_type']}\t{ioc['ioc_value']}\n")
    
    return output_file


def export_json(db, data: Dict, output_folder: Path) -> Path:
    """Export IOCs to JSON format with metadata"""
    iocs, _ = get_iocs_for_export(db, data)
    
    # Enrich IOCs with source and tag information
    source_ids_unique = list(set(ioc['source_id'] for ioc in iocs))
    # Build sources map efficiently without creating intermediate list
    sources_map = {}
    for sid in source_ids_unique:
        source = db.get_source(sid)
        if source:
            sources_map[source['id']] = source
    
    for ioc in iocs:
        source = sources_map.get(ioc['source_id'])
        if source:
            ioc['source'] = source
        # Get tags for this IOC
        full_ioc = db.get_ioc(ioc['id'])
        if full_ioc and full_ioc.get('tags'):
            ioc['tags'] = full_ioc['tags']
        else:
            ioc['tags'] = []
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_folder / "iocs" / f"export_{timestamp}.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    export_data = {
        'export_date': datetime.now().isoformat(),
        'total_iocs': len(iocs),
        'iocs': iocs
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
    
    return output_file


def export_csv(db, data: Dict, output_folder: Path) -> Path:
    """Export IOCs to CSV format"""
    iocs, _ = get_iocs_for_export(db, data)
    
    # Enrich IOCs with tags if needed
    for ioc in iocs:
        if 'tags' not in ioc:
            full_ioc = db.get_ioc(ioc['id'])
            if full_ioc and full_ioc.get('tags'):
                ioc['tags'] = full_ioc['tags']
            else:
                ioc['tags'] = []
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_folder / "iocs" / f"export_{timestamp}.csv"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        # Write header
        writer.writerow(['Type', 'Value', 'Source', 'Created At', 'Tags'])
        
        # Write IOCs
        for ioc in iocs:
            source = db.get_source(ioc.get('source_id'))
            source_name = source.get('name', '') if source else ioc.get('source_name', '')
            
            # Handle tags - can be list of strings or list of dicts
            tags_str = ''
            tags = ioc.get('tags', [])
            if tags:
                if isinstance(tags, list):
                    if tags and isinstance(tags[0], dict):
                        tags_str = ', '.join([tag.get('name', '') for tag in tags if tag.get('name')])
                    else:
                        tags_str = ', '.join([str(tag) for tag in tags if tag])
            
            writer.writerow([
                ioc.get('ioc_type', ''),
                ioc.get('ioc_value', ''),
                source_name,
                ioc.get('created_at', ''),
                tags_str
            ])
    
    return output_file


def export_stix(db, data: Dict, output_folder: Path, convert_to_stix_func) -> Optional[Path]:
    """Export IOCs to STIX format"""
    iocs, source_context = get_iocs_for_export(db, data)
    
    report_name = data.get('report_name', 'CTI Export')
    provided_context = data.get('source_context', '')
    
    # Use provided context or combine with source contexts
    if provided_context and source_context:
        final_context = f"{provided_context}\n\n---\n\n{source_context}"
    elif provided_context:
        final_context = provided_context
    else:
        final_context = source_context or 'CTI Export'
    
    # Convert to STIX
    stix_file = convert_to_stix_func(
        iocs_list=iocs,
        source_context=final_context,
        report_name=report_name
    )
    
    return stix_file

