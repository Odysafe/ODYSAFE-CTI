"""
ODYSAFE CTI Platform
Log Analyzer Routes
Handles log file upload, analysis, and MITRE ATT&CK mapping
"""

import logging
import csv
import json
import uuid
from datetime import datetime
from io import StringIO, BytesIO
from typing import List, Dict, Optional, Any
from flask import Blueprint, render_template, request, jsonify, send_file, g
from modules.log_mitre_mapper import LogMitreMapper, MitreMatch
from database import Database

logger = logging.getLogger(__name__)

# Create Blueprint
log_analyzer_bp = Blueprint('log_analyzer', __name__, url_prefix='/log-analyzer')

# Initialize mapper
mitre_mapper = LogMitreMapper()


def parse_csv_content(file_content: bytes) -> List[Dict]:
    """Parse CSV file content into list of dictionaries."""
    try:
        reader = csv.DictReader(StringIO(file_content.decode('utf-8')))
        return [row for row in reader]
    except Exception as e:
        logger.error(f"CSV parsing error: {e}")
        return []


def parse_json_content(file_content: bytes) -> List[Dict]:
    """Parse JSON file content into list of events."""
    try:
        data = json.loads(file_content.decode('utf-8'))
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            # Handle CloudTrail-style nested records
            if 'Records' in data and isinstance(data['Records'], list):
                return data['Records']
            return [data]
        return []
    except Exception as e:
        logger.error(f"JSON parsing error: {e}")
        return []


def parse_syslog_content(file_content: bytes) -> List[Dict]:
    """Parse syslog/text file into list of events."""
    try:
        lines = file_content.decode('utf-8').split('\n')
        events = []
        for idx, line in enumerate(lines):
            if line.strip():
                events.append({
                    'timestamp': datetime.now().isoformat(),
                    'source': 'syslog',
                    'description': line.strip(),
                    'raw': line.strip(),
                    'line_number': idx + 1
                })
        return events
    except Exception as e:
        logger.error(f"Syslog parsing error: {e}")
        return []


def extract_timestamp(event: Dict) -> str:
    """Extract timestamp from event dict with multiple fallback keys."""
    timestamp_keys = [
        'timestamp', 'time', 'date', 'datetime', '_time', 'Timestamp',
        'eventTime', ' CreationDate', 'log_timestamp', 'occurred'
    ]
    for key in timestamp_keys:
        if key in event and event[key]:
            return str(event[key])
    return datetime.now().isoformat()


def extract_description(event: Dict) -> str:
    """Extract description from event dict with multiple fallback keys."""
    desc_keys = [
        'message', 'description', 'event', 'detail', 'text', 'event_description',
        'Message', 'msg', 'summary', 'raw_log', 'log_message', 'eventName'
    ]
    for key in desc_keys:
        if key in event and event[key]:
            return str(event[key])
    # Fallback: join all values
    return ' '.join([str(v) for v in event.values() if v and not isinstance(v, dict)])


def extract_source(event: Dict) -> str:
    """Extract source from event dict."""
    source_keys = ['source', 'hostname', 'host', 'computer', 'device', 'source_address']
    for key in source_keys:
        if key in event and event[key]:
            return str(event[key])
    return 'Unknown'


@log_analyzer_bp.route('/')
def log_analyzer_home():
    """Log Analyzer home page."""
    return render_template('log_analyzer.html')


@log_analyzer_bp.route('/api/analyze', methods=['POST'])
def api_analyze_log():
    """API endpoint to upload and analyze log file."""
    try:
        if not hasattr(g, 'db'):
            g.db = Database()
        db = g.db
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        filename = file.filename.lower()
        file_content = file.read()
        
        # Parse based on extension
        if filename.endswith('.csv'):
            events = parse_csv_content(file_content)
        elif filename.endswith('.json'):
            events = parse_json_content(file_content)
        elif filename.endswith('.txt') or filename.endswith('.log'):
            events = parse_syslog_content(file_content)
        else:
            return jsonify({'error': 'Unsupported format. Use .csv, .json, .txt, or .log'}), 400
        
        if not events:
            return jsonify({'error': 'Could not parse file or file is empty'}), 400
        
        # Generate incident ID
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}"
        
        # Process events and map to MITRE
        processed_events = []
        technique_counts = {}
        
        with db.connection() as conn:
            cursor = conn.cursor()
            
            # Create incident record
            cursor.execute("""
                INSERT INTO incidents (id, name, filename, status, event_count, source_type)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (incident_id, file.filename, file.filename, 'analyzing', len(events), 'upload'))
            
            for idx, event in enumerate(events):
                timestamp = extract_timestamp(event)
                description = extract_description(event)
                source = extract_source(event)
                
                # Map to MITRE
                match = mitre_mapper.find_technique(description)
                
                # Insert event
                cursor.execute("""
                    INSERT INTO incident_events 
                    (incident_id, event_index, timestamp, source, description, raw_data,
                     mitre_tactic, mitre_technique_id, mitre_technique_name, 
                     mitre_subtechnique, confidence, matched_keywords)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    incident_id, idx, timestamp, source, description, 
                    json.dumps(event) if isinstance(event, dict) else str(event),
                    match.tactic if match else None,
                    match.technique_id if match else None,
                    match.technique_name if match else None,
                    match.subtechnique if match else None,
                    round(match.confidence * 100, 1) if match else 0,
                    json.dumps(match.matched_keywords) if match else None
                ))
                
                event_data = {
                    'id': cursor.lastrowid,
                    'index': idx,
                    'timestamp': timestamp,
                    'source': source,
                    'description': description,
                    'mitre_tactic': match.tactic if match else 'Unknown',
                    'mitre_technique_id': match.technique_id if match else None,
                    'mitre_technique_name': match.technique_name if match else None,
                    'mitre_subtechnique': match.subtechnique if match else None,
                    'confidence': round(match.confidence * 100, 1) if match else 0,
                }
                processed_events.append(event_data)
                
                # Count techniques
                if match:
                    tech_key = match.technique_id
                    if tech_key not in technique_counts:
                        technique_counts[tech_key] = {
                            'id': tech_key,
                            'tactic': match.tactic,
                            'name': match.technique_name,
                            'count': 0
                        }
                    technique_counts[tech_key]['count'] += 1
            
            # Update incident with final counts
            cursor.execute("""
                UPDATE incidents 
                SET status = ?, technique_count = ?, updated_at = ?
                WHERE id = ?
            """, ('completed', len(technique_counts), datetime.now().isoformat(), incident_id))
            
            conn.commit()
        
        # Build timeline by tactic
        timeline = build_timeline(processed_events)

        try:
            from modules import zettelforge_bridge as zf
            tech_lines = [
                f"{t['id']} {t['name']} ({t['count']} events)"
                for t in technique_counts.values()
            ]
            zf.remember_log_incident(incident_id, file.filename, tech_lines)
        except Exception as mem_err:
            logger.debug('CTI memory log incident skipped: %s', mem_err)
        
        return jsonify({
            'success': True,
            'incident_id': incident_id,
            'events_parsed': len(processed_events),
            'techniques_detected': len(technique_counts),
            'mitre_techniques': list(technique_counts.values()),
            'timeline': timeline,
            'events': processed_events[:100]  # Limit initial response
        }), 200
        
    except Exception as e:
        logger.error(f"Log analysis error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


def build_timeline(events: List[Dict]) -> List[Dict]:
    """Build timeline grouped by MITRE tactic."""
    TACTICS_ORDER = [
        'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
        'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
        'Collection', 'Exfiltration', 'Command and Control', 'Impact'
    ]
    
    timeline_phases = {}
    for event in events:
        tactic = event.get('mitre_tactic', 'Unknown')
        if tactic not in timeline_phases:
            timeline_phases[tactic] = []
        timeline_phases[tactic].append(event)
    
    # Sort by tactic order
    return [
        {'tactic': t, 'events': timeline_phases[t], 'event_count': len(timeline_phases[t])}
        for t in TACTICS_ORDER if t in timeline_phases
    ]


@log_analyzer_bp.route('/api/incident/<incident_id>')
def api_get_incident(incident_id: str):
    """Get incident details with all events."""
    try:
        if not hasattr(g, 'db'):
            g.db = Database()
        db = g.db
        
        with db.connection() as conn:
            cursor = conn.cursor()
            
            # Get incident
            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            incident_row = cursor.fetchone()
            
            if not incident_row:
                return jsonify({'error': 'Incident not found'}), 404
            
            incident = dict(incident_row)
            
            # Get events
            cursor.execute("""
                SELECT * FROM incident_events 
                WHERE incident_id = ? 
                ORDER BY event_index
            """, (incident_id,))
            events = [dict(row) for row in cursor.fetchall()]
            
            # Get technique summary
            cursor.execute("""
                SELECT mitre_technique_id as id, mitre_tactic as tactic, 
                       mitre_technique_name as name, COUNT(*) as count,
                       AVG(confidence) as avg_confidence
                FROM incident_events
                WHERE incident_id = ? AND mitre_technique_id IS NOT NULL
                GROUP BY mitre_technique_id
                ORDER BY count DESC
            """, (incident_id,))
            techniques = [dict(row) for row in cursor.fetchall()]
            
            return jsonify({
                'success': True,
                'incident': incident,
                'events': events,
                'techniques': techniques,
                'timeline': build_timeline(events)
            }), 200
            
    except Exception as e:
        logger.error(f"Get incident error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@log_analyzer_bp.route('/api/incidents')
def api_list_incidents():
    """List all incidents."""
    try:
        if not hasattr(g, 'db'):
            g.db = Database()
        db = g.db
        
        with db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM incidents 
                ORDER BY created_at DESC
            """)
            incidents = [dict(row) for row in cursor.fetchall()]
            
            return jsonify({
                'success': True,
                'incidents': incidents,
                'count': len(incidents)
            }), 200
            
    except Exception as e:
        logger.error(f"List incidents error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@log_analyzer_bp.route('/api/incident/<incident_id>', methods=['DELETE'])
def api_delete_incident(incident_id: str):
    """Delete an incident and all related events."""
    try:
        if not hasattr(g, 'db'):
            g.db = Database()
        db = g.db
        
        with db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
            conn.commit()
            
            if cursor.rowcount > 0:
                return jsonify({'success': True, 'message': 'Incident deleted'}), 200
            else:
                return jsonify({'error': 'Incident not found'}), 404
                
    except Exception as e:
        logger.error(f"Delete incident error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@log_analyzer_bp.route('/api/export/<incident_id>/<format>')
def api_export_incident(incident_id: str, format: str):
    """Export incident in various formats."""
    try:
        if not hasattr(g, 'db'):
            g.db = Database()
        db = g.db
        
        with db.connection() as conn:
            cursor = conn.cursor()
            
            # Get incident
            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            incident_row = cursor.fetchone()
            
            if not incident_row:
                return jsonify({'error': 'Incident not found'}), 404
            
            incident = dict(incident_row)
            
            # Get events
            cursor.execute("""
                SELECT * FROM incident_events 
                WHERE incident_id = ? 
                ORDER BY event_index
            """, (incident_id,))
            events = [dict(row) for row in cursor.fetchall()]
            
            if format == 'json':
                export_data = {
                    'incident': incident,
                    'events': events,
                    'export_date': datetime.now().isoformat()
                }
                return send_file(
                    BytesIO(json.dumps(export_data, indent=2, default=str).encode()),
                    mimetype='application/json',
                    as_attachment=True,
                    download_name=f'{incident_id}.json'
                )
            
            elif format == 'csv':
                output = StringIO()
                writer = csv.DictWriter(output, fieldnames=[
                    'Index', 'Timestamp', 'Source', 'Description', 'MITRE Tactic',
                    'MITRE Technique ID', 'MITRE Technique', 'Confidence'
                ])
                writer.writeheader()
                for event in events:
                    writer.writerow({
                        'Index': event['event_index'],
                        'Timestamp': event['timestamp'],
                        'Source': event['source'],
                        'Description': event['description'],
                        'MITRE Tactic': event['mitre_tactic'] or '',
                        'MITRE Technique ID': event['mitre_technique_id'] or '',
                        'MITRE Technique': event['mitre_technique_name'] or '',
                        'Confidence': f"{event['confidence']}%" if event['confidence'] else ''
                    })
                return send_file(
                    BytesIO(output.getvalue().encode()),
                    mimetype='text/csv',
                    as_attachment=True,
                    download_name=f'{incident_id}.csv'
                )
            
            else:
                return jsonify({'error': 'Unsupported format. Use json or csv'}), 400
                
    except Exception as e:
        logger.error(f"Export incident error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
