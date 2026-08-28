"""Flash Report routes for ODYSAFE CTI."""
import logging
from datetime import datetime
from flask import Blueprint, g, jsonify, render_template, request, send_file

logger = logging.getLogger(__name__)
flash_report_bp = Blueprint('flash_report', __name__, url_prefix='/flash-report')

def _normalise_flash_report_export(data):
    """Map form fields to the Excel report model."""
    data['title'] = data.get('subject') or data.get('title') or ''
    data['threat_type'] = data.get('incident_type') or data.get('threat_type') or ''
    data['entity_name'] = data.get('threat_actor') or data.get('entity_name') or ''
    data['likelihood'] = data.get('incident_confidence') or data.get('likelihood') or 'Unknown'
    data['trigger_details'] = data.get('initial_signal') or data.get('trigger_details') or ''
    data['relevant_background'] = data.get('threat_history') or data.get('relevant_background') or ''
    data['keyJudgements'] = data.get('key_judgements') or [{'judgement': value, 'evidence': ''} for value in (data.get('takeaways') or []) if str(value).strip()]
    detail_by_id = {str(item.get('technique') or '').upper(): item for item in (data.get('mitre_details') or []) if isinstance(item, dict)}
    data['techniques'] = data.get('ttps') or data.get('techniques') or []
    for technique in data['techniques']:
        if isinstance(technique, dict):
            detail = detail_by_id.get(str(technique.get('id') or '').upper(), {})
            for key in ('procedure', 'status', 'evidence', 'confidence'):
                technique[key] = detail.get(key) or technique.get(key) or ''
    data['hunts'] = data.get('hunt_leads') or data.get('hunts') or []
    data['detections'] = data.get('detection_rules') or data.get('detections') or []
    data['actions'] = data.get('recommendations') or data.get('actions') or []
    data['hunt_results'] = [{'result': data.get('hunt_result'), 'new_artifacts': data.get('hunt_new_artifacts'), 'interpretation': data.get('hunt_interpretation'), 'follow_up': data.get('hunt_follow_up')}]
    data['alternative_explanations'] = data.get('alternative_explanation') or data.get('alternative_explanations') or ''
    data['contradictory_evidence'] = data.get('biases') or data.get('contradictory_evidence') or ''
    data['handling_instructions'] = data.get('distribution_handling') or data.get('handling_instructions') or ''
    data['rfis_text'] = data.get('rfis') or data.get('rfis_text') or ''
    for event in data.get('timeline') or []:
        if isinstance(event, dict):
            event['significance'] = event.get('significance') or event.get('impact') or ''
    data['gaps'] = data.get('gaps') or []
    for ioc in data.get('iocs') or []:
        if isinstance(ioc, dict) and not ioc.get('notes'):
            ioc['notes'] = ioc.get('context') or ''

def _refresh_linked_ioc_notes(data):
    """Use the latest SQLite note for IOC rows linked by their occurrence ID."""
    for item in data.get('iocs', []):
        if str(item.get('notes') or '').strip():
            continue
        ioc_id = item.get('internal_id') or item.get('id')
        if not ioc_id:
            continue
        try:
            ioc = g.db.get_ioc(int(ioc_id))
        except (TypeError, ValueError):
            continue
        if not ioc or ioc.get('is_deleted'):
            continue
        notes = ioc.get('notes') or ''
        if not notes:
            try:
                from modules.cross_index import make_ref
                from modules import zettelforge_bridge as zf
                memory_note = zf.get_note_by_ref(make_ref('ioc', int(ioc_id)))
                if memory_note:
                    notes = '\n\n'.join(part for part in (
                        (memory_note.get('title') or '').strip(),
                        (memory_note.get('content') or '').strip(),
                    ) if part)
                    if notes:
                        g.db.update_ioc_notes(int(ioc_id), notes)
            except Exception as exc:
                logger.warning('Unable to reconcile Memory note for IOC %s: %s', ioc_id, exc)
        item['notes'] = notes

@flash_report_bp.route('/', methods=['GET'])
def flash_report_home():
    return render_template('flash_report/index.html', datetime=datetime)

@flash_report_bp.route('/export', methods=['POST'])
def export_flash_report():
    """Export a FLINT report as an Excel workbook."""
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid data format'}), 400
        _normalise_flash_report_export(data)
        _refresh_linked_ioc_notes(data)
        from modules.flash_report_export import build_workbook
        workbook_stream = build_workbook(data)
        reference = data.get('reference', 'FLINT-UNKNOWN')
        filename = f"{reference}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        memory_status = 'failed'
        try:
            from modules import zettelforge_bridge as zf
            memory_status = zf.remember_flash_report(data)
        except Exception as exc:
            logger.warning('CTI memory indexing failed for %s: %s', reference, exc)
        response = send_file(workbook_stream, as_attachment=True, download_name=filename,
                             mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response.headers['X-ODYSAFE-Memory-Indexed'] = str(memory_status == 'indexed').lower()
        response.headers['X-ODYSAFE-Memory-Index-Status'] = memory_status
        return response
    except Exception as exc:
        logger.error('Error exporting Flash Report: %s', exc, exc_info=True)
        return jsonify({'error': f'Export failed: {exc}'}), 500
