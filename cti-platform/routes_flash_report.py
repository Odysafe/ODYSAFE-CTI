"""Intelligence Workspace routes for ODYSAFE CTI."""
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
    data['attribution_basis'] = data.get('attribution_basis') or 'Unattributed'
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
    data['purpose'] = data.get('purpose') or ''
    data['intelligence_requirement'] = data.get('intelligence_requirement') or data.get('pir') or ''
    data['requester'] = data.get('requester') or ''
    data['intended_consumers'] = data.get('intended_consumers') or ''
    data['decision_requirement'] = data.get('decision_requirement') or ''
    data['decision_deadline'] = data.get('decision_deadline') or ''
    data['deadline_reason'] = data.get('deadline_reason') or ''
    data['scope'] = data.get('scope') or data.get('affected_scope') or ''
    data['observed_impact'] = data.get('observed_impact') or ''
    data['data_availability'] = data.get('data_availability') or []
    data['sharing_review'] = data.get('sharing_review') or {}
    data['closure'] = data.get('closure') or {}
    data['evidence_register'] = data.get('evidence_register') or []
    product_aliases = {'Flash Report': 'Intelligence Workspace', 'Vulnerability Alert': 'Vulnerability Intelligence Alert'}
    data['product_type'] = product_aliases.get(data.get('product_type'), data.get('product_type') or 'Intelligence Workspace')
    data['internal_relevance'] = data.get('internal_relevance') or {}
    for key, value in list(data['internal_relevance'].items()):
        if value == 'NOT_CHECKED':
            data['internal_relevance'][key] = 'NOT_ASSESSED'
    data['handoff'] = data.get('handoff') or {}
    data['investigation_journal'] = data.get('investigation_journal') or []
    for index, entry in enumerate(data['investigation_journal'], start=1):
        if isinstance(entry, dict):
            entry['entry_id'] = entry.get('entry_id') or f'JRN-{index:03d}'
            entry['entry_type'] = (entry.get('entry_type') or 'SEARCH').upper()
            entry['result_type'] = (entry.get('result_type') or 'INCONCLUSIVE').upper()
    for event in data.get('timeline') or []:
        if isinstance(event, dict):
            event['significance'] = event.get('significance') or event.get('impact') or ''
    data['gaps'] = data.get('gaps') or []
    for index, gap in enumerate(data['gaps'], start=1):
        if isinstance(gap, dict):
            gap['gap_id'] = gap.get('gap_id') or f'GAP-{index:03d}'
            gap['question'] = gap.get('question') or gap.get('gap') or ''
            gap['status'] = (gap.get('status') or 'OPEN').upper()
    data['analytic_claims'] = data.get('analytic_claims') or []
    for index, claim in enumerate(data['analytic_claims'], start=1):
        if isinstance(claim, dict):
            claim['claim_id'] = claim.get('claim_id') or f'CLAIM-{index:03d}'
            claim['claim_text'] = claim.get('claim_text') or claim.get('claim') or ''
            claim['analytical_status'] = (claim.get('analytical_status') or claim.get('status') or 'REPORTED').upper()
            claim['source_role'] = (claim.get('source_role') or 'UNKNOWN').upper()
            claim['source_independence'] = (claim.get('source_independence') or 'UNKNOWN').upper()
    for ioc in data.get('iocs') or []:
        if isinstance(ioc, dict):
            if not ioc.get('notes'):
                ioc['notes'] = ioc.get('context') or ''
            ioc['last_validated'] = ioc.get('last_validated') or ''
            ioc['artifact_context'] = (ioc.get('artifact_context') or 'UNKNOWN').upper()
            ioc['discriminative_value'] = (ioc.get('discriminative_value') or 'UNKNOWN').upper()
            ioc['false_positive_risk'] = (ioc.get('false_positive_risk') or 'UNKNOWN').upper()
            ioc['review_date'] = ioc.get('review_date') or ''
    for source in data.get('sources') or []:
        if isinstance(source, dict):
            source['information_credibility'] = (source.get('information_credibility') or 'UNKNOWN').upper()

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

@flash_report_bp.route('/workspaces', methods=['GET'])
def list_workspaces():
    """List server-saved Intelligence Workspaces."""
    try:
        return jsonify({'workspaces': g.db.list_intelligence_workspaces(limit=100)})
    except Exception as exc:
        logger.error('Error listing Intelligence Workspaces: %s', exc, exc_info=True)
        return jsonify({'error': f'Workspace list failed: {exc}'}), 500

@flash_report_bp.route('/workspaces/<workspace_id>', methods=['GET'])
def get_workspace(workspace_id):
    """Load a server-saved Intelligence Workspace."""
    try:
        record = g.db.get_intelligence_workspace(workspace_id)
        if not record:
            return jsonify({'error': 'Workspace not found'}), 404
        return jsonify(record)
    except Exception as exc:
        logger.error('Error loading Intelligence Workspace %s: %s', workspace_id, exc, exc_info=True)
        return jsonify({'error': f'Workspace load failed: {exc}'}), 500

@flash_report_bp.route('/workspaces/<workspace_id>', methods=['DELETE'])
def delete_workspace(workspace_id):
    """Delete a server-saved Intelligence Workspace."""
    try:
        deleted = g.db.delete_intelligence_workspace(workspace_id)
        if not deleted:
            return jsonify({'error': 'Workspace not found'}), 404
        return jsonify({'deleted': True})
    except Exception as exc:
        logger.error('Error deleting Intelligence Workspace %s: %s', workspace_id, exc, exc_info=True)
        return jsonify({'error': f'Workspace delete failed: {exc}'}), 500

@flash_report_bp.route('/save', methods=['POST'])
def save_workspace():
    """Save the full Intelligence Workspace JSON in SQLite and index it in Memory."""
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid data format'}), 400
        _normalise_flash_report_export(data)
        workspace_id = data.get('workspace_id') or data.get('reference') or f"workspace-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        data['workspace_id'] = workspace_id
        data['schema'] = data.get('schema') or 'odysafe.intelligence_workspace.v1'
        data['schema_version'] = data.get('schema_version') or '1.0'
        data['saved_at'] = datetime.utcnow().isoformat() + 'Z'
        memory_status = 'failed'
        try:
            from modules import zettelforge_bridge as zf
            memory_status = zf.remember_flash_report(data)
        except Exception as exc:
            logger.warning('CTI memory indexing failed for saved workspace %s: %s', workspace_id, exc)
        record = g.db.save_intelligence_workspace(workspace_id, data, memory_status)
        return jsonify({'workspace': record, 'memory_index_status': memory_status})
    except Exception as exc:
        logger.error('Error saving Intelligence Workspace: %s', exc, exc_info=True)
        return jsonify({'error': f'Workspace save failed: {exc}'}), 500

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
        logger.error('Error exporting Intelligence Workspace: %s', exc, exc_info=True)
        return jsonify({'error': f'Export failed: {exc}'}), 500
