"""
Modules d'intégration des outils CTI
"""

from flask import Blueprint

# Create blueprints
main_bp = Blueprint('main', __name__)
upload_bp = Blueprint('upload', __name__, url_prefix='/upload')
iocs_bp = Blueprint('iocs', __name__, url_prefix='/iocs')
sources_bp = Blueprint('sources', __name__, url_prefix='/sources')
export_bp = Blueprint('export', __name__, url_prefix='/export')
settings_bp = Blueprint('settings', __name__, url_prefix='/settings')
stix_graph_bp = Blueprint('stix_graph', __name__, url_prefix='/stix-graph')
cti_resources_bp = Blueprint('cti_resources', __name__, url_prefix='/cti-resources')
mitre_attack_bp = Blueprint('mitre_attack', __name__, url_prefix='/cti-resources/mitre-attack')
ransomware_matrix_bp = Blueprint('ransomware_matrix', __name__, url_prefix='/cti-resources/ransomware-matrix')





