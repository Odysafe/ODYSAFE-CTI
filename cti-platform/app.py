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

Application Flask principale - CTI Platform
"""
import os
import json
import csv
import logging
import sqlite3
import threading
import time
import zipfile
import tempfile
import socket
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session, g
from typing import List, Dict
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.serving import run_simple

from config import (
    UPLOAD_FOLDER, OUTPUT_FOLDER, ALLOWED_EXTENSIONS, ALLOWED_MIME_TYPES, MAX_FILE_SIZE,
    CLEANUP_DAYS, PORT, HOST, SECRET_KEY, DEBUG,
    USE_SSL, SSL_CERT_FILE, SSL_KEY_FILE
)
from database import Database
from modules.iocsearcher_wrapper import (
    extract_iocs, extract_from_text, extract_from_url,
    IOCSEARCHER_AVAILABLE
)
from modules.storage_monitor import get_storage_info, format_bytes
from modules.progress_tracker import progress_tracker
from modules.api_helpers import api_success, api_error, api_not_found
from modules.github_repo import github_repo_manager
from modules.github_repo_rtm import rtm_repo_manager
from modules.github_repo_data_shield import data_shield_repo_manager
from modules.export_helpers import (
    export_txt, export_json, export_csv, export_stix,
    export_txt_simple, export_csv_firewall, export_json_simple,
    export_xlsx
)
from modules.auth import (
    require_auth, is_auth_enabled, create_user, verify_user,
    change_password, user_exists, get_current_username
)
from markdown import markdown as md_markdown

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress werkzeug warnings for HTTPS attempts on HTTP server
werkzeug_logger = logging.getLogger('werkzeug')
# Filter out HTTPS connection attempts (TLS handshakes) and SSL errors
class HTTPSFilter(logging.Filter):
    def filter(self, record):
        msg_str = str(record.msg) if hasattr(record, 'msg') else ''
        # Filter out "Bad request version" errors that are TLS handshakes
        if 'Bad request version' in msg_str:
            return False
        # Filter out SSL EOF errors (HTTPS attempts on HTTP server)
        if 'SSLEOFError' in msg_str or 'EOF occurred in violation of protocol' in msg_str:
            return False
        return True

werkzeug_logger.addFilter(HTTPSFilter())

# Initialisation Flask
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
# Configuration de la session : pas de timeout automatique, session permanente jusqu'à déconnexion
# Utiliser une valeur très grande (10 ans) car Flask n'accepte pas None pour PERMANENT_SESSION_LIFETIME
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=3650)  # 10 ans (session quasi permanente)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = USE_SSL  # Secure cookies si SSL activé

# Initialisation base de données
db = Database()

# Mettre db dans flask.g pour chaque requête (utilisé par require_auth)
@app.before_request
def before_request():
    g.db = db

# Ajouter la fonction markdown au contexte des templates
@app.template_filter('markdown')
def markdown_filter(text):
    """Convert Markdown to HTML"""
    if not text:
        return ''
    return md_markdown(text, extensions=['fenced_code', 'tables', 'nl2br'])

# ========== HELPERS ==========

def allowed_file(filename):
    """Checks if the file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_mime(file_path: Path) -> bool:
    """
    Validates file MIME type using python-magic.
    Returns True if MIME type is allowed, False otherwise.
    """
    try:
        import magic
        mime = magic.Magic(mime=True)
        detected_mime = mime.from_file(str(file_path))
        
        # Normalize MIME type (remove charset, etc.)
        detected_mime = detected_mime.split(';')[0].strip()
        
        # Check if detected MIME is in allowed list
        if detected_mime in ALLOWED_MIME_TYPES:
            return True
        
        # Also check if it's a text file (many log files are detected as text/plain)
        if detected_mime.startswith('text/'):
            # Check extension to be sure
            ext = file_path.suffix.lower().lstrip('.')
            if ext in ['txt', 'log', 'md', 'html', 'htm', 'xml', 'csv']:
                return True
        
        logger.warning(f"File {file_path.name} has disallowed MIME type: {detected_mime}")
        return False
    except ImportError:
        # python-magic not available, skip MIME validation but log warning
        logger.warning("python-magic not available, MIME validation skipped")
        return True  # Allow file if magic is not available
    except Exception as e:
        logger.error(f"MIME validation error for {file_path.name}: {e}")
        # On error, be permissive but log it
        return True

def generate_default_context(source_type: str) -> str:
    """Generates a default context based on source type"""
    now = datetime.now()
    context_map = {
        'file_upload': f"File upload - {now.strftime('%Y-%m-%d %H:%M:%S')}",
        'paste': f"Paste - {now.strftime('%Y-%m-%d %H:%M:%S')}",
        'url': f"URL - {now.strftime('%Y-%m-%d %H:%M:%S')}"
    }
    return context_map.get(source_type, f"Source - {now.strftime('%Y-%m-%d %H:%M:%S')}")

def check_and_apply_auto_rotation(db_instance):
    """Checks and applies auto-rotation of sources if enabled"""
    auto_rotation = db_instance.get_setting('auto_rotation_enabled', 'false').lower() == 'true'
    if auto_rotation:
        max_sources = int(db_instance.get_setting('max_sources', '20'))
        deleted_count = db_instance.rotate_sources_if_needed(max_sources)
        if deleted_count > 0:
            logger.info(f"Auto-rotation: {deleted_count} oldest source(s) deleted")
        return deleted_count
    return 0

def _run_auto_pipeline(source_id: int, iocs_list: List[Dict], source_info: Dict):
    """Executes automatic report generation pipeline if enabled"""
    auto_generate = db.get_setting('auto_generate_reports', 'false') == 'true'
    if not auto_generate or not iocs_list:
        return
    
    pass

def _extract_iocs_background(source_id: int, extraction_func, extraction_args: tuple, 
                             initial_message: str, initial_percentage: int = 20):
    """Unified helper function for IOC extraction in background"""
    try:
        progress_tracker.update_progress(f"source_{source_id}", percentage=initial_percentage, message=initial_message)
        results = extraction_func(*extraction_args)
        progress_tracker.update_progress(f"source_{source_id}", percentage=60, message=f"{len(results)} IOCs extracted, processing...")
        
        # Get source info for automatic tags
        source_info = db.get_source(source_id)
        iocs_list = []
        
        for ioc_type, ioc_value, raw_value, offset in results:
            duplicate_id = db.check_duplicate(ioc_type, ioc_value, source_id)
            if not duplicate_id:
                ioc_id = db.create_ioc(source_id, ioc_type, ioc_value, raw_value, source_info=source_info)
                iocs_list.append({
                    'ioc_type': ioc_type,
                    'ioc_value': ioc_value,
                    'raw_value': raw_value
                })
        
        db.update_source_status(source_id, 'completed')
        
        # Automatic pipeline
        _run_auto_pipeline(source_id, iocs_list, source_info)
        
        progress_tracker.complete_task(f"source_{source_id}", f"Processing completed: {len(iocs_list)} IOCs extracted")
    except Exception as e:
        logger.error(f"IOC extraction error: {e}")
        db.update_source_status(source_id, 'error')
        progress_tracker.error_task(f"source_{source_id}", f"Error: {str(e)}")

def cleanup_old_files():
    """Cleans up files in uploads/ older than CLEANUP_DAYS days"""
    try:
        cutoff_date = datetime.now() - timedelta(days=CLEANUP_DAYS)
        deleted_count = 0
        
        for file_path in UPLOAD_FOLDER.iterdir():
            if file_path.is_file():
                file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_time < cutoff_date:
                    try:
                        file_path.unlink()
                        deleted_count += 1
                        logger.info(f"File deleted: {file_path}")
                    except Exception as e:
                        logger.warning(f"Unable to delete {file_path}: {e}")
        
        if deleted_count > 0:
            logger.info(f"Cleanup completed: {deleted_count} file(s) deleted")
    except Exception as e:
        logger.error(f"Cleanup error: {e}")


def cleanup_wal_shm_files():
    """Cleans up SQLite WAL and SHM files that are no longer needed.
    These files are created when SQLite uses WAL mode and should be cleaned up periodically."""
    try:
        # Use database instance to get path
        db_path = Path(db.db_path)
        db_dir = db_path.parent
        db_name = db_path.stem
        
        wal_file = db_dir / f"{db_name}.db-wal"
        shm_file = db_dir / f"{db_name}.db-shm"
        
        cleaned_count = 0
        
        # Check WAL file - only delete if database is not in use
        if wal_file.exists():
            try:
                # Try to checkpoint WAL file to merge it into main database
                # This requires a database connection, so we do it carefully
                conn = sqlite3.connect(str(db_path), timeout=5.0)
                try:
                    # Checkpoint WAL to merge changes
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    conn.close()
                    # After checkpoint, WAL file should be empty or small
                    if wal_file.stat().st_size < 1024:  # Less than 1KB
                        wal_file.unlink()
                        cleaned_count += 1
                        logger.info(f"Cleaned up WAL file: {wal_file}")
                except Exception as e:
                    logger.debug(f"Could not checkpoint WAL file: {e}")
                    conn.close()
            except sqlite3.OperationalError:
                # Database is locked, skip cleanup for now
                logger.debug("Database locked, skipping WAL cleanup")
            except Exception as e:
                logger.warning(f"Error cleaning WAL file: {e}")
        
        # Check SHM file - can be safely deleted if WAL is empty
        if shm_file.exists() and (not wal_file.exists() or wal_file.stat().st_size < 1024):
            try:
                shm_file.unlink()
                cleaned_count += 1
                logger.info(f"Cleaned up SHM file: {shm_file}")
            except Exception as e:
                logger.warning(f"Error cleaning SHM file: {e}")
        
        if cleaned_count > 0:
            logger.info(f"WAL/SHM cleanup completed: {cleaned_count} file(s) cleaned")
    except Exception as e:
        logger.error(f"WAL/SHM cleanup error: {e}")


# Start automatic cleanup in background
def start_cleanup_scheduler():
    """Starts the cleanup scheduler"""
    def cleanup_loop():
        while True:
            cleanup_old_files()
            cleanup_wal_shm_files()
            # Wait 24 hours before next cleanup
            time.sleep(86400)  # 24 hours
    
    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()
    logger.info("Cleanup scheduler started")

start_cleanup_scheduler()

# ========== AUTHENTICATION ROUTES ==========

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # Si l'auth n'est pas activée, rediriger vers le dashboard
    if not is_auth_enabled(db):
        return redirect(url_for('dashboard'))
    
    # Si déjà connecté, rediriger vers le dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            if request.is_json:
                return api_error("Username and password are required", 400)
            flash("Username and password are required", "error")
            return render_template('login.html')
        
        success, result = verify_user(db, username, password)
        if success:
            session.permanent = True  # Session permanente (pas de timeout)
            session['user_id'] = result
            session['username'] = username
            if request.is_json:
                return api_success({"message": "Login successful"})
            return redirect(url_for('dashboard'))
        else:
            if request.is_json:
                return api_error(result, 401)
            flash(result, "error")
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    """Logout"""
    session.clear()
    if request.is_json:
        return api_success({"message": "Logged out successfully"})
    return redirect(url_for('login'))

@app.route('/api/auth/status', methods=['GET'])
def api_auth_status():
    """API: Check authentication status"""
    try:
        enabled = is_auth_enabled(db)
        is_logged_in = 'user_id' in session
        username = get_current_username() if is_logged_in else None
        
        return api_success({
            "auth_enabled": enabled,
            "is_logged_in": is_logged_in,
            "username": username
        })
    except Exception as e:
        logger.error(f"api_auth_status error: {e}")
        return api_error(str(e), 500)

@app.route('/api/auth/create-user', methods=['POST'])
def api_auth_create_user():
    """API: Create user and enable authentication"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        password_confirm = data.get('password_confirm', '')
        
        if not username or not password:
            return api_error("Username and password are required", 400)
        
        if password != password_confirm:
            return api_error("Passwords do not match", 400)
        
        if len(password) < 8:
            return api_error("Password must be at least 8 characters long", 400)
        
        # Vérifier que le username est "odysafe"
        if username != 'odysafe':
            return api_error("Username must be 'odysafe'", 400)
        
        # Vérifier si l'utilisateur existe déjà
        if user_exists(db, username):
            return api_error("User already exists", 400)
        
        # Créer l'utilisateur
        success, message = create_user(db, username, password)
        if success:
            # Activer l'authentification après création de l'utilisateur
            db.set_setting('auth_enabled', 'true')
            return api_success({
                "message": message,
                "auth_enabled": True
            })
        else:
            return api_error(message, 400)
    
    except Exception as e:
        logger.error(f"api_auth_create_user error: {e}")
        return api_error(str(e), 500)

@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def api_auth_change_password():
    """API: Change password (requires authentication)"""
    try:
        if 'username' not in session:
            return api_error("Not authenticated", 401)
        
        data = request.get_json()
        old_password = data.get('old_password', '')
        new_password = data.get('new_password', '')
        new_password_confirm = data.get('new_password_confirm', '')
        
        if not old_password or not new_password:
            return api_error("Old password and new password are required", 400)
        
        if new_password != new_password_confirm:
            return api_error("New passwords do not match", 400)
        
        if len(new_password) < 8:
            return api_error("New password must be at least 8 characters long", 400)
        
        username = session['username']
        success, message = change_password(db, username, old_password, new_password)
        if success:
            return api_success({"message": message})
        else:
            return api_error(message, 400)
    
    except Exception as e:
        logger.error(f"api_auth_change_password error: {e}")
        return api_error(str(e), 500)

@app.route('/api/auth/toggle', methods=['POST'])
def api_auth_toggle():
    """API: Disable authentication (enable via create-user)"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', False)
        
        # On ne peut que désactiver via cette route (l'activation se fait via create-user)
        if enabled:
            return api_error("To enable authentication, please create a user first", 400)
        
        # Vérifier si l'auth est activée avant de désactiver
        current_auth_enabled = is_auth_enabled(db)
        if not current_auth_enabled:
            return api_error("Authentication is already disabled", 400)
        
        # Désactiver l'authentification
        db.set_setting('auth_enabled', 'false')
        
        # Déconnecter tous les utilisateurs
        session.clear()
        
        return api_success({
            "message": "Authentication disabled",
            "auth_enabled": False
        })
    
    except Exception as e:
        logger.error(f"api_auth_toggle error: {e}")
        return api_error(str(e), 500)

# ========== ROUTES GET ==========

@app.route('/')
@require_auth
def dashboard():
    """Home page with statistics"""
    try:
        stats = db.get_statistics()
        recent_limit = int(db.get_setting('recent_sources_limit', '20'))
        recent_sources = db.get_all_sources(limit=recent_limit)
        
        # CTI Resources statistics
        cti_stats = {}
        
        # DeepDarkCTI stats
        try:
            ddc_repo_exists = github_repo_manager.repo_exists()
            ddc_category_info = github_repo_manager.get_category_info()
            if ddc_repo_exists:
                categories = github_repo_manager.fetch_all_categories()
                cti_stats['deepdarkcti'] = {
                    'available': True,
                    'categories_count': len(categories) if categories else 0,
                    'last_update': ddc_category_info.get('last_update') if ddc_category_info else None
                }
            else:
                cti_stats['deepdarkcti'] = {
                    'available': False,
                    'categories_count': 0,
                    'last_update': None
                }
        except Exception as e:
            logger.error(f"Error fetching DeepDarkCTI stats: {e}")
            cti_stats['deepdarkcti'] = {
                'available': False,
                'categories_count': 0,
                'last_update': None
            }
        
        # Ransomware Tool Matrix stats
        try:
            rtm_repo_exists = rtm_repo_manager.repo_exists()
            if rtm_repo_exists:
                rtm_category_info = rtm_repo_manager.get_category_info()
                tools = rtm_repo_manager.fetch_tools()
                threat_intel = rtm_repo_manager.fetch_threat_intel()
                group_profiles = rtm_repo_manager.fetch_group_profiles()
                community_reports = rtm_repo_manager.fetch_community_reports()
                cti_stats['ransomware_matrix'] = {
                    'available': True,
                    'tools_count': sum(len(tool_data.get('tools', [])) for tool_data in tools.values()) if tools else 0,
                    'threat_intel_count': sum(len(intel_list) for intel_list in threat_intel.values()) if threat_intel else 0,
                    'group_profiles_count': len(group_profiles) if group_profiles else 0,
                    'community_reports_count': len(community_reports) if community_reports else 0,
                    'last_update': rtm_category_info.get('last_update') if rtm_category_info else None
                }
            else:
                cti_stats['ransomware_matrix'] = {
                    'available': False,
                    'tools_count': 0,
                    'threat_intel_count': 0,
                    'group_profiles_count': 0,
                    'community_reports_count': 0,
                    'last_update': None
                }
        except Exception as e:
            logger.error(f"Error fetching Ransomware Tool Matrix stats: {e}")
            cti_stats['ransomware_matrix'] = {
                'available': False,
                'tools_count': 0,
                'threat_intel_count': 0,
                'group_profiles_count': 0,
                'community_reports_count': 0,
                'last_update': None
            }
        
        # Data-Shield IPv4 Blocklist stats
        try:
            ds_status = data_shield_repo_manager.get_status()
            
            # Count imported IPs from database
            imported_count = 0
            try:
                with db.connection() as conn:
                    ody = conn.cursor()
                    ody.execute("""
                        SELECT COUNT(*) as count FROM iocs i
                        JOIN sources s ON i.source_id = s.id
                        WHERE s.name = 'data-shield' AND s.is_deleted = 0
                    """)
                    row = ody.fetchone()
                    if row:
                        imported_count = row['count']
            except Exception as e:
                logger.warning(f"Error counting imported IPs: {e}")
            
            cti_stats['data_shield'] = {
                'available': ds_status.get('repo_exists', False),
                'blocklist_exists': ds_status.get('blocklist_exists', False),
                'ip_count': ds_status.get('ip_count', 0),
                'imported_ip_count': imported_count,
                'last_update': ds_status.get('last_update')
            }
        except Exception as e:
            logger.error(f"Error fetching Data-Shield stats: {e}")
            cti_stats['data_shield'] = {
                'available': False,
                'blocklist_exists': False,
                'ip_count': 0,
                'imported_ip_count': 0,
                'last_update': None
            }
        
        return render_template('dashboard.html', stats=stats, recent_sources=recent_sources, cti_stats=cti_stats)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash("Error loading dashboard", "error")
        return render_template('dashboard.html', stats={}, recent_sources=[], cti_stats={})

@app.route('/upload')
@require_auth
def upload():
    """Upload/import page"""
    return render_template('upload.html')

@app.route('/iocs')
@require_auth
def iocs_list():
    """IOC list with filters"""
    try:
        from modules.ioc_query_urls import get_query_urls
        
        # Retrieve filtering parameters
        ioc_type = request.args.get('type', '').strip()
        search = request.args.get('search', '').strip()
        source_name = request.args.get('source', '').strip()
        date_range = request.args.get('date_range', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        page = int(request.args.get('page', 1))
        per_page = 50
        
        filters = {}
        if ioc_type:
            filters['ioc_type'] = ioc_type
        if search:
            filters['search'] = search
        if source_name:
            filters['source_name'] = source_name
        group_id = request.args.get('group', '').strip()
        if group_id:
            try:
                filters['group_id'] = int(group_id)
            except ValueError:
                pass
        # Duplicate filter
        show_duplicates = request.args.get('duplicates', '').strip()
        if show_duplicates == 'true':
            filters['show_duplicates'] = True
        if date_range:
            filters['date_range'] = date_range
            # Calculate date_from and date_to based on date_range
            from datetime import datetime, timedelta
            now = datetime.now()
            if date_range == '24h':
                filters['date_from'] = (now - timedelta(hours=24)).strftime('%Y-%m-%d')
            elif date_range == '7d':
                filters['date_from'] = (now - timedelta(days=7)).strftime('%Y-%m-%d')
            elif date_range == '30d':
                filters['date_from'] = (now - timedelta(days=30)).strftime('%Y-%m-%d')
            elif date_range == '3m':
                filters['date_from'] = (now - timedelta(days=90)).strftime('%Y-%m-%d')
            elif date_range == '1y':
                filters['date_from'] = (now - timedelta(days=365)).strftime('%Y-%m-%d')
            elif date_range == 'custom':
                if date_from:
                    filters['date_from'] = date_from
                if date_to:
                    filters['date_to'] = date_to
        else:
            if date_from:
                filters['date_from'] = date_from
            if date_to:
                filters['date_to'] = date_to
        
        offset = (page - 1) * per_page
        iocs, total = db.get_all_iocs(filters=filters, limit=per_page, offset=offset)
        
        # Enrich each IOC with its query URLs
        for ioc in iocs:
            ioc['query_urls'] = get_query_urls(ioc['ioc_type'], ioc['ioc_value'])
        
        # Retrieve unique IOC types present in the database
        unique_types = db.get_unique_ioc_types()
        
        # Retrieve unique source names
        unique_source_names = db.get_unique_source_names()
        
        # Retrieve all groups for the filter
        all_groups = db.get_all_groups()
        
        return render_template('iocs_list.html', 
                             iocs=iocs, 
                             total=total,
                             page=page,
                             per_page=per_page,
                             filters=filters,
                             unique_types=unique_types,
                             unique_source_names=unique_source_names,
                             all_groups=all_groups)
    except Exception as e:
        logger.error(f"IOCs list error: {e}")
        flash("Error loading IOCs", "error")
        return render_template('iocs_list.html', iocs=[], total=0, page=1, per_page=50, 
                             filters={}, unique_types=[], unique_source_names=[])

@app.route('/ioc/<int:ioc_id>')
@require_auth
def ioc_detail(ioc_id):
    """IOC detail page"""
    try:
        ioc = db.get_ioc(ioc_id)
        if not ioc:
            flash("IOC not found", "error")
            return redirect(url_for('iocs_list'))
        
        source = db.get_source(ioc['source_id'])
        tag_history = db.get_tag_history(ioc_id)
        all_tags = db.get_all_tags()
        
        return render_template('ioc_detail.html', 
                             ioc=ioc, 
                             source=source,
                             tag_history=tag_history,
                             all_tags=all_tags)
    except Exception as e:
        logger.error(f"IOC detail error: {e}")
        flash("Error loading IOC", "error")
        return redirect(url_for('iocs_list'))

@app.route('/sources')
@require_auth
def sources_list():
    """Sources list"""
    try:
        sources = db.get_all_sources(limit=1000)
        all_groups = db.get_all_groups()
        return render_template('sources_list.html', sources=sources, all_groups=all_groups)
    except Exception as e:
        logger.error(f"Sources list error: {e}")
        flash("Error loading sources", "error")
        return render_template('sources_list.html', sources=[], all_groups=[])


@app.route('/export')
@require_auth
def export():
    """Export page"""
    try:
        # Limit sources to reasonable number for dropdown (most recent first)
        sources = db.get_all_sources(limit=500)
        all_groups = db.get_all_groups()
        # Get total count without loading all IOCs
        _, total = db.get_all_iocs(limit=1, offset=0)
        # Get unique IOC types for filtering
        unique_types = db.get_unique_ioc_types()
        return render_template('export.html', sources=sources, all_groups=all_groups, total_iocs=total, unique_types=unique_types)
    except Exception as e:
        logger.error(f"Export error: {e}")
        return render_template('export.html', sources=[], all_groups=[], total_iocs=0, unique_types=[])

@app.route('/stix-graph')
@require_auth
def stix_graph():
    """STIX Graph Analyzer page - Interactive visualization of STIX bundles"""
    return render_template('stix_graph.html')

@app.route('/settings')
@require_auth
def settings():
    """Settings page"""
    return render_template('settings.html')

@app.route('/cti-resources')
@app.route('/cti-resources/deepdarkcti')
@require_auth
def cti_resources():
    """CTI Resources page - Main page with resource selector
    
    IMPORTANT: This route ONLY reads existing repository data.
    It does NOT trigger automatic download. Download must be done
    explicitly via /api/cti-resources/download or /api/cti-resources/update endpoints.
    """
    try:
        repo_exists = github_repo_manager.repo_exists()
        
        # Load categories once (optimization)
        # NOTE: fetch_all_categories() only reads from local files, never downloads
        categories = github_repo_manager.fetch_all_categories()
        
        # Get category info (includes last_update from cache, not current time)
        category_info = github_repo_manager.get_category_info()
        
        return render_template('deepdarkcti.html', 
                             repo_exists=repo_exists,
                             categories=categories, 
                             category_info=category_info)
    except Exception as e:
        logger.error(f"DeepDarkCTI error: {e}")
        flash("Error loading DeepDarkCTI data", "error")
        return render_template('deepdarkcti.html', 
                             repo_exists=False,
                             categories={}, 
                             category_info={})

@app.route('/cti-resources/ransomware-matrix')
@require_auth
def cti_resources_ransomware_matrix():
    """Ransomware Tool Matrix page within CTI Resources
    
    IMPORTANT: This route ONLY reads existing repository data.
    It does NOT trigger automatic download. Download must be done
    explicitly via /api/ransomware-tools/download or /api/ransomware-tools/update endpoints.
    """
    try:
        repo_exists = rtm_repo_manager.repo_exists()
        
        # Always try to load data, even if repo_exists is False (in case repo was just downloaded)
        tools = {}
        threat_intel = {}
        group_profiles = []
        community_reports = []
        
        if repo_exists:
            try:
                tools = rtm_repo_manager.fetch_tools()
            except Exception as e:
                logger.error(f"Error fetching tools: {e}")
            
            try:
                threat_intel = rtm_repo_manager.fetch_threat_intel()
            except Exception as e:
                logger.error(f"Error fetching threat intel: {e}")
            
            try:
                group_profiles = rtm_repo_manager.fetch_group_profiles()
            except Exception as e:
                logger.error(f"Error fetching group profiles: {e}")
            
            try:
                community_reports = rtm_repo_manager.fetch_community_reports()
            except Exception as e:
                logger.error(f"Error fetching community reports: {e}")
        
        # Re-check repo_exists after loading data (in case it was just downloaded)
        repo_exists = rtm_repo_manager.repo_exists()
        
        # Get category info (includes last_update from cache)
        category_info = rtm_repo_manager.get_category_info()
        
        return render_template('ransomware_tools.html', 
                             repo_exists=repo_exists,
                             tools=tools,
                             threat_intel=threat_intel,
                             group_profiles=group_profiles,
                             community_reports=community_reports,
                             category_info=category_info)
    except Exception as e:
        logger.error(f"Ransomware Tools error: {e}", exc_info=True)
        flash("Error loading Ransomware Tool Matrix data", "error")
        # Try to return with empty data but still show the page
        try:
            repo_exists = rtm_repo_manager.repo_exists()
            category_info = rtm_repo_manager.get_category_info()
        except:
            repo_exists = False
            category_info = {}
        return render_template('ransomware_tools.html', 
                             repo_exists=repo_exists,
                             tools={},
                             threat_intel={},
                             group_profiles=[],
                             community_reports=[],
                             category_info=category_info)

@app.route('/ransomware-tools')
@require_auth
def ransomware_tools():
    """Ransomware Tool Matrix page
    
    IMPORTANT: This route ONLY reads existing repository data.
    It does NOT trigger automatic download. Download must be done
    explicitly via /api/ransomware-tools/download or /api/ransomware-tools/update endpoints.
    """
    try:
        repo_exists = rtm_repo_manager.repo_exists()
        
        # Always try to load data, even if repo_exists is False (in case repo was just downloaded)
        tools = {}
        threat_intel = {}
        group_profiles = []
        community_reports = []
        
        if repo_exists:
            try:
                tools = rtm_repo_manager.fetch_tools()
            except Exception as e:
                logger.error(f"Error fetching tools: {e}")
            
            try:
                threat_intel = rtm_repo_manager.fetch_threat_intel()
            except Exception as e:
                logger.error(f"Error fetching threat intel: {e}")
            
            try:
                group_profiles = rtm_repo_manager.fetch_group_profiles()
            except Exception as e:
                logger.error(f"Error fetching group profiles: {e}")
            
            try:
                community_reports = rtm_repo_manager.fetch_community_reports()
            except Exception as e:
                logger.error(f"Error fetching community reports: {e}")
        
        # Re-check repo_exists after loading data (in case it was just downloaded)
        repo_exists = rtm_repo_manager.repo_exists()
        
        # Get category info (includes last_update from cache)
        category_info = rtm_repo_manager.get_category_info()
        
        return render_template('ransomware_tools.html', 
                             repo_exists=repo_exists,
                             tools=tools,
                             threat_intel=threat_intel,
                             group_profiles=group_profiles,
                             community_reports=community_reports,
                             category_info=category_info)
    except Exception as e:
        logger.error(f"Ransomware Tools error: {e}", exc_info=True)
        flash("Error loading Ransomware Tool Matrix data", "error")
        # Try to return with empty data but still show the page
        try:
            repo_exists = rtm_repo_manager.repo_exists()
            category_info = rtm_repo_manager.get_category_info()
        except:
            repo_exists = False
            category_info = {}
        return render_template('ransomware_tools.html', 
                             repo_exists=repo_exists,
                             tools={},
                             threat_intel={},
                             group_profiles=[],
                             community_reports=[],
                             category_info=category_info)

# ========== ROUTES API ==========

@app.route('/api/upload', methods=['POST'])
@require_auth
def api_upload():
    """API: File upload"""
    try:
        if 'file' not in request.files:
            return api_error('No file provided', 400)
        
        file = request.files['file']
        if file.filename == '':
            return api_error('No file selected', 400)
        
        if not allowed_file(file.filename):
            return api_error('File type not allowed', 400)
        
        name = request.form.get('name', '').strip()
        context = request.form.get('context', '').strip()
        
        if not name:
            return api_error('Source name is required', 400)
        
        # Auto-generate context if empty
        if not context:
            context = generate_default_context('file_upload')
        
        # Validate file before saving to disk
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        file_path = UPLOAD_FOLDER / unique_filename
        
        # Save to temporary file first for validation
        temp_file_path = None
        try:
            import tempfile
            temp_file_path = Path(tempfile.mkstemp(suffix=file_path.suffix)[1])
            file.save(str(temp_file_path))
            
            # Validate MIME type before moving to final location
            if not validate_file_mime(temp_file_path):
                return api_error('File type validation failed: MIME type not allowed', 400)
            
            # Move validated file to final location
            temp_file_path.rename(file_path)
            temp_file_path = None  # Prevent cleanup after successful move
            
        except Exception as e:
            logger.error(f"Error during file validation: {e}")
            return api_error(f'File processing error: {str(e)}', 500)
        finally:
            # Cleanup temporary file if it still exists
            if temp_file_path and temp_file_path.exists():
                try:
                    temp_file_path.unlink()
                except Exception as e:
                    logger.warning(f"Failed to delete temporary file {temp_file_path}: {e}")
        
        # Create source in database
        source_id = db.create_source(
            name=name,
            context=context,
            source_type='file_upload',
            file_path=str(file_path),
            original_filename=filename
        )
        
        # Check if auto-rotation is enabled and apply if needed
        check_and_apply_auto_rotation(db)
        
        # Update status
        db.update_source_status(source_id, 'processing')
        
        # Start progress tracking
        progress_tracker.start_task(f"source_{source_id}", "source_processing", total_steps=100)
        progress_tracker.update_progress(f"source_{source_id}", percentage=10, message="File uploaded, starting extraction...")
        
        # Extract IOCs in background
        thread = threading.Thread(
            target=_extract_iocs_background,
            args=(source_id, extract_iocs, (str(file_path),), "Extracting IOCs...", 20)
        )
        thread.start()
        
        return api_success(
            {'source_id': source_id},
            'File uploaded successfully, extraction in progress...'
        )
    
    except RequestEntityTooLarge:
        return api_error('File too large', 413)
    except Exception as e:
        logger.error(f"api_upload error: {e}")
        return api_error(str(e), 500)

@app.route('/api/paste', methods=['POST'])
@require_auth
def api_paste():
    """API: Paste text processing"""
    try:
        data = request.get_json()
        text_content = data.get('text', '')
        name = data.get('name', '').strip()
        context = data.get('context', '').strip()
        
        if not text_content:
            return api_error('No text provided', 400)
        
        if not name:
            return api_error('Source name is required', 400)
        
        # Auto-generate context if empty
        if not context:
            context = generate_default_context('paste')
        
        if not IOCSEARCHER_AVAILABLE:
            return api_error('iocsearcher is not available', 503)
        
        # Create temporary file for text
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_filename = f"paste_{timestamp}.txt"
        file_path = UPLOAD_FOLDER / temp_filename
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(text_content)
        
        # Create the source in the database
        source_id = db.create_source(
            name=name,
            context=context,
            source_type='paste',
            file_path=str(file_path),
            original_filename=temp_filename
        )
        
        # Check if auto-rotation is enabled
        auto_rotation = db.get_setting('auto_rotation_enabled', 'false').lower() == 'true'
        if auto_rotation:
            max_sources = int(db.get_setting('max_sources', '20'))
            deleted_count = db.rotate_sources_if_needed(max_sources)
            if deleted_count > 0:
                logger.info(f"Auto-rotation: {deleted_count} oldest source(s) deleted")
        
        db.update_source_status(source_id, 'processing')
        
        # Start progress tracking
        progress_tracker.start_task(f"source_{source_id}", "source_processing", total_steps=100)
        progress_tracker.update_progress(f"source_{source_id}", percentage=10, message="Text received, starting extraction...")
        
        # Extract IOCs in background
        thread = threading.Thread(
            target=_extract_iocs_background,
            args=(source_id, extract_from_text, (text_content,), "Extracting IOCs...", 20)
        )
        thread.start()
        
        return api_success(
            {'source_id': source_id},
            'Text processed successfully, extraction in progress...'
        )
    
    except Exception as e:
        logger.error(f"api_paste error: {e}")
        return api_error(str(e), 500)

@app.route('/api/url', methods=['POST'])
@require_auth
def api_url():
    """API: URL processing"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        name = data.get('name', '').strip()
        context = data.get('context', '').strip()
        
        if not url:
            return api_error('No URL provided', 400)
        
        if not name:
            return api_error('Source name is required', 400)
        
        # Auto-generate context if empty
        if not context:
            context = generate_default_context('url')
        
        if not IOCSEARCHER_AVAILABLE:
            return api_error('iocsearcher is not available', 503)
        
        # Create source in database
        source_id = db.create_source(
            name=name,
            context=context,
            source_type='url',
            file_path=None,
            original_filename=url
        )
        
        # Check if auto-rotation is enabled and apply if needed
        check_and_apply_auto_rotation(db)
        
        db.update_source_status(source_id, 'processing')
        
        # Start progress tracking
        progress_tracker.start_task(f"source_{source_id}", "source_processing", total_steps=100)
        progress_tracker.update_progress(f"source_{source_id}", percentage=10, message="URL received, downloading...")
        
        # Extract IOCs in background
        thread = threading.Thread(
            target=_extract_iocs_background,
            args=(source_id, extract_from_url, (url,), "Download completed, extracting IOCs...", 30)
        )
        thread.start()
        
        return api_success(
            {'source_id': source_id},
            'URL processed successfully, extraction in progress...'
        )
    
    except Exception as e:
        logger.error(f"api_url error: {e}")
        return api_error(str(e), 500)

@app.route('/api/ioc/<int:ioc_id>/tag', methods=['POST', 'DELETE'])
@require_auth
def api_ioc_tag(ioc_id):
    """API: Add/remove a tag from an IOC"""
    try:
        data = request.get_json()
        tag_name = data.get('tag_name', '')
        
        if not tag_name:
            return api_error('Tag name required', 400)
        
        # Retrieve or create the tag
        all_tags = db.get_all_tags()
        tag = next((t for t in all_tags if t['name'] == tag_name), None)
        
        if not tag:
            # Create a new custom tag
            tag_id = db.create_tag(tag_name, category='custom')
        else:
            tag_id = tag['id']
        
        if request.method == 'POST':
            db.add_tag_to_ioc(ioc_id, tag_id)
            return api_success(message='Tag added')
        else:  # DELETE
            db.remove_tag_from_ioc(ioc_id, tag_id)
            return api_success(message='Tag removed')
    
    except Exception as e:
        logger.error(f"api_ioc_tag error: {e}")
        return api_error(str(e), 500)

@app.route('/api/ioc/<int:ioc_id>/notes', methods=['POST'])
@require_auth
def api_ioc_notes(ioc_id):
    """API: Update IOC notes"""
    try:
        data = request.get_json()
        notes = data.get('notes', '')
        
        db.update_ioc_notes(ioc_id, notes)
        
        return api_success(message='Notes updated')
    
    except Exception as e:
        logger.error(f"api_ioc_notes error: {e}")
        return api_error(str(e), 500)

@app.route('/api/export/txt', methods=['POST'])
@require_auth
def api_export_txt():
    """API: Export TXT"""
    try:
        data = request.get_json()
        output_file = export_txt(db, data, OUTPUT_FOLDER)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(str(output_file), as_attachment=True, download_name=f"iocs_export_{timestamp}.txt")
    except Exception as e:
        logger.error(f"api_export_txt error: {e}")
        return api_error(str(e), 500)

@app.route('/api/export/json', methods=['POST'])
@require_auth
def api_export_json():
    """API: Export JSON interne"""
    try:
        data = request.get_json()
        output_file = export_json(db, data, OUTPUT_FOLDER)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(str(output_file), as_attachment=True, download_name=f"iocs_export_{timestamp}.json")
    except Exception as e:
        logger.error(f"api_export_json error: {e}")
        return api_error(str(e), 500)

@app.route('/api/export/csv', methods=['POST'])
@require_auth
def api_export_csv():
    """API: Export CSV"""
    try:
        data = request.get_json()
        output_file = export_csv(db, data, OUTPUT_FOLDER)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(str(output_file), as_attachment=True, download_name=f"iocs_export_{timestamp}.csv")
    except Exception as e:
        logger.error(f"api_export_csv error: {e}", exc_info=True)
        return api_error(str(e), 500)

@app.route('/api/export/txt-simple', methods=['POST'])
@require_auth
def api_export_txt_simple():
    """API: Export TXT - values only (Firewall/EDR compatible)"""
    try:
        data = request.get_json()
        output_file = export_txt_simple(db, data, OUTPUT_FOLDER)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(str(output_file), as_attachment=True, download_name=f"iocs_export_simple_{timestamp}.txt")
    except Exception as e:
        logger.error(f"api_export_txt_simple error: {e}")
        return api_error(str(e), 500)

@app.route('/api/export/csv-firewall', methods=['POST'])
@require_auth
def api_export_csv_firewall():
    """API: Export CSV - simplified format (Firewall/EDR compatible)"""
    try:
        data = request.get_json()
        output_file = export_csv_firewall(db, data, OUTPUT_FOLDER)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(str(output_file), as_attachment=True, download_name=f"iocs_export_firewall_{timestamp}.csv")
    except Exception as e:
        logger.error(f"api_export_csv_firewall error: {e}")
        return api_error(str(e), 500)

@app.route('/api/export/json-simple', methods=['POST'])
@require_auth
def api_export_json_simple():
    """API: Export JSON - simplified format grouped by type"""
    try:
        data = request.get_json()
        output_file = export_json_simple(db, data, OUTPUT_FOLDER)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(str(output_file), as_attachment=True, download_name=f"iocs_export_simple_{timestamp}.json")
    except Exception as e:
        logger.error(f"api_export_json_simple error: {e}")
        return api_error(str(e), 500)

@app.route('/api/export/xlsx', methods=['POST'])
@require_auth
def api_export_xlsx():
    """API: Export XLSX with elegant formatting"""
    try:
        data = request.get_json()
        output_file = export_xlsx(db, data, OUTPUT_FOLDER)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(str(output_file), as_attachment=True, download_name=f"iocs_export_{timestamp}.xlsx")
    except Exception as e:
        logger.error(f"api_export_xlsx error: {e}")
        return api_error(str(e), 500)

@app.route('/api/quick-export', methods=['POST'])
@require_auth
def api_quick_export():
    """API: Quick export - extract IOCs and export without saving to database"""
    try:
        if not IOCSEARCHER_AVAILABLE:
            return api_error('iocsearcher is not available', 503)
        
        input_type = request.form.get('input_type', '').strip()
        format_type = request.form.get('format', '').strip()
        
        if not input_type or not format_type:
            return api_error('Input type and format are required', 400)
        
        # Extract IOCs based on input type
        ioc_results = []
        temp_file_path = None
        
        try:
            if input_type == 'file':
                if 'file' not in request.files:
                    return api_error('No file provided', 400)
                
                file = request.files['file']
                if file.filename == '':
                    return api_error('No file selected', 400)
                
                if not allowed_file(file.filename):
                    return api_error('File type not allowed', 400)
                
                # Save to temporary file
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                temp_filename = f"quick_export_{timestamp}_{filename}"
                temp_file_path = UPLOAD_FOLDER / temp_filename
                file.save(str(temp_file_path))
                
                # Validate MIME type
                if not validate_file_mime(temp_file_path):
                    temp_file_path.unlink()
                    return api_error('File type validation failed', 400)
                
                # Extract IOCs
                ioc_results = extract_iocs(str(temp_file_path))
                
            elif input_type == 'paste':
                text_content = request.form.get('text', '').strip()
                if not text_content:
                    return api_error('No text provided', 400)
                
                # Extract IOCs from text
                ioc_results = extract_from_text(text_content)
                
            elif input_type == 'url':
                url = request.form.get('url', '').strip()
                if not url:
                    return api_error('No URL provided', 400)
                
                # Extract IOCs from URL
                ioc_results = extract_from_url(url)
                
            else:
                return api_error('Invalid input type', 400)
            
            if not ioc_results:
                return api_error('No IOCs found in the provided content', 404)
            
            # Convert extraction results to IOC dict format compatible with export functions
            iocs = []
            for ioc_type, ioc_value, raw_value, offset in ioc_results:
                ioc_dict = {
                    'id': len(iocs) + 1,  # Temporary ID
                    'ioc_type': ioc_type,
                    'ioc_value': ioc_value,
                    'raw_value': raw_value or ioc_value,
                    'source_id': 0,  # No source since not saved
                    'source_name': 'Quick Export',
                    'created_at': datetime.now().isoformat(),
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'tags': []
                }
                iocs.append(ioc_dict)
            
            # Create temporary data structure for export
            export_data = {'ioc_ids': [ioc['id'] for ioc in iocs]}
            
            # Export based on format
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = None
            
            # Create a mock database object for export functions
            class MockDB:
                def get_ioc(self, ioc_id):
                    return next((ioc for ioc in iocs if ioc['id'] == ioc_id), None)
                
                def get_source(self, source_id):
                    return None
                
                def get_iocs_by_source(self, source_id):
                    return []
            
            mock_db = MockDB()
            
            # Use export functions but with direct IOC list
            if format_type == 'txt':
                output_file = _quick_export_txt(iocs, OUTPUT_FOLDER, timestamp)
            elif format_type == 'txt-simple':
                output_file = _quick_export_txt_simple(iocs, OUTPUT_FOLDER, timestamp)
            elif format_type == 'csv':
                output_file = _quick_export_csv(iocs, OUTPUT_FOLDER, timestamp)
            elif format_type == 'csv-firewall':
                output_file = _quick_export_csv_firewall(iocs, OUTPUT_FOLDER, timestamp)
            elif format_type == 'json':
                output_file = _quick_export_json(iocs, OUTPUT_FOLDER, timestamp)
            elif format_type == 'json-simple':
                output_file = _quick_export_json_simple(iocs, OUTPUT_FOLDER, timestamp)
            elif format_type == 'xlsx':
                output_file = _quick_export_xlsx(iocs, OUTPUT_FOLDER, timestamp)
            else:
                return api_error('Invalid export format', 400)
            
            # Determine file extension
            ext_map = {
                'txt': 'txt',
                'txt-simple': 'txt',
                'csv': 'csv',
                'csv-firewall': 'csv',
                'json': 'json',
                'json-simple': 'json',
                'xlsx': 'xlsx'
            }
            ext = ext_map.get(format_type, 'txt')
            
            return send_file(str(output_file), as_attachment=True, download_name=f"quick_export_{timestamp}.{ext}")
            
        finally:
            # Clean up temporary file if created
            if temp_file_path and temp_file_path.exists():
                try:
                    temp_file_path.unlink()
                except Exception as e:
                    logger.warning(f"Failed to delete temp file {temp_file_path}: {e}")
    
    except RequestEntityTooLarge:
        return api_error('File too large', 413)
    except Exception as e:
        logger.error(f"api_quick_export error: {e}")
        return api_error(str(e), 500)

# Helper functions for quick export (without database)
def _quick_export_txt(iocs: List[Dict], output_folder: Path, timestamp: str) -> Path:
    """Quick export to TXT format"""
    output_file = output_folder / "iocs" / f"quick_export_{timestamp}.txt"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for ioc in iocs:
            f.write(f"{ioc['ioc_type']}\t{ioc['ioc_value']}\n")
    return output_file

def _quick_export_txt_simple(iocs: List[Dict], output_folder: Path, timestamp: str) -> Path:
    """Quick export to TXT simple format"""
    output_file = output_folder / "iocs" / f"quick_export_simple_{timestamp}.txt"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for ioc in iocs:
            f.write(f"{ioc['ioc_value']}\n")
    return output_file

def _quick_export_csv(iocs: List[Dict], output_folder: Path, timestamp: str) -> Path:
    """Quick export to CSV format"""
    output_file = output_folder / "iocs" / f"quick_export_{timestamp}.csv"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Type', 'Value', 'Source', 'Created At', 'Tags'])
        for ioc in iocs:
            writer.writerow([
                ioc.get('ioc_type', ''),
                ioc.get('ioc_value', ''),
                'Quick Export',
                ioc.get('created_at', ''),
                ''
            ])
    return output_file

def _quick_export_csv_firewall(iocs: List[Dict], output_folder: Path, timestamp: str) -> Path:
    """Quick export to CSV firewall format"""
    output_file = output_folder / "iocs" / f"quick_export_firewall_{timestamp}.csv"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['value'])
        for ioc in iocs:
            writer.writerow([ioc.get('ioc_value', '')])
    return output_file

def _quick_export_json(iocs: List[Dict], output_folder: Path, timestamp: str) -> Path:
    """Quick export to JSON format"""
    output_file = output_folder / "iocs" / f"quick_export_{timestamp}.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    export_data = {
        'export_date': datetime.now().isoformat(),
        'total_iocs': len(iocs),
        'source': 'Quick Export',
        'iocs': iocs
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
    return output_file

def _quick_export_json_simple(iocs: List[Dict], output_folder: Path, timestamp: str) -> Path:
    """Quick export to JSON simple format"""
    output_file = output_folder / "iocs" / f"quick_export_simple_{timestamp}.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Group by type
    grouped = {}
    for ioc in iocs:
        ioc_type = ioc.get('ioc_type', 'unknown')
        if ioc_type not in grouped:
            grouped[ioc_type] = []
        grouped[ioc_type].append(ioc.get('ioc_value', ''))
    
    export_data = {
        'export_date': datetime.now().isoformat(),
        'total_iocs': len(iocs),
        'source': 'Quick Export',
        'iocs_by_type': grouped
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
    return output_file

def _quick_export_xlsx(iocs: List[Dict], output_folder: Path, timestamp: str) -> Path:
    """Quick export to XLSX format"""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
        from openpyxl.utils import get_column_letter
    except ImportError:
        raise RuntimeError("openpyxl is not available. Please install it: pip install openpyxl")
    
    output_file = output_folder / "iocs" / f"quick_export_{timestamp}.xlsx"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    wb = Workbook()
    ws = wb.active
    ws.title = "IOCs"
    
    # Header
    header_fill = PatternFill(start_color="F5F5F7", end_color="F5F5F7", fill_type="solid")
    header_font = Font(name='Calibri', size=11, bold=True, color="1D1D1F")
    
    headers = ['Type', 'Value', 'Source', 'Created At']
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='left', vertical='center')
    
    # Data
    for row_idx, ioc in enumerate(iocs, 2):
        ws.cell(row=row_idx, column=1, value=ioc.get('ioc_type', ''))
        ws.cell(row=row_idx, column=2, value=ioc.get('ioc_value', ''))
        ws.cell(row=row_idx, column=3, value='Quick Export')
        ws.cell(row=row_idx, column=4, value=ioc.get('created_at', ''))
    
    # Auto-adjust column widths
    for col in range(1, len(headers) + 1):
        col_letter = get_column_letter(col)
        ws.column_dimensions[col_letter].width = 20
    
    wb.save(str(output_file))
    return output_file

# ========== ROUTES API STIX IMPORT > EXPORT ==========


@app.route('/api/stix/files', methods=['GET'])
@require_auth
def api_stix_files():
    """API: List all STIX files from stix and stix_conversions directories"""
    try:
        files = []
        
        # List files from main stix directory
        stix_dir = OUTPUT_FOLDER / "stix"
        if stix_dir.exists():
            for file_path in stix_dir.glob("*.json"):
                try:
                    stat = file_path.stat()
                    files.append({
                        'name': file_path.name,
                        'path': file_path.name,  # Relative path for download
                        'source': 'export',
                        'size': stat.st_size,
                        'size_formatted': format_bytes(stat.st_size),
                        'converted_at': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
                except Exception as e:
                    logger.warning(f"Error reading file {file_path}: {e}")
                    continue
        
        # List files from stix_conversions directory
        stix_conv_dir = OUTPUT_FOLDER / "stix_conversions"
        if stix_conv_dir.exists():
            for file_path in stix_conv_dir.glob("*.json"):
                try:
                    stat = file_path.stat()
                    files.append({
                        'name': file_path.name,
                        'path': f"stix_conversions/{file_path.name}",  # Relative path for download
                        'source': 'import',
                        'size': stat.st_size,
                        'size_formatted': format_bytes(stat.st_size),
                        'converted_at': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
                except Exception as e:
                    logger.warning(f"Error reading file {file_path}: {e}")
                    continue
        
        # Sort by modification time, newest first
        files.sort(key=lambda x: x['converted_at'], reverse=True)
        
        return api_success({'files': files})
    
    except Exception as e:
        logger.error(f"api_stix_files error: {e}")
        return api_error(str(e), 500)

@app.route('/api/stix/files/<path:filepath>/download', methods=['GET'])
@require_auth
def api_stix_files_download(filepath):
    """API: Download a STIX file from stix or stix_conversions directory"""
    try:
        # Check if path contains stix_conversions prefix
        if filepath.startswith('stix_conversions/'):
            base_dir = OUTPUT_FOLDER / "stix_conversions"
            relative_path = filepath[len('stix_conversions/'):]
        else:
            base_dir = OUTPUT_FOLDER / "stix"
            relative_path = filepath
        
        file_path = base_dir / relative_path
        
        # Prevent directory traversal - ensure file is within allowed directories
        outputs_dir = OUTPUT_FOLDER.resolve()
        if not str(file_path.resolve()).startswith(str(outputs_dir)):
            return api_error('Invalid file path', 400)
        
        if file_path.exists() and file_path.is_file():
            # Return file content as JSON (for graph loading) or as download
            if request.args.get('raw', 'false').lower() == 'true':
                return send_file(str(file_path), as_attachment=True, download_name=file_path.name)
            else:
                # Return JSON content directly for loading in graph
                return send_file(str(file_path), mimetype='application/json')
        else:
            return api_not_found('File')
    
    except Exception as e:
        logger.error(f"api_stix_files_download error: {e}")
        return api_error(str(e), 500)

@app.route('/api/stix/files/<path:filepath>/delete', methods=['DELETE'])
@require_auth
def api_stix_files_delete(filepath):
    """API: Delete a STIX file from stix or stix_conversions directory"""
    try:
        # Check if path contains stix_conversions prefix
        if filepath.startswith('stix_conversions/'):
            base_dir = OUTPUT_FOLDER / "stix_conversions"
            relative_path = filepath[len('stix_conversions/'):]
        else:
            base_dir = OUTPUT_FOLDER / "stix"
            relative_path = filepath
        
        file_path = base_dir / relative_path
        
        # Prevent directory traversal - ensure file is within allowed directories
        outputs_dir = OUTPUT_FOLDER.resolve()
        if not str(file_path.resolve()).startswith(str(outputs_dir)):
            return api_error('Invalid file path', 400)
        
        if file_path.exists() and file_path.is_file():
            file_path.unlink()
            return api_success(message='File deleted successfully')
        else:
            return api_not_found('File')
    
    except Exception as e:
        logger.error(f"api_stix_files_delete error: {e}")
        return api_error(str(e), 500)

@app.route('/api/stix/files/upload', methods=['POST'])
@require_auth
def api_stix_files_upload():
    """API: Upload a STIX file to stix_conversions directory"""
    try:
        if 'file' not in request.files:
            return api_error('No file provided', 400)
        
        file = request.files['file']
        if file.filename == '':
            return api_error('No file selected', 400)
        
        if not file.filename.endswith('.json'):
            return api_error('Only JSON files are allowed', 400)
        
        # Save to stix_conversions directory
        stix_conv_dir = OUTPUT_FOLDER / "stix_conversions"
        stix_conv_dir.mkdir(parents=True, exist_ok=True)
        
        # Use original filename or generate one
        filename = file.filename
        file_path = stix_conv_dir / filename
        
        # If file exists, add timestamp
        if file_path.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name_parts = filename.rsplit('.', 1)
            filename = f"{name_parts[0]}_{timestamp}.{name_parts[1]}"
            file_path = stix_conv_dir / filename
        
        file.save(str(file_path))
        
        return api_success({
            'filename': filename,
            'path': f"stix_conversions/{filename}"
        }, 'File uploaded successfully')
    
    except Exception as e:
        logger.error(f"api_stix_files_upload error: {e}")
        return api_error(str(e), 500)

# ========== ROUTES API SAVED STIX MODELS ==========

@app.route('/api/stix/models', methods=['GET'])
@require_auth
def api_stix_models_list():
    """API: List all saved STIX models"""
    try:
        models = db.get_all_saved_stix_models()
        return api_success({'models': models})
    except Exception as e:
        logger.error(f"api_stix_models_list error: {e}")
        return api_error(str(e), 500)

@app.route('/api/stix/models', methods=['POST'])
@require_auth
def api_stix_models_create():
    """API: Create a new saved STIX model"""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        stix_content = data.get('stix_content', '')
        description = data.get('description', '').strip()
        node_count = data.get('node_count', 0)
        edge_count = data.get('edge_count', 0)
        
        if not name:
            return api_error('Name is required', 400)
        if not stix_content:
            return api_error('STIX content is required', 400)
        
        model_id = db.create_saved_stix_model(
            name=name,
            stix_content=stix_content,
            description=description,
            node_count=node_count,
            edge_count=edge_count
        )
        
        return api_success({'id': model_id}, 'Model saved successfully')
    except Exception as e:
        logger.error(f"api_stix_models_create error: {e}")
        return api_error(str(e), 500)

@app.route('/api/stix/models/<int:model_id>', methods=['GET'])
@require_auth
def api_stix_models_get(model_id):
    """API: Get a saved STIX model by ID"""
    try:
        model = db.get_saved_stix_model(model_id)
        if not model:
            return api_not_found('Model')
        
        # Update last_loaded_at
        db.update_saved_stix_model_last_loaded(model_id)
        
        return api_success({'model': model})
    except Exception as e:
        logger.error(f"api_stix_models_get error: {e}")
        return api_error(str(e), 500)

@app.route('/api/stix/models/<int:model_id>', methods=['DELETE'])
@require_auth
def api_stix_models_delete(model_id):
    """API: Delete a saved STIX model"""
    try:
        success = db.delete_saved_stix_model(model_id)
        if not success:
            return api_not_found('Model')
        
        return api_success(message='Model deleted successfully')
    except Exception as e:
        logger.error(f"api_stix_models_delete error: {e}")
        return api_error(str(e), 500)

@app.route('/api/tags', methods=['GET'])
@require_auth
def api_tags():
    """API: Retrieve all tags"""
    try:
        tags = db.get_all_tags()
        return api_success({'tags': tags})
    except Exception as e:
        logger.error(f"api_tags error: {e}")
        return api_error(str(e), 500)

@app.route('/api/stats', methods=['GET'])
@require_auth
def api_stats():
    """API: Retrieve global statistics"""
    try:
        stats = db.get_statistics()
        recent_limit = int(db.get_setting('recent_sources_limit', '20'))
        recent_sources = db.get_all_sources(limit=recent_limit)
        return api_success({
            'stats': stats,
            'recent_sources': recent_sources
        })
    except Exception as e:
        logger.error(f"api_stats error: {e}")
        return api_error(str(e), 500)

# ========== ROUTES API RAPPORTS ==========

@app.route('/api/reports/<int:source_id>', methods=['GET'])
@require_auth
def api_reports_list(source_id):
    """API: List of generated reports for a source"""
    try:
        reports = db.get_reports_by_source(source_id)
        return api_success({'reports': reports})
    except Exception as e:
        logger.error(f"api_reports_list error: {e}")
        return api_error(str(e), 500)

@app.route('/api/reports/<int:report_id>/download', methods=['GET'])
@require_auth
def api_report_download(report_id):
    """API: Download a generated report"""
    try:
        report = db.get_report(report_id)
        if not report:
            return api_not_found('Report')
        
        file_path = Path(report['file_path'])
        if not file_path.exists():
            return api_not_found('Report file')
        
        # Determine download name
        report_type = report['report_type']
        extension = file_path.suffix or '.json'
        download_name = f"{report_type}_{file_path.stem}{extension}"
        
        return send_file(
            str(file_path),
            as_attachment=True,
            download_name=download_name
        )
    except Exception as e:
        logger.error(f"api_report_download error: {e}")
        return api_error(str(e), 500)

@app.route('/api/iocs/export', methods=['GET'])
@require_auth
def api_iocs_export():
    """API: Get IOC IDs with applied filters"""
    try:
        # Get filtering parameters (same logic as iocs_list)
        filters = {}
        if request.args.get('type'):
            filters['ioc_type'] = request.args.get('type')
        if request.args.get('search'):
            filters['search'] = request.args.get('search')
        if request.args.getlist('tag'):
            filters['tags'] = request.args.getlist('tag')
            filters['tag_logic'] = request.args.get('tag_logic', 'AND')
        if request.args.get('date_from'):
            filters['date_from'] = request.args.get('date_from')
        if request.args.get('date_to'):
            filters['date_to'] = request.args.get('date_to')
        
        # Get all IOCs with these filters using streaming for large datasets
        iocs = []
        for batch in db.get_all_iocs_streaming(filters=filters, limit=None):
            iocs.extend(batch)
        
        return api_success({
            'ioc_ids': [ioc['id'] for ioc in iocs],
            'count': len(iocs)
        })
    except Exception as e:
        logger.error(f"api_iocs_export error: {e}")
        return api_error(str(e), 500)


@app.route('/api/progress/<task_id>', methods=['GET'])
@require_auth
def api_get_progress(task_id):
    """API: Get task progress"""
    try:
        progress = progress_tracker.get_progress(task_id)
        if progress:
            return api_success({'progress': progress})
        else:
            return api_not_found('Task')
    except Exception as e:
        logger.error(f"api_get_progress error: {e}")
        return api_error(str(e), 500)

@app.route('/api/progress/<task_id>/stop', methods=['POST'])
@require_auth
def api_stop_task(task_id):
    """API: Stop a running task"""
    try:
        success = progress_tracker.stop_task(task_id)
        if success:
            return api_success({'message': 'Stop request sent'})
        else:
            return api_error('Task not found or cannot be stopped', 404)
    except Exception as e:
        logger.error(f"api_stop_task error: {e}")
        return api_error(str(e), 500)

@app.route('/api/progress/<task_id>/download', methods=['GET'])
@require_auth
def api_download_complete_report(task_id):
    """API: Download STIX report once generation is complete"""
    try:
        progress = progress_tracker.get_progress(task_id)
        if not progress:
            return api_not_found('Task')
        
        if progress.get('status') != 'completed':
            return api_error(
                'Report not yet completed',
                202,
                {
                'status': progress.get('status'),
                'progress': progress.get('percentage', 0)
                }
            )
        
        results = progress.get('results', {})
        if not results:
            return api_error('No results available', 404)
        
        # Use generated STIX file
        stix_file = results.get('stix_file')
        if not stix_file:
            return api_error('STIX file not found. The report may not have been fully generated.', 404)
        
        stix_path = Path(stix_file)
        if not stix_path.exists():
            return api_error('STIX file not found on filesystem', 404)
        
        # Send STIX file
        return send_file(
            str(stix_path),
            as_attachment=True,
            download_name=stix_path.name,
            mimetype='application/json'
        )
        
    except Exception as e:
        logger.error(f"api_download_complete_report error: {e}", exc_info=True)
        return api_error(str(e), 500)

# ========== ROUTES API SUPPRESSION IOCs ==========

@app.route('/api/iocs/bulk-delete', methods=['POST'])
@require_auth
def api_iocs_bulk_delete():
    """API: Delete multiple IOCs in bulk"""
    try:
        data = request.get_json()
        ioc_ids = data.get('ioc_ids', [])
        
        if not ioc_ids:
            return api_error('No IOCs selected', 400)
        
        count = 0
        for ioc_id in ioc_ids:
            if db.soft_delete_ioc(ioc_id):
                count += 1
        
        return api_success(
            {'count': count},
            f'{count} IOC(s) deleted successfully'
        )
    except Exception as e:
        logger.error(f"api_iocs_bulk_delete error: {e}")
        return api_error(str(e), 500)

@app.route('/api/iocs/all-ids', methods=['GET'])
@require_auth
def api_iocs_all_ids():
    """API: Retrieve all IOC IDs with current filters"""
    try:
        # Retrieve the same filters as the page
        ioc_type = request.args.get('type', '').strip()
        search = request.args.get('search', '').strip()
        source_name = request.args.get('source', '').strip()
        group_id = request.args.get('group', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        show_duplicates = request.args.get('duplicates', '').strip()
        
        filters = {}
        if ioc_type:
            filters['ioc_type'] = ioc_type
        if search:
            filters['search'] = search
        if source_name:
            filters['source_name'] = source_name
        if group_id:
            try:
                filters['group_id'] = int(group_id)
            except ValueError:
                pass
        if date_from:
            filters['date_from'] = date_from
        if date_to:
            filters['date_to'] = date_to
        if show_duplicates == 'true':
            filters['show_duplicates'] = True
        
        # Retrieve all IOCs with these filters using streaming
        iocs = []
        for batch in db.get_all_iocs_streaming(filters=filters, limit=None):
            iocs.extend(batch)
        ioc_ids = [ioc['id'] for ioc in iocs]
        
        return api_success({'ioc_ids': ioc_ids})
    except Exception as e:
        logger.error(f"api_iocs_all_ids error: {e}")
        return api_error(str(e), 500)

@app.route('/api/iocs/load', methods=['GET'])
@require_auth
def api_iocs_load():
    """API: Load IOCs with pagination for lazy loading"""
    try:
        from modules.ioc_query_urls import get_query_urls
        
        # Retrieve filtering parameters (same as iocs_list)
        ioc_type = request.args.get('type', '').strip()
        search = request.args.get('search', '').strip()
        source_name = request.args.get('source', '').strip()
        date_range = request.args.get('date_range', '')
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        
        # Handle hashtag filters
        hashtag_filters = request.args.get('hashtag_filters', '')
        if hashtag_filters:
            try:
                hashtag_filters_list = json.loads(hashtag_filters)
                # Convert hashtag filters to regular filters
                for filter_key in hashtag_filters_list:
                    if ':' in filter_key:
                        filter_type, filter_value = filter_key.split(':', 1)
                        if filter_type == 'type':
                            ioc_type = filter_value
                        elif filter_type == 'source':
                            source_name = filter_value
                        elif filter_type == 'group':
                            # Extract group ID from group name
                            groups = db.get_all_groups()
                            for group in groups:
                                group_name_clean = group['name'].replace(' ', '_').replace('/', '_').replace('\\', '_').replace('#', '').replace(':', '_')
                                if group_name_clean == filter_value:
                                    group_id = group['id']
                                    break
            except json.JSONDecodeError:
                pass
        
        filters = {}
        if ioc_type:
            filters['ioc_type'] = ioc_type
        if search:
            filters['search'] = search
        if source_name:
            filters['source_name'] = source_name
        group_id = request.args.get('group', '').strip()
        if group_id:
            try:
                filters['group_id'] = int(group_id)
            except ValueError:
                pass
        show_duplicates = request.args.get('duplicates', '').strip()
        if show_duplicates == 'true':
            filters['show_duplicates'] = True
        if date_range:
            filters['date_range'] = date_range
            from datetime import datetime, timedelta
            now = datetime.now()
            if date_range == '24h':
                filters['date_from'] = (now - timedelta(hours=24)).strftime('%Y-%m-%d')
            elif date_range == '7d':
                filters['date_from'] = (now - timedelta(days=7)).strftime('%Y-%m-%d')
            elif date_range == '30d':
                filters['date_from'] = (now - timedelta(days=30)).strftime('%Y-%m-%d')
            elif date_range == '3m':
                filters['date_from'] = (now - timedelta(days=90)).strftime('%Y-%m-%d')
            elif date_range == '1y':
                filters['date_from'] = (now - timedelta(days=365)).strftime('%Y-%m-%d')
            elif date_range == 'custom':
                if date_from:
                    filters['date_from'] = date_from
                if date_to:
                    filters['date_to'] = date_to
        else:
            if date_from:
                filters['date_from'] = date_from
            if date_to:
                filters['date_to'] = date_to
        
        offset = (page - 1) * per_page
        iocs, total = db.get_all_iocs(filters=filters, limit=per_page, offset=offset)
        
        # Enrich each IOC with its query URLs
        for ioc in iocs:
            ioc['query_urls'] = get_query_urls(ioc['ioc_type'], ioc['ioc_value'])
        
        return api_success({
            'iocs': iocs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'has_more': (page * per_page) < total
        })
    except Exception as e:
        logger.error(f"api_iocs_load error: {e}")
        return api_error(str(e), 500)

@app.route('/api/iocs/get-sources', methods=['POST'])
@require_auth
def api_iocs_get_sources():
    """API: Retrieve source_ids from ioc_ids"""
    try:
        data = request.get_json()
        ioc_ids = data.get('ioc_ids', [])
        
        if not ioc_ids:
            return api_error('No IOCs provided', 400)
        
        source_ids = []
        for ioc_id in ioc_ids:
            ioc = db.get_ioc(ioc_id)
            if ioc and ioc.get('source_id'):
                source_ids.append(ioc['source_id'])
        
        # Remove duplicates
        source_ids = list(set(source_ids))
        
        return api_success({'source_ids': source_ids})
    except Exception as e:
        logger.error(f"api_iocs_get_sources error: {e}")
        return api_error(str(e), 500)

@app.route('/api/iocs/bulk-add-group', methods=['POST'])
@require_auth
def api_iocs_bulk_add_group():
    """API: Add multiple IOCs to a group"""
    try:
        data = request.get_json()
        ioc_ids = data.get('ioc_ids', [])
        group_id = data.get('group_id')
        
        if not ioc_ids:
            return api_error('No IOCs selected', 400)
        if not group_id:
            return api_error('Group ID is required', 400)
        
        count = db.bulk_add_iocs_to_group(ioc_ids, group_id)
        
        return api_success(
            {'count': count},
            f'{count} IOC(s) added to group'
        )
    except Exception as e:
        logger.error(f"api_iocs_bulk_add_group error: {e}")
        return api_error(str(e), 500)

@app.route('/api/iocs/remove-group', methods=['POST'])
@require_auth
def api_iocs_remove_group():
    """API: Remove an IOC from a group (direct group or source group exclusion)"""
    try:
        data = request.get_json()
        ioc_id = data.get('ioc_id')
        group_id = data.get('group_id')
        is_source_group = data.get('is_source_group', False)  # Indicates if it's a source group
        
        if not ioc_id:
            return api_error('IOC ID is required', 400)
        if not group_id:
            return api_error('Group ID is required', 400)
        
        if is_source_group:
            # Exclude the source group for this IOC
            success = db.exclude_ioc_from_source_group(ioc_id, group_id)
            if success:
                return api_success(message='IOC excluded from source group successfully')
            else:
                return api_error('IOC was already excluded from this source group', 400)
        else:
            # Remove the direct group
            success = db.remove_ioc_from_group(ioc_id, group_id)
            if success:
                return api_success(message='IOC removed from group successfully')
            else:
                return api_error('IOC was not in this group', 400)
    except Exception as e:
        logger.error(f"api_iocs_remove_group error: {e}")
        return api_error(str(e), 500)

@app.route('/api/groups/create', methods=['POST'])
@require_auth
def api_groups_create():
    """API: Create a new group"""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        color = data.get('color', '#8B5CF6')
        
        if not name:
            return api_error('Group name is required', 400)
        
        group_id = db.create_group(name, color=color)
        return api_success(
            {'group_id': group_id},
            'Group created successfully'
        )
    except Exception as e:
        logger.error(f"api_groups_create error: {e}")
        return api_error(str(e), 500)

@app.route('/api/sources/bulk-add-group', methods=['POST'])
@require_auth
def api_sources_bulk_add_group():
    """API: Add multiple sources to a group"""
    try:
        data = request.get_json()
        source_ids = data.get('source_ids', [])
        group_id = data.get('group_id')
        
        if not source_ids:
            return api_error('No sources selected', 400)
        if not group_id:
            return api_error('Group ID is required', 400)
        
        count = 0
        for source_id in source_ids:
            if db.add_source_to_group(source_id, group_id):
                count += 1
        
        return api_success(
            {'count': count},
            f'{count} source(s) added to group'
        )
    except Exception as e:
        logger.error(f"api_sources_bulk_add_group error: {e}")
        return api_error(str(e), 500)

@app.route('/api/sources/remove-group', methods=['POST'])
@require_auth
def api_sources_remove_group():
    """API: Remove a source from a group"""
    try:
        data = request.get_json()
        source_id = data.get('source_id')
        group_id = data.get('group_id')
        
        if not source_id:
            return api_error('Source ID is required', 400)
        if not group_id:
            return api_error('Group ID is required', 400)
        
        success = db.remove_source_from_group(source_id, group_id)
        if success:
            return api_success(message='Source removed from group successfully')
        else:
            return api_error('Source was not in this group', 400)
    except Exception as e:
        logger.error(f"api_sources_remove_group error: {e}")
        return api_error(str(e), 500)

@app.route('/api/groups/<int:group_id>', methods=['DELETE'])
@require_auth
def api_groups_delete(group_id):
    """API: Delete a group"""
    try:
        # Vérifier que ce n'est pas un groupe système
        group = db.get_group_by_id(group_id)
        if not group:
            return api_not_found('Group')
        
        group_name = group.get('name', '')
        # Empêcher la suppression des groupes système
        system_groups = ['default', 'True Positive', 'False Positive']
        is_tlp_group = group_name.startswith('TLP:')
        
        if group_name in system_groups or is_tlp_group:
            return api_error('Cannot delete system groups (default, TLP groups, True/False Positive)', 400)
        
        success = db.delete_group(group_id)
        if success:
            return api_success(message='Group deleted successfully')
        else:
            return api_not_found('Group')
    except Exception as e:
        logger.error(f"api_groups_delete error: {e}")
        return api_error(str(e), 500)

@app.route('/api/groups/get-by-name', methods=['GET'])
@require_auth
def api_groups_get_by_name():
    """API: Retrieve a group by its name"""
    try:
        name = request.args.get('name', '').strip()
        
        if not name:
            return api_error('Group name is required', 400)
        
        group = db.get_group_by_name(name)
        if group:
            return api_success({'group_id': group['id'], 'group': group})
        else:
            return api_not_found('Group')
    except Exception as e:
        logger.error(f"api_groups_get_by_name error: {e}")
        return api_error(str(e), 500)

@app.route('/api/sources/bulk-remove-group', methods=['POST'])
@require_auth
def api_sources_bulk_remove_group():
    """API: Remove multiple sources from a group"""
    try:
        data = request.get_json()
        source_ids = data.get('source_ids', [])
        group_id = data.get('group_id')
        
        if not source_ids:
            return api_error('No sources selected', 400)
        if not group_id:
            return api_error('Group ID is required', 400)
        
        count = 0
        for source_id in source_ids:
            if db.remove_source_from_group(source_id, group_id):
                count += 1
        
        return api_success(
            {'count': count},
            f'{count} source(s) removed from group'
        )
    except Exception as e:
        logger.error(f"api_sources_bulk_remove_group error: {e}")
        return api_error(str(e), 500)

@app.route('/api/ioc/<int:ioc_id>/delete', methods=['POST'])
@require_auth
def api_ioc_delete(ioc_id):
    """API: Permanently delete an IOC"""
    try:
        success = db.hard_delete_ioc(ioc_id)
        if success:
            # Clean up orphaned tags
            db.cleanup_orphaned_tags()
            return api_success(message='IOC permanently deleted')
        else:
            return api_not_found('IOC')
    except Exception as e:
        logger.error(f"api_ioc_delete error: {e}")
        return api_error(str(e), 500)

@app.route('/api/tags/cleanup', methods=['POST'])
@require_auth
def api_tags_cleanup():
    """API: Force cleanup of orphaned tags"""
    try:
        db.cleanup_orphaned_tags()
        return api_success(message='Orphaned tags cleaned up')
    except Exception as e:
        logger.error(f"api_tags_cleanup error: {e}")
        return api_error(str(e), 500)

# ========== ROUTES API SUPPRESSION SOURCES ==========

@app.route('/api/sources/<int:source_id>/delete', methods=['POST', 'DELETE'])
@require_auth
def api_source_delete(source_id):
    """API: Delete a single source (soft delete)"""
    try:
        if db.soft_delete_source(source_id):
            return api_success({'source_id': source_id}, 'Source moved to trash')
        else:
            return api_error('Source not found or already deleted', 404)
    except Exception as e:
        logger.error(f"api_source_delete error: {e}")
        return api_error(str(e), 500)

@app.route('/api/sources/bulk-delete', methods=['POST'])
@require_auth
def api_sources_bulk_delete():
    """API: Permanently delete multiple sources"""
    try:
        data = request.get_json()
        source_ids = data.get('source_ids', [])
        
        if not source_ids:
            return api_error('No source selected', 400)
        
        count = 0
        for source_id in source_ids:
            if db.hard_delete_source(source_id):
                count += 1
        
        return api_success(
            {'count': count},
            f'{count} source(s) permanently deleted'
        )
    except Exception as e:
        logger.error(f"api_sources_bulk_delete error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/cleanup/all-sources', methods=['POST'])
@require_auth
def api_cleanup_all_sources():
    """API: Delete ALL sources and their IOCs"""
    try:
        count = db.delete_all_sources()
        return api_success(
            {'count': count},
            f'All sources ({count}) and their IOCs have been permanently deleted'
        )
    except Exception as e:
        logger.error(f"api_cleanup_all_sources error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/cleanup/all-iocs', methods=['POST'])
@require_auth
def api_cleanup_all_iocs():
    """API: Delete ALL IOCs"""
    try:
        count = db.delete_all_iocs()
        return api_success(
            {'count': count},
            f'All IOCs ({count}) have been permanently deleted'
        )
    except Exception as e:
        logger.error(f"api_cleanup_all_iocs error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/cleanup/all-stix-files', methods=['POST'])
@require_auth
def api_cleanup_all_stix_files():
    """API: Delete all STIX files from stix and stix_conversions directories"""
    try:
        deleted_count = 0
        
        # Delete files from stix directory
        stix_dir = OUTPUT_FOLDER / "stix"
        if stix_dir.exists():
            for file_path in stix_dir.glob("*.json"):
                try:
                    file_path.unlink()
                    deleted_count += 1
                except Exception as e:
                    logger.warning(f"Error deleting file {file_path}: {e}")
        
        # Delete files from stix_conversions directory
        stix_conv_dir = OUTPUT_FOLDER / "stix_conversions"
        if stix_conv_dir.exists():
            for file_path in stix_conv_dir.glob("*.json"):
                try:
                    file_path.unlink()
                    deleted_count += 1
                except Exception as e:
                    logger.warning(f"Error deleting file {file_path}: {e}")
        
        return api_success({'deleted_count': deleted_count}, f'Successfully deleted {deleted_count} STIX files')
    except Exception as e:
        logger.error(f"api_cleanup_all_stix_files error: {e}")
        return api_error(str(e), 500)

# ========== ROUTES API SETTINGS ==========

@app.route('/api/settings/auto-tag', methods=['GET', 'POST'])
@require_auth
def api_settings_auto_tag():
    """API: Manage auto-tagging"""
    try:
        if request.method == 'GET':
            enabled = db.get_setting('auto_tag_enabled', 'true')
            return api_success({'enabled': enabled.lower() == 'true'})
        
        elif request.method == 'POST':
            data = request.get_json()
            enabled = data.get('enabled', True)
            db.set_setting('auto_tag_enabled', 'true' if enabled else 'false')
            return api_success(message='Setting updated')
    except Exception as e:
        logger.error(f"api_settings_auto_tag error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/storage', methods=['GET'])
@require_auth
def api_settings_storage():
    """API: Get storage information"""
    try:
        storage_info = get_storage_info()
        return api_success(storage_info)
    except Exception as e:
        logger.error(f"api_settings_storage error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/source-rotation', methods=['GET', 'POST'])
@require_auth
def api_settings_source_rotation():
    """API: Manage automatic source rotation"""
    try:
        if request.method == 'GET':
            enabled = db.get_setting('auto_rotation_enabled', 'false')
            return api_success({'enabled': enabled.lower() == 'true'})
        
        elif request.method == 'POST':
            data = request.get_json()
            enabled = data.get('enabled', False)
            db.set_setting('auto_rotation_enabled', 'true' if enabled else 'false')
            return api_success(message='Setting updated')
    except Exception as e:
        logger.error(f"api_settings_source_rotation error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/max-sources', methods=['GET', 'POST'])
@require_auth
def api_settings_max_sources():
    """API: Manage maximum sources limit"""
    try:
        if request.method == 'GET':
            max_sources = db.get_setting('max_sources', '20')
            return api_success({'max_sources': int(max_sources)})
        
        elif request.method == 'POST':
            data = request.get_json()
            max_sources = data.get('max_sources', 20)
            if max_sources < 1:
                return api_error('Maximum sources must be at least 1', 400)
            db.set_setting('max_sources', str(max_sources))
            return api_success(message='Setting updated')
    except Exception as e:
        logger.error(f"api_settings_max_sources error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/recent-sources-limit', methods=['GET', 'POST'])
@require_auth
def api_settings_recent_sources_limit():
    """API: Manage recent sources display limit"""
    try:
        if request.method == 'GET':
            limit = db.get_setting('recent_sources_limit', '20')
            return api_success({'limit': int(limit)})
        
        elif request.method == 'POST':
            data = request.get_json()
            limit = data.get('limit', 20)
            if limit < 1:
                return api_error('Display limit must be at least 1', 400)
            db.set_setting('recent_sources_limit', str(limit))
            return api_success(message='Setting updated')
    except Exception as e:
        logger.error(f"api_settings_recent_sources_limit error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/trash-cleanup-days', methods=['GET', 'POST'])
@require_auth
def api_settings_trash_cleanup_days():
    """API: Manage trash cleanup days"""
    try:
        if request.method == 'GET':
            days = db.get_setting('trash_cleanup_days', '5')
            return api_success({'days': int(days)})
        
        elif request.method == 'POST':
            data = request.get_json()
            days = data.get('days', 5)
            if days < 1:
                return api_error('Cleanup days must be at least 1', 400)
            db.set_setting('trash_cleanup_days', str(days))
            return api_success(message='Setting updated')
    except Exception as e:
        logger.error(f"api_settings_trash_cleanup_days error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/cleanup-trash-now', methods=['POST'])
@require_auth
def api_settings_cleanup_trash_now():
    """API: Manually trigger trash cleanup"""
    try:
        days = int(db.get_setting('trash_cleanup_days', '5'))
        deleted_count = db.cleanup_trash(days)
        return api_success(
            {'deleted_count': deleted_count},
            f'{deleted_count} source(s) permanently deleted from trash'
        )
    except Exception as e:
        logger.error(f"api_settings_cleanup_trash_now error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/export-zip', methods=['POST'])
@require_auth
def api_settings_export_zip():
    """API: Export IOCs, sources, groups, configuration, and CTI favorites to ZIP file"""
    try:
        # Create temporary ZIP file
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_zip_path = temp_zip.name
        temp_zip.close()
        
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Export all IOCs using streaming (tags are now included in the query)
            iocs = []
            for batch in db.get_all_iocs_streaming(limit=None):
                iocs.extend(batch)
            
            # Format IOCs for export
            iocs_export = []
            for ioc in iocs:
                ioc_export = {
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
                    'groups': [{'id': g.get('id'), 'name': g.get('name'), 'color': g.get('color')} 
                              for g in ioc.get('groups', [])],
                    'tags': [{'id': t.get('id'), 'name': t.get('name'), 'category': t.get('category')} 
                            for t in ioc.get('tags', [])]
                }
                iocs_export.append(ioc_export)
            
            # Add IOCs to ZIP
            zipf.writestr('iocs.json', json.dumps(iocs_export, indent=2, default=str))
            
            # Export all sources with their groups
            all_sources = db.get_all_sources(limit=100000)  # Large limit to get all sources
            sources_export = []
            for source in all_sources:
                source_export = {
                    'id': source.get('id'),
                    'name': source.get('name'),
                    'context': source.get('context'),
                    'source_type': source.get('source_type'),
                    'file_path': source.get('file_path'),
                    'original_filename': source.get('original_filename'),
                    'created_at': source.get('created_at'),
                    'status': source.get('status'),
                    'groups': [{'id': g.get('id'), 'name': g.get('name'), 'color': g.get('color')} 
                              for g in source.get('groups', [])]
                }
                sources_export.append(source_export)
            
            zipf.writestr('sources.json', json.dumps(sources_export, indent=2, default=str))
            
            # Export all configuration
            config_export = {}
            
            # Export all settings (not just a few)
            # Note: User passwords are stored in the 'users' table, not in settings
            # Only settings are exported (auth_enabled, auto_tag_enabled, etc.)
            all_settings = db.get_all_settings()
            config_export['settings'] = all_settings
            
            # Export groups
            all_groups = db.get_all_groups()
            config_export['groups'] = [
                {
                    'id': g.get('id'),
                    'name': g.get('name'),
                    'description': g.get('description'),
                    'color': g.get('color'),
                    'created_at': g.get('created_at')
                }
                for g in all_groups
            ]
            
            # Export CTI favorites
            cti_favorites = list(github_repo_manager.favorites) if hasattr(github_repo_manager, 'favorites') else []
            config_export['cti_favorites'] = cti_favorites
            
            zipf.writestr('config.json', json.dumps(config_export, indent=2, default=str))
            
            # Add metadata
            metadata = {
                'export_date': datetime.now().isoformat(),
                'total_iocs': len(iocs_export),
                'total_sources': len(sources_export),
                'total_groups': len(all_groups),
                'total_favorites': len(cti_favorites),
                'version': '1.0'
            }
            zipf.writestr('metadata.json', json.dumps(metadata, indent=2, default=str))
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'cti-export-{timestamp}.zip'
        
        # Return ZIP file and schedule cleanup
        # Use a longer delay (5 minutes) to ensure file is downloaded
        def remove_file():
            try:
                if os.path.exists(temp_zip_path):
                    os.unlink(temp_zip_path)
                    logger.debug(f"Temporary ZIP file cleaned up: {temp_zip_path}")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary ZIP file {temp_zip_path}: {e}")
        
        # Schedule cleanup after response is sent (5 minutes should be enough for download)
        threading.Timer(300.0, remove_file).start()
        
        return send_file(
            temp_zip_path,
            mimetype='application/zip',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f"api_settings_export_zip error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/import-zip', methods=['POST'])
@require_auth
def api_settings_import_zip():
    """API: Import IOCs, sources, groups, and configuration from ZIP file"""
    try:
        if 'file' not in request.files:
            return api_error('No file provided', 400)
        
        file = request.files['file']
        if file.filename == '':
            return api_error('No file selected', 400)
        
        if not file.filename.endswith('.zip'):
            return api_error('File must be a ZIP file', 400)
        
        # Save uploaded file temporarily
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_zip_path = temp_zip.name
        file.save(temp_zip_path)
        temp_zip.close()
        
        stats = {
            'groups_imported': 0,
            'sources_imported': 0,
            'iocs_imported': 0,
            'config_imported': False
        }
        
        # Map to store old IDs to new IDs for groups and sources
        group_id_map = {}  # old_id -> new_id
        source_id_map = {}  # old_id -> new_id
        
        try:
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                # Read metadata
                metadata = {}
                if 'metadata.json' in zipf.namelist():
                    metadata_content = zipf.read('metadata.json').decode('utf-8')
                    metadata = json.loads(metadata_content)
                
                # Import configuration first (groups)
                if 'config.json' in zipf.namelist():
                    config_content = zipf.read('config.json').decode('utf-8')
                    config = json.loads(config_content)
                    
                    # Import groups
                    if 'groups' in config:
                        for group_data in config['groups']:
                            old_group_id = group_data.get('id')
                            group_name = group_data.get('name')
                            group_color = group_data.get('color', '#8B5CF6')
                            group_description = group_data.get('description', '')
                            
                            # Check if group already exists by name
                            existing_group = db.get_group_by_name(group_name)
                            if existing_group:
                                new_group_id = existing_group['id']
                            else:
                                # Create new group
                                new_group_id = db.create_group(
                                    name=group_name,
                                    color=group_color,
                                    description=group_description
                                )
                                stats['groups_imported'] += 1
                            
                            if old_group_id:
                                group_id_map[old_group_id] = new_group_id
                    
                    # Import settings
                    for key, value in config.items():
                        if key != 'groups' and value is not None:
                            db.set_setting(key, str(value))
                    
                    stats['config_imported'] = True
                
                # Import IOCs
                if 'iocs.json' in zipf.namelist():
                    iocs_content = zipf.read('iocs.json').decode('utf-8')
                    iocs_data = json.loads(iocs_content)
                    
                    # Group IOCs by source
                    sources_dict = {}  # source_name -> {source_data, iocs, source_groups_set, ioc_groups_map}
                    
                    for ioc_data in iocs_data:
                        source_name = ioc_data.get('source_name')
                        if not source_name:
                            continue
                        
                        if source_name not in sources_dict:
                            sources_dict[source_name] = {
                                'source_data': {
                                    'name': source_name,
                                    'context': f"Imported - {source_name}",
                                    'source_type': 'import',
                                    'file_path': None,
                                    'original_filename': None
                                },
                                'iocs': [],
                                'source_groups_set': set(),  # Groups that appear on all IOCs (likely source groups)
                                'ioc_groups_map': {}  # ioc_index -> list of groups (IOC-specific groups)
                            }
                        
                        # Store IOC data
                        ioc_index = len(sources_dict[source_name]['iocs'])
                        sources_dict[source_name]['iocs'].append(ioc_data)
                        
                        # Store groups for this IOC
                        ioc_groups = [g.get('name') for g in ioc_data.get('groups', []) if g.get('name')]
                        sources_dict[source_name]['ioc_groups_map'][ioc_index] = ioc_groups
                        
                        # Add to source groups set (we'll filter later)
                        for group_name in ioc_groups:
                            sources_dict[source_name]['source_groups_set'].add(group_name)
                    
                    # Determine which groups are source-level (appear on all IOCs of a source)
                    # and which are IOC-level (appear on only some IOCs)
                    for source_name in sources_dict:
                        source_info = sources_dict[source_name]
                        all_ioc_groups = list(source_info['source_groups_set'])
                        source_groups = []
                        ioc_groups_final = {}
                        
                        # If a group appears on all IOCs, it's likely a source group
                        # Otherwise, it's an IOC-specific group
                        for group_name in all_ioc_groups:
                            appears_on_all = all(
                                group_name in source_info['ioc_groups_map'].get(i, [])
                                for i in range(len(source_info['iocs']))
                            )
                            if appears_on_all and len(source_info['iocs']) > 0:
                                source_groups.append(group_name)
                            else:
                                # This is an IOC-specific group
                                for ioc_idx, ioc_groups in source_info['ioc_groups_map'].items():
                                    if group_name in ioc_groups:
                                        if ioc_idx not in ioc_groups_final:
                                            ioc_groups_final[ioc_idx] = []
                                        ioc_groups_final[ioc_idx].append(group_name)
                        
                        source_info['source_groups'] = source_groups
                        source_info['ioc_groups_final'] = ioc_groups_final
                    
                    # Create sources and import IOCs
                    for source_name, source_info in sources_dict.items():
                        # Create source
                        source_id = db.create_source(
                            name=source_info['source_data']['name'],
                            context=source_info['source_data']['context'],
                            source_type=source_info['source_data']['source_type'],
                            file_path=source_info['source_data']['file_path'],
                            original_filename=source_info['source_data']['original_filename']
                        )
                        stats['sources_imported'] += 1
                        
                        # Add source to groups
                        for group_name in source_info['source_groups']:
                            group = db.get_group_by_name(group_name)
                            if group:
                                db.add_source_to_group(source_id, group['id'])
                        
                        # Import IOCs for this source
                        for ioc_idx, ioc_data in enumerate(source_info['iocs']):
                            ioc_type = ioc_data.get('ioc_type')
                            ioc_value = ioc_data.get('ioc_value')
                            raw_value = ioc_data.get('raw_value') or ioc_value
                            
                            # Create IOC
                            ioc_id = db.create_ioc(
                                source_id=source_id,
                                ioc_type=ioc_type,
                                ioc_value=ioc_value,
                                raw_value=raw_value
                            )
                            stats['iocs_imported'] += 1
                            
                            # Add IOC to groups (only IOC-specific groups, not source groups)
                            ioc_specific_groups = source_info.get('ioc_groups_final', {}).get(ioc_idx, [])
                            for group_name in ioc_specific_groups:
                                group_obj = db.get_group_by_name(group_name)
                                if group_obj:
                                    db.add_ioc_to_group(ioc_id, group_obj['id'])
        finally:
            # Clean up temp file
            try:
                if os.path.exists(temp_zip_path):
                    os.unlink(temp_zip_path)
            except Exception as e:
                logger.warning(f"Failed to clean up temporary ZIP file {temp_zip_path}: {e}")
        
        return api_success(
            stats,
            f"Import completed: {stats['iocs_imported']} IOCs, {stats['sources_imported']} sources, {stats['groups_imported']} groups imported"
        )
    except zipfile.BadZipFile:
        return api_error('Invalid ZIP file', 400)
    except json.JSONDecodeError as e:
        return api_error(f'Invalid JSON in ZIP file: {str(e)}', 400)
    except Exception as e:
        logger.error(f"api_settings_import_zip error: {e}")
        return api_error(str(e), 500)

@app.route('/api/outputs/<path:filename>/delete', methods=['DELETE'])
@require_auth
def api_output_delete(filename):
    """API: Delete an export file directly"""
    try:
        file_path = OUTPUT_FOLDER / filename
        if file_path.exists() and file_path.is_file():
            file_path.unlink()
            return api_success(message='File deleted')
        else:
            return api_not_found('File')
    except Exception as e:
        logger.error(f"api_output_delete error: {e}")
        return api_error(str(e), 500)

@app.route('/api/uploads/<path:filename>/delete', methods=['DELETE'])
@require_auth
def api_upload_delete(filename):
    """API: Delete an uploaded file directly"""
    try:
        file_path = UPLOAD_FOLDER / filename
        if file_path.exists() and file_path.is_file():
            file_path.unlink()
            return api_success(message='File deleted')
        else:
            return api_not_found('File')
    except Exception as e:
        logger.error(f"api_upload_delete error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/outputs/recent', methods=['GET'])
@require_auth
def api_settings_outputs_recent():
    """API: Get recent output files"""
    try:
        from modules.storage_monitor import format_bytes
        
        recent_outputs = []
        max_files = 5
        
        # Get all output files from subfolders
        for subfolder in ['iocs', 'stix', 'reports']:
            subfolder_path = OUTPUT_FOLDER / subfolder
            if subfolder_path.exists():
                for file_path in subfolder_path.iterdir():
                    if file_path.is_file():
                        try:
                            mtime = file_path.stat().st_mtime
                            size = file_path.stat().st_size
                            recent_outputs.append({
                                'path': str(file_path),
                                'name': file_path.name,
                                'folder': subfolder,
                                'size': size,
                                'size_formatted': format_bytes(size),
                                'modified': datetime.fromtimestamp(mtime).isoformat(),
                                'modified_timestamp': mtime
                            })
                        except OSError:
                            continue
        
        # Sort by modification date (most recent first) and limit to max_files
        recent_outputs.sort(key=lambda x: x['modified_timestamp'], reverse=True)
        recent_outputs = recent_outputs[:max_files]
        
        return api_success({'outputs': recent_outputs})
    except Exception as e:
        logger.error(f"api_settings_outputs_recent error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/cleanup/uploads', methods=['POST'])
@require_auth
def api_settings_cleanup_uploads():
    """API: Delete all uploaded files"""
    try:
        from modules.storage_monitor import format_bytes
        
        deleted_count = 0
        total_size = 0
        
        if UPLOAD_FOLDER.exists():
            for file_path in UPLOAD_FOLDER.iterdir():
                if file_path.is_file():
                    try:
                        size = file_path.stat().st_size
                        file_path.unlink()
                        deleted_count += 1
                        total_size += size
                        logger.info(f"Upload file deleted: {file_path.name}")
                    except Exception as e:
                        logger.warning(f"Unable to delete {file_path}: {e}")
        
        return api_success(
            {'deleted_count': deleted_count, 'total_size': total_size},
            f'Cleanup completed: {deleted_count} file(s) deleted ({format_bytes(total_size)})'
        )
    except Exception as e:
        logger.error(f"api_settings_cleanup_uploads error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/cleanup/outputs', methods=['POST'])
@require_auth
def api_settings_cleanup_outputs():
    """API: Delete all output files"""
    try:
        from modules.storage_monitor import format_bytes
        
        deleted_count = 0
        total_size = 0
        
        # Delete files from all output subfolders
        for subfolder in ['iocs', 'stix', 'reports']:
            subfolder_path = OUTPUT_FOLDER / subfolder
            if subfolder_path.exists():
                for file_path in subfolder_path.iterdir():
                    if file_path.is_file():
                        try:
                            size = file_path.stat().st_size
                            file_path.unlink()
                            deleted_count += 1
                            total_size += size
                            logger.info(f"Output file deleted: {file_path.name}")
                        except Exception as e:
                            logger.warning(f"Unable to delete {file_path}: {e}")
        
        return api_success(
            {'deleted_count': deleted_count, 'total_size': total_size},
            f'Cleanup completed: {deleted_count} file(s) deleted ({format_bytes(total_size)})'
        )
    except Exception as e:
        logger.error(f"api_settings_cleanup_outputs error: {e}")
        return api_error(str(e), 500)

@app.route('/api/settings/outputs/<path:filepath>/download', methods=['GET'])
@require_auth
def api_settings_outputs_download(filepath):
    """API: Download an output file"""
    try:
        file_path = OUTPUT_FOLDER / filepath
        if file_path.exists() and file_path.is_file():
            return send_file(str(file_path), as_attachment=True, download_name=file_path.name)
        else:
            return api_not_found('File')
    except Exception as e:
        logger.error(f"api_settings_outputs_download error: {e}")
        return api_error(str(e), 500)

# ========== ROUTES API DeepDarkCTI ==========

@app.route('/api/cti-resources/download', methods=['POST'])
@require_auth
def api_cti_resources_download():
    """API: Download deepdarkcti repository"""
    try:
        logger.info("Downloading DeepDarkCTI repository...")
        
        success = github_repo_manager.download_repo()
        
        if success:
            return api_success({'message': 'Repository downloaded successfully'})
        else:
            return api_error("Repository download error", 500)
    except Exception as e:
        logger.error(f"api_cti_resources_download error: {e}", exc_info=True)
        return api_error(str(e), 500)

@app.route('/api/cti-resources/update', methods=['POST'])
@require_auth
def api_cti_resources_update():
    """API: Update repository (deletes cache + old repo + downloads new one)"""
    try:
        logger.info("Updating DeepDarkCTI repository...")
        
        success = github_repo_manager.update_repo()
        
        if success:
            return api_success({'message': 'Repository updated successfully'})
        else:
            return api_error("Repository update failed. Please check the logs for details.", 500)
    except RuntimeError as e:
        logger.error(f"Error api_cti_resources_update: {e}", exc_info=True)
        return api_error(str(e), 500)
    except Exception as e:
        logger.error(f"Error api_cti_resources_update: {e}", exc_info=True)
        return api_error(f"Repository update error: {str(e)}", 500)

@app.route('/api/cti-resources/source/delete', methods=['POST'])
@require_auth
def api_cti_resources_delete_source():
    """API: Delete a source"""
    try:
        data = request.get_json()
        category = data.get('category')
        source_url = data.get('url')
        is_manual = data.get('is_manual', False)
        
        if not source_url:
            return api_error("URL required", 400)
        
        # If it's a manual source, use specific method
        if is_manual or category == '_manual_sources':
            success = github_repo_manager.delete_manual_source(source_url)
        else:
            if not category:
                return api_error("Category required for repository sources", 400)
            success = github_repo_manager.delete_source(category, source_url)
        
        if success:
            return api_success({'message': 'Source deleted successfully'})
        else:
            return api_error("Deletion error", 500)
    except Exception as e:
        logger.error(f"api_cti_resources_delete_source error: {e}")
        return api_error(str(e), 500)

@app.route('/api/cti-resources/manual-source/add', methods=['POST'])
@require_auth
def api_cti_resources_add_manual_source():
    """API: Add a source manually"""
    try:
        data = request.get_json()
        url = data.get('url')
        name = data.get('name')
        description = data.get('description')
        
        if not url:
            return api_error("URL required", 400)
        
        # Validate that it's a valid URL
        if not url.startswith('http://') and not url.startswith('https://'):
            return api_error("Invalid URL. Must start with http:// or https://", 400)
        
        success = github_repo_manager.add_manual_source(url, name, description)
        
        if success:
            return api_success({'message': 'Source added successfully'})
        else:
            return api_error("This URL already exists", 400)
    except Exception as e:
        logger.error(f"api_cti_resources_add_manual_source error: {e}")
        return api_error(str(e), 500)

@app.route('/api/ransomware-tools/download', methods=['POST'])
@require_auth
def api_ransomware_tools_download():
    """API: Download Ransomware Tool Matrix repository"""
    try:
        logger.info("Downloading Ransomware Tool Matrix repository...")
        
        success = rtm_repo_manager.download_repo()
        
        if success:
            return api_success({'message': 'Repository downloaded successfully'})
        else:
            return api_error("Repository download error", 500)
    except Exception as e:
        logger.error(f"api_ransomware_tools_download error: {e}", exc_info=True)
        return api_error(str(e), 500)

@app.route('/api/ransomware-tools/update', methods=['POST'])
@require_auth
def api_ransomware_tools_update():
    """API: Update repository (deletes cache + old repo + downloads new one)"""
    try:
        logger.info("Updating Ransomware Tool Matrix repository...")
        
        success = rtm_repo_manager.update_repo()
        
        if success:
            return api_success({'message': 'Repository updated successfully'})
        else:
            return api_error("Repository update failed. Please check the logs for details.", 500)
    except RuntimeError as e:
        logger.error(f"Error api_ransomware_tools_update: {e}", exc_info=True)
        return api_error(str(e), 500)
    except Exception as e:
        logger.error(f"Error api_ransomware_tools_update: {e}", exc_info=True)
        return api_error(f"Repository update error: {str(e)}", 500)

@app.route('/api/ransomware-tools/favorite/toggle', methods=['POST'])
@require_auth
def api_ransomware_tools_toggle_favorite():
    """API: Add/remove a source from favorites"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return api_error("URL required", 400)
        
        is_favorite = rtm_repo_manager.toggle_favorite(url)
        
        return api_success({
            'message': 'Favorite updated successfully',
            'is_favorite': is_favorite
        })
    except Exception as e:
        logger.error(f"api_ransomware_tools_toggle_favorite error: {e}")
        return api_error(str(e), 500)

@app.route('/api/cti-resources/favorite/toggle', methods=['POST'])
@require_auth
def api_cti_resources_toggle_favorite():
    """API: Add/remove a source from favorites"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return api_error("URL required", 400)
        
        is_favorite = github_repo_manager.toggle_favorite(url)
        
        return api_success({
            'message': 'Favorite updated successfully',
            'is_favorite': is_favorite
        })
    except Exception as e:
        logger.error(f"api_cti_resources_toggle_favorite error: {e}")
        return api_error(str(e), 500)

@app.route('/api/iocs/add-manual', methods=['POST'])
@require_auth
def api_iocs_add_manual():
    """API: Add a single IOC manually"""
    try:
        data = request.get_json()
        ioc_type = data.get('ioc_type', '').strip()
        ioc_value = data.get('ioc_value', '').strip()
        context = data.get('context', 'Manual IOC entry').strip()
        
        if not ioc_type or not ioc_value:
            return api_error("IOC type and value are required", 400)
        
        # Get or create "Manual" source
        source_context = context if context else 'Manual IOC entries'
        
        with db.connection() as conn:
            ody = conn.cursor()
            
            # Check if "Manual" source exists
            ody.execute("SELECT id FROM sources WHERE name = 'Manual' AND is_deleted = 0 LIMIT 1")
            source_row = ody.fetchone()
            
            if source_row:
                source_id = source_row[0]
            else:
                # Create "Manual" source with explicit local timestamp
                from database import get_local_timestamp
                ody.execute("""
                    INSERT INTO sources (name, context, source_type, created_at)
                    VALUES (?, ?, ?, ?)
                """, ('Manual', source_context, 'manual', get_local_timestamp()))
                source_id = ody.lastrowid
                
                # Add to default group
                default_group = db.get_group_by_name("default", conn)
                if default_group:
                    try:
                        ody.execute("""
                            INSERT OR IGNORE INTO source_groups (source_id, group_id)
                            VALUES (?, ?)
                        """, (source_id, default_group['id']))
                    except Exception as e:
                        logger.warning(f"Failed to add manual source to default group: {e}")
                conn.commit()
        
        # Create the IOC
        ioc_id = db.create_ioc(source_id, ioc_type, ioc_value, ioc_value)
        
        return api_success({
            'message': 'IOC added successfully',
            'ioc_id': ioc_id
        })
    except Exception as e:
        logger.error(f"api_iocs_add_manual error: {e}")
        return api_error(str(e), 500)

# ========== ROUTES API Data-Shield IPv4 Blocklist ==========

@app.route('/api/data-shield/status', methods=['GET'])
@require_auth
def api_data_shield_status():
    """API: Get Data-Shield repository status"""
    try:
        status = data_shield_repo_manager.get_status()
        
        # Count imported IPs from database
        imported_count = 0
        try:
            with db.connection() as conn:
                ody = conn.cursor()
                ody.execute("""
                    SELECT COUNT(*) as count FROM iocs i
                    JOIN sources s ON i.source_id = s.id
                    WHERE s.name = 'data-shield' AND s.is_deleted = 0
                """)
                row = ody.fetchone()
                if row:
                    imported_count = row['count']
        except Exception as e:
            logger.warning(f"Error counting imported IPs: {e}")
        
        status['imported_ip_count'] = imported_count
        
        return api_success(status)
    except Exception as e:
        logger.error(f"api_data_shield_status error: {e}")
        return api_error(str(e), 500)

@app.route('/api/data-shield/download', methods=['POST'])
@require_auth
def api_data_shield_download():
    """API: Download/update Data-Shield repository"""
    try:
        logger.info("Downloading malicious IPv4 IP list from Data-Shield...")
        
        success = data_shield_repo_manager.download_blocklist()
        
        if success:
            return api_success({'message': 'Repository downloaded successfully'})
        else:
            return api_error("Repository download error", 500)
    except Exception as e:
        logger.error(f"api_data_shield_download error: {e}", exc_info=True)
        return api_error(str(e), 500)

def _import_data_shield_ips() -> Dict:
    """Helper function to import IPs from Data-Shield blocklist"""
    # Check if blocklist file exists
    if not data_shield_repo_manager.blocklist_file_exists():
        raise ValueError("Blocklist file not found. Please download it first.")
    
    # Get IPs from blocklist
    ips = data_shield_repo_manager.get_blocklist_ips()
    
    if not ips:
        raise ValueError("No valid IPs found in blocklist file")
    
    logger.info(f"Importing {len(ips)} IPs from Data-Shield blocklist...")
    
    # Get or create source "data-shield"
    source_name = "data-shield"
    source_context = "Data-Shield IPv4 Blocklist - Malicious IP addresses blocklist"
    
    # Check if source already exists
    source_id = None
    with db.connection() as conn:
        ody = conn.cursor()
        ody.execute("SELECT id FROM sources WHERE name = ? AND is_deleted = 0 LIMIT 1", (source_name,))
        source_row = ody.fetchone()
        
        if source_row:
            source_id = source_row['id']
            logger.info(f"Using existing source: {source_id}")
    
    if source_id:
        # Delete all existing IOCs from this source before importing new ones
        logger.info(f"Deleting existing IOCs from source {source_id}...")
        with db.connection() as conn:
            ody = conn.cursor()
            try:
                # Delete IOC group associations
                ody.execute("""
                    DELETE FROM ioc_groups 
                    WHERE ioc_id IN (SELECT id FROM iocs WHERE source_id = ?)
                """, (source_id,))
                
                # Delete IOC source group exclusions
                ody.execute("""
                    DELETE FROM ioc_source_group_exclusions 
                    WHERE ioc_id IN (SELECT id FROM iocs WHERE source_id = ?)
                """, (source_id,))
                
                # Delete IOC tags
                ody.execute("""
                    DELETE FROM ioc_tags 
                    WHERE ioc_id IN (SELECT id FROM iocs WHERE source_id = ?)
                """, (source_id,))
                
                # Delete IOCs
                ody.execute("DELETE FROM iocs WHERE source_id = ?", (source_id,))
                deleted_count = ody.rowcount
                logger.info(f"Deleted {deleted_count} existing IOCs from source")
            except Exception as e:
                logger.error(f"Error deleting existing IOCs: {e}")
                raise
    else:
        # Create new source
        source_id = db.create_source(
            name=source_name,
            context=source_context,
            source_type='file_upload',
            file_path=str(data_shield_repo_manager.blocklist_file),
            original_filename="prod_data-shield_ipv4_blocklist.txt"
        )
        logger.info(f"Created new source: {source_id}")
    
    conn.close()
    
    # Get True Positive group
    true_positive_group = db.get_group_by_name("True Positive")
    if not true_positive_group:
        raise ValueError("True Positive group not found. Please ensure the database is properly initialized.")
    
    # Remove source from default group if it exists (using direct SQL query)
    default_group = db.get_group_by_name("default")
    if default_group:
        try:
            with db.connection() as conn:
                ody = conn.cursor()
                ody.execute("""
                    SELECT 1 FROM source_groups 
                    WHERE source_id = ? AND group_id = ?
                """, (source_id, default_group['id']))
                if ody.fetchone():
                    db.remove_source_from_group(source_id, default_group['id'])
                    logger.info("Removed source from default group")
        except Exception as e:
            logger.warning(f"Could not remove source from default group: {e}")
    
    # Add source to True Positive group
    # Note: add_source_to_group() automatically:
    # - Removes from other positive groups (True/False Positive) before adding
    # - Uses INSERT OR IGNORE, so it's safe to call even if already in the group
    db.add_source_to_group(source_id, true_positive_group['id'])
    logger.info("Source added to True Positive group (or already was)")
    
    # Import IPs using batch operations for performance
    from database import get_local_timestamp
    
    local_ts = get_local_timestamp()
    batch_size = 1000
    
    logger.info(f"Importing {len(ips)} IPs using batch operations...")
    
    try:
        with db.connection() as conn:
            ody = conn.cursor()
            
            # Batch insert IOCs using INSERT OR IGNORE
            # Since we deleted all IOCs from this source before, all should insert successfully
            for i in range(0, len(ips), batch_size):
                batch = ips[i:i + batch_size]
                ioc_values = [(source_id, 'ipv4', ip, ip, local_ts, local_ts, local_ts) for ip in batch]
                
                ody.executemany("""
                    INSERT OR IGNORE INTO iocs (source_id, ioc_type, ioc_value, raw_value, first_seen, last_seen, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, ioc_values)
                
                # Commit every batch
                conn.commit()
                
                # Log progress
                if (i + batch_size) % 10000 == 0 or (i + batch_size) >= len(ips):
                    logger.info(f"Processing IPs... ({i + batch_size}/{len(ips)})")
            
            # Get all IOC IDs that were just inserted for this source
            ody.execute("""
                SELECT id FROM iocs 
                WHERE source_id = ? AND ioc_type = 'ipv4'
            """, (source_id,))
            ioc_ids = [row[0] for row in ody.fetchall()]
            imported_count = len(ioc_ids)
            
            # Note: IOCs inherit "True Positive" group from their source (already assigned at line 3738)
            # No need to assign directly to each IOC to avoid duplication
            
            skipped_count = len(ips) - imported_count
    except Exception as e:
        logger.error(f"Error during batch import: {e}")
        raise
    
    logger.info(f"Import completed: {imported_count} imported, {skipped_count} skipped")
    
    return {
        'imported_count': imported_count,
        'skipped_count': skipped_count,
        'total_count': len(ips)
    }

@app.route('/api/data-shield/update', methods=['POST'])
@require_auth
def api_data_shield_update():
    """API: Update repository (deletes cache + old repo + downloads new one) and auto-import IPs"""
    try:
        logger.info("Downloading malicious IPv4 IP list from Data-Shield...")
        
        success = data_shield_repo_manager.update_blocklist()
        
        if not success:
            return api_error("Repository update failed. Please check the logs for details.", 500)
        
        # Automatically import IPs after successful download
        try:
            import_result = _import_data_shield_ips()
            return api_success({
                'message': f'IP list downloaded and {import_result["imported_count"]} IPs imported successfully',
                'imported_count': import_result['imported_count'],
                'skipped_count': import_result['skipped_count'],
                'total_count': import_result['total_count']
            })
        except Exception as import_error:
            logger.warning(f"IP list downloaded but import failed: {import_error}")
            return api_success({
                'message': 'IP list downloaded successfully, but IP import failed. You can import manually.',
                'import_error': str(import_error)
            })
            
    except RuntimeError as e:
        logger.error(f"Error api_data_shield_update: {e}", exc_info=True)
        return api_error(str(e), 500)
    except Exception as e:
        logger.error(f"Error api_data_shield_update: {e}", exc_info=True)
        return api_error(f"Repository update error: {str(e)}", 500)

@app.route('/api/data-shield/import', methods=['POST'])
@require_auth
def api_data_shield_import():
    """API: Import IPs from Data-Shield blocklist"""
    try:
        import_result = _import_data_shield_ips()
        
        return api_success({
            'message': f'Import completed: {import_result["imported_count"]} IPs imported, {import_result["skipped_count"]} skipped',
            'imported_count': import_result['imported_count'],
            'skipped_count': import_result['skipped_count'],
            'total_count': import_result['total_count']
        })
        
    except ValueError as e:
        return api_error(str(e), 400)
    except Exception as e:
        logger.error(f"api_data_shield_import error: {e}", exc_info=True)
        return api_error(str(e), 500)

# ========== ERROR HANDLERS ==========

# ========== ERROR HANDLERS ==========

@app.errorhandler(413)
def request_entity_too_large(error):
    return api_error('File too large', 413)

@app.errorhandler(400)
def bad_request(error):
    # Silently handle HTTPS connection attempts to HTTP server
    # These are common from bots/scanners and don't need to be logged
    try:
        request_data = request.get_data()
        if request_data and len(request_data) >= 2:
            # Check if it's a TLS handshake (starts with 0x16 0x03)
            if request_data[0] == 0x16 and request_data[1] == 0x03:
                # This is a TLS/HTTPS handshake attempt, silently ignore
                return '', 400
    except Exception:
        # Ignore errors when checking request data for TLS handshakes
        pass
    # For other 400 errors, return normal error response
    return api_error('Bad request', 400)

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    logger.error(f"Internal error: {error}", exc_info=True)
    return api_error('Internal server error', 500)

# ========== MAIN ==========

if __name__ == '__main__':
    logger.info(f"Starting Odysafe CTI Platform application on {HOST}:{PORT}")
    logger.info(f"iocsearcher available: {IOCSEARCHER_AVAILABLE}")
    
    # Check SSL configuration
    ssl_context = None
    if USE_SSL:
        if SSL_CERT_FILE.exists() and SSL_KEY_FILE.exists():
            ssl_context = (str(SSL_CERT_FILE), str(SSL_KEY_FILE))
            logger.info(f"SSL enabled - Certificate: {SSL_CERT_FILE}")
            logger.info(f"Interface accessible at: https://0.0.0.0:{PORT} or https://localhost:{PORT}")
            logger.info("IMPORTANT: Use HTTPS in your browser (https://localhost:5001)")
            logger.info("HTTP connections are not supported when SSL is enabled")
        else:
            logger.error(f"SSL enabled but certificates not found!")
            logger.error(f"Certificate file: {SSL_CERT_FILE} (exists: {SSL_CERT_FILE.exists()})")
            logger.error(f"Key file: {SSL_KEY_FILE} (exists: {SSL_KEY_FILE.exists()})")
            logger.error("Cannot start with SSL enabled without certificates.")
            logger.error("Generate certificates with: scripts/generate-ssl-cert.sh")
            logger.error("Or disable SSL by setting CTI_USE_SSL=false")
            exit(1)
    else:
        logger.warning("SSL is disabled. For security, SSL should be enabled in production.")
        logger.info(f"Interface accessible at: http://0.0.0.0:{PORT} or http://localhost:{PORT}")
        logger.info("To enable SSL, set CTI_USE_SSL=true and ensure certificates exist")
    
    # Enable SO_REUSEADDR to allow immediate port reuse on restart
    # This prevents "Address already in use" errors when restarting the service
    # We patch socket.socket to always enable SO_REUSEADDR for new sockets
    original_socket = socket.socket
    
    class SocketWithReuseAddr(original_socket):
        """Socket class that automatically enables SO_REUSEADDR"""
        def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
            super().__init__(family, type, proto, fileno)
            # Enable SO_REUSEADDR for all new sockets
            try:
                self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except (OSError, AttributeError):
                # If setsockopt fails (e.g., socket already closed), continue anyway
                pass
    
    # Temporarily replace socket.socket with our version
    socket.socket = SocketWithReuseAddr
    
    try:
        # Use run_simple which will now create sockets with SO_REUSEADDR enabled
        run_simple(
            hostname=HOST,
            port=PORT,
            application=app,
            use_reloader=False,  # Disable reloader in production
            use_debugger=DEBUG,
            ssl_context=ssl_context,
            threaded=True
        )
    finally:
        # Restore original socket class
        socket.socket = original_socket
















