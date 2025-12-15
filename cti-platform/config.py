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

CTI Platform application configuration
"""
import os
from pathlib import Path

# Application base directory
BASE_DIR = Path(__file__).parent

# Storage folders
UPLOAD_FOLDER = BASE_DIR / "uploads"
OUTPUT_FOLDER = BASE_DIR / "outputs"

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'txt', 'html', 'htm', 'docx', 'doc',
    'csv', 'json', 'log', 'xml', 'md'
}

# Allowed MIME types (for additional security validation)
ALLOWED_MIME_TYPES = {
    'text/plain',
    'text/html',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # .docx
    'application/msword',  # .doc
    'text/csv',
    'application/json',
    'text/xml',
    'application/xml',
    'text/markdown',
    'application/octet-stream'  # For some log files
}

# Maximum file size (100 MB)
MAX_FILE_SIZE = 100 * 1024 * 1024

# Days before automatic cleanup of temporary files
CLEANUP_DAYS = 7

# Server configuration
HOST = os.getenv('CTI_HOST', '0.0.0.0')  # Listen on all interfaces
PORT = int(os.getenv('CTI_PORT', '5001'))

# SSL/TLS configuration
SSL_DIR = BASE_DIR / "ssl"
SSL_CERT_FILE = SSL_DIR / "cert.pem"
SSL_KEY_FILE = SSL_DIR / "key.pem"
# SSL can be disabled via environment variable (useful for development or reverse proxy setups)
USE_SSL = os.getenv('CTI_USE_SSL', 'true').lower() == 'true'  # Enable SSL by default
# Auto-disable SSL if certificates don't exist (graceful degradation)
if USE_SSL and (not SSL_CERT_FILE.exists() or not SSL_KEY_FILE.exists()):
    import warnings
    warnings.warn(
        "SSL enabled but certificates not found. Disabling SSL. "
        "Generate certificates with: scripts/generate-ssl-cert.sh",
        UserWarning
    )
    USE_SSL = False

# Flask secret key
# WARNING: In production, set CTI_SECRET_KEY environment variable with a strong random key
# Generate a secure key with: python -c "import secrets; print(secrets.token_hex(32))"
# Default value is for development only and should NEVER be used in production
SECRET_KEY = os.getenv('CTI_SECRET_KEY', None)
if SECRET_KEY is None:
    import secrets
    import warnings
    SECRET_KEY = secrets.token_hex(32)
    warnings.warn(
        "Using auto-generated SECRET_KEY. Set CTI_SECRET_KEY environment variable in production!",
        UserWarning
    )

# Debug mode
# WARNING: Debug mode should be disabled in production for security reasons
# Set CTI_DEBUG=true only for development/testing
DEBUG = os.getenv('CTI_DEBUG', 'false').lower() == 'true'

# Database path
DATABASE_PATH = BASE_DIR / "database" / "cti_platform.db"

# Predefined tags
PREDEFINED_TAGS = [
    # TLP tags
    {"name": "TLP:RED", "category": "tlp", "color": "#DC2626", "auto": False},
    {"name": "TLP:AMBER", "category": "tlp", "color": "#F59E0B", "auto": False},
    {"name": "TLP:GREEN", "category": "tlp", "color": "#10B981", "auto": False},
    {"name": "TLP:WHITE", "category": "tlp", "color": "#6B7280", "auto": False},
    {"name": "TLP:CLEAR", "category": "tlp", "color": "#9CA3AF", "auto": False},
    
    # Attack tags
    {"name": "Brute Force", "category": "attack_type", "color": "#EF4444", "auto": False},
    {"name": "Phishing", "category": "attack_type", "color": "#F97316", "auto": False},
    {"name": "Malware", "category": "attack_type", "color": "#8B5CF6", "auto": False},
    {"name": "C2 Server", "category": "attack_type", "color": "#EC4899", "auto": False},
    {"name": "APT Group", "category": "attack_type", "color": "#6366F1", "auto": False},
    
    # Status tags
    {"name": "False Positive", "category": "status", "color": "#6B7280", "auto": False},
    {"name": "Verified", "category": "status", "color": "#10B981", "auto": False},
    {"name": "Under Investigation", "category": "status", "color": "#F59E0B", "auto": False},
]

# Mapping of IOC types to automatic tag names
IOC_TYPE_TAGS = {
    "ipv4": "Type:IPv4",
    "ipv6": "Type:IPv6",
    "domain": "Type:Domain",
    "fqdn": "Type:FQDN",
    "url": "Type:URL",
    "email": "Type:Email",
    "md5": "Type:MD5",
    "sha1": "Type:SHA1",
    "sha256": "Type:SHA256",
    "sha512": "Type:SHA512",
    "cve": "Type:CVE",
    "file_path": "Type:File Path",
    "file_name": "Type:File Name",
    "mutex": "Type:Mutex",
    "registry": "Type:Registry",
    "user_agent": "Type:User Agent",
    "bitcoin": "Type:Bitcoin",
    "ethereum": "Type:Ethereum",
    "tor": "Type:TOR",
    "mac_address": "Type:MAC Address",
    "asn": "Type:ASN",
    "subnet": "Type:Subnet",
}

# Mapping of source types to automatic tag names
SOURCE_TYPE_TAGS = {
    "file": "Source:File",
    "url": "Source:URL",
    "paste": "Source:Paste",
    "upload": "Source:Upload",
}

# Create necessary folders if they don't exist
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
(OUTPUT_FOLDER / "iocs").mkdir(parents=True, exist_ok=True)
(OUTPUT_FOLDER / "stix").mkdir(parents=True, exist_ok=True)
(OUTPUT_FOLDER / "reports").mkdir(parents=True, exist_ok=True)
(DATABASE_PATH.parent).mkdir(parents=True, exist_ok=True)






