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

Storage monitoring module
"""
import os
import shutil
from pathlib import Path
from typing import Dict
from config import UPLOAD_FOLDER, DATABASE_PATH, OUTPUT_FOLDER


def format_bytes(bytes_value: int) -> str:
    """Formats bytes to readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def get_directory_size(directory: Path) -> int:
    """Calculates total size of a directory in bytes"""
    total_size = 0
    try:
        if directory.exists() and directory.is_dir():
            for dirpath, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = Path(dirpath) / filename
                    try:
                        total_size += filepath.stat().st_size
                    except (OSError, FileNotFoundError):
                        pass
    except (OSError, PermissionError):
        pass
    return total_size


def get_file_size(file_path: Path) -> int:
    """Calculates file size in bytes"""
    try:
        if file_path.exists() and file_path.is_file():
            return file_path.stat().st_size
    except (OSError, FileNotFoundError):
        pass
    return 0


def get_storage_info() -> Dict:
    """
    Retrieves storage information from server and application
    
    Returns:
        Dict containing:
        - total: Total disk space (bytes)
        - used: Used space (bytes)
        - free: Free space (bytes)
        - percent_used: Percentage of space used
        - app_usage: Application usage details
            - uploads: Uploads folder size
            - database: Database size
            - outputs: Outputs folder size
            - total_app: Total used by application
    """
    # Get system disk space
    # Use application root directory as reference
    root_path = Path(UPLOAD_FOLDER).resolve()
    # Find filesystem root
    while root_path != root_path.parent and not os.path.ismount(str(root_path)):
        root_path = root_path.parent
    # If we reach absolute root, use '/'
    if root_path == Path('/'):
        root_path = Path('/')
    else:
        # Otherwise, use mount point
        root_path = Path('/')
    
    disk_usage = shutil.disk_usage(str(root_path))
    
    total = disk_usage.total
    used = disk_usage.used
    free = disk_usage.free
    percent_used = (used / total) * 100 if total > 0 else 0
    
    # Calculate application usage
    uploads_size = get_directory_size(Path(UPLOAD_FOLDER))
    database_size = get_file_size(Path(DATABASE_PATH))
    outputs_size = get_directory_size(Path(OUTPUT_FOLDER))
    total_app = uploads_size + database_size + outputs_size
    
    return {
        'total': total,
        'used': used,
        'free': free,
        'percent_used': round(percent_used, 2),
        'app_usage': {
            'uploads': uploads_size,
            'database': database_size,
            'outputs': outputs_size,
            'total_app': total_app
        },
        'formatted': {
            'total': format_bytes(total),
            'used': format_bytes(used),
            'free': format_bytes(free),
            'uploads': format_bytes(uploads_size),
            'database': format_bytes(database_size),
            'outputs': format_bytes(outputs_size),
            'total_app': format_bytes(total_app)
        }
    }

