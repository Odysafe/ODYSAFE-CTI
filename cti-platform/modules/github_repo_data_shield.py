"""
Odysafe CTI Platform
Copyright (C) 2026 ODYSAFE CTI Project

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

Data-Shield IPv4 Blocklist management module
Downloads and parses IP addresses from the blocklist file directly
"""
import os
import json
import logging
import re
import tempfile
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Blocklist file URL (raw GitHub)
BLOCKLIST_URL = "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/main/prod_data-shield_ipv4_blocklist.txt"

# File storage configuration
CACHE_DIR = Path(__file__).parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)
CACHE_FILE = CACHE_DIR / "data_shield_cache.json"
BLOCKLIST_DIR = Path(__file__).parent / "data_shield"
BLOCKLIST_DIR.mkdir(exist_ok=True)
BLOCKLIST_FILE = BLOCKLIST_DIR / "prod_data-shield_ipv4_blocklist.txt"


class DataShieldRepoManager:
    """Manager for Data-Shield IPv4 Blocklist file download"""
    
    def __init__(self):
        self.blocklist_file = BLOCKLIST_FILE
    
    def blocklist_file_exists(self) -> bool:
        """Checks if the blocklist file exists"""
        return self.blocklist_file.exists() and self.blocklist_file.is_file()
    
    def download_blocklist(self) -> bool:
        """Download and validate the new snapshot before replacing the local file."""
        pending = None
        try:
            with requests.get(BLOCKLIST_URL, timeout=(10, 30), stream=True,
                              headers={'User-Agent': 'ODYSAFE CTI'}) as response:
                response.raise_for_status()
                with tempfile.NamedTemporaryFile(dir=self.blocklist_file.parent, delete=False) as target:
                    pending = Path(target.name)
                    for chunk in response.iter_content(chunk_size=65536):
                        if target.tell() + len(chunk) > 50 * 1024 * 1024:
                            raise ValueError('Data-Shield list exceeds 50 MiB.')
                        target.write(chunk)
                with pending.open(encoding='utf-8') as saved:
                    if not any(self._is_valid_ipv4(line.strip()) for line in saved):
                        raise ValueError('Data-Shield file contains no IPv4 addresses.')
                pending.replace(self.blocklist_file)

            logger.info(f"Malicious IPv4 IP list downloaded successfully. Thanks to Data-Shield for providing this blocklist!")
            
            # Update last_update timestamp
            last_update = datetime.now().isoformat()
            try:
                cache_data = {
                    'last_update': last_update,
                    'cached_at': datetime.now().isoformat()
                }
                with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, indent=2, ensure_ascii=False)
                logger.info(f"Blocklist download timestamp saved: {last_update}")
            except Exception as e:
                logger.warning(f"Error saving last_update: {e}")
            
            return True
        except requests.RequestException as e:
            logger.error(f"Download error: {e}")
            return False
        except Exception as e:
            logger.error(f"Error downloading blocklist: {e}")
            return False
        finally:
            if pending is not None:
                pending.unlink(missing_ok=True)
    
    def update_blocklist(self) -> bool:
        """Refresh the snapshot, keeping the previous copy on failure."""
        if not self.download_blocklist():
            raise RuntimeError("Failed to download blocklist. Please check your internet connection and try again.")
        return True

    def get_status(self) -> Dict:
        """Returns status information about the blocklist"""
        blocklist_exists = self.blocklist_file_exists()
        
        # Get last_update from cache if available
        last_update = None
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                    if 'last_update' in cache_data:
                        last_update = cache_data['last_update']
            except Exception:
                pass
        
        # If not in cache but file exists, use file modification time
        if not last_update and blocklist_exists and self.blocklist_file.exists():
            try:
                file_mtime = self.blocklist_file.stat().st_mtime
                last_update = datetime.fromtimestamp(file_mtime).isoformat()
                # Save it to cache for future use
                try:
                    cache_data = {
                        'last_update': last_update,
                        'cached_at': datetime.now().isoformat()
                    }
                    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                        json.dump(cache_data, f, indent=2, ensure_ascii=False)
                except Exception:
                    pass
            except Exception:
                pass
        
        # Count IPs in blocklist file if it exists
        ip_count = 0
        if blocklist_exists:
            try:
                with open(self.blocklist_file, 'r', encoding='utf-8') as f:
                    ip_count = sum(1 for line in f if line.strip())
            except Exception as e:
                logger.warning(f"Error counting IPs: {e}")
        
        return {
            'repo_exists': blocklist_exists,  # Keep for compatibility
            'blocklist_exists': blocklist_exists,
            'last_update': last_update,
            'ip_count': ip_count,
            'blocklist_file_path': str(self.blocklist_file) if blocklist_exists else None
        }
    
    def get_blocklist_ips(self) -> List[str]:
        """Returns list of IPs from the blocklist file"""
        if not self.blocklist_file_exists():
            return []
        
        ips = []
        try:
            with open(self.blocklist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    ip = line.strip()
                    if ip and self._is_valid_ipv4(ip):
                        ips.append(ip)
        except Exception as e:
            logger.error(f"Error reading blocklist file: {e}")
        
        return ips
    
    def _is_valid_ipv4(self, ip: str) -> bool:
        """Validates IPv4 address format"""
        pattern = r'^([0-9]{1,3}\.){3}[0-9]{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        parts = ip.split('.')
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    # Compatibility methods (for backward compatibility)
    def repo_exists(self) -> bool:
        """Checks if the blocklist file exists (for compatibility)"""
        return self.blocklist_file_exists()
    
    def download_repo(self) -> bool:
        """Downloads the blocklist (for compatibility)"""
        return self.download_blocklist()
    
    def update_repo(self) -> bool:
        """Updates the blocklist (for compatibility)"""
        return self.update_blocklist()


# Global instance
data_shield_repo_manager = DataShieldRepoManager()

