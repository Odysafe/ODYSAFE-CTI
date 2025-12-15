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

GitHub repository management module for Ransomware-Tool-Matrix
Retrieves and parses markdown files from the repository via local git clone
"""
import os
import json
import logging
import re
import subprocess
import shutil
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from markdown import markdown
from bs4 import BeautifulSoup
from .download_lock import download_lock

logger = logging.getLogger(__name__)

# Repository configuration
GITHUB_REPO_URL = "https://github.com/BushidoUK/Ransomware-Tool-Matrix.git"
REPO_DIR = Path(__file__).parent / "Ransomware-Tool-Matrix-main"

# Cache configuration
CACHE_DIR = Path(__file__).parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)
CACHE_FILE = CACHE_DIR / "rtm_cache.json"
CATEGORIES_CACHE_FILE = CACHE_DIR / "rtm_categories_cache.json"
FAVORITES_FILE = CACHE_DIR / "rtm_favorites.json"


class RTMRepoManager:
    """GitHub repository manager for Ransomware-Tool-Matrix via local git clone"""
    
    def __init__(self):
        self.repo_dir = REPO_DIR
        self.favorites = self._load_favorites()
    
    def repo_exists(self) -> bool:
        """Checks if the repository exists"""
        return self.repo_dir.exists() and (self.repo_dir / ".git").exists()
    
    def download_repo(self) -> bool:
        """Downloads the repository (removes old one if it exists)"""
        temp_clone_dir = None
        try:
            # Acquire download lock to prevent simultaneous downloads
            with download_lock("rtm", timeout=300):
                # Check that git is installed
                try:
                    subprocess.run(['git', '--version'], capture_output=True, check=True, timeout=5)
                except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                    logger.error("Git is not installed")
                    return False
                
                # Create parent directory if necessary
                self.repo_dir.parent.mkdir(parents=True, exist_ok=True)
                
                # Remove old directory if it exists
                if self.repo_dir.exists():
                    logger.info("Removing old repository...")
                    shutil.rmtree(self.repo_dir, ignore_errors=True)
                
                # Create temporary directory for clone
                temp_clone_dir = self.repo_dir.parent / "Ransomware-Tool-Matrix_temp"
                if temp_clone_dir.exists():
                    shutil.rmtree(temp_clone_dir, ignore_errors=True)
                
                logger.info(f"Cloning repository to {temp_clone_dir}...")
                result = subprocess.run(
                    ['git', 'clone', GITHUB_REPO_URL, str(temp_clone_dir)],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.returncode != 0:
                    logger.error(f"Clone error: {result.stderr}")
                    return False
                
                # Rename cloned directory
                if self.repo_dir.exists():
                    shutil.rmtree(self.repo_dir, ignore_errors=True)
                temp_clone_dir.rename(self.repo_dir)
                temp_clone_dir = None  # Prevent cleanup after successful rename
                
                logger.info(f"Repository cloned successfully to {self.repo_dir}")
                
                # Update last_update timestamp
                last_update = datetime.now().isoformat()
                try:
                    if CATEGORIES_CACHE_FILE.exists():
                        with open(CATEGORIES_CACHE_FILE, 'r', encoding='utf-8') as f:
                            cache_data = json.load(f)
                    else:
                        cache_data = {}
                    
                    cache_data['last_update'] = last_update
                    cache_data['cached_at'] = datetime.now().isoformat()
                    
                    with open(CATEGORIES_CACHE_FILE, 'w', encoding='utf-8') as f:
                        json.dump(cache_data, f, indent=2, ensure_ascii=False)
                    logger.info(f"Repository download timestamp saved: {last_update}")
                except Exception as e:
                    logger.warning(f"Error saving last_update: {e}")
                
                return True
        except RuntimeError as e:
            # Lock timeout or other runtime errors
            logger.error(f"Download lock error: {e}")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Timeout during clone")
            return False
        except Exception as e:
            logger.error(f"Cloning error: {e}")
            return False
        finally:
            # Cleanup temporary directory if it still exists
            if temp_clone_dir and temp_clone_dir.exists():
                try:
                    shutil.rmtree(temp_clone_dir, ignore_errors=True)
                    logger.debug(f"Cleaned up temporary clone directory: {temp_clone_dir}")
                except Exception as e:
                    logger.warning(f"Error cleaning up temporary directory {temp_clone_dir}: {e}")
    
    def update_repo(self) -> bool:
        """Updates the repository: deletes cache + old repo + downloads new one"""
        try:
            # Check that git is installed
            try:
                subprocess.run(['git', '--version'], capture_output=True, check=True, timeout=5)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                error_msg = "Git is not installed. Please install git to update the repository."
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            # Delete cache
            if CACHE_FILE.exists():
                try:
                    CACHE_FILE.unlink()
                    logger.info("Cache deleted")
                except Exception as e:
                    logger.warning(f"Unable to delete cache: {e}")
            
            # Delete categories cache
            if CATEGORIES_CACHE_FILE.exists():
                try:
                    CATEGORIES_CACHE_FILE.unlink()
                    logger.info("Categories cache deleted")
                except Exception as e:
                    logger.warning(f"Unable to delete categories cache: {e}")
            
            # Remove old repository
            if self.repo_dir.exists():
                logger.info("Removing old repository...")
                shutil.rmtree(self.repo_dir, ignore_errors=True)
            
            # Download new repository
            success = self.download_repo()
            if not success:
                raise RuntimeError("Failed to download repository. Check your internet connection and try again.")
            
            return True
        except RuntimeError as e:
            logger.error(f"Update error: {e}")
            raise
        except Exception as e:
            error_msg = f"Unexpected error during update: {str(e)}"
            logger.error(f"Update error: {error_msg}", exc_info=True)
            raise RuntimeError(error_msg)
    
    def _load_favorites(self) -> set:
        """Loads the list of favorites (URLs)"""
        if FAVORITES_FILE.exists():
            try:
                with open(FAVORITES_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return set(data) if isinstance(data, list) else set()
            except Exception as e:
                logger.warning(f"Error loading favorites: {e}")
        return set()
    
    def _save_favorites(self):
        """Saves the list of favorites"""
        try:
            with open(FAVORITES_FILE, 'w', encoding='utf-8') as f:
                json.dump(list(self.favorites), f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving favorites: {e}")
    
    def toggle_favorite(self, url: str) -> bool:
        """Adds or removes a source from favorites. Returns True if added, False if removed"""
        try:
            if url in self.favorites:
                self.favorites.remove(url)
                self._save_favorites()
                logger.info(f"Favorite removed: {url}")
                return False
            else:
                self.favorites.add(url)
                self._save_favorites()
                logger.info(f"Favorite added: {url}")
                return True
        except Exception as e:
            logger.error(f"Error toggling favorite: {e}")
            return False
    
    def is_favorite(self, url: str) -> bool:
        """Checks if a URL is in favorites"""
        return url in self.favorites
    
    def _parse_markdown_table(self, content: str) -> List[Dict]:
        """Parses markdown tables from content"""
        entries = []
        lines = content.split('\n')
        
        table_lines = []
        in_table = False
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('|') and '|' in line[1:]:
                # Skip separator lines
                if re.match(r'^\|\s*[-:]+\s*\|', line):
                    continue
                
                in_table = True
                table_lines.append(line)
            elif in_table and not line.startswith('|'):
                break
        
        if len(table_lines) < 2:
            return entries
        
        # Parse header
        header_line = table_lines[0]
        headers = [cell.strip() for cell in header_line.split('|')[1:-1]]
        
        # Parse data rows
        for row_line in table_lines[1:]:
            cells = [cell.strip() for cell in row_line.split('|')[1:-1]]
            if len(cells) != len(headers):
                continue
            
            entry = {}
            for i, header in enumerate(headers):
                if i < len(cells):
                    entry[header] = cells[i]
            entries.append(entry)
        
        return entries
    
    def fetch_tools(self) -> Dict[str, Dict]:
        """Fetches and parses all tool files from Tools/ directory"""
        tools = {}
        
        if not self.repo_exists():
            return tools
        
        tools_dir = self.repo_dir / "Tools"
        if not tools_dir.exists():
            logger.warning("Tools directory not found")
            return tools
        
        # List of tool files to parse
        tool_files = [
            'RMM-Tools.md',
            'Exfiltration.md',
            'CredentialTheft.md',
            'DefenseEvasion.md',
            'Networking.md',
            'DiscoveryEnum.md',
            'Offsec.md',
            'LOLBAS.md'
        ]
        
        for tool_file in tool_files:
            file_path = tools_dir / tool_file
            if not file_path.exists():
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Extract title (first ## heading)
                title_match = re.search(r'^##\s+(.+)$', content, re.MULTILINE)
                title = title_match.group(1) if title_match else tool_file.replace('.md', '')
                
                # Extract tip/important blocks
                tip_match = re.search(r'>\s*\[!TIP\](.*?)(?=>|$)', content, re.DOTALL)
                tip = tip_match.group(1).strip() if tip_match else None
                
                important_match = re.search(r'>\s*\[!IMPORTANT\](.*?)(?=>|$)', content, re.DOTALL)
                important = important_match.group(1).strip() if important_match else None
                
                # Parse table
                entries = self._parse_markdown_table(content)
                
                # Process entries to extract tool names and threat groups
                tool_entries = []
                for entry in entries:
                    tool_name = entry.get('Tool Name', '').strip()
                    threat_groups = entry.get('Threat Group Usage', '').strip()
                    
                    if tool_name:
                        # Split threat groups by comma
                        groups = [g.strip() for g in threat_groups.split(',') if g.strip()]
                        tool_entries.append({
                            'tool_name': tool_name,
                            'threat_groups': groups,
                            'threat_groups_count': len(groups)
                        })
                
                tools[tool_file.replace('.md', '')] = {
                    'title': title,
                    'tip': tip,
                    'important': important,
                    'tools': tool_entries,
                    'tools_count': len(tool_entries)
                }
                
            except Exception as e:
                logger.error(f"Error parsing {tool_file}: {e}")
                continue
        
        return tools
    
    def fetch_threat_intel(self) -> Dict[str, Dict]:
        """Fetches and parses all threat intel files from ThreatIntel/ directory"""
        threat_intel = {}
        
        if not self.repo_exists():
            return threat_intel
        
        threat_intel_dir = self.repo_dir / "ThreatIntel"
        if not threat_intel_dir.exists():
            logger.warning("ThreatIntel directory not found")
            return threat_intel
        
        # List of threat intel files
        intel_files = [
            'CISAThreatGroups.md',
            'TheDFIRReportGroups.md',
            'TrendMicroThreatGroups.md',
            'ExtraThreatIntel.md'
        ]
        
        for intel_file in intel_files:
            file_path = threat_intel_dir / intel_file
            if not file_path.exists():
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Extract title
                title_match = re.search(r'^##\s+(.+)$', content, re.MULTILINE)
                title = title_match.group(1) if title_match else intel_file.replace('.md', '')
                
                # Extract important block
                important_match = re.search(r'>\s*\[!IMPORTANT\](.*?)(?=>|$)', content, re.DOTALL)
                important = important_match.group(1).strip() if important_match else None
                
                # Parse table
                entries = self._parse_markdown_table(content)
                
                # Process entries
                intel_entries = []
                for entry in entries:
                    # Extract links from cells
                    processed_entry = {}
                    for key, value in entry.items():
                        # Extract markdown links [text](url)
                        links = re.findall(r'\[([^\]]+)\]\(([^\)]+)\)', value)
                        if links:
                            # Replace markdown links with HTML links in text
                            text_with_links = value
                            for link_text, link_url in links:
                                text_with_links = text_with_links.replace(f'[{link_text}]({link_url})', link_text)
                            processed_entry[key] = {
                                'text': text_with_links,
                                'links': [{'text': link[0], 'url': link[1]} for link in links]
                            }
                        else:
                            processed_entry[key] = value
                    intel_entries.append(processed_entry)
                
                threat_intel[intel_file.replace('.md', '')] = {
                    'title': title,
                    'important': important,
                    'entries': intel_entries,
                    'entries_count': len(intel_entries)
                }
                
            except Exception as e:
                logger.error(f"Error parsing {intel_file}: {e}")
                continue
        
        return threat_intel
    
    def fetch_group_profiles(self) -> List[Dict]:
        """Fetches list of group profiles from GroupProfiles/ directory"""
        profiles = []
        
        if not self.repo_exists():
            return profiles
        
        profiles_dir = self.repo_dir / "GroupProfiles"
        if not profiles_dir.exists():
            logger.warning("GroupProfiles directory not found")
            return profiles
        
        for profile_file in sorted(profiles_dir.glob('*.md')):
            try:
                with open(profile_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Extract title (first # heading)
                title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
                title = title_match.group(1) if title_match else profile_file.stem
                
                # Extract table if present
                entries = self._parse_markdown_table(content)
                
                # Extract sources section
                sources_match = re.search(r'####\s+Sources\s*\n(.*?)(?=####|$)', content, re.DOTALL)
                sources = []
                if sources_match:
                    sources_table = self._parse_markdown_table(sources_match.group(1))
                    sources = sources_table
                
                profiles.append({
                    'filename': profile_file.name,
                    'title': title,
                    'tools_table': entries,
                    'sources': sources,
                    'content_preview': content[:500]  # First 500 chars for preview
                })
                
            except Exception as e:
                logger.error(f"Error parsing {profile_file}: {e}")
                continue
        
        return profiles
    
    def _month_to_number(self, month_str: str) -> int:
        """Convert month string (JAN, January, etc.) to number (1-12)"""
        if not month_str:
            return 0
        
        month_str = month_str.upper()
        month_map = {
            'JAN': 1, 'JANUARY': 1,
            'FEB': 2, 'FEBRUARY': 2,
            'MAR': 3, 'MARCH': 3,
            'APR': 4, 'APRIL': 4,
            'MAY': 5,
            'JUN': 6, 'JUNE': 6,
            'JUL': 7, 'JULY': 7,
            'AUG': 8, 'AUGUST': 8,
            'SEP': 9, 'SEPT': 9, 'SEPTEMBER': 9,
            'OCT': 10, 'OCTOBER': 10,
            'NOV': 11, 'NOVEMBER': 11,
            'DEC': 12, 'DECEMBER': 12
        }
        return month_map.get(month_str, 0)
    
    def fetch_community_reports(self) -> List[Dict]:
        """Fetches list of community reports from CommunityReports/ directory"""
        reports = []
        
        if not self.repo_exists():
            return reports
        
        reports_dir = self.repo_dir / "CommunityReports"
        if not reports_dir.exists():
            logger.warning("CommunityReports directory not found")
            return reports
        
        for report_file in sorted(reports_dir.glob('*.md')):
            # Skip template
            if 'Template' in report_file.name:
                continue
            
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Extract title (first # heading)
                title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
                title = title_match.group(1) if title_match else report_file.stem
                
                # Extract metadata from filename (format: CR-XXX-GROUP-MON-YYYY.md)
                filename_parts = report_file.stem.split('-')
                # report_id is "CR-XXX", so combine first two parts
                if len(filename_parts) >= 2:
                    report_id = f"{filename_parts[0]}-{filename_parts[1]}"
                else:
                    report_id = filename_parts[0] if len(filename_parts) > 0 else ''
                group_name = filename_parts[2] if len(filename_parts) > 2 else ''
                month = filename_parts[3] if len(filename_parts) > 3 else ''
                year = filename_parts[4] if len(filename_parts) > 4 else ''
                
                # Convert month to number for proper sorting
                month_num = self._month_to_number(month)
                
                reports.append({
                    'filename': report_file.name,
                    'report_id': report_id,
                    'group_name': group_name,
                    'month': month,
                    'month_num': month_num,
                    'year': year,
                    'title': title,
                    'content_preview': content[:500],  # First 500 chars for preview
                    'full_content': content  # Full content for display
                })
                
            except Exception as e:
                logger.error(f"Error parsing {report_file}: {e}")
                continue
        
        # Sort by year (descending), then by month number (descending), then by report_id number (descending)
        def get_report_number(report_id):
            """Extract numeric part from report_id (e.g., 'CR-001' -> 1)"""
            if not report_id:
                return 0
            # Remove 'CR-' prefix and extract number
            try:
                num_str = report_id.replace('CR-', '').strip()
                return int(num_str) if num_str.isdigit() else 0
            except (ValueError, AttributeError):
                return 0
        
        return sorted(reports, key=lambda x: (
            int(x.get('year', '0') or '0'),
            x.get('month_num', 0),
            get_report_number(x.get('report_id', ''))
        ), reverse=True)
    
    def get_category_info(self) -> Dict:
        """Returns category information including last_update"""
        info = {
            'last_update': None,
            'cached_at': None
        }
        
        if CATEGORIES_CACHE_FILE.exists():
            try:
                with open(CATEGORIES_CACHE_FILE, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                    info['last_update'] = cache_data.get('last_update')
                    info['cached_at'] = cache_data.get('cached_at')
            except Exception as e:
                logger.warning(f"Error loading category info: {e}")
        
        return info


# Global instance
rtm_repo_manager = RTMRepoManager()

