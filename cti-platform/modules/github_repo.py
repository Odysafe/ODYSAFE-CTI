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

GitHub repository management module for deepdarkCTI
Retrieves and parses markdown files from the repository via local git clone
Simplified version
"""
import os
import json
import logging
import re
import subprocess
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from markdown import markdown
from bs4 import BeautifulSoup
from .download_lock import download_lock

logger = logging.getLogger(__name__)

# Repository configuration
GITHUB_REPO_URL = "https://github.com/fastfire/deepdarkCTI.git"
REPO_DIR = Path(__file__).parent / "deepdarkCTI-main"

# Cache configuration
CACHE_DIR = Path(__file__).parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)
CACHE_FILE = CACHE_DIR / "deepdarkcti_cache.json"
DELETED_SOURCES_FILE = CACHE_DIR / "deepdarkcti_deleted_sources.json"
MANUAL_SOURCES_FILE = CACHE_DIR / "deepdarkcti_manual_sources.json"
FAVORITES_FILE = CACHE_DIR / "deepdarkcti_favorites.json"
CATEGORIES_CACHE_FILE = CACHE_DIR / "deepdarkcti_categories_cache.json"


class GitHubRepoManager:
    """GitHub repository manager for deepdarkCTI via local git clone"""
    
    def __init__(self):
        self.repo_dir = REPO_DIR
        self.deleted_sources = self._load_deleted_sources()
        self.manual_sources = self._load_manual_sources()
        self.favorites = self._load_favorites()
    
    def repo_exists(self) -> bool:
        """Checks if the repository exists"""
        return self.repo_dir.exists() and (self.repo_dir / ".git").exists()
    
    def download_repo(self) -> bool:
        """Downloads the repository (removes old one if it exists)"""
        temp_clone_dir = None
        try:
            # Acquire download lock to prevent simultaneous downloads
            with download_lock("deepdarkcti", timeout=300):
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
                temp_clone_dir = self.repo_dir.parent / "deepdarkCTI_temp"
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
                
                # Rename cloned directory to deepdarkCTI-main
                if self.repo_dir.exists():
                    shutil.rmtree(self.repo_dir, ignore_errors=True)
                temp_clone_dir.rename(self.repo_dir)
                temp_clone_dir = None  # Prevent cleanup after successful rename
                
                logger.info(f"Repository cloned successfully to {self.repo_dir}")
                
                # Update last_update timestamp after successful download
                # This represents when the repository was last downloaded
                last_update = datetime.now().isoformat()
                # Save last_update to cache (create or update)
                try:
                    if CATEGORIES_CACHE_FILE.exists():
                        with open(CATEGORIES_CACHE_FILE, 'r', encoding='utf-8') as f:
                            cache_data = json.load(f)
                    else:
                        cache_data = {'categories': {}}
                    
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
        """Updates the repository: deletes cache + old repo + deleted sources + downloads new one"""
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
            
            # Delete deleted sources file (start fresh)
            if DELETED_SOURCES_FILE.exists():
                try:
                    DELETED_SOURCES_FILE.unlink()
                    logger.info("Deleted sources file removed (starting fresh)")
                    # Reset list in memory
                    self.deleted_sources = {}
                except Exception as e:
                    logger.warning(f"Unable to delete deleted sources file: {e}")
            
            # Remove old repository
            if self.repo_dir.exists():
                logger.info("Removing old repository...")
                shutil.rmtree(self.repo_dir, ignore_errors=True)
            
            # Download new repository
            success = self.download_repo()
            if not success:
                raise RuntimeError("Failed to download repository. Check your internet connection and try again.")
            
            # Update last_update timestamp after successful download
            # This represents when the repository was last downloaded
            last_update = datetime.now().isoformat()
            # Create cache file with last_update
            try:
                cache_data = {
                    'last_update': last_update,
                    'categories': {},
                    'cached_at': datetime.now().isoformat()
                }
                with open(CATEGORIES_CACHE_FILE, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, indent=2, ensure_ascii=False)
                logger.info(f"Repository download timestamp saved: {last_update}")
            except Exception as e:
                logger.warning(f"Error saving last_update: {e}")
            
            return True
        except RuntimeError as e:
            logger.error(f"Update error: {e}")
            raise  # Re-raise RuntimeError with message
        except Exception as e:
            error_msg = f"Unexpected error during update: {str(e)}"
            logger.error(f"Update error: {error_msg}", exc_info=True)
            raise RuntimeError(error_msg)
    
    def _load_deleted_sources(self) -> Dict:
        """Loads the list of deleted sources from file"""
        if DELETED_SOURCES_FILE.exists():
            try:
                with open(DELETED_SOURCES_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Error loading deleted sources: {e}")
        return {}
    
    def _save_deleted_sources(self):
        """Saves the list of deleted sources"""
        try:
            with open(DELETED_SOURCES_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.deleted_sources, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving deleted sources: {e}")
    
    def _load_manual_sources(self) -> List[Dict]:
        """Loads the list of manually added sources"""
        if MANUAL_SOURCES_FILE.exists():
            try:
                with open(MANUAL_SOURCES_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Error loading manual sources: {e}")
        return []
    
    def _save_manual_sources(self):
        """Saves the list of manually added sources"""
        try:
            with open(MANUAL_SOURCES_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.manual_sources, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving manual sources: {e}")
    
    def add_manual_source(self, url: str, name: str = None, description: str = None) -> bool:
        """Adds a source manually"""
        try:
            # Vérifier que l'URL n'existe pas déjà
            if any(s.get('url') == url for s in self.manual_sources):
                return False
            
            # Extract name from URL if not provided
            if not name:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                name = parsed.netloc or url[:50]
            
            source = {
                'url': url,
                'name': name,
                'description': description or '',
                'status': 'ONLINE',
                'is_manual': True,
                'added_at': datetime.now().isoformat()
            }
            
            self.manual_sources.append(source)
            self._save_manual_sources()
            logger.info(f"Manual source added: {url}")
            return True
        except Exception as e:
            logger.error(f"Error adding manual source: {e}")
            return False
    
    def delete_manual_source(self, url: str) -> bool:
        """Deletes a manual source"""
        try:
            initial_count = len(self.manual_sources)
            self.manual_sources = [s for s in self.manual_sources if s.get('url') != url]
            
            if len(self.manual_sources) < initial_count:
                self._save_manual_sources()
                logger.info(f"Manual source deleted: {url}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting manual source: {e}")
            return False
    
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
    
    def _get_cache_key(self) -> str:
        """Generates a cache key based on file modification dates"""
        if not self.repo_exists():
            return ""
        
        try:
            markdown_files = self._fetch_local_file_list()
            if not markdown_files:
                return ""
            
            files_to_process = [f for f in markdown_files if f.lower() not in ['readme.md', 'license', 'license.md', 'commercial_services.md']]
            mtimes = []
            for filename in files_to_process:
                file_path = self.repo_dir / filename
                if file_path.exists():
                    mtimes.append((filename, file_path.stat().st_mtime))
            
            # Create a key based on names and modification dates
            import hashlib
            key_data = str(sorted(mtimes))
            return hashlib.md5(key_data.encode()).hexdigest()
        except Exception as e:
            logger.warning(f"Error generating cache key: {e}")
            return ""
    
    def _load_cached_categories(self) -> Optional[Dict]:
        """Loads categories from cache if valid"""
        if not CATEGORIES_CACHE_FILE.exists():
            return None
        
        try:
            with open(CATEGORIES_CACHE_FILE, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            # Vérifier si le cache est valide
            cache_key = self._get_cache_key()
            if cache_key and cache_data.get('cache_key') == cache_key:
                logger.info("Loading categories from cache")
                return cache_data.get('categories', {})
            else:
                logger.info("Cache invalid, re-parsing required")
                return None
        except Exception as e:
            logger.warning(f"Error loading cache: {e}")
            return None
    
    def _save_cached_categories(self, categories: Dict, last_update: str = None):
        """Saves categories to cache"""
        try:
            cache_key = self._get_cache_key()
            cache_data = {
                'cache_key': cache_key,
                'categories': categories,
                'cached_at': datetime.now().isoformat()
            }
            # Preserve last_update if provided, otherwise keep existing one
            if last_update:
                cache_data['last_update'] = last_update
            elif CATEGORIES_CACHE_FILE.exists():
                try:
                    with open(CATEGORIES_CACHE_FILE, 'r', encoding='utf-8') as f:
                        existing_data = json.load(f)
                        if 'last_update' in existing_data:
                            cache_data['last_update'] = existing_data['last_update']
                except Exception:
                    pass
            
            with open(CATEGORIES_CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            logger.info("Categories saved to cache")
        except Exception as e:
            logger.warning(f"Error saving cache: {e}")
    
    def delete_source(self, category: str, source_url: str) -> bool:
        """Marks a source as deleted"""
        try:
            if category not in self.deleted_sources:
                self.deleted_sources[category] = []
            
            if source_url not in self.deleted_sources[category]:
                self.deleted_sources[category].append(source_url)
                self._save_deleted_sources()
                logger.info(f"Source deleted: {category} - {source_url}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting source: {e}")
            return False
    
    def _filter_deleted_sources(self, categories: Dict) -> Dict:
        """Filters deleted sources from categories"""
        filtered_categories = {}
        total_deleted = 0
        
        for category_name, category_data in categories.items():
            if category_name not in self.deleted_sources or not self.deleted_sources[category_name]:
                filtered_categories[category_name] = category_data
                continue
            
            deleted_urls = set(self.deleted_sources[category_name])
            original_count = len(category_data.get('sources', []))
            filtered_sources = [
                source for source in category_data.get('sources', [])
                if source.get('url') not in deleted_urls
            ]
            
            deleted_count = original_count - len(filtered_sources)
            if deleted_count > 0:
                total_deleted += deleted_count
                logger.info(f"Filtering: {deleted_count} source(s) deleted from {category_name}")
            
            filtered_category = category_data.copy()
            filtered_category['sources'] = filtered_sources
            filtered_category['source_count'] = len(filtered_sources)
            filtered_categories[category_name] = filtered_category
        
        if total_deleted > 0:
            logger.info(f"Total: {total_deleted} deleted source(s) filtered")
        
        return filtered_categories
    
    def _fetch_local_file_list(self) -> List[str]:
        """Retrieves the list of markdown files from local repository"""
        try:
            if not self.repo_dir.exists():
                return []
            
            markdown_files = [
                f.name for f in self.repo_dir.iterdir()
                if f.is_file() and f.name.endswith('.md')
            ]
            return sorted(markdown_files)
        except Exception as e:
            logger.error(f"Error retrieving file list: {e}")
            return []
    
    def _fetch_file_content(self, filename: str) -> Optional[str]:
        """Retrieves raw content of a file from local repository"""
        try:
            file_path = self.repo_dir / filename
            if not file_path.exists():
                logger.warning(f"File {filename} not found in local repository")
                return None
            
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file {filename}: {e}")
            return None
    
    def _clean_text(self, text: str) -> str:
        """Cleans text by removing table headers, separators, etc."""
        if not text:
            return ""
        
        # Remove markdown table header patterns
        text = re.sub(r'^\s*\|[^|]*\|\s*$', '', text, flags=re.MULTILINE)
        text = re.sub(r'^\s*\|[\s\-:]+\|\s*$', '', text, flags=re.MULTILINE)
        text = re.sub(r'^\s*\|[^|]*\|[^|]*\|\s*$', '', text, flags=re.MULTILINE)
        
        # Clean up unwanted characters
        text = re.sub(r'\s*\|\s*', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()
        
        # Remove common prefixes/suffixes
        text = re.sub(r'^(Name|Link|URL|Description|Status)\s*:\s*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'^\s*-\s*', '', text)
        
        return text
    
    def _parse_markdown_table_raw(self, content: str) -> List[Dict]:
        """Parses markdown tables directly from raw text"""
        sources = []
        lines = content.split('\n')
        
        table_lines = []
        in_table = False
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('|') and '|' in line[1:]:
                if re.match(r'^\|\s*[-:]+\s*\|', line):
                    continue
                
                in_table = True
                table_lines.append(line)
            elif in_table and not line.startswith('|'):
                break
        
        if len(table_lines) < 2:
            return sources
        
        header_line = table_lines[0]
        raw_header_cells = [cell.strip() for cell in header_line.split('|')[1:-1]]
        
        header_cells = []
        for h in raw_header_cells:
            cleaned = self._clean_text(h)
            header_cells.append(cleaned if cleaned else '')
        
        link_col_idx = None
        name_col_idx = None
        desc_col_idx = None
        
        for idx, header in enumerate(header_cells):
            if not header:
                continue
                
            header_lower = header.lower()
            
            if any(keyword in header_lower for keyword in ['link', 'url', 'telegram', 'poc']):
                link_col_idx = idx
            elif 'name' in header_lower:
                name_col_idx = idx
            elif 'description' in header_lower or 'desc' in header_lower:
                desc_col_idx = idx
            elif 'type' in header_lower and desc_col_idx is None:
                desc_col_idx = idx
        
        if link_col_idx is None:
            if len(table_lines) > 1:
                first_col_sample = table_lines[1].split('|')[1].strip() if '|' in table_lines[1] else ''
                if 'http' in first_col_sample or '[' in first_col_sample:
                    link_col_idx = 0
                else:
                    for test_line in table_lines[1:min(4, len(table_lines))]:
                        if '|' not in test_line:
                            continue
                        cells = [cell.strip() for cell in test_line.split('|')[1:-1]]
                        for idx, cell in enumerate(cells):
                            if 'http' in cell or '[' in cell:
                                link_col_idx = idx
                                break
                        if link_col_idx is not None:
                            break
                
                if link_col_idx is None:
                    if name_col_idx is not None:
                        link_col_idx = name_col_idx
                    else:
                        link_col_idx = 0
        
        for line in table_lines[1:]:
            cells = [cell.strip() for cell in line.split('|')[1:-1]]
            
            while len(cells) < len(header_cells):
                cells.append('')
            
            if len(cells) <= link_col_idx:
                continue
            
            link_cell = cells[link_col_idx] if link_col_idx < len(cells) else ''
            
            link_match = re.search(r'\[([^\]]+)\]\(([^\)]+)\)', link_cell)
            if link_match:
                link_text = link_match.group(1).strip()
                link_url = link_match.group(2).strip()
            else:
                url_match = re.search(r'(https?://[^\s|\)\]]+)', link_cell)
                if url_match:
                    link_url = url_match.group(1).strip()
                    link_text = link_cell.replace(link_url, '').strip()
                else:
                    if link_cell.startswith('http://') or link_cell.startswith('https://'):
                        link_url = link_cell
                        link_text = ''
                    else:
                        found_url = False
                        for alt_idx, alt_cell in enumerate(cells):
                            if alt_idx == link_col_idx:
                                continue
                            alt_url_match = re.search(r'(https?://[^\s|\)\]]+)', alt_cell)
                            if alt_url_match:
                                link_url = alt_url_match.group(1).strip()
                                if link_cell.strip():
                                    link_text = link_cell.strip()
                                else:
                                    link_text = alt_cell.replace(link_url, '').strip()
                                    if not link_text and alt_idx > 0:
                                        link_text = cells[0].strip()
                                found_url = True
                                break
                        
                        if not found_url:
                            continue
            
            link_text = self._clean_text(link_text)
            if not link_text:
                link_text = link_url[:60] + ('...' if len(link_url) > 60 else '')
            
            description = ""
            status = None
            metadata = {}
            
            for idx, cell in enumerate(cells):
                if idx == link_col_idx:
                    continue
                
                if idx >= len(header_cells):
                    continue
                
                cell_clean = self._clean_text(cell)
                
                if cell_clean:
                    cell_upper = cell_clean.upper()
                    if cell_upper in ['ONLINE', 'OFFLINE', 'VALID', 'EXPIRED']:
                        status = cell_upper
                        continue
                
                header_name = header_cells[idx].strip() if idx < len(header_cells) else ''
                
                if not header_name:
                    continue
                
                header_lower = header_name.lower()
                
                if 'description' in header_lower or 'desc' in header_lower:
                    if cell_clean:
                        description = cell_clean
                elif 'name' in header_lower and not link_text:
                    if cell_clean:
                        link_text = cell_clean
                elif 'status' in header_lower:
                    if cell_clean:
                        cell_upper = cell_clean.upper()
                        if cell_upper in ['ONLINE', 'OFFLINE', 'VALID', 'EXPIRED']:
                            status = cell_upper
                else:
                    if cell_clean:
                        metadata_key = re.sub(r'[^\w\s]', '', header_name.lower()).strip().replace(' ', '_')
                        metadata_key = re.sub(r'_+', '_', metadata_key).strip('_')
                        if metadata_key and cell_clean:
                            metadata[metadata_key] = cell_clean
            
            if not description:
                for idx, cell in enumerate(cells):
                    if idx == link_col_idx:
                        continue
                    cell_clean = self._clean_text(cell)
                    if cell_clean and cell_clean.upper() not in ['ONLINE', 'OFFLINE', 'VALID', 'EXPIRED']:
                        description = cell_clean
                        break
            
            if link_url and (link_url.startswith('http://') or link_url.startswith('https://')):
                source_data = {
                    'name': link_text,
                    'url': link_url,
                    'description': description,
                    'status': status,
                    'section': None
                }
                
                if metadata:
                    source_data['metadata'] = metadata
                
                sources.append(source_data)
        
        return sources
    
    def _extract_from_table(self, soup: BeautifulSoup) -> List[Dict]:
        """Extracts sources from markdown tables (HTML fallback)"""
        sources = []
        tables = soup.find_all('table')
        
        for table in tables:
            rows = table.find_all('tr')
            if len(rows) < 2:
                continue
            
            header_row = rows[0]
            headers = [th.get_text().strip().lower() for th in header_row.find_all(['th', 'td'])]
            
            link_col_idx = None
            desc_col_idx = None
            
            for idx, header in enumerate(headers):
                header_clean = self._clean_text(header)
                if any(keyword in header_clean for keyword in ['link', 'url', 'name']):
                    link_col_idx = idx
                if 'description' in header_clean or 'desc' in header_clean:
                    desc_col_idx = idx
            
            if link_col_idx is None:
                link_col_idx = 0
            
            for row in rows[1:]:
                cells = row.find_all(['td', 'th'])
                if len(cells) <= link_col_idx:
                    continue
                
                link_cell = cells[link_col_idx]
                link_elem = link_cell.find('a')
                
                if link_elem:
                    link_url = link_elem.get('href', '').strip()
                    link_text = link_elem.get_text().strip()
                else:
                    cell_text = link_cell.get_text().strip()
                    url_match = re.search(r'(https?://[^\s|]+)', cell_text)
                    if url_match:
                        link_url = url_match.group(1)
                        link_text = cell_text.replace(link_url, '').strip() or link_url
                    else:
                        link_url = cell_text if (cell_text.startswith('http://') or cell_text.startswith('https://')) else ''
                        link_text = cell_text if not link_url else ''
                
                link_text = self._clean_text(link_text)
                if not link_text and link_url:
                    link_text = link_url[:50] + ('...' if len(link_url) > 50 else '')
                
                description = ""
                if desc_col_idx is not None and len(cells) > desc_col_idx:
                    desc_cell = cells[desc_col_idx]
                    description = self._clean_text(desc_cell.get_text().strip())
                elif len(cells) > link_col_idx + 1:
                    next_cell = cells[link_col_idx + 1]
                    description = self._clean_text(next_cell.get_text().strip())
                
                if link_url and (link_url.startswith('http://') or link_url.startswith('https://')):
                    sources.append({
                        'name': link_text or link_url[:50],
                        'url': link_url,
                        'description': description,
                        'section': None
                    })
        
        return sources
    
    def _parse_markdown_content(self, content: str, filename: str) -> Dict:
        """Parse markdown content and extract CTI sources"""
        category_name = filename.replace('.md', '').replace('_', ' ').title()
        
        sources = []
        current_section = None
        
        table_sources = self._parse_markdown_table_raw(content)
        sources.extend(table_sources)
        
        html_content = markdown(content, extensions=['tables'])
        soup = BeautifulSoup(html_content, 'html.parser')
        
        if not sources:
            table_sources_html = self._extract_from_table(soup)
            sources.extend(table_sources_html)
        
        for element in soup.find_all(['h1', 'h2', 'h3', 'h4', 'p', 'ul', 'li']):
            if element.name in ['h1', 'h2', 'h3', 'h4']:
                current_section = self._clean_text(element.get_text().strip())
            
            elif element.name == 'li':
                links = element.find_all('a')
                if links:
                    for link in links:
                        link_text = self._clean_text(link.get_text().strip())
                        link_url = link.get('href', '').strip()
                        
                        if link_url and (link_url.startswith('http://') or link_url.startswith('https://')):
                            li_text = element.get_text().strip()
                            description = self._clean_text(li_text.replace(link_text, '').strip())
                            
                            if not any(s['url'] == link_url for s in sources):
                                sources.append({
                                    'name': link_text or link_url[:50],
                                    'url': link_url,
                                    'description': description,
                                    'section': current_section
                                })
            
            elif element.name == 'p':
                links = element.find_all('a')
                for link in links:
                    link_text = self._clean_text(link.get_text().strip())
                    link_url = link.get('href', '').strip()
                    
                    if link_url and (link_url.startswith('http://') or link_url.startswith('https://')):
                        p_text = element.get_text().strip()
                        description = self._clean_text(p_text.replace(link_text, '').strip())
                        
                        if not any(s['url'] == link_url for s in sources):
                            sources.append({
                                'name': link_text or link_url[:50],
                                'url': link_url,
                                'description': description,
                                'section': current_section
                            })
        
        if not sources:
            link_pattern = r'\[([^\]]+)\]\(([^\)]+)\)'
            for line in content.split('\n'):
                matches = re.findall(link_pattern, line)
                for match in matches:
                    link_text, link_url = match
                    if link_url.startswith('http'):
                        sources.append({
                            'name': link_text.strip(),
                            'url': link_url.strip(),
                            'description': '',
                            'section': None
                        })
        
        unique_sources = []
        seen_urls = set()
        for source in sources:
            url = source['url']
            if url and url not in seen_urls:
                seen_urls.add(url)
                source['name'] = self._clean_text(source['name'])
                source['description'] = self._clean_text(source['description'])
                unique_sources.append(source)
        
        # Calculate unique statuses present in this category
        unique_statuses = set()
        for source in unique_sources:
            if source.get('status'):
                unique_statuses.add(source['status'].upper())
        
        return {
            'name': category_name,
            'filename': filename,
            'sources': unique_sources,
            'source_count': len(unique_sources),
            'available_statuses': list(unique_statuses)
        }
    
    def fetch_all_categories(self) -> Dict:
        """Reads all categories from local repository (with cache)
        
        IMPORTANT: This function ONLY reads from existing local repository.
        It does NOT download the repository automatically.
        Download must be triggered explicitly via download_repo() or update_repo().
        """
        # Reload deleted, manual sources and favorites
        self.deleted_sources = self._load_deleted_sources()
        self.manual_sources = self._load_manual_sources()
        self.favorites = self._load_favorites()
        
        categories = {}
        
        # Load categories from repository if available
        # NOTE: If repo doesn't exist, we return empty categories (no automatic download)
        if self.repo_exists():
            # Try to load from cache
            cached_categories = self._load_cached_categories()
            
            if cached_categories:
                categories = cached_categories
                logger.info("Categories loaded from cache (near-instantaneous)")
            else:
                # Parse files if cache is not valid
                logger.info("Retrieving data from local repository...")
                
                markdown_files = self._fetch_local_file_list()
                
                if markdown_files:
                    files_to_process = [f for f in markdown_files if f.lower() not in ['readme.md', 'license', 'license.md', 'commercial_services.md']]
                    
                    for filename in files_to_process:
                        content = self._fetch_file_content(filename)
                        if content:
                            try:
                                category_data = self._parse_markdown_content(content, filename)
                                # S'assurer que available_statuses existe
                                if 'available_statuses' not in category_data:
                                    category_data['available_statuses'] = []
                                categories[filename] = category_data
                                logger.info(f"Category {filename} parsed: {category_data['source_count']} sources")
                            except Exception as e:
                                logger.error(f"Error parsing {filename}: {e}", exc_info=True)
                
                # Save to cache
                if categories:
                    # Preserve existing last_update if available, don't update it here
                    # last_update is only updated when repository is downloaded/updated
                    self._save_cached_categories(categories)
            
            # Add favorite info for each source (always up to date)
            for category_data in categories.values():
                for source in category_data.get('sources', []):
                    source['is_favorite'] = self.is_favorite(source.get('url', ''))
            
            # Filter deleted sources before returning
            categories = self._filter_deleted_sources(categories)
        
        # Add manual sources category if it exists
        if self.manual_sources:
            # Add favorite info for manual sources
            unique_statuses_manual = set()
            for source in self.manual_sources:
                source['is_favorite'] = self.is_favorite(source.get('url', ''))
                if source.get('status'):
                    unique_statuses_manual.add(source['status'].upper())
            categories['_manual_sources'] = {
                'name': 'Manually Added Sources',
                'filename': '_manual_sources',
                'sources': self.manual_sources,
                'source_count': len(self.manual_sources),
                'is_manual': True,
                'available_statuses': list(unique_statuses_manual)
            }
        
        return categories
    
    def get_category_info(self) -> Dict:
        """Returns general information about categories"""
        self.deleted_sources = self._load_deleted_sources()
        self.manual_sources = self._load_manual_sources()
        categories = self.fetch_all_categories()
        
        # Count categories (exclude manual category from count)
        regular_categories = {k: v for k, v in categories.items() if k != '_manual_sources'}
        total_sources = sum(cat['source_count'] for cat in categories.values())
        
        # Get last_update from cache if available
        # This represents when the repository was last downloaded
        last_update = None
        if CATEGORIES_CACHE_FILE.exists():
            try:
                with open(CATEGORIES_CACHE_FILE, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                    if 'last_update' in cache_data:
                        last_update = cache_data['last_update']
            except Exception:
                pass
        
        # If not in cache but repository exists, use repository directory modification time
        # This represents when the repository was downloaded/cloned
        if not last_update and self.repo_exists() and self.repo_dir.exists():
            try:
                # Get the modification time of the repository directory
                repo_mtime = self.repo_dir.stat().st_mtime
                last_update = datetime.fromtimestamp(repo_mtime).isoformat()
                # Save it to cache for future use
                try:
                    if CATEGORIES_CACHE_FILE.exists():
                        with open(CATEGORIES_CACHE_FILE, 'r', encoding='utf-8') as f:
                            cache_data = json.load(f)
                    else:
                        cache_data = {'categories': {}}
                    cache_data['last_update'] = last_update
                    with open(CATEGORIES_CACHE_FILE, 'w', encoding='utf-8') as f:
                        json.dump(cache_data, f, indent=2, ensure_ascii=False)
                except Exception:
                    pass
            except Exception:
                pass
        
        # If still no last_update, return None (will not display in template)
        if not last_update:
            last_update = None
        
        return {
            'total_categories': len(regular_categories),
            'total_sources': total_sources,
            'last_update': last_update,
            'categories': {k: {
                'name': v['name'],
                'source_count': v['source_count']
            } for k, v in categories.items()}
        }


# Instance globale
github_repo_manager = GitHubRepoManager()
