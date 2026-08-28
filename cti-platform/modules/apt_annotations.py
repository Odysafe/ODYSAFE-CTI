"""
APT Research Base - Neo23x0 Google CSE annotations.xml
Trusted CTI reference sources for APT/threat actor research.
"""
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

ANNOTATIONS_URL = (
    "https://gist.githubusercontent.com/Neo23x0/c4f40629342769ad0a8f3980942e21d3/raw/"
    "922bb089e6ac648dba9c4c4eb1404d1cf6db600f/annotations.xml"
)

CACHE_DIR = Path(__file__).parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)
ANNOTATIONS_FILE = CACHE_DIR / "apt_annotations.xml"
CACHE_FILE = CACHE_DIR / "apt_annotations_cache.json"
MANUAL_SOURCES_FILE = CACHE_DIR / "apt_annotations_manual.json"
FAVORITES_FILE = CACHE_DIR / "apt_annotations_favorites.json"


class AptAnnotationsManager:
    """Manage APT reference source list from Neo23x0 annotations.xml."""

    def __init__(self):
        self._sources: List[Dict] = []
        self._last_update: Optional[str] = None
        self.manual_sources = self._load_json(MANUAL_SOURCES_FILE, [])
        self.favorites = set(self._load_json(FAVORITES_FILE, []))
        self._load_cache()

    @staticmethod
    def _load_json(path: Path, default):
        if not path.exists():
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load {path}: {e}")
            return default

    @staticmethod
    def _save_json(path: Path, data) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Could not save {path}: {e}")

    def _load_cache(self) -> None:
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._sources = data.get("sources", [])
                self._last_update = data.get("last_update")
                if self._sources:
                    return
            except Exception as e:
                logger.warning(f"Could not load APT annotations cache: {e}")

        if ANNOTATIONS_FILE.exists():
            try:
                self._sources = self._parse_xml(ANNOTATIONS_FILE.read_text(encoding="utf-8"))
                if self._sources and not self._last_update:
                    self._last_update = datetime.fromtimestamp(
                        ANNOTATIONS_FILE.stat().st_mtime
                    ).isoformat()
                    self._save_cache()
            except Exception as e:
                logger.warning(f"Could not parse local APT annotations file: {e}")

    def ensure_available(self) -> bool:
        """Download annotations on first use if not cached locally."""
        if self.annotations_exist() and self._sources:
            return True
        if ANNOTATIONS_FILE.exists() and not self._sources:
            self._sources = self._parse_xml(ANNOTATIONS_FILE.read_text(encoding="utf-8"))
            if self._sources:
                self._save_cache()
                return True
        return self.download_annotations()

    def _save_cache(self) -> None:
        self._save_json(CACHE_FILE, {
            "last_update": self._last_update,
            "sources": self._sources,
            "cached_at": datetime.now().isoformat(),
        })

    def annotations_exist(self) -> bool:
        return ANNOTATIONS_FILE.exists() or bool(self._sources)

    def get_status(self) -> Dict:
        self.ensure_available()
        return {
            "available": self.annotations_exist(),
            "source_count": len(self.get_all_sources()),
            "last_update": self._last_update,
            "favorites_count": len(self.favorites),
        }

    def download_annotations(self) -> bool:
        try:
            logger.info("Downloading APT annotations from Neo23x0 gist...")
            response = requests.get(
                ANNOTATIONS_URL,
                timeout=60,
                headers={"User-Agent": "Mozilla/5.0 (Odysafe CTI Platform)"},
            )
            response.raise_for_status()
            ANNOTATIONS_FILE.write_text(response.text, encoding="utf-8")
            self._last_update = datetime.now().isoformat()
            self._sources = self._parse_xml(response.text)
            self._save_cache()
            logger.info(f"APT annotations downloaded: {len(self._sources)} sources")
            return True
        except requests.RequestException as e:
            logger.error(f"APT annotations download error: {e}")
            return False

    def update_annotations(self) -> bool:
        return self.download_annotations()

    def _parse_xml(self, xml_text: str) -> List[Dict]:
        sources = []
        try:
            root = ET.fromstring(xml_text)
            for annotation in root.findall("Annotation"):
                url = None
                for extra in annotation.findall("AdditionalData"):
                    if extra.get("attribute") == "original_url":
                        url = extra.get("value")
                        break
                if not url:
                    about = annotation.get("about", "")
                    url = about.replace("/*", "/").replace("*.", "")
                    if not url.startswith("http"):
                        url = f"https://{url.lstrip('/')}"

                parsed = urlparse(url)
                domain = parsed.netloc or parsed.path.split("/")[0]
                name = domain.replace("www.", "")

                sources.append({
                    "url": url.rstrip("/"),
                    "name": name,
                    "domain": domain,
                    "source": "APT Research Base",
                    "is_manual": False,
                })
        except ET.ParseError as e:
            logger.error(f"APT annotations XML parse error: {e}")
        return sources

    def get_all_sources(self) -> List[Dict]:
        combined = []
        seen_urls = set()

        for src in self._sources + self.manual_sources:
            url = src.get("url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            entry = dict(src)
            entry["is_favorite"] = url in self.favorites
            combined.append(entry)

        return sorted(combined, key=lambda s: s.get("name", "").lower())

    def search_sources(self, query: str = "", limit: int = 50) -> List[Dict]:
        query = (query or "").strip().lower()
        results = self.get_all_sources()
        if query:
            results = [
                s for s in results
                if query in s.get("name", "").lower()
                or query in s.get("url", "").lower()
                or query in s.get("domain", "").lower()
            ]
        return results[:limit]

    def add_manual_source(self, url: str, name: str = None) -> bool:
        url = url.strip()
        if not url.startswith("http"):
            url = f"https://{url}"
        if any(s.get("url") == url for s in self.manual_sources):
            return False
        parsed = urlparse(url)
        self.manual_sources.append({
            "url": url,
            "name": name or parsed.netloc.replace("www.", ""),
            "domain": parsed.netloc,
            "source": "Manual",
            "is_manual": True,
            "added_at": datetime.now().isoformat(),
        })
        self._save_json(MANUAL_SOURCES_FILE, self.manual_sources)
        return True

    def delete_manual_source(self, url: str) -> bool:
        before = len(self.manual_sources)
        self.manual_sources = [s for s in self.manual_sources if s.get("url") != url]
        if len(self.manual_sources) < before:
            self._save_json(MANUAL_SOURCES_FILE, self.manual_sources)
            self.favorites.discard(url)
            self._save_json(FAVORITES_FILE, list(self.favorites))
            return True
        return False

    def toggle_favorite(self, url: str) -> bool:
        if url in self.favorites:
            self.favorites.discard(url)
            is_fav = False
        else:
            self.favorites.add(url)
            is_fav = True
        self._save_json(FAVORITES_FILE, list(self.favorites))
        return is_fav

    def get_search_urls_for_actor(self, actor_name: str) -> List[Dict]:
        """Return reference sources with Google search links scoped to actor name."""
        actor = (actor_name or "").strip()
        if not actor:
            return []
        results = []
        for src in self.get_all_sources():
            search_url = f"https://www.google.com/search?q=site:{src['domain']}+{actor.replace(' ', '+')}"
            entry = dict(src)
            entry["search_url"] = search_url
            results.append(entry)
        return results


apt_annotations_manager = AptAnnotationsManager()
