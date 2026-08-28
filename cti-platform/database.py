"""
Odysafe CTI Platform
Copyright (C) 2026 Bastien GUIDONE

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

SQLite database management
"""
import sqlite3
import json
import logging
import time
import hashlib
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Iterator, Any
from config import DATABASE_PATH, PREDEFINED_TAGS

logger = logging.getLogger(__name__)


def get_local_timestamp() -> str:
    """Retourne l'heure locale actuelle formatée pour SQLite (format: YYYY-MM-DD HH:MM:SS)"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


class Database:
    def __init__(self, db_path: Path = DATABASE_PATH):
        self.db_path = db_path
        # In-memory cache for query results
        self._count_cache: Dict[str, Tuple[int, float]] = {}  # {cache_key: (count, timestamp)}
        self._metadata_cache: Dict[str, Tuple[Any, float]] = {}  # {cache_key: (data, timestamp)}
        # Improved cache TTL: 5 minutes for counts (frequently accessed), 15 minutes for metadata
        self._count_cache_ttl = 300  # 5 minutes
        self._metadata_cache_ttl = 900  # 15 minutes
        self._max_cache_size = 1000  # Maximum cache entries to prevent memory issues
        # Thread-local connection pool for SQLite (one connection per thread)
        self._local = threading.local()
        self._connection_lock = threading.Lock()
        # Connection pool limits
        # Note: Thread-local connections are reused and not counted in the pool
        # This limit applies only to non-thread-local connections
        self._max_connections = 50  # Maximum number of concurrent non-thread-local connections
        self._active_connections = 0  # Counter for active non-thread-local connections
        self.init_database()

    def get_connection(self):
        """Returns a database connection with timeout and WAL mode.
        Uses thread-local connection pooling for better performance.
        Thread-local connections are reused and not counted in the pool limit.
        Only non-thread-local connections count toward the pool limit."""
        # Use thread-local connection if available and valid
        if hasattr(self._local, 'connection'):
            conn = self._local.connection
            try:
                # Test if connection is still valid
                conn.execute("SELECT 1")
                return conn
            except (sqlite3.ProgrammingError, sqlite3.OperationalError):
                # Connection is closed or invalid, create new one
                delattr(self._local, 'connection')
                # Note: thread-local connections don't count in pool, so no decrement needed
        
        # Check connection pool limit (only for non-thread-local connections)
        # Thread-local connections are reused per thread and don't count
        with self._connection_lock:
            if self._active_connections >= self._max_connections:
                logger.warning(f"Connection pool limit reached ({self._max_connections}). Waiting for available connection...")
                # Wait a bit and retry
                time.sleep(0.5)
                if self._active_connections >= self._max_connections:
                    raise RuntimeError(f"Maximum number of database connections ({self._max_connections}) exceeded. Please retry later.")
        
        max_retries = 5
        retry_delay = 0.2
        
        for attempt in range(max_retries):
            try:
                conn = sqlite3.connect(self.db_path, timeout=30.0)
                conn.row_factory = sqlite3.Row
                
                # Register custom SQLite function for local timestamp
                def local_timestamp():
                    """Custom SQLite function that returns local time"""
                    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                conn.create_function('LOCAL_TIMESTAMP', 0, local_timestamp)
                
                # Enable WAL mode for better concurrency
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA busy_timeout=30000")
                
                # Store connection in thread-local storage for reuse
                # Thread-local connections are reused and don't count in pool
                self._local.connection = conn
                # Don't increment counter for thread-local connections
                return conn
            except sqlite3.OperationalError as e:
                error_msg = str(e).lower()
                if "database is locked" in error_msg and attempt < max_retries - 1:
                    wait_time = retry_delay * (attempt + 1)
                    logger.warning(f"Database locked, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                logger.error(f"Database connection error: {e}")
                raise
            except Exception as e:
                logger.error(f"Unexpected database connection error: {e}")
                raise
    
    def _close_connection_if_needed(self, conn):
        """Close connection only if it's not a thread-local connection.
        Thread-local connections are kept open for reuse."""
        if conn and (not hasattr(self._local, 'connection') or self._local.connection != conn):
            try:
                conn.close()
                with self._connection_lock:
                    self._active_connections = max(0, self._active_connections - 1)
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")

    @contextmanager
    def connection(self):
        """Context manager for database connections. Ensures proper cleanup.
        Uses thread-local connection pooling - connections are reused within the same thread.
        Non-thread-local connections are counted in the pool and closed after use."""
        conn = None
        is_thread_local = False
        try:
            conn = self.get_connection()
            # Check if this is a thread-local connection (already stored)
            is_thread_local = hasattr(self._local, 'connection') and self._local.connection == conn
            
            # If not thread-local, increment counter
            if not is_thread_local:
                with self._connection_lock:
                    self._active_connections += 1
            
            yield conn
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database transaction error: {e}")
            raise
        finally:
            # Only close connection if it's not thread-local (new connection)
            # Thread-local connections are kept open for reuse
            if conn and not is_thread_local:
                try:
                    conn.close()
                    with self._connection_lock:
                        self._active_connections = max(0, self._active_connections - 1)
                except Exception as e:
                    logger.warning(f"Error closing connection: {e}")
    
    def _get_cache_key(self, prefix: str, data: Any) -> str:
        """Generate a cache key from data"""
        cache_data = json.dumps(data, sort_keys=True)
        return f"{prefix}:{hashlib.md5(cache_data.encode()).hexdigest()}"
    
    
    
    def _get_cached_metadata(self, cache_key: str) -> Optional[Any]:
        """Get cached metadata if valid"""
        if cache_key in self._metadata_cache:
            data, timestamp = self._metadata_cache[cache_key]
            if time.time() - timestamp < self._metadata_cache_ttl:
                return data
            else:
                del self._metadata_cache[cache_key]
        return None
    
    def _set_cached_metadata(self, cache_key: str, data: Any):
        """Cache metadata result with size limit"""
        # Evict oldest entries if cache is too large
        if len(self._metadata_cache) >= self._max_cache_size:
            # Remove oldest 20% of entries
            sorted_entries = sorted(self._metadata_cache.items(), key=lambda x: x[1][1])
            for key, _ in sorted_entries[:self._max_cache_size // 5]:
                del self._metadata_cache[key]
        self._metadata_cache[cache_key] = (data, time.time())
    
    def invalidate_cache(self):
        """Invalidate all caches (call after IOC/source modifications)"""
        self._count_cache.clear()
        self._metadata_cache.clear()

    def init_database(self):
        """Initializes the database with necessary tables"""
        conn = self.get_connection()
        ody = conn.cursor()

        # Table sources
        ody.execute("""
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                context TEXT NOT NULL,
                source_type TEXT NOT NULL,
                file_path TEXT,
                original_filename TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP,
                status TEXT DEFAULT 'pending',
                is_deleted BOOLEAN DEFAULT 0,
                deleted_at TIMESTAMP NULL
            )
        """)
        
        # Migration: Add trash columns if they don't exist
        try:
            ody.execute("ALTER TABLE sources ADD COLUMN is_deleted BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            ody.execute("ALTER TABLE sources ADD COLUMN deleted_at TIMESTAMP NULL")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # Table iocs
        ody.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                raw_value TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_whitelisted BOOLEAN DEFAULT 0,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_deleted BOOLEAN DEFAULT 0,
                deleted_at TIMESTAMP NULL,
                partition_key TEXT,
                -- IOC Lifecycle Management Fields
                tlp TEXT DEFAULT 'WHITE',
                validation_status TEXT DEFAULT 'Unverified',
                confidence TEXT DEFAULT 'Unknown',
                expiry_date TIMESTAMP NULL,
                lifecycle_status TEXT DEFAULT 'Active',
                kill_chain_phase TEXT,
                mitre_technique TEXT,
                context TEXT,
                FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE,
                UNIQUE(source_id, ioc_type, ioc_value)
            )
        """)
        
        # Migration: Add trash columns if they don't exist
        try:
            ody.execute("ALTER TABLE iocs ADD COLUMN is_deleted BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists
            
        # Migration: Add IOC lifecycle management fields
        lifecycle_fields = [
            "tlp TEXT DEFAULT 'WHITE'",
            "validation_status TEXT DEFAULT 'Unverified'", 
            "confidence TEXT DEFAULT 'Unknown'",
            "expiry_date TIMESTAMP NULL",
            "lifecycle_status TEXT DEFAULT 'Active'",
            "kill_chain_phase TEXT",
            "mitre_technique TEXT",
            "context TEXT"
        ]
        
        for field in lifecycle_fields:
            try:
                ody.execute(f"ALTER TABLE iocs ADD COLUMN {field}")
            except sqlite3.OperationalError:
                pass  # Column already exists
        
        try:
            ody.execute("ALTER TABLE iocs ADD COLUMN deleted_at TIMESTAMP NULL")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # Migration: Add partition_key column for temporal partitioning
        try:
            ody.execute("ALTER TABLE iocs ADD COLUMN partition_key TEXT")
            # Populate partition_key for existing records (YYYY-MM format)
            ody.execute("""
                UPDATE iocs 
                SET partition_key = strftime('%Y-%m', created_at)
                WHERE partition_key IS NULL
            """)
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Tags table (enhanced)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                color TEXT,
                is_auto BOOLEAN DEFAULT 0,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Migration: Add new columns if they don't exist
        try:
            ody.execute("ALTER TABLE tags ADD COLUMN is_auto BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            ody.execute("ALTER TABLE tags ADD COLUMN metadata TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            ody.execute("ALTER TABLE tags ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # ioc_tags junction table
        ody.execute("""
            CREATE TABLE IF NOT EXISTS ioc_tags (
                ioc_id INTEGER NOT NULL,
                tag_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ioc_id, tag_id),
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
            )
        """)

        # Tag history table
        ody.execute("""
            CREATE TABLE IF NOT EXISTS tag_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id INTEGER NOT NULL,
                tag_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
            )
        """)

        # Table source_templates
        ody.execute("""
            CREATE TABLE IF NOT EXISTS source_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                context TEXT NOT NULL,
                source_type TEXT NOT NULL,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Migration: add tags column if it doesn't exist
        try:
            ody.execute("ALTER TABLE source_templates ADD COLUMN tags TEXT")
        except Exception:
            # Column already exists or error (ignored)
            pass

        # Table groups
        ody.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                color TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Table source_groups (liaison many-to-many entre sources et groups)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS source_groups (
                source_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (source_id, group_id),
                FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            )
        """)

        # Table ioc_groups (liaison many-to-many entre iocs et groups)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS ioc_groups (
                ioc_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ioc_id, group_id),
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            )
        """)

        # Table ioc_source_group_exclusions (to exclude source groups for a specific IOC)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS ioc_source_group_exclusions (
                ioc_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ioc_id, group_id),
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            )
        """)

        # Table ioc_ttp_links (link IOCs to MITRE ATT&CK techniques)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS ioc_ttp_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id INTEGER NOT NULL,
                technique_id TEXT NOT NULL,
                confidence TEXT DEFAULT 'medium',
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                UNIQUE(ioc_id, technique_id)
            )
        """)
        ody.execute("CREATE INDEX IF NOT EXISTS idx_ioc_ttp_links_ioc ON ioc_ttp_links(ioc_id)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_ioc_ttp_links_technique ON ioc_ttp_links(technique_id)")

        # Cross-module index registry (source_ref lifecycle, content hashes)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS cross_refs (
                ref_key TEXT PRIMARY KEY,
                ref_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                content_hash TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        ody.execute("CREATE INDEX IF NOT EXISTS idx_cross_refs_type_entity ON cross_refs(ref_type, entity_id)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_cross_refs_status ON cross_refs(status)")

        # Table settings
        ody.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table users
        ody.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table generated_reports
        ody.execute("""
            CREATE TABLE IF NOT EXISTS generated_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER NOT NULL,
                report_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
            )
        """)


        # Index to improve performance
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source_id)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_is_deleted ON iocs(is_deleted)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_created_at ON iocs(created_at)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_first_seen ON iocs(first_seen)")
        # Composite indexes for common filter combinations
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_deleted_created ON iocs(is_deleted, created_at DESC)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_deleted_type ON iocs(is_deleted, ioc_type)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(ioc_type, ioc_value)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_deleted_type_created ON iocs(is_deleted, ioc_type, created_at DESC)")
        # Additional composite indexes for optimized filtered queries
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_deleted_type_value ON iocs(is_deleted, ioc_type, ioc_value)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_deleted_created_type ON iocs(is_deleted, created_at DESC, ioc_type)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_source_deleted ON iocs(source_id, is_deleted)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value_deleted ON iocs(ioc_value, is_deleted)")
        # Index for temporal partitioning
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_partition_key ON iocs(partition_key)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_iocs_partition_deleted_created ON iocs(partition_key, is_deleted, created_at DESC)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_sources_is_deleted ON sources(is_deleted)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_sources_created_at ON sources(created_at)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_sources_status ON sources(status)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_sources_deleted_name ON sources(is_deleted, name)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_ioc_tags_ioc ON ioc_tags(ioc_id)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_ioc_tags_tag ON ioc_tags(tag_id)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_ioc_groups_ioc ON ioc_groups(ioc_id)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_ioc_groups_group ON ioc_groups(group_id)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_source_templates_type ON source_templates(source_type)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_source_groups_source ON source_groups(source_id)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_source_groups_group ON source_groups(group_id)")
        # Table saved_stix_models
        ody.execute("""
            CREATE TABLE IF NOT EXISTS saved_stix_models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                stix_content TEXT NOT NULL,
                local_metadata TEXT,
                node_count INTEGER DEFAULT 0,
                edge_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_loaded_at TIMESTAMP
            )
        """)
        saved_stix_columns = {row[1] for row in ody.execute("PRAGMA table_info(saved_stix_models)").fetchall()}
        if 'local_metadata' not in saved_stix_columns:
            ody.execute("ALTER TABLE saved_stix_models ADD COLUMN local_metadata TEXT")
        
        ody.execute("CREATE INDEX IF NOT EXISTS idx_saved_stix_models_name ON saved_stix_models(name)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_saved_stix_models_created ON saved_stix_models(created_at)")

        ody.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                table_name TEXT NOT NULL,
                record_id TEXT NOT NULL,
                action TEXT NOT NULL,
                field TEXT,
                old_val TEXT,
                new_val TEXT,
                analyst TEXT,
                created_at TEXT NOT NULL
            )
        """)

        # MITRE ATT&CK tables
        ody.execute("""
            CREATE TABLE IF NOT EXISTS mitre_tactics (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                url TEXT,
                shortname TEXT
            )
        """)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS mitre_techniques (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                url TEXT,
                is_subtechnique INTEGER DEFAULT 0,
                parent_id TEXT,
                deprecated INTEGER DEFAULT 0
            )
        """)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS mitre_technique_tactics (
                technique_id TEXT NOT NULL,
                tactic_id TEXT NOT NULL,
                PRIMARY KEY (technique_id, tactic_id),
                FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id),
                FOREIGN KEY (tactic_id) REFERENCES mitre_tactics(id)
            )
        """)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS mitre_groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                aliases TEXT,
                description TEXT,
                url TEXT
            )
        """)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS mitre_software (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT,
                description TEXT,
                url TEXT
            )
        """)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS mitre_group_uses (
                id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                software_id TEXT,
                use_description TEXT,
                FOREIGN KEY (group_id) REFERENCES mitre_groups(id),
                FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id),
                FOREIGN KEY (software_id) REFERENCES mitre_software(id)
            )
        """)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS mitre_mitigations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                url TEXT
            )
        """)
        ody.execute("""
            CREATE TABLE IF NOT EXISTS mitre_technique_mitigations (
                technique_id TEXT NOT NULL,
                mitigation_id TEXT NOT NULL,
                PRIMARY KEY (technique_id, mitigation_id),
                FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id),
                FOREIGN KEY (mitigation_id) REFERENCES mitre_mitigations(id)
            )
        """)
        ody.execute("CREATE INDEX IF NOT EXISTS idx_mitre_tech_parent ON mitre_techniques(parent_id)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_mitre_tech_sub ON mitre_techniques(is_subtechnique)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_mitre_group_uses_group ON mitre_group_uses(group_id)")
        ody.execute("CREATE INDEX IF NOT EXISTS idx_mitre_group_uses_tech ON mitre_group_uses(technique_id)")

        # Migrate audit_log.id from INTEGER AUTOINCREMENT to TEXT (recreate table)
        try:
            _id_types = [r[2] for r in ody.execute("PRAGMA table_info(audit_log)").fetchall() if r[1] == 'id']
            if _id_types and _id_types[0].upper() in ('INTEGER', 'INT'):
                ody.execute("ALTER TABLE audit_log RENAME TO _audit_log_old")
                ody.execute("""
                    CREATE TABLE audit_log (
                        id TEXT PRIMARY KEY,
                        table_name TEXT NOT NULL,
                        record_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        field TEXT,
                        old_val TEXT,
                        new_val TEXT,
                        analyst TEXT,
                        created_at TEXT NOT NULL
                    )
                """)
                ody.execute("DROP TABLE _audit_log_old")
        except Exception:
            pass

        
        conn.commit()
        self._close_connection_if_needed(conn)

        # Initialize predefined tags
        self.init_predefined_tags()
        
        # Initialize default settings
        self.init_default_settings()
        
        # Ensure default groups exist (default, TLP groups, True/False Positive)
        self._ensure_default_group()
        
        # Initialize default templates
        self.init_default_templates()

    def init_predefined_tags(self):
        """Initializes predefined tags"""
        conn = self.get_connection()
        ody = conn.cursor()

        for tag in PREDEFINED_TAGS:
            is_auto = tag.get("auto", False)
            ody.execute("""
                INSERT OR IGNORE INTO tags (name, category, color, is_auto)
                VALUES (?, ?, ?, ?)
            """, (tag["name"], tag["category"], tag["color"], 1 if is_auto else 0))

        conn.commit()
        self._close_connection_if_needed(conn)
    
    def init_default_settings(self):
        """Initializes default settings"""
        conn = self.get_connection()
        ody = conn.cursor()

        default_settings = {
            'auto_tag_enabled': 'true',
            'storage_check_interval': '1',
            'auto_generate_reports': 'false'  # Automatic pipeline disabled by default
        }

        for key, value in default_settings.items():
            ody.execute("""
                INSERT OR IGNORE INTO settings (key, value)
                VALUES (?, ?)
            """, (key, value))

        conn.commit()
        self._close_connection_if_needed(conn)
    
    def init_default_templates(self):
        """Initializes default templates with pre-filled tags"""
        conn = self.get_connection()
        ody = conn.cursor()
        
        # Check if templates already exist
        ody.execute("SELECT COUNT(*) FROM source_templates")
        if ody.fetchone()[0] > 0:
            self._close_connection_if_needed(conn)
            return  # Templates already created
        
        import json
        
        # Get tag IDs by name for templates
        def get_tag_id_by_name(name: str) -> Optional[int]:
            ody.execute("SELECT id FROM tags WHERE name = ?", (name,))
            row = ody.fetchone()
            return row[0] if row else None
        
        # Template "Network Admin"
        admin_tags = []
        for tag_name in ["Type:IPv4", "Type:Domain", "Source:File", "Type:URL"]:
            tag_id = get_tag_id_by_name(tag_name)
            if tag_id:
                admin_tags.append(tag_id)
        
        ody.execute("""
            INSERT INTO source_templates (name, context, source_type, tags)
            VALUES (?, ?, ?, ?)
        """, (
            "Network Admin",
            "Template for network administration and equipment monitoring",
            "file_upload",
            json.dumps({"tag_ids": admin_tags}) if admin_tags else None
        ))
        
        # Template "CTI Expert"
        cti_tags = []
        for tag_name in ["Type:Hash", "Type:URL", "Type:Domain", "Type:IPv4"]:
            tag_id = get_tag_id_by_name(tag_name)
            if tag_id:
                cti_tags.append(tag_id)
        
        ody.execute("""
            INSERT INTO source_templates (name, context, source_type, tags)
            VALUES (?, ?, ?, ?)
        """, (
            "CTI Expert",
            "Template for threat analysis and IOCs",
            "file_upload",
            json.dumps({"tag_ids": cti_tags}) if cti_tags else None
        ))
        
        # Template "Operational Security"
        sec_tags = []
        for tag_name in ["Type:Hash", "Type:URL", "Type:Domain"]:
            tag_id = get_tag_id_by_name(tag_name)
            if tag_id:
                sec_tags.append(tag_id)
        
        ody.execute("""
            INSERT INTO source_templates (name, context, source_type, tags)
            VALUES (?, ?, ?, ?)
        """, (
            "Operational Security",
            "Template for security incidents and alerts",
            "file_upload",
            json.dumps({"tag_ids": sec_tags}) if sec_tags else None
        ))
        
        # Template "Research"
        research_tags = []
        for tag_name in ["Type:Domain", "Type:URL", "Type:IPv4"]:
            tag_id = get_tag_id_by_name(tag_name)
            if tag_id:
                research_tags.append(tag_id)
        
        ody.execute("""
            INSERT INTO source_templates (name, context, source_type, tags)
            VALUES (?, ?, ?, ?)
        """, (
            "Research",
            "Template for analysis",
            "file_upload",
            json.dumps({"tag_ids": research_tags}) if research_tags else None
        ))
        
        conn.commit()
        self._close_connection_if_needed(conn)
    
    def _ensure_default_group(self):
        """Ensures the default group exists"""
        with self.connection() as conn:
            default_group = self.get_group_by_name("default", conn)
            if not default_group:
                self.create_group("default", color="#6B7280", description="Default group for all sources", conn=conn)
            
            # Ensure TLP groups exist
            tlp_groups = [
                ("TLP:RED", "#DC2626", "Traffic Light Protocol - Red"),
                ("TLP:AMBER", "#F59E0B", "Traffic Light Protocol - Amber"),
                ("TLP:GREEN", "#10B981", "Traffic Light Protocol - Green"),
                ("TLP:CLEAR", "#E5E7EB", "Traffic Light Protocol - Clear")
            ]
            
            for name, color, description in tlp_groups:
                existing = self.get_group_by_name(name, conn)
                if not existing:
                    self.create_group(name, color=color, description=description, conn=conn)
            
            # Ensure True Positive and False Positive groups exist
            fp_tp_groups = [
                ("True Positive", "#10B981", "IOCs confirmed as true positives"),
                ("False Positive", "#DC2626", "IOCs identified as false positives")
            ]
            
            for name, color, description in fp_tp_groups:
                existing = self.get_group_by_name(name, conn)
                if not existing:
                    self.create_group(name, color=color, description=description, conn=conn)
    
    # ========== CRUD Sources ==========

    def create_source(self, name: str, context: str, source_type: str, 
                     file_path: Optional[str] = None, original_filename: Optional[str] = None) -> int:
        """Creates a new source and returns its ID. Auto-increments name if duplicate."""
        with self.connection() as conn:
            ody = conn.cursor()

            # Auto-increment name if it already exists
            final_name = name
            counter = 1
            while True:
                ody.execute("SELECT id FROM sources WHERE name = ? AND is_deleted = 0", (final_name,))
                if ody.fetchone() is None:
                    break
                if counter == 1:
                    final_name = f"{name}_1"
                else:
                    final_name = f"{name}_{counter}"
                counter += 1

            ody.execute("""
                INSERT INTO sources (name, context, source_type, file_path, original_filename, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (final_name, context, source_type, file_path, original_filename, get_local_timestamp()))

            source_id = ody.lastrowid
            
            # Invalidate cache when new source is created
            self.invalidate_cache()
            
            # Assign to default group automatically
            # Use the same connection to avoid nested connections
            default_group = self.get_group_by_name("default", conn)
            if not default_group:
                # Create default group if it doesn't exist
                default_group_id = self.create_group("default", color="#6B7280", description="Default group for all sources", conn=conn)
            else:
                default_group_id = default_group['id']
            
            # Add source to default group
            try:
                ody.execute("""
                    INSERT OR IGNORE INTO source_groups (source_id, group_id)
                    VALUES (?, ?)
                """, (source_id, default_group_id))
            except Exception:
                pass  # Ignore if already exists
            
            return source_id

    def get_source(self, source_id: int) -> Optional[Dict]:
        """Retrieves a source by its ID"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("SELECT * FROM sources WHERE id = ?", (source_id,))
        row = ody.fetchone()
        self._close_connection_if_needed(conn)

        if row:
            return dict(row)
        return None

    def update_source_status(self, source_id: int, status: str):
        """Updates a source status"""
        with self.connection() as conn:
            ody = conn.cursor()
            if status == 'completed':
                ody.execute("""
                    UPDATE sources 
                    SET status = ?, processed_at = ?
                    WHERE id = ?
                """, (status, get_local_timestamp(), source_id))
            else:
                ody.execute("""
                    UPDATE sources 
                    SET status = ?
                    WHERE id = ?
                """, (status, source_id))
        # Invalidate cache when source status is updated
        self.invalidate_cache()

    def get_all_sources(self, limit: int = 50) -> List[Dict]:
        """Retrieves all sources (not deleted) with their groups"""
        with self.connection() as conn:
            ody = conn.cursor()
            ody.execute("""
                SELECT s.*, 
                       GROUP_CONCAT(DISTINCT g.id || '|||' || g.name || '|||' || COALESCE(g.color, '')) as group_data
                FROM sources s
                LEFT JOIN source_groups sg ON s.id = sg.source_id
                LEFT JOIN groups g ON sg.group_id = g.id
                WHERE s.is_deleted = 0
                GROUP BY s.id
                ORDER BY s.created_at DESC, s.id DESC
                LIMIT ?
            """, (limit,))

            sources = []
            for row in ody.fetchall():
                source = dict(row)
                # Parse groups
                if source.get("group_data"):
                    groups_list = []
                    for group_str in source["group_data"].split(","):
                        parts = group_str.split("|||", 2)
                        if len(parts) >= 2:
                            group_info = {
                                "id": int(parts[0]),
                                "name": parts[1],
                                "color": parts[2] if len(parts) > 2 and parts[2] else None
                            }
                            groups_list.append(group_info)
                    source["groups"] = groups_list
                else:
                    source["groups"] = []
                sources.append(source)
            
            return sources

    def get_iocs_by_tag_ids(self, tag_ids: List[int]) -> List[Dict]:
        """Returns all non-deleted IOCs that have at least one of the given tag IDs."""
        if not tag_ids:
            return []
        placeholders = ','.join('?' * len(tag_ids))
        with self.connection() as conn:
            rows = conn.execute(f"""
                SELECT DISTINCT i.*
                FROM iocs i
                JOIN ioc_tags it ON it.ioc_id = i.id
                WHERE i.is_deleted = 0
                  AND it.tag_id IN ({placeholders})
                ORDER BY i.created_at DESC
            """, tag_ids).fetchall()
        return [dict(r) for r in rows]

    def get_ioc_type_counts_by_source(self) -> Dict[int, List[Dict]]:
        """Returns IOC type breakdown per source: {source_id: [{'ioc_type': t, 'count': n}, ...]}"""
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT source_id, ioc_type, COUNT(*) AS cnt
                FROM iocs
                WHERE is_deleted = 0
                GROUP BY source_id, ioc_type
                ORDER BY source_id, cnt DESC
            """).fetchall()
        result: Dict[int, List[Dict]] = {}
        for row in rows:
            sid = row['source_id']
            if sid not in result:
                result[sid] = []
            result[sid].append({'ioc_type': row['ioc_type'], 'count': row['cnt']})
        return result

    def count_iocs_by_ttp(self, technique_id: str) -> int:
        """Returns the count of non-deleted TTP IOCs whose value matches a MITRE technique ID."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE is_deleted=0 AND ioc_type='ttp' AND UPPER(ioc_value)=UPPER(?)",
                (technique_id,)
            ).fetchone()
        return row[0] if row else 0


    # ========== Cross-module index & MITRE links ==========

    def upsert_cross_ref(
        self,
        ref_key: str,
        ref_type: str,
        entity_id: str,
        content_hash: str = '',
        status: str = 'active',
    ) -> None:
        with self.connection() as conn:
            conn.execute("""
                INSERT INTO cross_refs (ref_key, ref_type, entity_id, content_hash, status, indexed_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ref_key) DO UPDATE SET
                    content_hash = excluded.content_hash,
                    status = excluded.status,
                    updated_at = excluded.updated_at
            """, (
                ref_key, ref_type, str(entity_id), content_hash or '', status,
                get_local_timestamp(), get_local_timestamp(),
            ))

    def get_cross_ref(self, ref_key: str) -> Optional[Dict]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM cross_refs WHERE ref_key = ?", (ref_key,)
            ).fetchone()
            return dict(row) if row else None

    def mark_cross_ref_status(self, ref_key: str, status: str) -> None:
        with self.connection() as conn:
            conn.execute("""
                UPDATE cross_refs SET status = ?, updated_at = ? WHERE ref_key = ?
            """, (status, get_local_timestamp(), ref_key))

    def get_ioc_ttp_links(self, ioc_id: int) -> List[Dict]:
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT technique_id, confidence, notes, created_at
                FROM ioc_ttp_links WHERE ioc_id = ?
                ORDER BY technique_id
            """, (ioc_id,)).fetchall()
            return [dict(r) for r in rows]

    def ensure_ioc_ttp_link(self, ioc_id: int, technique_id: str, confidence: str = 'medium') -> None:
        tech = (technique_id or '').strip().upper()
        if not tech:
            return
        with self.connection() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO ioc_ttp_links (ioc_id, technique_id, confidence, created_at)
                VALUES (?, ?, ?, ?)
            """, (ioc_id, tech, confidence, get_local_timestamp()))

    def sync_ttp_ioc_link(self, ioc_id: int, ioc_type: str, ioc_value: str) -> None:
        """When an IOC is a MITRE technique id (type ttp), mirror into ioc_ttp_links."""
        from modules.cross_index import normalize_ttp_id
        if (ioc_type or '').lower() not in ('ttp', 'mitre_attack', 'attack', 'mitre attack'):
            return
        tech = normalize_ttp_id(ioc_value)
        if tech:
            self.ensure_ioc_ttp_link(ioc_id, tech)

    def get_workspace_technique_coverage(self, technique_ids: List[str]) -> set:
        """Technique IDs covered by TTP-type IOCs or ioc_ttp_links in active IOCs."""
        if not technique_ids:
            return set()
        placeholders = ','.join(['?'] * len(technique_ids))
        upper = [t.upper() for t in technique_ids]
        covered = set()
        with self.connection() as conn:
            rows = conn.execute(f"""
                SELECT DISTINCT UPPER(ioc_value) FROM iocs
                WHERE is_deleted = 0 AND LOWER(ioc_type) IN ('ttp', 'mitre_attack', 'attack')
                  AND UPPER(ioc_value) IN ({placeholders})
            """, upper).fetchall()
            covered.update(r[0] for r in rows if r[0])
            rows2 = conn.execute(f"""
                SELECT DISTINCT UPPER(itl.technique_id) FROM ioc_ttp_links itl
                JOIN iocs i ON i.id = itl.ioc_id
                WHERE i.is_deleted = 0 AND UPPER(itl.technique_id) IN ({placeholders})
            """, upper).fetchall()
            covered.update(r[0] for r in rows2 if r[0])
        return covered

    def find_active_iocs_by_value(self, ioc_type: str, ioc_value: str, limit: int = 5) -> List[Dict]:
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT id, ioc_type, ioc_value, source_id, tlp, validation_status
                FROM iocs
                WHERE is_deleted = 0 AND LOWER(ioc_type) = LOWER(?) AND ioc_value = ?
                ORDER BY last_seen DESC
                LIMIT ?
            """, (ioc_type, ioc_value, limit)).fetchall()
            return [dict(r) for r in rows]

    # ========== CRUD IOCs ==========

    def create_ioc(self, source_id: int, ioc_type: str, ioc_value: str,
                   raw_value: Optional[str] = None, source_info: Optional[Dict] = None,
                   tlp: str = 'WHITE', validation_status: str = 'Unverified',
                   confidence: str = 'Unknown') -> int:
        """Creates an IOC and returns its ID (or existing ID if duplicate)
        Automatically adds tags based on type, source, etc.
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        # Check if IOC already exists for this source
        cursor.execute("""
            SELECT id, last_seen FROM iocs 
            WHERE source_id = ? AND ioc_type = ? AND ioc_value = ?
        """, (source_id, ioc_type, ioc_value))

        existing = cursor.fetchone()

        if existing:
            # Update last_seen
            cursor.execute("""
                UPDATE iocs 
                SET last_seen = ?
                WHERE id = ?
            """, (get_local_timestamp(), existing["id"]))
            ioc_id = existing["id"]
            conn.commit()
        else:
            # Create new IOC with explicit local timestamps
            local_ts = get_local_timestamp()
            cursor.execute("""
                INSERT INTO iocs (
                    source_id, ioc_type, ioc_value, raw_value, first_seen, last_seen,
                    created_at, tlp, validation_status, confidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                source_id, ioc_type, ioc_value, raw_value or ioc_value, local_ts, local_ts,
                local_ts, tlp, validation_status, confidence,
            ))
            ioc_id = cursor.lastrowid
            
            # Add automatic tags
            self._add_auto_tags(cursor, ioc_id, ioc_type, source_id, source_info)
            
            # Add a tag based on value if it's an appropriate type
            self._add_value_based_tag(cursor, ioc_id, ioc_type, ioc_value)
            
            conn.commit()

        self.sync_ttp_ioc_link(ioc_id, ioc_type, ioc_value)
        self._close_connection_if_needed(conn)
        return ioc_id
    
    def _add_auto_tags(self, ody, ioc_id: int, ioc_type: str, source_id: int, source_info: Optional[Dict] = None):
        """Automatically adds tags to an IOC when auto-tagging is enabled"""
        auto_tag = self.get_setting('auto_tag_enabled', 'true')
        if auto_tag.lower() != 'true':
            return

        from config import IOC_TYPE_TAGS, SOURCE_TYPE_TAGS
        from datetime import datetime
        import json
        
        # Get source info if not provided
        if source_info is None:
            ody.execute("SELECT * FROM sources WHERE id = ?", (source_id,))
            source_row = ody.fetchone()
            if source_row:
                source_info = dict(source_row)
        
        tags_to_add = []
        
        # 1. Tag based on IOC type
        if ioc_type in IOC_TYPE_TAGS:
            tag_name = IOC_TYPE_TAGS[ioc_type]
            tags_to_add.append((tag_name, "ioc_type", "#8B5CF6", True, None))
        
        # 2. Tag based on source type
        if source_info and source_info.get('source_type') in SOURCE_TYPE_TAGS:
            tag_name = SOURCE_TYPE_TAGS[source_info['source_type']]
            tags_to_add.append((tag_name, "source_type", "#6D28D9", True, None))
        
        # 3. Tag based on date (day) with complete metadata
        now = datetime.now()
        day_tag = f"Date:{now.strftime('%Y-%m-%d')}"
        date_metadata = {
            "date": now.isoformat(),
            "year": now.year,
            "month": now.month,
            "day": now.day,
            "hour": now.hour,
            "minute": now.minute,
            "second": now.second,
            "weekday": now.strftime("%A")
        }
        tags_to_add.append((day_tag, "date", "#A78BFA", True, json.dumps(date_metadata)))
        
        # 4. Tag based on source name (always added if available)
        if source_info and source_info.get('name'):
            source_name = source_info['name']
            # Clean name for tag (remove special characters)
            clean_name = source_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
            clean_name = ''.join(c for c in clean_name if c.isalnum() or c in ('_', '-', '.'))[:50]  # Limit length
            if clean_name:
                tags_to_add.append((f"Source:{clean_name}", "source_name", "#10B981", True, json.dumps({"source_name": source_name, "source_id": source_id})))
        
        # 5. Tag based on filename (if available)
        if source_info and source_info.get('original_filename'):
            filename = source_info['original_filename']
            # Extract extension
            if '.' in filename:
                ext = filename.rsplit('.', 1)[1].upper()
                tags_to_add.append((f"Format:{ext}", "file_format", "#DDD6FE", True, json.dumps({"extension": ext})))
        
        # 6. Tag based on context (extract keywords)
        if source_info and source_info.get('context'):
            context = source_info['context'].lower()
            # Detect certain keywords in context
            if any(word in context for word in ['brute', 'force', 'bf']):
                tags_to_add.append(("Brute Force", "attack_type", "#F59E0B", True, None))
            if any(word in context for word in ['phishing', 'email', 'spam']):
                tags_to_add.append(("Phishing", "attack_type", "#EF4444", True, None))
            if any(word in context for word in ['malware', 'virus', 'trojan']):
                tags_to_add.append(("Malware", "attack_type", "#8B5CF6", True, None))
            if any(word in context for word in ['apt', 'advanced persistent']):
                tags_to_add.append(("APT Group", "attack_type", "#DC2626", True, None))
        
        # Add all tags
        for tag_name, category, color, is_auto, metadata in tags_to_add:
            # Create or retrieve tag
            ody.execute("""
                INSERT OR IGNORE INTO tags (name, category, color, is_auto, metadata)
                VALUES (?, ?, ?, ?, ?)
            """, (tag_name, category, color, 1 if is_auto else 0, metadata))
            
            # Get tag ID
            ody.execute("SELECT id FROM tags WHERE name = ?", (tag_name,))
            tag_row = ody.fetchone()
            if tag_row:
                tag_id = tag_row["id"]
                # Associate tag to IOC (if not already associated)
                ody.execute("""
                    INSERT OR IGNORE INTO ioc_tags (ioc_id, tag_id)
                    VALUES (?, ?)
                """, (ioc_id, tag_id))
    
    def _add_value_based_tag(self, ody, ioc_id: int, ioc_type: str, ioc_value: str):
        """Adds a tag based on IOC value if appropriate"""
        # IOC types for which to create value-based tags
        value_based_types = ['domain', 'fqdn', 'ipv4', 'ipv6', 'url', 'email', 
                             'md5', 'sha1', 'sha256', 'sha512', 'cve']
        
        if ioc_type not in value_based_types:
            return
        
        # Check how many IOCs have this value
        ody.execute("""
            SELECT COUNT(*) as count
            FROM iocs
            WHERE ioc_type = ? AND ioc_value = ? AND is_deleted = 0
        """, (ioc_type, ioc_value))
        
        result = ody.fetchone()
        occurrences = result['count'] if result else 0
        
        # Create tag only if value appears at least 2 times
        # (to avoid too many unique tags)
        if occurrences >= 2:
            # Create formatted tag name
            if len(ioc_value) > 50:
                display_value = ioc_value[:47] + "..."
            else:
                display_value = ioc_value
            
            tag_name = f"{ioc_type.capitalize()}:{display_value}"
            
            # Create tag with metadata
            import json
            metadata = {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "occurrences": occurrences
            }
            metadata_json = json.dumps(metadata)
            
            # Color based on type
            color_map = {
                'domain': '#10B981',
                'fqdn': '#10B981',
                'ipv4': '#3B82F6',
                'ipv6': '#3B82F6',
                'url': '#F59E0B',
                'email': '#EC4899',
                'md5': '#8B5CF6',
                'sha1': '#8B5CF6',
                'sha256': '#8B5CF6',
                'sha512': '#8B5CF6',
                'cve': '#EF4444'
            }
            color = color_map.get(ioc_type, '#6B7280')
            
            # Create or retrieve tag
            ody.execute("""
                INSERT OR IGNORE INTO tags (name, category, color, is_auto, metadata)
                VALUES (?, ?, ?, ?, ?)
            """, (tag_name, "ioc_value", color, 1, metadata_json))
            
            # Get tag ID
            ody.execute("SELECT id FROM tags WHERE name = ?", (tag_name,))
            tag_row = ody.fetchone()
            
            if tag_row:
                tag_id = tag_row["id"]
                # Associate tag to IOC
                ody.execute("""
                    INSERT OR IGNORE INTO ioc_tags (ioc_id, tag_id)
                    VALUES (?, ?)
                """, (ioc_id, tag_id))

    def get_ioc(self, ioc_id: int) -> Optional[Dict]:
        """Retrieves an IOC by its ID with its tags"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("SELECT * FROM iocs WHERE id = ?", (ioc_id,))
        row = ody.fetchone()

        if row:
            ioc = dict(row)
            # Get tags with their metadata
            ody.execute("""
                SELECT t.id, t.name, t.category, t.color, t.is_auto, t.metadata
                FROM tags t
                JOIN ioc_tags it ON t.id = it.tag_id
                WHERE it.ioc_id = ?
            """, (ioc_id,))
            ioc["tags"] = [dict(tag) for tag in ody.fetchall()]
            self._close_connection_if_needed(conn)
            return ioc
        self._close_connection_if_needed(conn)
        return None

    def get_iocs_by_source(self, source_id: int) -> List[Dict]:
        """Retrieves all IOCs from a source"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("""
            SELECT i.*, 
                   GROUP_CONCAT(t.name) as tag_names
            FROM iocs i
            LEFT JOIN ioc_tags it ON i.id = it.ioc_id
            LEFT JOIN tags t ON it.tag_id = t.id
            WHERE i.source_id = ?
            GROUP BY i.id
            ORDER BY i.created_at DESC
        """, (source_id,))

        iocs = []
        for row in ody.fetchall():
            ioc = dict(row)
            if ioc["tag_names"]:
                ioc["tags"] = ioc["tag_names"].split(",")
            else:
                ioc["tags"] = []
            iocs.append(ioc)

        self._close_connection_if_needed(conn)
        return iocs

    def _build_filter_query(self, filters: Optional[Dict]) -> Tuple[str, List]:
        """Builds WHERE clause and parameters for IOC filters"""
        where_clause = "WHERE i.is_deleted = 0 AND s.is_deleted = 0"
        params = []
        
        if not filters:
            return where_clause, params
        
        # Base filters
        if filters.get("ioc_type"):
            where_clause += " AND i.ioc_type = ?"
            params.append(filters["ioc_type"])
        if filters.get("ioc_value"):
            where_clause += " AND i.ioc_value = ?"
            params.append(filters["ioc_value"])
        if filters.get("ioc_types"):
            # Support for multiple IOC types
            ioc_types = filters["ioc_types"]
            if isinstance(ioc_types, list) and len(ioc_types) > 0:
                placeholders = ','.join(['?'] * len(ioc_types))
                where_clause += f" AND i.ioc_type IN ({placeholders})"
                params.extend(ioc_types)
        if filters.get("search"):
            # Clean search term: remove leading/trailing spaces and decode URL encoding
            search_term = filters['search'].strip()
            if search_term:
                # Escape special SQL LIKE characters
                search_term = search_term.replace('%', '\\%').replace('_', '\\_')
                search_term = f"%{search_term}%"
                where_clause += " AND (i.ioc_value LIKE ? ESCAPE '\\' OR i.ioc_type LIKE ? ESCAPE '\\')"
                params.extend([search_term, search_term])
        
        # Source name filtering
        if filters.get("source_name"):
            where_clause += " AND s.name = ?"
            params.append(filters["source_name"])
        
        # Group filtering (sources or IOCs)
        if filters.get("group_id"):
            where_clause += " AND (EXISTS (SELECT 1 FROM source_groups sg WHERE sg.source_id = s.id AND sg.group_id = ?) OR EXISTS (SELECT 1 FROM ioc_groups iog WHERE iog.ioc_id = i.id AND iog.group_id = ?))"
            params.extend([filters["group_id"], filters["group_id"]])
        
        # Date/time filters
        if filters.get("date_from"):
            where_clause += " AND DATE(i.created_at) >= ?"
            params.append(filters["date_from"])
        if filters.get("date_to"):
            where_clause += " AND DATE(i.created_at) <= ?"
            params.append(filters["date_to"])
        if filters.get("year"):
            where_clause += " AND strftime('%Y', i.created_at) = ?"
            params.append(str(filters["year"]))
        if filters.get("month"):
            where_clause += " AND strftime('%m', i.created_at) = ?"
            params.append(str(filters["month"]).zfill(2))
        if filters.get("day"):
            where_clause += " AND strftime('%d', i.created_at) = ?"
            params.append(str(filters["day"]).zfill(2))
        if filters.get("hour"):
            where_clause += " AND strftime('%H', i.created_at) = ?"
            params.append(str(filters["hour"]).zfill(2))
        
        # Duplicate filter (IOCs appearing in multiple sources)
        if filters.get("show_duplicates"):
            # Utiliser une sous-requête pour trouver les IOCs en double
            where_clause += """ AND EXISTS (
                SELECT 1 FROM iocs i2
                JOIN sources s2 ON i2.source_id = s2.id
                WHERE i2.ioc_type = i.ioc_type 
                AND i2.ioc_value = i.ioc_value
                AND i2.id != i.id
                AND i2.is_deleted = 0
                AND s2.is_deleted = 0
            )"""
        
        return where_clause, params

    def get_all_iocs(self, filters: Optional[Dict] = None, limit: int = 100, 
                    offset: int = 0) -> Tuple[List[Dict], int]:
        """Retrieves all IOCs with optional filters (including tag filtering)"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Build filters once
        where_clause, params = self._build_filter_query(filters)

        query = f"""
            SELECT i.*, s.name as source_name, s.context as source_context,
                   s.source_type, s.created_at as source_created_at,
                   GROUP_CONCAT(DISTINCT g.id || '|||' || g.name || '|||' || COALESCE(g.color, '')) as source_group_data,
                   GROUP_CONCAT(DISTINCT ig.id || '|||' || ig.name || '|||' || COALESCE(ig.color, '')) as ioc_group_data,
                   GROUP_CONCAT(DISTINCT ex.group_id) as excluded_group_ids
            FROM iocs i
            JOIN sources s ON i.source_id = s.id
            LEFT JOIN source_groups sg ON s.id = sg.source_id
            LEFT JOIN groups g ON sg.group_id = g.id
            LEFT JOIN ioc_groups iog ON i.id = iog.ioc_id
            LEFT JOIN groups ig ON iog.group_id = ig.id
            LEFT JOIN ioc_source_group_exclusions ex ON i.id = ex.ioc_id
            {where_clause}
            GROUP BY i.id
            ORDER BY i.created_at DESC LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        cursor.execute(query, params)
        iocs = []
        for row in cursor.fetchall():
            ioc = dict(row)
            # Parse excluded group IDs
            excluded_group_ids = set()
            if ioc.get("excluded_group_ids"):
                for group_id_str in ioc["excluded_group_ids"].split(","):
                    if group_id_str:
                        try:
                            excluded_group_ids.add(int(group_id_str))
                        except ValueError:
                            pass
            
            # Parse source groups (excluding those in exclusions)
            source_groups_list = []
            if ioc.get("source_group_data"):
                for group_str in ioc["source_group_data"].split(","):
                    if group_str:
                        parts = group_str.split("|||", 2)
                        if len(parts) >= 2:
                            group_id = int(parts[0])
                            # Skip if this group is excluded
                            if group_id not in excluded_group_ids:
                                group_info = {
                                    "id": group_id,
                                    "name": parts[1],
                                    "color": parts[2] if len(parts) > 2 and parts[2] else None
                                }
                                source_groups_list.append(group_info)
            
            # Parse IOC groups (directly associated)
            ioc_groups_list = []
            if ioc.get("ioc_group_data"):
                for group_str in ioc["ioc_group_data"].split(","):
                    if group_str:
                        parts = group_str.split("|||", 2)
                        if len(parts) >= 2:
                            group_info = {
                                "id": int(parts[0]),
                                "name": parts[1],
                                "color": parts[2] if len(parts) > 2 and parts[2] else None
                            }
                            ioc_groups_list.append(group_info)
            
            # Combine both lists, removing duplicates
            all_groups = {}
            for group in source_groups_list + ioc_groups_list:
                all_groups[group["id"]] = group
            ioc["groups"] = list(all_groups.values())
            ioc["source_groups"] = source_groups_list  # Keep source groups separate for hashtag display
            ioc["ioc_groups"] = ioc_groups_list  # Keep direct IOC groups separate for hashtag display
            iocs.append(ioc)

        # Count total with same filters
        count_where_clause, count_params = self._build_filter_query(filters)
        count_query = f"""
            SELECT COUNT(DISTINCT i.id) 
            FROM iocs i
            JOIN sources s ON i.source_id = s.id
            {count_where_clause}
        """

        cursor.execute(count_query, count_params)
        total = cursor.fetchone()[0]

        self._close_connection_if_needed(conn)
        return iocs, total

    def get_all_iocs_streaming(self, filters: Optional[Dict] = None, 
                                limit: Optional[int] = None, 
                                batch_size: int = 1000) -> Iterator[List[Dict]]:
        """
        Retrieves IOCs with streaming for large datasets.
        Yields batches of IOCs to avoid loading everything in memory.
        
        Args:
            filters: Optional filters dict
            limit: Optional maximum number of IOCs to retrieve (None = no limit)
            batch_size: Number of IOCs to retrieve per batch
            
        Yields:
            List of IOC dicts (batch)
        """
        conn = self.get_connection()
        ody = conn.cursor()
        
        # Build filters once
        where_clause, params = self._build_filter_query(filters)
        
        offset = 0
        total_retrieved = 0
        
        while True:
            # Determine batch limit
            batch_limit = batch_size
            if limit is not None:
                remaining = limit - total_retrieved
                if remaining <= 0:
                    break
                batch_limit = min(batch_size, remaining)
            
            query = f"""
                SELECT i.*, s.name as source_name, s.context as source_context,
                       s.source_type, s.created_at as source_created_at,
                       GROUP_CONCAT(DISTINCT g.id || '|||' || g.name || '|||' || COALESCE(g.color, '')) as source_group_data,
                       GROUP_CONCAT(DISTINCT ig.id || '|||' || ig.name || '|||' || COALESCE(ig.color, '')) as ioc_group_data,
                       GROUP_CONCAT(DISTINCT ex.group_id) as excluded_group_ids,
                       GROUP_CONCAT(DISTINCT t.id || '|||' || t.name || '|||' || COALESCE(t.category, '')) as tag_data
                FROM iocs i
                JOIN sources s ON i.source_id = s.id
                LEFT JOIN source_groups sg ON s.id = sg.source_id
                LEFT JOIN groups g ON sg.group_id = g.id
                LEFT JOIN ioc_groups iog ON i.id = iog.ioc_id
                LEFT JOIN groups ig ON iog.group_id = ig.id
                LEFT JOIN ioc_source_group_exclusions ex ON i.id = ex.ioc_id
                LEFT JOIN ioc_tags it ON i.id = it.ioc_id
                LEFT JOIN tags t ON it.tag_id = t.id
                {where_clause}
                GROUP BY i.id
                ORDER BY i.created_at DESC LIMIT ? OFFSET ?
            """
            batch_params = params + [batch_limit, offset]
            
            ody.execute(query, batch_params)
            rows = ody.fetchall()
            
            if not rows:
                break
            
            # Process batch
            iocs = []
            for row in rows:
                ioc = dict(row)
                # Parse excluded group IDs
                excluded_group_ids = set()
                if ioc.get("excluded_group_ids"):
                    for group_id_str in ioc["excluded_group_ids"].split(","):
                        if group_id_str:
                            try:
                                excluded_group_ids.add(int(group_id_str))
                            except ValueError:
                                pass
                
                # Parse source groups
                source_groups_list = []
                if ioc.get("source_group_data"):
                    for group_str in ioc["source_group_data"].split(","):
                        if group_str:
                            parts = group_str.split("|||", 2)
                            if len(parts) >= 2:
                                group_id = int(parts[0])
                                if group_id not in excluded_group_ids:
                                    group_info = {
                                        "id": group_id,
                                        "name": parts[1],
                                        "color": parts[2] if len(parts) > 2 and parts[2] else None
                                    }
                                    source_groups_list.append(group_info)
                
                # Parse IOC groups
                ioc_groups_list = []
                if ioc.get("ioc_group_data"):
                    for group_str in ioc["ioc_group_data"].split(","):
                        if group_str:
                            parts = group_str.split("|||", 2)
                            if len(parts) >= 2:
                                group_info = {
                                    "id": int(parts[0]),
                                    "name": parts[1],
                                    "color": parts[2] if len(parts) > 2 and parts[2] else None
                                }
                                ioc_groups_list.append(group_info)
                
                # Combine groups
                all_groups = {}
                for group in source_groups_list + ioc_groups_list:
                    all_groups[group["id"]] = group
                ioc["groups"] = list(all_groups.values())
                ioc["source_groups"] = source_groups_list
                ioc["ioc_groups"] = ioc_groups_list
                
                # Parse tags
                tags_list = []
                if ioc.get("tag_data"):
                    for tag_str in ioc["tag_data"].split(","):
                        if tag_str:
                            parts = tag_str.split("|||", 2)
                            if len(parts) >= 2:
                                tag_info = {
                                    "id": int(parts[0]),
                                    "name": parts[1],
                                    "category": parts[2] if len(parts) > 2 and parts[2] else None
                                }
                                tags_list.append(tag_info)
                ioc["tags"] = tags_list
                
                iocs.append(ioc)
            
            yield iocs
            
            total_retrieved += len(iocs)
            offset += batch_limit
            
            # Check if we've reached the limit
            if limit is not None and total_retrieved >= limit:
                break
            
            # If we got fewer rows than requested, we're done
            if len(rows) < batch_limit:
                break
        
        self._close_connection_if_needed(conn)


    def update_ioc_notes(self, ioc_id: int, notes: str):
        """Updates IOC notes"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("""
            UPDATE iocs 
            SET notes = ?
            WHERE id = ?
        """, (notes, ioc_id))

        conn.commit()
        self._close_connection_if_needed(conn)
        # Invalidate cache when IOC is updated
        self.invalidate_cache()

    def check_duplicate(self, ioc_type: str, ioc_value: str, source_id: int) -> Optional[int]:
        """Checks if an IOC already exists for this source"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("""
            SELECT id FROM iocs 
            WHERE source_id = ? AND ioc_type = ? AND ioc_value = ?
        """, (source_id, ioc_type, ioc_value))

        row = ody.fetchone()
        self._close_connection_if_needed(conn)

        if row:
            return row["id"]
        return None

    # ========== CRUD Tags ==========

    def get_all_tags(self, category: Optional[str] = None, include_stats: bool = False, only_with_iocs: bool = True) -> List[Dict]:
        """Retrieves all tags, optionally filtered by category, with optional statistics"""
        conn = self.get_connection()
        ody = conn.cursor()

        if include_stats:
            # Get tags with number of associated IOCs
            # Filter only tags that have at least one non-deleted IOC
            if category:
                query = """
                    SELECT t.*, COUNT(DISTINCT it.ioc_id) as ioc_count
                    FROM tags t
                    INNER JOIN ioc_tags it ON t.id = it.tag_id
                    INNER JOIN iocs i ON it.ioc_id = i.id AND i.is_deleted = 0
                    WHERE t.category = ?
                    GROUP BY t.id
                    HAVING COUNT(DISTINCT it.ioc_id) > 0
                    ORDER BY ioc_count DESC, t.name
                """
                ody.execute(query, (category,))
            else:
                query = """
                    SELECT t.*, COUNT(DISTINCT it.ioc_id) as ioc_count
                    FROM tags t
                    INNER JOIN ioc_tags it ON t.id = it.tag_id
                    INNER JOIN iocs i ON it.ioc_id = i.id AND i.is_deleted = 0
                    GROUP BY t.id
                    HAVING COUNT(DISTINCT it.ioc_id) > 0
                    ORDER BY t.category, ioc_count DESC, t.name
                """
                ody.execute(query)
        else:
            if only_with_iocs:
                # Filter only tags with IOCs even without stats
                if category:
                    query = """
                        SELECT DISTINCT t.*
                        FROM tags t
                        INNER JOIN ioc_tags it ON t.id = it.tag_id
                        INNER JOIN iocs i ON it.ioc_id = i.id AND i.is_deleted = 0
                        WHERE t.category = ?
                        ORDER BY t.name
                    """
                    ody.execute(query, (category,))
                else:
                    query = """
                        SELECT DISTINCT t.*
                        FROM tags t
                        INNER JOIN ioc_tags it ON t.id = it.tag_id
                        INNER JOIN iocs i ON it.ioc_id = i.id AND i.is_deleted = 0
                        ORDER BY t.category, t.name
                    """
                    ody.execute(query)
            else:
                if category:
                    ody.execute("SELECT * FROM tags WHERE category = ? ORDER BY name", (category,))
                else:
                    ody.execute("SELECT * FROM tags ORDER BY category, name")
        
        tags = []
        for row in ody.fetchall():
            tag = dict(row)
            if include_stats:
                tag['ioc_count'] = tag.get('ioc_count', 0)
            tags.append(tag)
        
        self._close_connection_if_needed(conn)
        return tags
    

    def create_tag(self, name: str, category: str = "custom", color: Optional[str] = None) -> int:
        """Creates a new tag and returns its ID"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("""
            INSERT OR IGNORE INTO tags (name, category, color)
            VALUES (?, ?, ?)
        """, (name, category, color or "#8B5CF6"))

        ody.execute("SELECT id FROM tags WHERE name = ?", (name,))
        tag_id = ody.fetchone()["id"]

        conn.commit()
        self._close_connection_if_needed(conn)
        return tag_id


    def add_tag_to_ioc(self, ioc_id: int, tag_id: int):
        """Adds a tag to an IOC"""
        conn = self.get_connection()
        ody = conn.cursor()

        # Check if tag is not already associated
        ody.execute("""
            SELECT 1 FROM ioc_tags 
            WHERE ioc_id = ? AND tag_id = ?
        """, (ioc_id, tag_id))

        if not ody.fetchone():
            ody.execute("""
                INSERT INTO ioc_tags (ioc_id, tag_id)
                VALUES (?, ?)
            """, (ioc_id, tag_id))

            # Add to history
            ody.execute("""
                INSERT INTO tag_history (ioc_id, tag_id, action)
                VALUES (?, ?, 'added')
            """, (ioc_id, tag_id))

        conn.commit()
        self._close_connection_if_needed(conn)

    def remove_tag_from_ioc(self, ioc_id: int, tag_id: int):
        """Retire un tag d'un IOC"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("""
            DELETE FROM ioc_tags 
            WHERE ioc_id = ? AND tag_id = ?
        """, (ioc_id, tag_id))

        # Add to history
        ody.execute("""
            INSERT INTO tag_history (ioc_id, tag_id, action)
            VALUES (?, ?, 'removed')
        """, (ioc_id, tag_id))

        conn.commit()
        self._close_connection_if_needed(conn)

    def get_tag_history(self, ioc_id: int) -> List[Dict]:
        """Retrieves tag history for an IOC"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("""
            SELECT th.*, t.name as tag_name, t.color as tag_color
            FROM tag_history th
            JOIN tags t ON th.tag_id = t.id
            WHERE th.ioc_id = ?
            ORDER BY th.created_at DESC
        """, (ioc_id,))

        history = [dict(row) for row in ody.fetchall()]
        self._close_connection_if_needed(conn)
        return history

    # ========== CRUD Source Templates ==========


    def get_all_source_templates(self, source_type: Optional[str] = None) -> List[Dict]:
        """Retrieves all source templates, optionally filtered by type"""
        conn = self.get_connection()
        ody = conn.cursor()

        if source_type:
            ody.execute("""
                SELECT * FROM source_templates 
                WHERE source_type = ?
                ORDER BY name
            """, (source_type,))
        else:
            ody.execute("""
                SELECT * FROM source_templates 
                ORDER BY source_type, name
            """)

        templates = []
        import json
        for row in ody.fetchall():
            template = dict(row)
            # Parse JSON tags
            if template.get('tags'):
                try:
                    tags_data = json.loads(template['tags'])
                    template['tag_ids'] = tags_data.get('tag_ids', [])
                except Exception:
                    # Invalid JSON, use empty list
                    template['tag_ids'] = []
            else:
                template['tag_ids'] = []
            templates.append(template)
        self._close_connection_if_needed(conn)
        return templates




    # ========== CRUD Settings ==========

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves a setting value"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = ody.fetchone()
        self._close_connection_if_needed(conn)

        if row:
            return row["value"]
        return default

    def set_setting(self, key: str, value: str) -> bool:
        """Sets a setting value"""
        with self.connection() as conn:
            ody = conn.cursor()
            ody.execute("""
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (key, value, get_local_timestamp()))
        return True

    def get_all_settings(self) -> Dict[str, str]:
        """Retrieves all settings"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("SELECT key, value FROM settings")
        settings = {row["key"]: row["value"] for row in ody.fetchall()}
        self._close_connection_if_needed(conn)
        return settings

    # ========== CRUD Generated Reports ==========

    def create_generated_report(self, source_id: int, report_type: str, file_path: str) -> int:
        """Creates an entry for a generated report"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("""
            INSERT INTO generated_reports (source_id, report_type, file_path)
            VALUES (?, ?, ?)
        """, (source_id, report_type, str(file_path)))

        report_id = ody.lastrowid
        conn.commit()
        self._close_connection_if_needed(conn)
        return report_id

    def get_reports_by_source(self, source_id: int) -> List[Dict]:
        """Retrieves all generated reports for a source"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("""
            SELECT * FROM generated_reports
            WHERE source_id = ?
            ORDER BY created_at DESC
        """, (source_id,))

        reports = [dict(row) for row in ody.fetchall()]
        self._close_connection_if_needed(conn)
        return reports

    def get_report(self, report_id: int) -> Optional[Dict]:
        """Retrieves a report by its ID"""
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("SELECT * FROM generated_reports WHERE id = ?", (report_id,))
        row = ody.fetchone()
        self._close_connection_if_needed(conn)

        if row:
            return dict(row)
        return None


    # ========== Statistiques ==========

    def get_statistics(self) -> Dict:
        """Retrieves global statistics with comprehensive KPIs.
        Uses cache to improve performance on repeated calls."""
        from datetime import datetime, timedelta
        
        # Check cache first
        cache_key = self._get_cache_key("stats", {})
        cached_stats = self._get_cached_metadata(cache_key)
        if cached_stats is not None:
            return cached_stats
        
        with self.connection() as conn:
            ody = conn.cursor()

        stats = {}
        now = datetime.now()

        # Total number of sources (exclude deleted)
        ody.execute("SELECT COUNT(*) FROM sources WHERE is_deleted = 0")
        stats["total_sources"] = ody.fetchone()[0]

        # Total number of IOCs (exclude deleted and those whose source is deleted)
        ody.execute("""
            SELECT COUNT(*) 
            FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.is_deleted = 0 
            AND s.is_deleted = 0
        """)
        stats["total_iocs"] = ody.fetchone()[0]

        # Distribution by type (exclude deleted and those whose source is deleted)
        ody.execute("""
            SELECT i.ioc_type, COUNT(*) as count
            FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.is_deleted = 0 
            AND s.is_deleted = 0
            GROUP BY i.ioc_type
            ORDER BY count DESC
            LIMIT 10
        """)
        stats["by_type"] = {row["ioc_type"]: row["count"] for row in ody.fetchall()}

        # ========== 1. TENDANCES TEMPORELLES ==========
        # IOCs ajoutés (24h, 7j, 30j)
        date_24h = (now - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        date_7d = (now - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
        date_30d = (now - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
        
        ody.execute("""
            SELECT COUNT(*) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.created_at >= ? AND i.is_deleted = 0 AND s.is_deleted = 0
        """, (date_24h,))
        stats["iocs_24h"] = ody.fetchone()[0]
        
        ody.execute("""
            SELECT COUNT(*) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.created_at >= ? AND i.is_deleted = 0 AND s.is_deleted = 0
        """, (date_7d,))
        stats["iocs_7d"] = ody.fetchone()[0]
        
        ody.execute("""
            SELECT COUNT(*) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.created_at >= ? AND i.is_deleted = 0 AND s.is_deleted = 0
        """, (date_30d,))
        stats["iocs_30d"] = ody.fetchone()[0]
        
        # Sources ajoutées (24h, 7j, 30j)
        ody.execute("""
            SELECT COUNT(*) FROM sources WHERE created_at >= ? AND is_deleted = 0
        """, (date_24h,))
        stats["sources_24h"] = ody.fetchone()[0]
        
        ody.execute("""
            SELECT COUNT(*) FROM sources WHERE created_at >= ? AND is_deleted = 0
        """, (date_7d,))
        stats["sources_7d"] = ody.fetchone()[0]
        
        ody.execute("""
            SELECT COUNT(*) FROM sources WHERE created_at >= ? AND is_deleted = 0
        """, (date_30d,))
        stats["sources_30d"] = ody.fetchone()[0]
        
        # Nouveaux IOCs uniques (première apparition - last 24h)
        ody.execute("""
            SELECT COUNT(DISTINCT i.ioc_type || '||' || i.ioc_value)
            FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.first_seen >= ? AND i.is_deleted = 0 AND s.is_deleted = 0
        """, (date_24h,))
        stats["new_unique_iocs_24h"] = ody.fetchone()[0]

        # ========== 2. RÉPARTITION PAR TYPE ==========
        # Top 5 types d'IOC
        ody.execute("""
            SELECT i.ioc_type, COUNT(*) as count
            FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.is_deleted = 0 AND s.is_deleted = 0
            GROUP BY i.ioc_type
            ORDER BY count DESC
            LIMIT 5
        """)
        stats["top5_types"] = [{"type": row["ioc_type"], "count": row["count"]} for row in ody.fetchall()]
        
        # Distribution par catégorie
        category_mapping = {
            'url': 'Network', 'fqdn': 'Network', 'ip4': 'Network', 'ip6': 'Network',
            'md5': 'Hash', 'sha1': 'Hash', 'sha256': 'Hash',
            'bitcoin': 'Blockchain', 'ethereum': 'Blockchain', 'monero': 'Blockchain',
            'email': 'Communication', 'phoneNumber': 'Communication',
            'cve': 'Vulnerability', 'ttp': 'Vulnerability'
        }
        
        ody.execute("""
            SELECT i.ioc_type, COUNT(*) as count
            FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.is_deleted = 0 AND s.is_deleted = 0
            GROUP BY i.ioc_type
        """)
        category_counts = {}
        for row in ody.fetchall():
            ioc_type_lower = row["ioc_type"].lower()
            category = category_mapping.get(ioc_type_lower, 'Autre')
            category_counts[category] = category_counts.get(category, 0) + row["count"]
        stats["by_category"] = category_counts

        # ========== 3. QUALITY AND VALIDATION ==========
        # Ratio True Positive / False Positive
        # Count IOCs with True Positive directly OR via their source
        ody.execute("""
            SELECT COUNT(DISTINCT i.id) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            LEFT JOIN ioc_groups iog ON i.id = iog.ioc_id
            LEFT JOIN groups ig ON iog.group_id = ig.id AND ig.name = 'True Positive'
            LEFT JOIN source_groups sg ON s.id = sg.source_id
            LEFT JOIN groups sg_g ON sg.group_id = sg_g.id AND sg_g.name = 'True Positive'
            WHERE i.is_deleted = 0 AND s.is_deleted = 0 
            AND (ig.id IS NOT NULL OR sg_g.id IS NOT NULL)
        """)
        stats["true_positive_count"] = ody.fetchone()[0]
        
        # Count IOCs with False Positive directly OR via their source
        ody.execute("""
            SELECT COUNT(DISTINCT i.id) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            LEFT JOIN ioc_groups iog ON i.id = iog.ioc_id
            LEFT JOIN groups ig ON iog.group_id = ig.id AND ig.name = 'False Positive'
            LEFT JOIN source_groups sg ON s.id = sg.source_id
            LEFT JOIN groups sg_g ON sg.group_id = sg_g.id AND sg_g.name = 'False Positive'
            WHERE i.is_deleted = 0 AND s.is_deleted = 0 
            AND (ig.id IS NOT NULL OR sg_g.id IS NOT NULL)
        """)
        stats["false_positive_count"] = ody.fetchone()[0]
        
        total_validated = stats["true_positive_count"] + stats["false_positive_count"]
        if total_validated > 0:
            stats["true_positive_ratio"] = round((stats["true_positive_count"] / total_validated) * 100, 1)
        else:
            stats["true_positive_ratio"] = 0
        
        # IOCs without validation group (neither directly, nor via source)
        ody.execute("""
            SELECT COUNT(DISTINCT i.id) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            LEFT JOIN ioc_groups iog ON i.id = iog.ioc_id
            LEFT JOIN groups ig ON iog.group_id = ig.id AND ig.name IN ('True Positive', 'False Positive')
            LEFT JOIN source_groups sg ON s.id = sg.source_id
            LEFT JOIN groups sg_g ON sg.group_id = sg_g.id AND sg_g.name IN ('True Positive', 'False Positive')
            WHERE i.is_deleted = 0 AND s.is_deleted = 0 
            AND ig.id IS NULL AND sg_g.id IS NULL
        """)
        stats["iocs_without_validation"] = ody.fetchone()[0]

        # ========== 4. ACTIVITÉ RÉCENTE ==========
        # IOCs vus pour la première fois (last 24h)
        ody.execute("""
            SELECT COUNT(*) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.first_seen >= ? AND i.is_deleted = 0 AND s.is_deleted = 0
        """, (date_24h,))
        stats["first_seen_24h"] = ody.fetchone()[0]
        
        # IOCs récurrents (apparus plusieurs fois - même type+valeur dans sources différentes)
        ody.execute("""
            SELECT i.ioc_type || '||' || i.ioc_value as ioc_key, COUNT(DISTINCT i.source_id) as source_count
            FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.is_deleted = 0 AND s.is_deleted = 0
            GROUP BY ioc_key
            HAVING source_count > 1
        """)
        stats["recurrent_iocs_count"] = len(ody.fetchall())
        
        # Sources les plus productives (top 5)
        ody.execute("""
            SELECT s.name, COUNT(i.id) as ioc_count
            FROM sources s
            JOIN iocs i ON s.id = i.source_id
            WHERE s.is_deleted = 0 AND i.is_deleted = 0
            GROUP BY s.id, s.name
            ORDER BY ioc_count DESC
            LIMIT 5
        """)
        stats["top5_sources"] = [{"name": row["name"], "count": row["ioc_count"]} for row in ody.fetchall()]

        # ========== 5. TLP ET CLASSIFICATION ==========
        # TLP can be attached directly to IOCs OR to sources
        tlp_counts = {}
        for tlp in ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:RED']:
            # Count IOCs with TLP directly attached
            ody.execute("""
                SELECT COUNT(DISTINCT i.id) FROM iocs i
                JOIN ioc_groups iog ON i.id = iog.ioc_id
                JOIN groups g ON iog.group_id = g.id
                JOIN sources s ON i.source_id = s.id
                WHERE g.name = ? AND i.is_deleted = 0 AND s.is_deleted = 0
            """, (tlp,))
            count_ioc_tlp = ody.fetchone()[0]
            
            # Count IOCs with TLP via their source (without direct TLP on the IOC)
            ody.execute("""
                SELECT COUNT(DISTINCT i.id) FROM iocs i
                JOIN sources s ON i.source_id = s.id
                JOIN source_groups sg ON s.id = sg.source_id
                JOIN groups g ON sg.group_id = g.id
                LEFT JOIN ioc_groups iog ON i.id = iog.ioc_id
                LEFT JOIN groups ig ON iog.group_id = ig.id AND ig.name LIKE 'TLP:%'
                WHERE g.name = ? AND i.is_deleted = 0 AND s.is_deleted = 0 AND ig.id IS NULL
            """, (tlp,))
            count_source_tlp = ody.fetchone()[0]
            
            tlp_counts[tlp.replace('TLP:', '')] = count_ioc_tlp + count_source_tlp
        stats["tlp_distribution"] = tlp_counts
        
        # IOCs not classified TLP (neither directly, nor via source)
        ody.execute("""
            SELECT COUNT(DISTINCT i.id) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            LEFT JOIN ioc_groups iog ON i.id = iog.ioc_id
            LEFT JOIN groups ig ON iog.group_id = ig.id AND ig.name LIKE 'TLP:%'
            LEFT JOIN source_groups sg ON s.id = sg.source_id
            LEFT JOIN groups sg_g ON sg.group_id = sg_g.id AND sg_g.name LIKE 'TLP:%'
            WHERE i.is_deleted = 0 AND s.is_deleted = 0 
            AND ig.id IS NULL AND sg_g.id IS NULL
        """)
        stats["iocs_without_tlp"] = ody.fetchone()[0]

        # ========== 6. MÉTRIQUES OPÉRATIONNELLES ==========
        # Temps moyen de traitement des sources (sources complétées)
        ody.execute("""
            SELECT AVG((julianday(processed_at) - julianday(created_at)) * 24 * 60) as avg_minutes
            FROM sources
            WHERE status = 'completed' AND processed_at IS NOT NULL AND is_deleted = 0
        """)
        result = ody.fetchone()[0]
        stats["avg_processing_time_minutes"] = round(result, 1) if result else 0
        
        # Taux de duplication
        ody.execute("""
            SELECT COUNT(*) as total, COUNT(DISTINCT ioc_type || '||' || ioc_value) as unique_count
            FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.is_deleted = 0 AND s.is_deleted = 0
        """)
        dup_result = ody.fetchone()
        total_iocs_all = dup_result[0]
        unique_iocs = dup_result[1]
        if total_iocs_all > 0:
            stats["duplication_rate"] = round(((total_iocs_all - unique_iocs) / total_iocs_all) * 100, 1)
        else:
            stats["duplication_rate"] = 0
        
        # IOCs avec notes
        ody.execute("""
            SELECT COUNT(*) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.notes IS NOT NULL AND i.notes != '' AND i.is_deleted = 0 AND s.is_deleted = 0
        """)
        stats["iocs_with_notes"] = ody.fetchone()[0]

        # ========== 7. ALERTES ET VIGILANCE ==========
        # IOCs critiques (TLP:RED + True Positive) - peut être via IOC ou source
        ody.execute("""
            SELECT COUNT(DISTINCT i.id) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            LEFT JOIN ioc_groups iog_tlp ON i.id = iog_tlp.ioc_id
            LEFT JOIN groups g_tlp_ioc ON iog_tlp.group_id = g_tlp_ioc.id AND g_tlp_ioc.name = 'TLP:RED'
            LEFT JOIN source_groups sg_tlp ON s.id = sg_tlp.source_id
            LEFT JOIN groups g_tlp_src ON sg_tlp.group_id = g_tlp_src.id AND g_tlp_src.name = 'TLP:RED'
            LEFT JOIN ioc_groups iog_pos ON i.id = iog_pos.ioc_id
            LEFT JOIN groups g_pos_ioc ON iog_pos.group_id = g_pos_ioc.id AND g_pos_ioc.name = 'True Positive'
            LEFT JOIN source_groups sg_pos ON s.id = sg_pos.source_id
            LEFT JOIN groups g_pos_src ON sg_pos.group_id = g_pos_src.id AND g_pos_src.name = 'True Positive'
            WHERE i.is_deleted = 0 AND s.is_deleted = 0
            AND (g_tlp_ioc.id IS NOT NULL OR g_tlp_src.id IS NOT NULL)
            AND (g_pos_ioc.id IS NOT NULL OR g_pos_src.id IS NOT NULL)
        """)
        stats["critical_iocs"] = ody.fetchone()[0]
        
        # Recent IOCs without validation (last 24h - neither True Positive nor False Positive)
        ody.execute("""
            SELECT COUNT(DISTINCT i.id) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            LEFT JOIN ioc_groups iog ON i.id = iog.ioc_id
            LEFT JOIN groups g ON iog.group_id = g.id AND g.name IN ('True Positive', 'False Positive')
            LEFT JOIN source_groups sg ON s.id = sg.source_id
            LEFT JOIN groups sg_g ON sg.group_id = sg_g.id AND sg_g.name IN ('True Positive', 'False Positive')
            WHERE i.created_at >= ? AND i.is_deleted = 0 AND s.is_deleted = 0
            AND g.id IS NULL AND sg_g.id IS NULL
        """, (date_24h,))
        stats["recent_unvalidated_24h"] = ody.fetchone()[0]
        
        # Sources in error
        ody.execute("""
            SELECT COUNT(*) FROM sources WHERE status = 'error' AND is_deleted = 0
        """)
        stats["sources_in_error"] = ody.fetchone()[0]

        # ========== 8. ENRICHISSEMENT ==========
        # IOCs avec URLs de requête disponibles (estimation basée sur les types supportés)
        supported_types = ['URL', 'FQDN', 'DOMAIN', 'IP', 'IPV4', 'IPV6', 'MD5', 'SHA1', 'SHA256', 
                          'BITCOIN', 'ETHEREUM', 'CVE', 'TTP', 'MITRE_ATTACK', 'EMAIL', 
                          'TWITTER', 'GITHUB', 'INSTAGRAM', 'LINKEDIN', 'FACEBOOK', 'YOUTUBE', 
                          'TELEGRAM', 'PINTEREST', 'PACKAGE_ANDROID', 'WEBMONEY', 'url', 'fqdn', 
                          'domain', 'ip4', 'ip6', 'md5', 'sha1', 'sha256', 'bitcoin', 'ethereum', 
                          'cve', 'ttp', 'email', 'twitter', 'github', 'instagram', 'linkedin', 
                          'facebook', 'youtube', 'telegram', 'pinterest', 'packagename', 'webmoney']
        placeholders = ','.join(['?'] * len(supported_types))
        ody.execute(f"""
            SELECT COUNT(*) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE UPPER(i.ioc_type) IN ({placeholders}) AND i.is_deleted = 0 AND s.is_deleted = 0
        """, [t.upper() for t in supported_types])
        stats["iocs_with_query_urls"] = ody.fetchone()[0]
        
        # IOCs sans notes
        ody.execute("""
            SELECT COUNT(*) FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE (i.notes IS NULL OR i.notes = '') AND i.is_deleted = 0 AND s.is_deleted = 0
        """)
        stats["iocs_without_notes"] = ody.fetchone()[0]
        
        # Cache the results for better performance
        self._set_cached_metadata(cache_key, stats)
        
        return stats

    def get_unique_ioc_types(self) -> List[str]:
        """Retrieves unique IOC types present in the database"""
        cache_key = "unique_ioc_types"
        cached = self._get_cached_metadata(cache_key)
        if cached is not None:
            return cached
        
        conn = self.get_connection()
        ody = conn.cursor()
        
        ody.execute("""
            SELECT DISTINCT i.ioc_type
            FROM iocs i
            JOIN sources s ON i.source_id = s.id
            WHERE i.is_deleted = 0 
            AND s.is_deleted = 0
            ORDER BY i.ioc_type
        """)
        
        types = [row["ioc_type"] for row in ody.fetchall()]
        self._close_connection_if_needed(conn)
        
        # Cache the result
        self._set_cached_metadata(cache_key, types)
        return types

    def get_unique_source_names(self) -> List[str]:
        """Retrieves unique source names present in the database"""
        cache_key = "unique_source_names"
        cached = self._get_cached_metadata(cache_key)
        if cached is not None:
            return cached
        
        conn = self.get_connection()
        ody = conn.cursor()
        
        ody.execute("""
            SELECT DISTINCT s.name
            FROM sources s
            JOIN iocs i ON s.id = i.source_id
            WHERE i.is_deleted = 0 
            AND s.is_deleted = 0
            ORDER BY s.name
        """)
        
        names = [row["name"] for row in ody.fetchall()]
        self._close_connection_if_needed(conn)
        
        # Cache the result
        self._set_cached_metadata(cache_key, names)
        return names

    # ========== TRASH IOCs ==========

    def cleanup_orphaned_tags(self):
        """Cleans up tags that no longer have associated IOCs (non-deleted)"""
        with self.connection() as conn:
            ody = conn.cursor()
            # Remove tag associations with deleted IOCs
            ody.execute("""
                DELETE FROM ioc_tags 
                WHERE ioc_id IN (SELECT id FROM iocs WHERE is_deleted = 1)
            """)

    def soft_delete_ioc(self, ioc_id: int) -> bool:
        """Moves an IOC to trash (soft delete)"""
        with self.connection() as conn:
            ody = conn.cursor()
            ody.execute("""
                UPDATE iocs 
                SET is_deleted = 1, deleted_at = ?
                WHERE id = ?
            """, (get_local_timestamp(), ioc_id))
            success = ody.rowcount > 0
        
        # Clean up orphaned tags after deletion (in separate transaction)
        if success:
            self.cleanup_orphaned_tags()
            self.invalidate_cache()
            try:
                from modules.cross_index import make_ref
                from modules import zettelforge_bridge as zf
                zf.mark_ref_deleted(make_ref('ioc', ioc_id))
            except Exception as exc:
                logger.debug('cross_ref ioc delete hook: %s', exc)
        
        return success


    def hard_delete_ioc(self, ioc_id: int) -> bool:
        """Permanently deletes an IOC"""
        with self.connection() as conn:
            ody = conn.cursor()
            ody.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
            success = ody.rowcount > 0
        
        # Clean up orphaned tags after deletion (in separate transaction)
        if success:
            self.cleanup_orphaned_tags()
            self.invalidate_cache()
            try:
                from modules.cross_index import make_ref
                from modules import zettelforge_bridge as zf
                zf.mark_ref_deleted(make_ref('ioc', ioc_id))
            except Exception as exc:
                logger.debug('cross_ref ioc hard delete hook: %s', exc)
        
        return success



    # ========== SOURCES TRASH ==========


    def soft_delete_source(self, source_id: int) -> bool:
        """Moves a source to trash (soft delete)"""
        with self.connection() as conn:
            ody = conn.cursor()
            ody.execute("""
                UPDATE sources 
                SET is_deleted = 1, deleted_at = ?
                WHERE id = ? AND is_deleted = 0
            """, (get_local_timestamp(), source_id))
            success = ody.rowcount > 0
            if success:
                self.invalidate_cache()
                try:
                    from modules.cross_index import make_ref
                    from modules import zettelforge_bridge as zf
                    zf.mark_ref_deleted(make_ref('source', source_id))
                except Exception as exc:
                    logger.debug('cross_ref source delete hook: %s', exc)
            return success

    def hard_delete_source(self, source_id: int) -> bool:
        """Permanently deletes a source"""
        with self.connection() as conn:
            ody = conn.cursor()
            ody.execute("DELETE FROM sources WHERE id = ?", (source_id,))
            success = ody.rowcount > 0
            if success:
                # Invalidate cache when source is permanently deleted
                self.invalidate_cache()
            return success

    def delete_all_sources(self) -> int:
        """Permanently deletes ALL sources and their associated IOCs"""
        try:
            with self.connection() as conn:
                ody = conn.cursor()
                
                # Count sources before deletion
                ody.execute("SELECT COUNT(*) FROM sources")
                source_count = ody.fetchone()[0]
                
                # Count IOCs before deletion
                ody.execute("SELECT COUNT(*) FROM iocs")
                ioc_count = ody.fetchone()[0]
                
                logger.info(f"About to delete {source_count} sources and {ioc_count} IOCs")
                
                # Delete all IOCs first (foreign key constraint)
                ody.execute("DELETE FROM iocs")
                deleted_iocs = ody.rowcount
                
                # Delete all sources
                ody.execute("DELETE FROM sources")
                deleted_sources = ody.rowcount
                
                # Clean up all orphaned tags (since all IOCs are deleted)
                ody.execute("DELETE FROM ioc_tags")
                
                # Clean up all group associations
                ody.execute("DELETE FROM ioc_groups")
                ody.execute("DELETE FROM source_groups")
                ody.execute("DELETE FROM ioc_source_group_exclusions")
                
                logger.info(f"Successfully deleted {deleted_sources} sources and {deleted_iocs} IOCs")
                return deleted_sources
        except Exception as e:
            logger.error(f"Error in delete_all_sources: {e}")
            raise

    def delete_all_iocs(self) -> int:
        """Permanently deletes ALL IOCs"""
        try:
            with self.connection() as conn:
                ody = conn.cursor()
                
                # Count IOCs before deletion
                ody.execute("SELECT COUNT(*) FROM iocs")
                ioc_count = ody.fetchone()[0]
                
                logger.info(f"About to delete {ioc_count} IOCs")
                
                # Delete all IOCs
                ody.execute("DELETE FROM iocs")
                deleted_iocs = ody.rowcount
                
                # Clean up all orphaned tags (since all IOCs are deleted)
                ody.execute("DELETE FROM ioc_tags")
                
                # Clean up all IOC group associations
                ody.execute("DELETE FROM ioc_groups")
                ody.execute("DELETE FROM ioc_source_group_exclusions")
                
                logger.info(f"Successfully deleted {deleted_iocs} IOCs")
                return deleted_iocs
        except Exception as e:
            logger.error(f"Error in delete_all_iocs: {e}")
            raise



    def cleanup_trash(self, days: int = 5) -> int:
        """Permanently deletes sources in trash older than specified days"""
        conn = self.get_connection()
        ody = conn.cursor()
        
        ody.execute("""
            SELECT id FROM sources 
            WHERE is_deleted = 1 
            AND deleted_at < datetime('now', '-' || ? || ' days')
        """, (days,))
        
        source_ids = [row[0] for row in ody.fetchall()]
        count = len(source_ids)
        
        if count > 0:
            placeholders = ','.join(['?'] * count)
            ody.execute(f"DELETE FROM sources WHERE id IN ({placeholders})", source_ids)
        
        conn.commit()
        self._close_connection_if_needed(conn)
        return count

    def rotate_sources_if_needed(self, max_sources: int) -> int:
        """Rotates sources by deleting oldest ones if count exceeds max_sources"""
        conn = self.get_connection()
        ody = conn.cursor()
        
        # Count non-deleted sources
        ody.execute("SELECT COUNT(*) FROM sources WHERE is_deleted = 0")
        current_count = ody.fetchone()[0]
        
        if current_count <= max_sources:
            self._close_connection_if_needed(conn)
            return 0
        
        # Get oldest sources to delete
        excess_count = current_count - max_sources
        ody.execute("""
            SELECT id FROM sources 
            WHERE is_deleted = 0 
            ORDER BY created_at ASC 
            LIMIT ?
        """, (excess_count,))
        
        source_ids = [row[0] for row in ody.fetchall()]
        deleted_count = len(source_ids)
        
        if deleted_count > 0:
            placeholders = ','.join(['?'] * deleted_count)
            ody.execute(f"DELETE FROM sources WHERE id IN ({placeholders})", source_ids)
        
        conn.commit()
        self._close_connection_if_needed(conn)
        return deleted_count

    # ========== GROUPS MANAGEMENT ==========

    def get_all_groups(self) -> List[Dict]:
        """Retrieves all groups"""
        cache_key = "all_groups"
        cached = self._get_cached_metadata(cache_key)
        if cached is not None:
            return cached
        
        conn = self.get_connection()
        ody = conn.cursor()

        ody.execute("""
            SELECT * FROM groups
            ORDER BY name
        """)

        groups = [dict(row) for row in ody.fetchall()]
        self._close_connection_if_needed(conn)
        
        # Cache the result
        self._set_cached_metadata(cache_key, groups)
        return groups

    def get_group_by_name(self, name: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict]:
        """Retrieves a group by name. Optionally uses provided connection."""
        should_close = False
        if conn is None:
            conn = self.get_connection()
            should_close = True
        
        try:
            ody = conn.cursor()
            ody.execute("SELECT * FROM groups WHERE name = ?", (name,))
            row = ody.fetchone()
            
            if row:
                return dict(row)
            return None
        finally:
            if should_close:
                self._close_connection_if_needed(conn)

    def get_group_by_id(self, group_id: int) -> Optional[Dict]:
        """Retrieves a group by ID"""
        conn = self.get_connection()
        ody = conn.cursor()
        
        ody.execute("SELECT * FROM groups WHERE id = ?", (group_id,))
        row = ody.fetchone()
        
        self._close_connection_if_needed(conn)
        if row:
            return dict(row)
        return None

    def create_group(self, name: str, color: str = '#8B5CF6', description: str = '', conn: Optional[sqlite3.Connection] = None) -> int:
        """Creates a new group. Optionally uses provided connection."""
        should_close = False
        if conn is None:
            conn = self.get_connection()
            should_close = True
        
        try:
            ody = conn.cursor()
            try:
                ody.execute("""
                    INSERT INTO groups (name, color, description)
                    VALUES (?, ?, ?)
                """, (name, color, description))
                group_id = ody.lastrowid
                if should_close:
                    conn.commit()
                return group_id
            except sqlite3.IntegrityError:
                # Group already exists, return existing ID
                if should_close:
                    conn.rollback()
                group = self.get_group_by_name(name, conn)
                return group['id'] if group else None
        finally:
            if should_close:
                self._close_connection_if_needed(conn)

    def add_source_to_group(self, source_id: int, group_id: int) -> bool:
        """Adds a source to a group. If group is TLP or Positive, removes from other groups of same type first."""
        conn = self.get_connection()
        ody = conn.cursor()
        
        try:
            # Get group info to check if it's TLP or Positive group
            ody.execute("SELECT name FROM groups WHERE id = ?", (group_id,))
            group_row = ody.fetchone()
            if not group_row:
                self._close_connection_if_needed(conn)
                return False
            
            group_name = group_row[0]
            is_tlp = group_name.startswith('TLP:')
            is_positive = group_name in ['True Positive', 'False Positive']
            
            # If adding to TLP group, remove from other TLP groups first
            if is_tlp:
                ody.execute("""
                    DELETE FROM source_groups
                    WHERE source_id = ? AND group_id IN (
                        SELECT id FROM groups WHERE name LIKE 'TLP:%'
                    )
                """, (source_id,))
            
            # If adding to Positive group, remove from other Positive groups
            if is_positive:
                ody.execute("""
                    DELETE FROM source_groups
                    WHERE source_id = ? AND group_id IN (
                        SELECT id FROM groups WHERE name IN ('True Positive', 'False Positive')
                    )
                """, (source_id,))
            
            # Add to new group
            ody.execute("""
                INSERT OR IGNORE INTO source_groups (source_id, group_id)
                VALUES (?, ?)
            """, (source_id, group_id))
            success = ody.rowcount > 0
            conn.commit()
            self._close_connection_if_needed(conn)
            return success
        except Exception:
            conn.rollback()
            self._close_connection_if_needed(conn)
            return False

    def remove_source_from_group(self, source_id: int, group_id: int) -> bool:
        """Removes a source from a group"""
        conn = self.get_connection()
        ody = conn.cursor()
        
        ody.execute("""
            DELETE FROM source_groups
            WHERE source_id = ? AND group_id = ?
        """, (source_id, group_id))
        
        success = ody.rowcount > 0
        conn.commit()
        self._close_connection_if_needed(conn)
        return success

    def get_sources_by_group(self, group_id: int) -> List[int]:
        """Retrieves all source IDs belonging to a group"""
        conn = self.get_connection()
        ody = conn.cursor()
        
        ody.execute("""
            SELECT source_id FROM source_groups
            WHERE group_id = ?
        """, (group_id,))
        
        source_ids = [row[0] for row in ody.fetchall()]
        self._close_connection_if_needed(conn)
        return source_ids

    def delete_group(self, group_id: int) -> bool:
        """Deletes a group (removes all associations first)"""
        conn = self.get_connection()
        ody = conn.cursor()
        
        # First remove all source associations
        ody.execute("DELETE FROM source_groups WHERE group_id = ?", (group_id,))
        
        # Then delete the group
        ody.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        
        success = ody.rowcount > 0
        conn.commit()
        self._close_connection_if_needed(conn)
        return success

    def add_ioc_to_group(self, ioc_id: int, group_id: int) -> bool:
        """Adds an IOC to a group"""
        conn = self.get_connection()
        ody = conn.cursor()
        
        try:
            ody.execute("""
                INSERT OR IGNORE INTO ioc_groups (ioc_id, group_id)
                VALUES (?, ?)
            """, (ioc_id, group_id))
            success = ody.rowcount > 0
            conn.commit()
            self._close_connection_if_needed(conn)
            return success
        except Exception:
            conn.rollback()
            self._close_connection_if_needed(conn)
            return False

    def remove_ioc_from_group(self, ioc_id: int, group_id: int) -> bool:
        """Removes an IOC from a group (direct IOC group assignment)"""
        conn = self.get_connection()
        ody = conn.cursor()
        
        ody.execute("""
            DELETE FROM ioc_groups
            WHERE ioc_id = ? AND group_id = ?
        """, (ioc_id, group_id))
        
        success = ody.rowcount > 0
        conn.commit()
        self._close_connection_if_needed(conn)
        return success

    def exclude_ioc_from_source_group(self, ioc_id: int, group_id: int) -> bool:
        """Excludes an IOC from inheriting a source group"""
        conn = self.get_connection()
        ody = conn.cursor()
        
        try:
            ody.execute("""
                INSERT OR IGNORE INTO ioc_source_group_exclusions (ioc_id, group_id)
                VALUES (?, ?)
            """, (ioc_id, group_id))
            success = ody.rowcount > 0
            conn.commit()
            self._close_connection_if_needed(conn)
            return success
        except Exception:
            conn.rollback()
            self._close_connection_if_needed(conn)
            return False


    def bulk_add_iocs_to_group(self, ioc_ids: List[int], group_id: int) -> int:
        """Adds multiple IOCs to a group. Returns count of successfully added IOCs.
        If adding a TLP group, removes other TLP groups first.
        If adding a Positive group, removes other Positive groups first.
        Also excludes source groups of the same category to ensure direct assignment takes priority."""
        with self.connection() as conn:
            ody = conn.cursor()
            
            # Get group info to check if it's TLP or Positive group
            ody.execute("SELECT name FROM groups WHERE id = ?", (group_id,))
            group_row = ody.fetchone()
            if not group_row:
                return 0
            
            group_name = group_row[0]
            is_tlp = group_name.startswith('TLP:')
            is_positive = group_name in ['True Positive', 'False Positive']
            
            count = 0
            for ioc_id in ioc_ids:
                # If adding to TLP group, remove from other TLP groups first
                if is_tlp:
                    # Remove direct TLP group assignments
                    ody.execute("""
                        DELETE FROM ioc_groups
                        WHERE ioc_id = ? 
                        AND group_id IN (
                            SELECT id FROM groups WHERE name LIKE 'TLP:%'
                        )
                    """, (ioc_id,))
                    
                    # Exclude all TLP groups from source inheritance
                    ody.execute("""
                        INSERT OR IGNORE INTO ioc_source_group_exclusions (ioc_id, group_id)
                        SELECT ?, id FROM groups WHERE name LIKE 'TLP:%'
                    """, (ioc_id,))

                    tlp_value = group_name.split(':', 1)[1]
                    ody.execute(
                        "UPDATE iocs SET tlp = ? WHERE id = ?",
                        (tlp_value, ioc_id)
                    )
                
                # If adding to Positive group, remove from other Positive groups
                if is_positive:
                    # Remove direct Positive group assignments
                    ody.execute("""
                        DELETE FROM ioc_groups
                        WHERE ioc_id = ? 
                        AND group_id IN (
                            SELECT id FROM groups WHERE name IN ('True Positive', 'False Positive')
                        )
                    """, (ioc_id,))
                    
                    # Exclude all Positive groups from source inheritance
                    # This ensures that direct IOC assignment takes priority over source assignment
                    ody.execute("""
                        INSERT OR IGNORE INTO ioc_source_group_exclusions (ioc_id, group_id)
                        SELECT ?, id FROM groups WHERE name IN ('True Positive', 'False Positive')
                    """, (ioc_id,))

                    validation_status = 'TP' if group_name == 'True Positive' else 'FP'
                    ody.execute(
                        "UPDATE iocs SET validation_status = ? WHERE id = ?",
                        (validation_status, ioc_id)
                    )
                
                # Remove the IOC from the target group first (in case it already exists)
                ody.execute("""
                    DELETE FROM ioc_groups
                    WHERE ioc_id = ? AND group_id = ?
                """, (ioc_id, group_id))
                
                # Add to new group
                ody.execute("""
                    INSERT INTO ioc_groups (ioc_id, group_id)
                    VALUES (?, ?)
                """, (ioc_id, group_id))
                count += 1
            
            return count


    # ========== SAVED STIX MODELS ==========
    
    def create_saved_stix_model(self, name: str, stix_content: str, description: str = None,
                                 node_count: int = 0, edge_count: int = 0,
                                 local_metadata: str = None) -> int:
        """Creates a new saved STIX model"""
        with self.connection() as conn:
            ody = conn.cursor()
            ody.execute("""
                INSERT INTO saved_stix_models (name, description, stix_content, node_count, edge_count, local_metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, description, stix_content, node_count, edge_count, local_metadata))
            conn.commit()
            return ody.lastrowid

    # ========== MITRE ATT&CK ==========












    def get_mitre_groups(self, search: str = None) -> List[Dict]:
        """Gets MITRE ATT&CK groups (APTs)"""
        with self.connection() as conn:
            ody = conn.cursor()
            query = "SELECT id, name, aliases, description, url FROM mitre_groups"
            params = []
            if search:
                query += " WHERE id LIKE ? OR name LIKE ? OR aliases LIKE ?"
                params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
            query += " ORDER BY id"
            rows = ody.execute(query, params).fetchall()
            return [dict(row) for row in rows]



    
    
    def get_saved_stix_model(self, model_id: int) -> Optional[Dict]:
        """Retrieves a saved STIX model by ID"""
        with self.connection() as conn:
            conn.row_factory = sqlite3.Row
            ody = conn.cursor()
            ody.execute("""
                SELECT * FROM saved_stix_models WHERE id = ?
            """, (model_id,))
            row = ody.fetchone()
            if row:
                return {
                    'id': row['id'],
                    'name': row['name'],
                    'description': row['description'],
                    'stix_content': row['stix_content'],
                    'local_metadata': row['local_metadata'],
                    'node_count': row['node_count'],
                    'edge_count': row['edge_count'],
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'],
                    'last_loaded_at': row['last_loaded_at']
                }
            return None
    
    def get_all_saved_stix_models(self) -> List[Dict]:
        """Retrieves all saved STIX models"""
        with self.connection() as conn:
            conn.row_factory = sqlite3.Row
            ody = conn.cursor()
            ody.execute("""
                SELECT * FROM saved_stix_models 
                ORDER BY updated_at DESC, created_at DESC
            """)
            rows = ody.fetchall()
            return [{
                'id': row['id'],
                'name': row['name'],
                'description': row['description'],
                'node_count': row['node_count'],
                'edge_count': row['edge_count'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
                'last_loaded_at': row['last_loaded_at']
            } for row in rows]
    
    def update_saved_stix_model(self, model_id: int, name: str = None, description: str = None,
                                stix_content: str = None, node_count: int = None, edge_count: int = None,
                                local_metadata: str = None):
        """Updates a saved STIX model"""
        with self.connection() as conn:
            ody = conn.cursor()
            updates = []
            params = []
            
            if name is not None:
                updates.append("name = ?")
                params.append(name)
            if description is not None:
                updates.append("description = ?")
                params.append(description)
            if stix_content is not None:
                updates.append("stix_content = ?")
                params.append(stix_content)
            if node_count is not None:
                updates.append("node_count = ?")
                params.append(node_count)
            if edge_count is not None:
                updates.append("edge_count = ?")
                params.append(edge_count)
            if local_metadata is not None:
                updates.append("local_metadata = ?")
                params.append(local_metadata)
            
            if updates:
                updates.append("updated_at = CURRENT_TIMESTAMP")
                params.append(model_id)
                ody.execute(f"""
                    UPDATE saved_stix_models 
                    SET {', '.join(updates)}
                    WHERE id = ?
                """, params)
                conn.commit()
    
    def update_saved_stix_model_last_loaded(self, model_id: int):
        """Updates the last_loaded_at timestamp for a saved STIX model"""
        with self.connection() as conn:
            ody = conn.cursor()
            ody.execute("""
                UPDATE saved_stix_models 
                SET last_loaded_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (model_id,))
            conn.commit()
    
    def delete_saved_stix_model(self, model_id: int) -> bool:
        """Deletes a saved STIX model"""
        with self.connection() as conn:
            ody = conn.cursor()
            ody.execute("DELETE FROM saved_stix_models WHERE id = ?", (model_id,))
            conn.commit()
            return ody.rowcount > 0
