#!/usr/bin/env python3
"""
Migration: Add ioc_ttp_links table for MITRE ATT&CK TTP linking
Run this to add the table to an existing database
"""
import sqlite3
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from database import get_db_path

def migrate():
    db_path = get_db_path()
    print(f"Migrating database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    ody = conn.cursor()
    
    # Check if table already exists
    ody.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ioc_ttp_links'")
    if ody.fetchone():
        print("Table ioc_ttp_links already exists - skipping migration")
        conn.close()
        return
    
    print("Creating ioc_ttp_links table...")
    
    # Create the table
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
    
    # Create indexes
    ody.execute("CREATE INDEX IF NOT EXISTS idx_ioc_ttp_links_ioc ON ioc_ttp_links(ioc_id)")
    ody.execute("CREATE INDEX IF NOT EXISTS idx_ioc_ttp_links_technique ON ioc_ttp_links(technique_id)")
    
    conn.commit()
    conn.close()
    
    print("✅ Migration complete - ioc_ttp_links table created")

if __name__ == '__main__':
    migrate()
