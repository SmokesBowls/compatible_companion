import sqlite3
import hashlib
import json
import time
from typing import List, Dict, Any, Optional

class MemoryStore:
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()
        self.staged_units = []

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS units (
                id TEXT PRIMARY KEY,
                scope TEXT,
                content_type TEXT,
                body TEXT,
                body_hash TEXT,
                tags TEXT,
                entities TEXT,
                ttl_expires_at INTEGER,
                created_at INTEGER,
                snapshot_id TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                receipt_id TEXT PRIMARY KEY,
                phase TEXT,
                verdict TEXT,
                input_hash TEXT,
                output_hash TEXT,
                prev_receipt_hash TEXT,
                ts INTEGER
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS provenance (
                unit_id TEXT,
                receipt_id TEXT,
                op TEXT,
                FOREIGN KEY(unit_id) REFERENCES units(id),
                FOREIGN KEY(receipt_id) REFERENCES events(receipt_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policy_rules (
                rule_id TEXT PRIMARY KEY,
                scope TEXT,
                predicate TEXT,
                on_fail TEXT
            )
        """)
        self.conn.commit()

    def stage_unit(self, unit: Dict[str, Any]):
        """Stages a unit for commitment. Minimal validation here."""
        self.staged_units.append(unit)

    def clear_staged(self):
        self.staged_units = []

    def commit_staged(self, receipt_id: str, snapshot_id: str):
        """Promotes staged units to the units table."""
        cursor = self.conn.cursor()
        ts = int(time.time())
        for unit in self.staged_units:
            # Check for existing unit to record proper op in provenance
            cursor.execute("SELECT body_hash FROM units WHERE id = ?", (unit['id'],))
            row = cursor.fetchone()
            op = 'update' if row else 'create'
            
            cursor.execute("""
                INSERT OR REPLACE INTO units 
                (id, scope, content_type, body, body_hash, tags, entities, ttl_expires_at, created_at, snapshot_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                unit['id'], unit['scope'], unit.get('content_type', 'plain'),
                unit['body'], unit['body_hash'], json.dumps(unit.get('tags', [])),
                json.dumps(unit.get('entities', [])), unit.get('ttl_expires_at'),
                unit.get('created_at', ts), snapshot_id
            ))
            
            cursor.execute("""
                INSERT INTO provenance (unit_id, receipt_id, op)
                VALUES (?, ?, ?)
            """, (unit['id'], receipt_id, op))
        
        self.conn.commit()
        self.clear_staged()

    def add_event(self, event: Dict[str, Any]):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO events (receipt_id, phase, verdict, input_hash, output_hash, prev_receipt_hash, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event['receipt_id'], event['phase'], event['verdict'],
            event.get('input_hash'), event.get('output_hash'),
            event.get('prev_receipt_hash'), event.get('ts', int(time.time()))
        ))
        self.conn.commit()

    def derive_state_hash(self, receipt_log_head: str) -> str:
        """
        Derives state hash from all committed units and the current receipt log head.
        state_hash = SHA256( sorted(unit.body_hash for unit in committed_units) + receipt_log_head )
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT body_hash FROM units ORDER BY id ASC")
        hashes = [row['body_hash'] for row in cursor.fetchall()]
        
        # Canonical string of hashes
        hash_string = "".join(hashes)
        
        hasher = hashlib.sha256()
        hasher.update(hash_string.encode('utf-8'))
        hasher.update(receipt_log_head.encode('utf-8'))
        return hasher.hexdigest()

    def get_policy_rules(self, scope: Optional[str] = None) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        if scope:
            cursor.execute("SELECT * FROM policy_rules WHERE scope = ?", (scope,))
        else:
            cursor.execute("SELECT * FROM policy_rules")
        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        self.conn.close()
