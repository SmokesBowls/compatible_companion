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
                unit_id TEXT PRIMARY KEY,
                scope TEXT,
                content_type TEXT,
                body TEXT,
                body_hash TEXT,
                tags TEXT,
                entities TEXT,
                ttl_expires_at TEXT,
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
                scope TEXT,
                body TEXT,
                ts INTEGER,
                op TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policy_rules (
                rule_id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                predicate TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def mem_store(self, unit_id: str, scope: str, body: Dict[str, Any], tags: List[str] = None, ttl_expires_at: str = None) -> str:
        """
        Stages a unit write. Returns unit_id.
        ttl_expires_at: ISO 8601 UTC string or None.
        """
        # Ensure we have a hash for the body
        body_json = json.dumps(body, sort_keys=True)
        body_hash = hashlib.sha256(body_json.encode()).hexdigest()
        
        unit = {
            "id": unit_id,
            "scope": scope,
            "body": body,
            "body_hash": body_hash,
            "tags": tags or [],
            "ttl_expires_at": ttl_expires_at
        }
        self.staged_units.append(unit)
        return unit_id

    def stage_unit(self, unit: Dict[str, Any]):
        """Legacy helper for Stage 1/2 tests."""
        self.staged_units.append(unit)

    def clear_staged(self):
        self.staged_units = []

    def commit_staged(self, receipt_id: str, snapshot_id: str):
        """Promotes staged units to the units table."""
        cursor = self.conn.cursor()
        ts = int(time.time())
        for unit in self.staged_units:
            # Check for existing unit to record proper op in provenance
            uid = unit.get('unit_id') or unit.get('id')
            cursor.execute("SELECT body_hash FROM units WHERE unit_id = ?", (uid,))
            row = cursor.fetchone()
            op = 'update' if row else 'create'
            
            cursor.execute("""
                INSERT OR REPLACE INTO units 
                (unit_id, scope, body, body_hash, tags, entities, ttl_expires_at, created_at, snapshot_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                uid, unit['scope'], 
                json.dumps(unit['body']) if isinstance(unit['body'], (dict, list)) else unit['body'],
                unit['body_hash'], json.dumps(unit.get('tags', [])),
                json.dumps(unit.get('entities', [])), unit.get('ttl_expires_at'),
                unit.get('created_at', ts), snapshot_id
            ))
            
            cursor.execute("""
                INSERT INTO provenance (unit_id, receipt_id, scope, body, ts, op)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (uid, receipt_id, unit['scope'], 
                  json.dumps(unit['body']) if isinstance(unit['body'], (dict, list)) else unit['body'],
                  ts, op))
        
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
        cursor.execute("SELECT body_hash FROM units ORDER BY unit_id ASC")
        hashes = [row['body_hash'] for row in cursor.fetchall()]
        
        # Canonical string of hashes
        hash_string = "".join(hashes)
        
        hasher = hashlib.sha256()
        hasher.update(hash_string.encode('utf-8'))
        hasher.update(receipt_log_head.encode('utf-8'))
        return hasher.hexdigest()

    def get_unit(self, unit_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM units WHERE unit_id = ?", (unit_id,))
        row = cursor.fetchone()
        if not row: return None
        data = dict(row)
        if isinstance(data.get('body'), str):
            try:
                data['body'] = json.loads(data['body'])
            except json.JSONDecodeError:
                pass
        return data

    def mem_find(self, scope: str) -> List[Dict[str, Any]]:
        """Returns committed units for a scope, filtering out expired ones."""
        from datetime import datetime, UTC
        now_iso = datetime.now(UTC).isoformat()
        
        cursor = self.conn.cursor()
        cursor.execute(
            '''SELECT * FROM units 
               WHERE scope = ? 
                 AND (ttl_expires_at IS NULL 
                      OR ttl_expires_at > ?)''', 
            (scope, now_iso)
        )
        results = []
        for row in cursor.fetchall():
            data = dict(row)
            if isinstance(data.get('body'), str):
                try:
                    data['body'] = json.loads(data['body'])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(data)
        return results

    def get_raw_unit(self, unit_id: str) -> Optional[Dict[str, Any]]:
        """SELECT without TTL filter. Test-only."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM units WHERE unit_id = ?", (unit_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def add_policy_rule(self, rule_id: str, description: str, predicate: str):
        """Adds a policy rule to the store."""
        from datetime import datetime, UTC
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO policy_rules (rule_id, description, predicate, is_active, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (rule_id, description, predicate, 1, datetime.now(UTC).isoformat()))
        self.conn.commit()

    def get_policy_rules(self, scope: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns active policy rules."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM policy_rules WHERE is_active = 1")
        return [dict(row) for row in cursor.fetchall()]

    def mem_store_zw(self, zw_text: str, unit_id: str, ttl_expires_at: str = None) -> str:
        """
        Parse a ZW block, extract scope from @meta, call mem_store.
        Raises ValueError if block has no @meta scope line.
        """
        from cc.zw_block import parse_zw_block, canonical_bytes
        parsed = parse_zw_block(zw_text)
        scope = parsed['meta'].get('scope')
        if not scope:
            raise ValueError('ZW block must have @meta scope line')
        _, block_hash = canonical_bytes(parsed)
        body = {'meta': parsed['meta'], 'body_lines': parsed['body_lines'],
                'zw_hash': block_hash}
        return self.mem_store(unit_id, scope, body, ttl_expires_at=ttl_expires_at)

    def get_provenance(self, scope: Optional[str] = None) -> List[Dict[str, Any]]:
        """SELECT from provenance, optionally filtered by scope, ordered by ts ASC."""
        cursor = self.conn.cursor()
        # Add column if missing (Week 4 requirement)
        try:
            cursor.execute("SELECT scope FROM provenance LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE provenance ADD COLUMN scope TEXT")
            cursor.execute("ALTER TABLE provenance ADD COLUMN body TEXT")
            cursor.execute("ALTER TABLE provenance ADD COLUMN ts INTEGER")

        if scope:
            cursor.execute("SELECT * FROM provenance WHERE scope = ? ORDER BY ts ASC", (scope,))
        else:
            cursor.execute("SELECT * FROM provenance ORDER BY ts ASC")
        
        results = []
        for row in cursor.fetchall():
            res = dict(row)
            if 'body' in res and isinstance(res['body'], str):
                try:
                    res['body'] = json.loads(res['body'])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(res)
        return results

    def close(self):
        self.conn.close()
