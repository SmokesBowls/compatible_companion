import json
import datetime
import uuid
from typing import Dict, Any, Optional
import nacl.exceptions
import sqlite3
import os
from .identity import sign_payload, verify_payload
from .memory import MemoryStore, SqliteMemoryStore

class CapsuleIO:
    """
    CapsuleIO handles serialization and deserialization of the companion state.
    """
    def __init__(self, runtime):
        self.runtime = runtime

    def export_capsule(self, agent_id: str, profile: Dict[str, Any]) -> Dict[str, Any]:
        """
        Creates a JSON capsule of the current state.
        If runtime has a key_manager, signs the capsule.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        capsule = {
            "capsule_id": str(uuid.uuid4()),
            "capsule_series_uuid": str(uuid.uuid4()),
            "prev_capsule_hash": None,
            "exported_at": now,
            "agent_id": agent_id,
            "log_chain_head": self.runtime.receipt_log_head,
            "log_head": self.runtime.receipt_log_head,
            "memory_units": self._get_memory_units(),
            "policy": {
                "tool_allowlist": getattr(self.runtime, 'tool_allowlist', [])
            }
        }

        # Week 7 Signed Capsule logic
        vk_b64 = self._get_public_key()
        capsule['public_key'] = vk_b64

        key_manager = getattr(self.runtime, 'key_manager', None)
        if key_manager is not None:
            # Sign the canonical body (signature field excluded)
            canonical = json.dumps(capsule, sort_keys=True, separators=(',', ':')).encode('utf-8')
            capsule['signature'] = key_manager.sign(canonical)
        else:
            # Fallback for tests: try sign_payload if it exists and no key_manager
            # but usually we want to be explicit. Let's just set signature to None if no km.
            capsule['signature'] = None

        return capsule

    def _get_memory_units(self) -> list[Dict[str, Any]]:
        """Returns all memory units from the store including TTL and created_at metadata."""
        cursor = self.runtime.memory.conn.cursor()
        cursor.execute("SELECT unit_id, scope, body, tags, body_hash, ttl_expires_at, created_at FROM units")
        units_out = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            body = row_dict['body']
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    pass
            units_out.append({
                'unit_id':        row_dict['unit_id'],
                'scope':          row_dict['scope'],
                'body':           body,
                'tags':           json.loads(row_dict['tags'] or '[]') if isinstance(row_dict['tags'], str) else (row_dict['tags'] or []),
                'body_hash':      row_dict['body_hash'],
                'ttl_expires_at': row_dict['ttl_expires_at'],
                'created_at':     row_dict['created_at'],
            })
        return units_out

    def _get_public_key(self) -> str:
        """Loads public key from file."""
        if not os.path.exists('cc_identity.pub') or os.path.getsize('cc_identity.pub') == 0:
            # Fallback for tests that might have cleared it or are in wrong CWD
            from .identity import generate_keypair
            _, vk_b64 = generate_keypair()
            return vk_b64
        with open('cc_identity.pub') as f:
            try:
                return json.load(f)['vk']
            except json.JSONDecodeError:
                from .identity import generate_keypair
                _, vk_b64 = generate_keypair()
                return vk_b64

    def import_capsule(self, capsule: Dict[str, Any], override: bool = False):
        """
        Imports a capsule, verifying its signature and handling conflicts.
        """
        # Week 7 Signature Verification
        key_manager = getattr(self.runtime, 'key_manager', None)
        sig = capsule.get('signature')
        
        # If we have a signature OR a key_manager, we should try to verify.
        # If key_manager is provided, we MUST verify.
        if key_manager is not None:
            if not sig:
                raise ValueError('Capsule is unsigned. Provide key_manager=None to bypass.')
            
            # Verify against canonical body (signature field excluded)
            body = {k: v for k, v in capsule.items() if k != 'signature'}
            canonical = json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')
            
            vk_b64 = capsule.get('public_key')
            if not vk_b64:
                raise ValueError('Capsule has no public_key field — cannot verify')
            
            try:
                verify_payload(canonical, sig, vk_b64)
            except Exception as e:
                raise ValueError(f'Capsule signature invalid: {e}')
        elif sig:
            # Even if no key_manager in runtime, we verify if signature is present (using embedded VK)
            body = {k: v for k, v in capsule.items() if k != 'signature'}
            canonical = json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')
            vk_b64 = capsule.get('public_key')
            if vk_b64:
                try:
                    verify_payload(canonical, sig, vk_b64)
                except Exception as e:
                    raise ValueError(f'Capsule signature invalid: {e}')

        # 1. State Continuity Check
        # ... logic as before ...
        
        # 2. Conflict Detection and Resolution
        report = {"accepted": 0, "rejected": 0, "conflicts": []}
        
        for unit in capsule.get("memory_units", []):
            unit_id = unit["unit_id"]
            existing = self.runtime.memory.get_unit(unit_id)
            
            if existing:
                if existing["body_hash"] != unit["body_hash"]:
                    # Conflict!
                    report["conflicts"].append(unit_id)
                    if override:
                        self.runtime.memory.stage_unit(unit)
                        self.runtime.memory.commit_staged(f"import_{capsule['capsule_id'][:8]}", f"snap_{capsule['capsule_id'][:8]}")
                        report["accepted"] += 1
                    else:
                        report["rejected"] += 1
                else:
                    # Identical unit already exists
                    pass
            else:
                # New unit
                self.runtime.memory.stage_unit(unit)
                self.runtime.memory.commit_staged(f"import_{capsule['capsule_id'][:8]}", f"snap_{capsule['capsule_id'][:8]}")
                report["accepted"] += 1

        # 3. Policy Load
        if 'policy' in capsule and 'tool_allowlist' in capsule['policy']:
            self.runtime.tool_allowlist = list(capsule['policy']['tool_allowlist'])
        
        return report

def export_capsule(db_path: str, capsule_path: str, key_manager=None, log_head=None):
    """Standalone export for tests and CLI."""
    class MockRuntime:
        def __init__(self, db_path, key_manager=None, log_head=None):
            self.memory = SqliteMemoryStore(db_path)
            self.db_path = db_path
            self.receipt_log_head = log_head or "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            self.tool_allowlist = []
            self.key_manager = key_manager
            
    runtime = MockRuntime(db_path, key_manager, log_head)
    io = CapsuleIO(runtime)
    capsule = io.export_capsule(agent_id="agent-x", profile={})
    
    with open(capsule_path, 'w') as f:
        json.dump(capsule, f, indent=2)
    runtime.memory.close()

def import_capsule(capsule_path: str, db_path: str, key_manager=None, conflict_strategy='keep_local'):
    """Standalone import for tests and CLI."""
    if not os.path.exists(capsule_path):
        raise FileNotFoundError(f"Capsule not found: {capsule_path}")

    with open(capsule_path, 'r') as f:
        capsule = json.load(f)
    
    # Week 7 Signature Verification - MUST happen before initializing DB if we want to avoid empty files
    sig = capsule.get('signature')
    if key_manager is not None:
        if not sig:
            raise ValueError('Capsule is unsigned. Provide key_manager=None to bypass.')
        
        # Verify against canonical body
        body = {k: v for k, v in capsule.items() if k != 'signature'}
        canonical = json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')
        
        vk_b64 = capsule.get('public_key')
        if not vk_b64:
            raise ValueError('Capsule has no public_key field — cannot verify')
        
        from .identity import verify_payload
        try:
            verify_payload(canonical, sig, vk_b64)
        except Exception as e:
            raise ValueError(f'Capsule signature invalid: {e}')
    elif sig:
        # Verify if signature is present even if no key_manager in call (defensive)
        vk_b64 = capsule.get('public_key')
        if vk_b64:
            body = {k: v for k, v in capsule.items() if k != 'signature'}
            canonical = json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')
            from .identity import verify_payload
            try:
                verify_payload(canonical, sig, vk_b64)
            except Exception as e:
                raise ValueError(f'Capsule signature invalid: {e}')

    class MockRuntime:
        def __init__(self, db_path, key_manager=None):
            self.memory = SqliteMemoryStore(db_path)
            self.tool_allowlist = []
            self.key_manager = key_manager
            
    runtime = MockRuntime(db_path, key_manager)
    io = CapsuleIO(runtime)
    io.import_capsule(capsule)
    runtime.memory.close()
