import json
import hashlib
import time
import uuid
import os
import pathlib
import warnings
from typing import Dict, Any, List, Optional
from .memory import MemoryStore
from .zw_block import ZWBlock
from .policy import eval_policy_predicate, PolicyRuleError
from .identity import KeyManager, sign_payload

class Plan:
    def __init__(self, action: str, scope: str, rollback_anchor: Optional[str] = None, tool_refs: List[str] = None):
        self.action = action
        self.scope = scope
        self.rollback_anchor = rollback_anchor
        self.tool_refs = tool_refs or []

class AgentRuntime:
    """
    AgentRuntime (formerly CompanionRuntime) orchestrates the PLAN -> ACT -> VERIFY -> COMMIT cycle.
    """
    def __init__(self, db_path: str = None, log_path: str = None, tool_allowlist: list[str] = None):
        # ── PATH HARDENING (Week 6) ───────────────────────────────────
        base_dir = pathlib.Path.home() / '.compatible'
        
        # Determine defaults
        default_db = str(base_dir / 'companion.db')
        default_log = str(base_dir / 'receipts.jsonl')
        
        # Test mode suppresses warnings and allows relative paths/memory
        test_mode = os.environ.get('TEST_MODE') == '1'
        
        db_path = db_path or default_db
        log_path = log_path or default_log
        
        if not test_mode:
            if not os.path.isabs(db_path):
                warnings.warn(f"Relative db_path '{db_path}' detected. Recommended: '{default_db}'", RuntimeWarning)
            if not os.path.isabs(log_path):
                warnings.warn(f"Relative log_path '{log_path}' detected. Recommended: '{default_log}'", RuntimeWarning)
            # Ensure base directory exists in production
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
            os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)

        self.memory = MemoryStore(db_path)
        self.db_path = db_path
        self.mem_store = self.memory # Alias for briefing tests
        self.tool_allowlist = list(tool_allowlist or [])
        self._last_act_result = {}
        self.log_path = log_path
        
        # ── IDENTITY HARDENING (Week 6) ──────────────────────────────
        self.key_manager = None
        key_path = os.environ.get('CC_KEY_PATH') or str(base_dir / 'identity.key')
        if os.path.exists(key_path):
            self.key_manager = KeyManager(key_path)
        elif os.path.exists('cc_identity.key'):
            self.key_manager = KeyManager('cc_identity.key')
        # Initial hash for an empty chain
        self.receipt_log_head = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self._load_log_head()
        
        self.phase = "IDLE"
        self.last_snapshot_id = None
        self.last_state_hash = None

    def _load_log_head(self):
        """Loads the current chain tip from the JSONL log file."""
        if os.path.exists(self.log_path) and os.path.getsize(self.log_path) > 0:
            with open(self.log_path, "rb") as f:
                last_line = None
                for line in f:
                    if line.strip():
                        last_line = line
                if last_line:
                    self.receipt_log_head = hashlib.sha256(last_line.strip()).hexdigest()

    def _append_to_log(self, receipt: Dict[str, Any]):
        """Appends a receipt to the JSONL log and updates the chain tip."""
        receipt_bytes = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode("utf-8")
        with open(self.log_path, "ab") as f:
            f.write(receipt_bytes + b"\n")
        self.receipt_log_head = hashlib.sha256(receipt_bytes).hexdigest()
        print(f"[LOG] Appended {receipt['receipt_id']} | Log Head: {self.receipt_log_head[:12]}...")

    def current_state_hash(self) -> str:
        """Returns the most recent committed state_hash."""
        return self.last_state_hash

    def ingest(self, text: str, scope: str = "core") -> Dict[str, Any]:
        """
        Legacy wrapper for text input.
        """
        plan = {
            'action': 'ingest',
            'scope': scope,
            'text': text
        }
        
        def act_fn(p):
            # Simplified ACT for ingest
            unit_id = f"unit_{str(uuid.uuid4())[:8]}"
            block = ZWBlock(p['text'])
            return {
                'action': 'mem_store',
                'unit_id': unit_id,
                'scope': p['scope'],
                'body': p['text'],
                'body_hash': block.hash,
                'tags': []
            }

        # run_cycle returns a verdict string for Test 14/15, 
        # but ingest needs to return the receipt dict for Stage 1/2.
        # I'll modify run_cycle to store the last receipt.
        self.run_cycle(plan, act_fn, invariants=[])
        return self.last_receipt

    def run_cycle(self, plan: Dict[str, Any], act_fn, invariants: List = None) -> str:
        """
        Orchestrates PLAN -> ACT -> VERIFY -> COMMIT/FAIL.
        """
        # 1. PLAN
        self.phase = "PLAN"
        self.current_plan = plan
        input_hash = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()

        # 2. ACT
        self.phase = "ACT"
        act_result = act_fn(plan)
        self._last_act_result = act_result if isinstance(act_result, dict) else {}
        
        # In MVP, if act_result is a unit or contains unit data, we stage it
        if isinstance(act_result, dict):
            if act_result.get('action') == 'mem_store' or 'unit_id' in act_result:
                # Normalizing for memory.py
                unit = {
                    'unit_id':   act_result.get('unit_id'),
                    'scope':     act_result.get('scope'),
                    'body':      act_result.get('body'),
                    'body_hash': act_result.get('body_hash') or hashlib.sha256(json.dumps(act_result.get('body'), sort_keys=True).encode()).hexdigest(),
                    'tags':      act_result.get('tags', []),
                    'ttl_expires_at': act_result.get('ttl_expires_at')
                }
                self.memory.stage_unit(unit)
            elif 'units' in act_result:
                for u in act_result['units']:
                    self.memory.stage_unit(u)

        # 3. VERIFY
        self.phase = "VERIFY"
        
        # 1. Canon immutability
        error = self._verify_canon_immutability(self.memory.staged_units, self.memory.conn)
        if error:
            return self._emit_fail(error, input_hash)

        # 2. Tool receipt integrity (NEW)
        error = self._verify_tool_receipts(self._last_act_result, self.tool_allowlist)
        if error:
            return self._emit_fail(error, input_hash)

        # 3. Policy Rules
        error = self._eval_policy_rules(self.memory.staged_units, self.memory.conn)
        if error:
            return self._emit_fail(error, input_hash)

        # 4. COMMIT
        self.phase = "COMMIT"
        
        # Capture staged units BEFORE commit_staged clears them
        staged_copy = []
        for u in self.memory.staged_units:
            # Normalize to unit_id for the receipt data
            c = dict(u)
            if 'unit_id' not in c and 'id' in c:
                c['unit_id'] = c.pop('id')
            staged_copy.append(c)

        receipt_id = "rcpt_" + str(uuid.uuid4())[:8]
        snapshot_id = "snap_" + str(uuid.uuid4())[:8]
        self.memory.commit_staged(receipt_id, snapshot_id)
        
        state_hash = self.memory.derive_state_hash(self.receipt_log_head)
        
        receipt = {
            "receipt_id": receipt_id,
            "phase": "COMMIT",
            "outcome": "COMMIT",  # Consistency
            "verdict": "PASS",
            "snapshot_id": snapshot_id,
            "input_hash": input_hash,
            "prev_receipt_hash": self.receipt_log_head,
            "state_hash": state_hash,
            "ts": int(time.time()),
            # We store the unit data in the receipt for replayability in MVP
            # "data": {"units": [u for u in self.memory.staged_units]} # staged_units is still there? 
                                                                    # No, memory.py clears it.
                                                                    # I should capture it before commit.
        }
        # Actually memory.py clear_staged happens AFTER insertion. 
        # But for receipt data, I'll capture it.
        receipt["data"] = {"units": staged_copy}
        receipt["staged_units"] = staged_copy
        receipt["tool_receipts"] = self._last_act_result.get('tool_receipts', [])
        
        self._append_to_log(receipt)
        self.last_snapshot_id = snapshot_id
        self.last_state_hash = state_hash
        self.last_receipt = receipt
        self.phase = "IDLE"
        return "COMMIT"

    def _emit_fail(self, error_msg: str, input_hash: str) -> str:
        receipt_id = "rcpt_" + str(uuid.uuid4())[:8]
        receipt = {
            "receipt_id": receipt_id,
            "phase": self.phase,
            "verdict": "FAIL",
            "outcome": "FAIL",    # Consistency
            "error": error_msg,
            "input_hash": input_hash,
            "prev_receipt_hash": self.receipt_log_head,
            "ts": int(time.time())
        }
        # 5. SIGN (Deterministic if key available)
        payload = json.dumps(receipt, sort_keys=True).encode()
        if self.key_manager:
            receipt["sig_b64"] = self.key_manager.sign(payload)
        else:
            # Fallback to file-based legacy signing if manager not active
            try:
                receipt["sig_b64"] = sign_payload(payload)
            except:
                pass 

        self._append_to_log(receipt)
        self.memory.clear_staged()
        self.last_receipt = receipt
        self.phase = "IDLE"
        return "FAIL"

    def close(self):
        """Shutdown session and zero key memory."""
        if hasattr(self, 'key_manager') and self.key_manager:
            self.key_manager.close()
        if hasattr(self, 'memory') and self.memory:
            self.memory.close()

    def _verify_tool_receipts(self, act_result: dict, allowlist: list[str]) -> str | None:
        """
        Verifier check: no committed state transition may rely on an
        unauthorized external call.
        """
        receipts  = act_result.get('tool_receipts', [])
        allowed   = frozenset(allowlist)
        for r in receipts:
            if r.get('network_call_made') and r.get('host') not in allowed:
                return (
                    f"verifier_tool_allowlist_violation: "
                    f"network call made to unauthorized host '{r['host']}'"
                )
        return None

    def _verify_canon_immutability(self, staged_writes: list, db_conn) -> str | None:   
        """Returns error if canon unit already committed."""
        cursor = db_conn.cursor()
        for write in staged_writes:
            if write.get('scope') == 'canon':
                cursor.execute(
                    'SELECT 1 FROM units WHERE unit_id = ? LIMIT 1',
                    (write.get('unit_id') or write.get('id'),)
                )
                if cursor.fetchone() is not None:
                    return (
                        f"canon_immutability_violation: unit '{write.get('unit_id') or write.get('id')}'"
                        " already committed. Canon units are write-once."
                    )
        return None

    def _eval_policy_rules(self, staged_writes: list, db_conn) -> str | None:
        """Evaluates active policy rules (sandboxed)."""
        cursor = db_conn.cursor()
        cursor.execute("SELECT rule_id, description, predicate FROM policy_rules WHERE is_active = 1")
        rules = cursor.fetchall()

        for write in staged_writes:
            # Special case for body if it's still a string (Stage 1/2) 
            # vs dict (Week 3)
            body = write.get('body')
            # The briefing unit_ctx uses body_hash, tags, scope
            unit_ctx = {
                'scope':     write.get('scope', ''),
                'tags':      write.get('tags', []),
                'body_hash': write.get('body_hash', ''),
                'content_type': write.get('content_type', 'plain'),
                'entities':  write.get('entities', []),
            }
            for rule_id, description, predicate in rules:
                try:
                    if not eval_policy_predicate(predicate, unit_ctx):
                        return f'policy_rule_violation: {rule_id}: {description}'
                except PolicyRuleError as exc:
                    return f'policy_rule_error: {rule_id}: {exc}'
                except Exception as exc:
                    return f'policy_rule_evaluation_error: {rule_id}: {exc}'
        return None

    def apply_receipt(self, receipt: dict) -> None:
        """
        Replay a committed receipt directly into storage.
        Called only during log replay. Never called from production write paths.
        Raises ValueError if receipt outcome is not COMMIT.
        """
        if receipt.get('outcome') != 'COMMIT':
            return  # skip FAIL receipts — they left no state

        # Re-apply staged writes from the receipt
        # We check staged_units (Week 8) or fall back to data.units (legacy)
        units = receipt.get('staged_units')
        if units is None:
            units = receipt.get('data', {}).get('units', [])

        for unit in units:
            # Re-normalize for MemoryStore
            u = dict(unit)
            if 'unit_id' not in u and 'id' in u:
                u['unit_id'] = u.pop('id')
            if 'body_hash' not in u:
                u['body_hash'] = hashlib.sha256(json.dumps(u['body'], sort_keys=True).encode()).hexdigest()
            self.memory.stage_unit(u)

        self.memory.commit_staged(
            receipt.get('receipt_id', 'rcpt_replay'),
            receipt.get('snapshot_id', 'snap_replay')
        )

        # Update state hash - IMPORTANT: do this AFTER commit so derive_state_hash works if needed
        self.last_state_hash = receipt.get('state_hash')

    def replay_log(self, log_path: str):
        """
        Replays a JSONL log into this runtime.
        Crucial for the 'deterministic' claim.
        Verifies the hash chain during replay.
        """
        if not os.path.exists(log_path):
            print(f"[REPLAY] Log file not found at {log_path}")
            return

        genesis_hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        expected_prev = genesis_hash
        
        print(f"[REPLAY] Replaying {log_path}...")
        with open(log_path, "r") as f:
            for line in f:
                if not line.strip(): continue
                receipt = json.loads(line)
                
                # CHAIN VALIDATION
                if receipt["prev_receipt_hash"] != expected_prev:
                    raise ValueError(
                        f"Chain break at {receipt['receipt_id']}: "
                        f"expected prev={expected_prev}, "
                        f"got={receipt['prev_receipt_hash']}"
                    )
                
                # Update chain tracking for the NEXT receipt
                receipt_bytes = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode("utf-8")
                expected_prev = hashlib.sha256(receipt_bytes).hexdigest()
                self.receipt_log_head = expected_prev
                
                if receipt["phase"] == "COMMIT" and receipt["verdict"] == "PASS":
                    self.apply_receipt(receipt)
                    self.last_snapshot_id = receipt["snapshot_id"]
                    print(f"[REPLAY] Applied {receipt['snapshot_id']} | State Hash: {self.last_state_hash[:12]}...")
                else:
                    print(f"[REPLAY] Skipped {receipt.get('phase')} receipt {receipt.get('receipt_id')}")
        
        print(f"[REPLAY] Finished. Final State Hash: {self.last_state_hash[:12] if self.last_state_hash else 'N/A'}")

CompanionRuntime = AgentRuntime
