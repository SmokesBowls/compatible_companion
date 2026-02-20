import json
import hashlib
import time
import uuid
import os
import pathlib
import warnings
import threading
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from .memory import MemoryStore
from .zw_block import ZWBlock
from .identity import KeyManager, sign_payload
from .policy_store import SQLitePolicyStore, verify_policy_integrity

class Plan:
    def __init__(self, action: str, scope: str, rollback_anchor: Optional[str] = None, tool_refs: List[str] = None):
        self.action = action
        self.scope = scope
        self.rollback_anchor = rollback_anchor
        self.tool_refs = tool_refs or []

@dataclass
class SessionContext:
    session_id: str
    staged_units: List[Dict[str, Any]] = field(default_factory=list)
    key_manager: Optional[Any] = None

class AgentRuntime:
    """
    AgentRuntime (formerly CompanionRuntime) orchestrates the PLAN -> ACT -> VERIFY -> COMMIT cycle.
    """
    def __init__(self, 
                 memory: Optional[MemoryStore] = None, 
                 log_path: str = None,
                 key_manager: Optional[KeyManager] = None,
                 tool_allowlist: List[str] = None,
                 db_path: Optional[str] = None):
        """
        AgentRuntime (formerly CompanionRuntime) orchestrates the PLAN -> ACT -> VERIFY -> COMMIT cycle.
        
        Args:
            memory: A MemoryStore instance (e.g. SqliteMemoryStore).
            log_path: Path to the receipt log file.
            key_manager: A KeyManager instance for signing.
            tool_allowlist: List of allowed tool hosts.
            db_path: Legacy alias for memory. If provided and memory is None, 
                    SqliteMemoryStore(db_path) will be used.
        """
        if memory is None and db_path is not None:
            # Import here to avoid circular dependencies if any
            from .memory import SqliteMemoryStore
            self.memory = SqliteMemoryStore(db_path)
        elif memory is not None:
            self.memory = memory
        else:
            raise ValueError("Must provide either 'memory' or 'db_path'")

        self.log_path = log_path or "receipts.jsonl"
        self.key_manager = key_manager
        self.tool_allowlist = list(tool_allowlist or [])
        
        self.mem_store = self.memory # Alias for back-compat
        self._last_act_result = {}
        
        # Initial hash for an empty chain
        self.receipt_log_head = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self._load_log_head()
        
        self.phase = "IDLE"
        self.last_state_hash = None
        
        # P2: Freeze lock to prevent COMMIT during snapshot export
        self._compact_lock = threading.Lock()

        # ── POLICY INTEGRITY (Week 9.5) ──────────────────────────────
        # We assume for now that memory has a .conn (SqliteMemoryStore)
        if hasattr(self.memory, 'conn'):
            self.policy_store = SQLitePolicyStore(self.memory.conn)
        else:
            self.policy_store = None

        self.policy_mode = 'normal'
        self.policy_integrity_warning = None
        
        if self.policy_store and os.path.exists(self.log_path):
            integrity_ok, reason = verify_policy_integrity(self.policy_store, self.log_path)
            if not integrity_ok:
                self.policy_mode = 'locked_down'
                self.policy_integrity_warning = reason
                self._emit_receipt('POLICY_INTEGRITY_FAIL', error=reason)
        elif self.policy_store:
            # New log
            self.policy_mode = 'locked_down'
            self.policy_integrity_warning = 'policy set has never been sealed'

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

    def ingest(self, text: str, scope: str = "core", session_context: SessionContext = None) -> Dict[str, Any]:
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

        self.run_cycle(plan, act_fn, invariants=[], session_context=session_context)
        return self.last_receipt

    def ingest_chat_turn(self, text: str, scope: str = "core", session_context: SessionContext = None) -> Dict[str, Any]:
        """
        Chat turn committed as one receipt:
          - user unit
          - assistant unit (Ollama)
        Both are auditable and chained.
        """
        from .config import load_config
        from .llm import OllamaBackend

        cfg = load_config()
        llm_cfg = (cfg.get("llm") or {})
        base_url = llm_cfg.get("base_url", "http://127.0.0.1:11434")
        model = llm_cfg.get("model", "llama3")
        timeout_s = int(llm_cfg.get("timeout_s", 30))

        backend_name = (llm_cfg.get("backend") or "ollama").lower()
        if backend_name not in ("ollama", "local"):
            # If someone sets backend to "none", fall back to single-unit ingest.
            return self.ingest(text, scope=scope, session_context=session_context)

        llm = OllamaBackend(base_url=base_url, model=model, timeout_s=timeout_s)

        messages = [
            {"role": "system", "content": "You are Compatible Companion. Be precise, local-first, and auditable."},
            {"role": "user", "content": text},
        ]
        self.phase = "ACT"
        res = llm.complete(messages)
        tool_rcpt = llm.tool_receipt()

        if not res.get("ok"):
            # Fail the cycle (no DB write) instead of committing the error string.
            err_type = res.get("error_type") or "llm_error"
            err_detail = res.get("error_detail") or "unknown_llm_error"
            self._emit_fail(
                f"llm_call_failed: {err_type}", 
                input_hash="llm_fail", 
                session_context=session_context,
                error_type=err_type,
                error_detail=err_detail
            )
            return self.last_receipt

        assistant_content = res.get("content", "")

        plan = {
            "action": "chat_turn",
            "scope": scope,
            "text": text,
            "assistant_content": assistant_content,
            "llm": {"backend": "ollama", "model": model, "base_url": base_url},
        }

        def act_fn(p):
            user_unit_id = f"unit_{str(uuid.uuid4())[:8]}"
            asst_unit_id = f"unit_{str(uuid.uuid4())[:8]}"

            user_block = ZWBlock(p["text"])
            asst_block = ZWBlock(p["assistant_content"])

            return {
                "units": [
                    {
                        "action": "mem_store",
                        "unit_id": user_unit_id,
                        "scope": p["scope"],
                        "body": {"role": "user", "content": p["text"]},
                        "body_hash": user_block.hash,
                        "tags": ["chat", "user"],
                        "content_type": "json",
                    },
                    {
                        "action": "mem_store",
                        "unit_id": asst_unit_id,
                        "scope": p["scope"],
                        "body": {"role": "assistant", "content": p["assistant_content"]},
                        "body_hash": asst_block.hash,
                        "tags": ["chat", "assistant"],
                        "content_type": "json",
                    },
                ],
                "tool_receipts": [tool_rcpt],
            }

        self.run_cycle(plan, act_fn, invariants=[], session_context=session_context)
        return self.last_receipt

    def run_cycle(self, plan: Dict[str, Any], act_fn, invariants: List = None, session_context: SessionContext = None) -> str:
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
        
        # Use session context staged_units if available, else global ones
        staged_units = session_context.staged_units if session_context else self.memory.staged_units

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
                staged_units.append(unit)
            elif 'units' in act_result:
                for u in act_result['units']:
                    # Normalize missing body_hash for batch units
                    if 'body_hash' not in u and 'body' in u:
                        u['body_hash'] = hashlib.sha256(json.dumps(u['body'], sort_keys=True).encode()).hexdigest()
                    staged_units.append(u)

        # 3. VERIFY
        self.phase = "VERIFY"
        
        # 1. Canon immutability
        error = self._verify_canon_immutability(staged_units, self.memory.conn)
        if error:
            return self._emit_fail(error, input_hash, session_context)

        # 2. Tool receipt integrity (NEW)
        error = self._verify_tool_receipts(self._last_act_result, self.tool_allowlist)
        if error:
            return self._emit_fail(error, input_hash, session_context)

        # 3. Policy Rules
        error = self._eval_policy_rules(staged_units, self.memory.conn)
        if error:
            return self._emit_fail(error, input_hash, session_context)

        # 4. COMMIT
        self.phase = "COMMIT"
        
        # Capture staged units BEFORE commit
        staged_copy = []
        for u in staged_units:
            # Normalize to unit_id for the receipt data
            c = dict(u)
            if 'unit_id' not in c and 'id' in c:
                c['unit_id'] = c.pop('id')
            staged_copy.append(c)

        receipt_id = "rcpt_" + str(uuid.uuid4())[:8]
        snapshot_id = "snap_" + str(uuid.uuid4())[:8]
        
        # COMMIT phase — must not run during snapshot export
        with self._compact_lock:
            # Commit to shared DB
            if session_context:
                self.memory.commit_staged(receipt_id, snapshot_id, units=staged_units)
                session_context.staged_units = []
            else:
                self.memory.commit_staged(receipt_id, snapshot_id) # self.memory.staged_units cleared internally
            
            state_hash = self.memory.derive_state_hash(self.receipt_log_head)
            
            receipt = {
                "receipt_id": receipt_id,
                "phase": "COMMIT",
                "outcome": "COMMIT",
                "verdict": "PASS",
                "snapshot_id": snapshot_id,
                "input_hash": input_hash,
                "prev_receipt_hash": self.receipt_log_head,
                "state_hash": state_hash,
                "ts": int(time.time()),
                "data": {"units": staged_copy},
                "staged_units": staged_copy,
                "tool_receipts": self._last_act_result.get('tool_receipts', [])
            }
            
            # SIGN
            km = session_context.key_manager if session_context else self.key_manager
            payload = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode()
            if km:
                receipt["sig_b64"] = km.sign(payload)
            
            self._append_to_log(receipt)
            self.last_snapshot_id = snapshot_id
            self.last_state_hash = state_hash
            self.last_receipt = receipt
            
        self.phase = "IDLE"
        return "COMMIT"

    def _emit_fail(self, error_msg: str, input_hash: str, session_context: SessionContext = None, error_type: str = None, error_detail: str = None) -> str:
        receipt_id = "rcpt_" + str(uuid.uuid4())[:8]
        receipt = {
            "receipt_id": receipt_id,
            "phase": self.phase,
            "verdict": "FAIL",
            "outcome": "FAIL",
            "error": error_msg,
            "error_type": error_type,
            "error_detail": error_detail,
            "input_hash": input_hash,
            "prev_receipt_hash": self.receipt_log_head,
            "ts": int(time.time())
        }
        # 5. SIGN
        km = session_context.key_manager if session_context else self.key_manager
        payload = json.dumps(receipt, sort_keys=True).encode()
        if km:
            receipt["sig_b64"] = km.sign(payload)
        else:
            # Fallback to file-based legacy signing if manager not active
            try:
                receipt["sig_b64"] = sign_payload(payload)
            except:
                pass 

        self._append_to_log(receipt)
        if session_context:
            session_context.staged_units = []
        else:
            self.memory.clear_staged()
        self.last_receipt = receipt
        self.phase = "IDLE"
        return "FAIL"

    def _emit_receipt(self, receipt_type: str, outcome: str = "FAIL", error: str = None):
        """Helper to log a simple system receipt."""
        receipt = {
            "receipt_id": "rcpt_" + str(uuid.uuid4())[:8],
            "type": receipt_type,
            "outcome": outcome,
            "error": error,
            "policy_mode": getattr(self, 'policy_mode', 'unknown'),
            "ts": int(time.time()),
            "timestamp": int(time.time()), # Briefing used timestamp
            "prev_receipt_hash": self.receipt_log_head
        }
        self._append_to_log(receipt)

    def _recheck_policy_integrity(self):
        """Re-run integrity check after sealing. Updates policy_mode in place."""
        ok, reason = verify_policy_integrity(self.policy_store, self.log_path)
        self.policy_mode = 'normal' if ok else 'locked_down'
        self.policy_integrity_warning = None if ok else reason

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
        """Evaluates active policy rules (pure Python pattern matching). No eval."""
        # If policy integrity check failed at startup, DB rules are untrusted.
        # Only hardcoded constitutional rules apply.
        if getattr(self, 'policy_mode', 'normal') == 'locked_down':
            return None

        from .policy_store import evaluate_rule
        rules = self.policy_store.get_active_rules()

        for write in staged_writes:
            # Special case for body if it's still a string (Stage 1/2) 
            # vs dict (Week 3)
            # The briefing unit_ctx uses body_hash, tags, scope
            unit_ctx = {
                'scope':     write.get('scope', ''),
                'tags':      write.get('tags', []),
                'body_hash': write.get('body_hash', ''),
                'content_type': write.get('content_type', 'plain'),
                'entities':  write.get('entities', []),
                'unit_id':   write.get('unit_id'),
            }
            # Also allow dot-access into body if it's a dict
            if isinstance(write.get('body'), dict):
                unit_ctx['body'] = write['body']

            for rule_row in rules:
                import json
                try:
                    # check if predicate is a JSON string or already a dict
                    pred = rule_row['predicate']
                    if isinstance(pred, str) and pred.strip().startswith('{'):
                        rule = json.loads(pred)
                    else:
                        return f"policy_rule_error: {rule_row['rule_id']}: legacy string predicate not supported"
                    
                    if not evaluate_rule(rule, unit_ctx):
                        return f'policy_rule_violation: {rule_row.get("rule_id")}: {rule_row.get("description")}'
                except Exception as exc:
                    return f'policy_rule_evaluation_error: {rule_row.get("rule_id")}: {exc}'
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
                
                if receipt.get("phase") == "COMMIT" and receipt.get("verdict") == "PASS":
                    self.apply_receipt(receipt)
                    self.last_snapshot_id = receipt["snapshot_id"]
                    print(f"[REPLAY] Applied {receipt['snapshot_id']} | State Hash: {self.last_state_hash[:12]}...")
                else:
                    print(f"[REPLAY] Skipped {receipt.get('phase')} receipt {receipt.get('receipt_id')}")
        
        print(f"[REPLAY] Finished. Final State Hash: {self.last_state_hash[:12] if self.last_state_hash else 'N/A'}")

CompanionRuntime = AgentRuntime
