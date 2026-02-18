import json
import hashlib
import time
import uuid
import os
from typing import Dict, Any, List, Optional
from .memory import MemoryStore
from .tools import TypedToolGateway
from .zw_block import ZWBlock

class Plan:
    def __init__(self, action: str, scope: str, rollback_anchor: Optional[str] = None, tool_refs: List[str] = None):
        self.action = action
        self.scope = scope
        self.rollback_anchor = rollback_anchor
        self.tool_refs = tool_refs or []

class CompanionRuntime:
    """
    CompanionRuntime orchestrates the PLAN -> ACT -> VERIFY -> COMMIT cycle.
    It manages the SQLite MemoryStore and the JSONL Receipt Log.
    """
    def __init__(self, db_path: str = ":memory:", log_path: str = "receipts.jsonl"):
        self.memory = MemoryStore(db_path)
        self.gateway = TypedToolGateway()
        self.log_path = log_path
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
        receipt_bytes = json.dumps(receipt, sort_keys=True).encode("utf-8")
        with open(self.log_path, "ab") as f:
            f.write(receipt_bytes + b"\n")
        self.receipt_log_head = hashlib.sha256(receipt_bytes).hexdigest()
        print(f"[LOG] Appended {receipt['receipt_id']} | Log Head: {self.receipt_log_head[:12]}...")

    def ingest(self, text: str, scope: str = "core") -> Dict[str, Any]:
        """
        Runs a full cycle for a text input.
        """
        input_hash = hashlib.sha256(text.encode()).hexdigest()
        print(f"\n[INGEST] Input: '{text[:30]}...' | Hash: {input_hash[:12]}...")
        
        # 1. PLAN
        self.phase = "PLAN"
        plan = Plan(action="ingest", scope=scope, rollback_anchor=self.last_snapshot_id)
        
        # 2. ACT
        self.phase = "ACT"
        # In this simple MVP, ACT creates a unit from the input text
        unit_id = f"unit_{str(uuid.uuid4())[:8]}"
        block = ZWBlock(text)
        unit = {
            "id": unit_id,
            "scope": scope,
            "content_type": "plain",
            "body": text,
            "body_hash": block.hash,
            "tags": [],
            "entities": []
        }
        self.memory.stage_unit(unit)
        staged_output = {"units": [unit], "output_hash": hashlib.sha256(json.dumps(unit).encode()).hexdigest()}
        
        # 3. VERIFY
        self.phase = "VERIFY"
        verdict = "PASS"
        if not self._run_invariants(unit):
            verdict = "FAIL"
        
        # 4. COMMIT or DISCARD
        receipt_id = "rcpt_" + str(uuid.uuid4())[:8]
        if verdict == "PASS":
            self.phase = "COMMIT"
            snapshot_id = "snap_" + str(uuid.uuid4())[:8]
            self.memory.commit_staged(receipt_id, snapshot_id)
            state_hash = self.memory.derive_state_hash(self.receipt_log_head)
            
            receipt = {
                "receipt_id": receipt_id,
                "phase": "COMMIT",
                "verdict": "PASS",
                "snapshot_id": snapshot_id,
                "input_hash": input_hash,
                "output_hash": staged_output["output_hash"],
                "prev_receipt_hash": self.receipt_log_head,
                "state_hash": state_hash,
                "ts": int(time.time()),
                # We store the unit data in the receipt for replayability in MVP
                "data": {"units": [unit]}
            }
            self._append_to_log(receipt)
            self.last_snapshot_id = snapshot_id
            self.last_state_hash = state_hash
            print(f"[COMMIT] {snapshot_id} | State Hash: {state_hash[:12]}...")
            self.phase = "IDLE"
            return receipt
        else:
            self.phase = "DISCARD"
            self.memory.clear_staged()
            receipt = {
                "receipt_id": receipt_id,
                "phase": "DISCARD",
                "verdict": "FAIL",
                "input_hash": input_hash,
                "prev_receipt_hash": self.receipt_log_head,
                "ts": int(time.time())
            }
            self._append_to_log(receipt)
            print(f"[DISCARD] Verification failed for {receipt_id}")
            self.phase = "IDLE"
            return receipt

    def _run_invariants(self, unit: Dict[str, Any]) -> bool:
        """Evaluates built-in and policy-based invariants."""
        # Built-in: non-empty body
        if not unit.get("body"):
            return False
            
        # Policy rules
        rules = self.memory.get_policy_rules(unit.get("scope"))
        for rule in rules:
            try:
                # Weak eval stub
                if not eval(rule["predicate"], {"body": unit["body"]}):
                    if rule["on_fail"] == "block":
                        print(f"[VERIFY] Rule {rule['rule_id']} failed (BLOCK)")
                        return False
            except Exception as e:
                print(f"[VERIFY] Error evaluating rule {rule['rule_id']}: {e}")
                return False
        return True

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
                receipt_bytes = json.dumps(receipt, sort_keys=True).encode("utf-8")
                expected_prev = hashlib.sha256(receipt_bytes).hexdigest()
                self.receipt_log_head = expected_prev
                
                if receipt["phase"] == "COMMIT" and receipt["verdict"] == "PASS":
                    # Apply units in data
                    for unit in receipt["data"]["units"]:
                        self.memory.stage_unit(unit)
                    self.memory.commit_staged(receipt["receipt_id"], receipt["snapshot_id"])
                    
                    self.last_snapshot_id = receipt["snapshot_id"]
                    self.last_state_hash = receipt["state_hash"]
                    print(f"[REPLAY] Applied {receipt['snapshot_id']} | State Hash: {self.last_state_hash[:12]}...")
                else:
                    print(f"[REPLAY] Skipped {receipt.get('phase')} receipt {receipt.get('receipt_id')}")
        
        print(f"[REPLAY] Finished. Final State Hash: {self.last_state_hash[:12] if self.last_state_hash else 'N/A'}")

    def close(self):
        self.memory.close()
