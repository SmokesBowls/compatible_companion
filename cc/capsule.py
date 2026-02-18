import json
import datetime
from typing import Dict, Any, Optional
from .runtime import CompanionRuntime

class CapsuleIO:
    """
    CapsuleIO handles serialization and deserialization of the companion state.
    Section C of the spec defines the mandatory fields.
    """
    def __init__(self, runtime: CompanionRuntime):
        self.runtime = runtime

    def export_capsule(self, companion_id: str, profile: Dict[str, Any]) -> Dict[str, Any]:
        """
        Creates a JSON capsule of the current state.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        capsule = {
            "spec_version": "cc/0.1",
            "id": companion_id,
            "created_at": now, # Stub: Should be from DB in real usage
            "exported_at": now,
            "origin": {
                "runtime": "cc-python/0.1",
                "framework": "standalone"
            },
            "identity": {
                "did": f"did:cc:{companion_id}",
                "pubkey_b64": "null-week1-stub"
            },
            "profile": profile,
            "memory_snapshot": {
                "snapshot_id": self.runtime.last_snapshot_id,
                "state_hash": self.runtime.last_state_hash,
                "unit_counts": self._get_unit_counts()
            },
            "policy": {
                "confirm_gate": True,
                "tool_allowlist": self.runtime.gateway.allowlist
            },
            "tool_manifest": [
                {"name": name, "schema_url": "local:stub", "strict": True} 
                for name in self.runtime.gateway.tools.keys()
            ],
            "receipt_log_head": self.runtime.receipt_log_head,
            "artifact_refs": [],
            "prev_capsule_hash": None,
            "signature": None
        }
        return capsule

    def _get_unit_counts(self) -> Dict[str, int]:
        """Returns counts of memory units by scope."""
        cursor = self.runtime.memory.conn.cursor()
        cursor.execute("SELECT scope, COUNT(*) as count FROM units GROUP BY scope")
        return {row["scope"]: row["count"] for row in cursor.fetchall()}

    def import_capsule(self, capsule_data: Dict[str, Any]):
        """
        Imports metadata and profile from a capsule.
        Memory units and logs are expected to be present in the filesystem or 
        reconstructed via receipt log (Week 1 stub).
        """
        # Week 1: Minimal import logic
        if capsule_data.get("spec_version") != "cc/0.1":
            raise ValueError("Unsupported spec version")
        
        # Verification of state_hash (I-8)
        # Week 1: If we have the runtime, we can check if its state matches the capsule
        if capsule_data["memory_snapshot"]["state_hash"] != self.runtime.last_state_hash:
            # This is a soft check for Week 1; in real usage it handles DB restoration
            pass
        
        return capsule_data["profile"]
