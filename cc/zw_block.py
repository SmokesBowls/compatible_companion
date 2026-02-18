import hashlib
import json
from datetime import datetime
from typing import Optional, Dict, Any

class ZWBlock:
    """
    ZWBlock handles canonicalization and hashing of memory units.
    In Week 1, it supports plain text ingestion and mapping to bytes.
    """
    def __init__(self, content: str, content_type: str = "plain"):
        self.content = content
        self.content_type = content_type
        self.canonical_bytes = self._canonicalize()
        self.hash = self._calculate_hash()

    def _canonicalize(self) -> bytes:
        """Produces deterministic bytes based on content type."""
        if self.content_type == "json":
            # Sort keys for determinism
            if isinstance(self.content, str):
                data = json.loads(self.content)
            else:
                data = self.content
            return json.dumps(data, sort_keys=True).encode("utf-8")
        
        # Default to utf-8 encoded string
        if isinstance(self.content, str):
            return self.content.encode("utf-8")
        return str(self.content).encode("utf-8")

    def _calculate_hash(self) -> str:
        """SHA256 hash of canonical bytes."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "content_type": self.content_type,
            "body_hash": self.hash
        }
