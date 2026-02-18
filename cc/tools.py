import json
import hashlib
import time
import uuid
from typing import Dict, Any, List, Callable, Optional

class TypedToolGateway:
    """
    TypedToolGateway manages tool registration and execution with allowlist enforcement.
    """
    def __init__(self, allowlist: List[str] = None):
        self.tools: Dict[str, Dict[str, Any]] = {}
        self.allowlist = allowlist or []
        self.receipts: List[Dict[str, Any]] = []

    def register_tool(self, name: str, func: Callable, schema: Dict[str, Any] = None):
        self.tools[name] = {
            "func": func,
            "schema": schema,
            "name": name
        }

    def set_allowlist(self, allowlist: List[str]):
        self.allowlist = allowlist

    def call_tool(self, name: str, **kwargs) -> Any:
        """
        Executes a registered tool if it is in the allowlist.
        Emits a tool_receipt for every call.
        """
        if name not in self.allowlist:
            raise PermissionError(f"Tool '{name}' is not in the allowlist.")
        
        if name not in self.tools:
            raise ValueError(f"Tool '{name}' is not registered.")

        tool = self.tools[name]
        
        # In Week 1, we focus on the record-keeping and allowlist.
        # Schema validation is optional/stubbed.
        
        try:
            result = tool["func"](**kwargs)
            verdict = "PASS"
        except Exception as e:
            result = str(e)
            verdict = "FAIL"

        receipt = {
            "tool_call_id": str(uuid.uuid4()),
            "name": name,
            "inputs": kwargs,
            "output": result if verdict == "PASS" else None,
            "error": result if verdict == "FAIL" else None,
            "verdict": verdict,
            "ts": int(time.time())
        }
        self.receipts.append(receipt)
        
        if verdict == "FAIL":
            raise RuntimeError(f"Tool execution failed: {result}")
            
        return result

    def get_receipts(self) -> List[Dict[str, Any]]:
        return self.receipts

    def clear_receipts(self):
        self.receipts = []
