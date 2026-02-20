# cc/llm.py
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, TypedDict, Literal

Message = Dict[str, str]  # {"role": "...", "content": "..."}

class LLMResult(TypedDict, total=False):
    ok: bool
    content: str
    error_type: str
    error_detail: str

def _host(base_url: str) -> str:
    u = urlparse(base_url)
    return u.hostname or ""

@dataclass
class OllamaBackend:
    base_url: str
    model: str
    timeout_s: int = 30
    _last_tool_receipt: Dict[str, Any] = None

    def complete(self, messages: List[Message]) -> LLMResult:
        host = _host(self.base_url)

        # Prefer chat-style if available; fallback to generate if /api/chat is missing.
        chat_url = self.base_url.rstrip("/") + "/api/chat"
        gen_url  = self.base_url.rstrip("/") + "/api/generate"

        def _post(url: str, payload: dict) -> dict:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url, data=data, headers={"Content-Type": "application/json"}, method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw)

        # 1) Try /api/chat
        try:
            out = _post(chat_url, {"model": self.model, "messages": messages, "stream": False})
            content = (out.get("message") or {}).get("content", "")
            self._last_tool_receipt = {"network_call_made": True, "host": host, "backend": "ollama",
                                      "endpoint": chat_url, "model": self.model, "ok": True}
            return {"ok": True, "content": content}
        except urllib.error.HTTPError as e:
            if getattr(e, "code", None) != 404:
                err_msg = f"HTTPError: {e}"[:400]
                self._last_tool_receipt = {"network_call_made": True, "host": host, "backend": "ollama",
                                          "endpoint": chat_url, "model": self.model, "ok": False,
                                          "error": err_msg}
                return {"ok": False, "error_type": "http_error", "error_detail": err_msg}
            # else: fall through to /api/generate
        except Exception as e:
            err_msg = f"{type(e).__name__}: {e}"[:400]
            self._last_tool_receipt = {"network_call_made": True, "host": host, "backend": "ollama",
                                      "endpoint": chat_url, "model": self.model, "ok": False,
                                      "error": err_msg}
            return {"ok": False, "error_type": "llm_error", "error_detail": err_msg}

        # 2) Fallback /api/generate
        try:
            # Convert messages to a single prompt (minimal, deterministic)
            prompt = "\n".join([f"{m['role']}: {m['content']}" for m in messages])
            out = _post(gen_url, {"model": self.model, "prompt": prompt, "stream": False})
            content = out.get("response", "")
            self._last_tool_receipt = {"network_call_made": True, "host": host, "backend": "ollama",
                                      "endpoint": gen_url, "model": self.model, "ok": True}
            return {"ok": True, "content": content}
        except Exception as e:
            err_msg = f"{type(e).__name__}: {e}"[:400]
            self._last_tool_receipt = {"network_call_made": True, "host": host, "backend": "ollama",
                                      "endpoint": gen_url, "model": self.model, "ok": False,
                                      "error": err_msg}
            return {"ok": False, "error_type": "llm_error", "error_detail": err_msg}

    def tool_receipt(self) -> Dict[str, Any]:
        return self._last_tool_receipt or {
            "network_call_made": True,
            "host": _host(self.base_url),
            "backend": "ollama",
            "model": self.model,
            "ok": False,
            "error": "no_call_made",
        }
