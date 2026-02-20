# cc/config.py
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "llm": {
        "backend": "ollama",
        "model": "llama3",
        "base_url": "http://127.0.0.1:11434",
        "timeout_s": 30
    },
    "security": {
        "tool_allowlist": ["127.0.0.1", "localhost"]
    }
}

def config_path() -> Path:
    return Path(os.path.expanduser("~/.compatible/config.json"))

def load_config() -> Dict[str, Any]:
    p = config_path()
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        return dict(DEFAULT_CONFIG)

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return dict(DEFAULT_CONFIG)

        merged = dict(DEFAULT_CONFIG)

        llm = dict(DEFAULT_CONFIG["llm"])
        llm_in = data.get("llm")
        if isinstance(llm_in, dict):
            llm.update(llm_in)
        merged["llm"] = llm

        sec = dict(DEFAULT_CONFIG["security"])
        sec_in = data.get("security")
        if isinstance(sec_in, dict):
            sec.update(sec_in)
        merged["security"] = sec

        return merged
    except Exception:
        return dict(DEFAULT_CONFIG)

def save_config(cfg: Dict[str, Any]) -> None:
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    os.replace(tmp, p)
