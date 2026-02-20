# cc/api.py
from __future__ import annotations

import json
import os
import datetime
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Compatible Companion API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPO_ROOT = Path(__file__).resolve().parent.parent
UI_DIST = REPO_ROOT / "ui" / "dist"
UI_DEV = REPO_ROOT / "ui"

# Mount built UI only if present.
if UI_DIST.is_dir():
    app.mount("/static", StaticFiles(directory=str(UI_DIST), html=True), name="static")

# Serve zero-build UI at /ui/*
if UI_DEV.is_dir():
    app.mount("/ui", StaticFiles(directory=str(UI_DEV), html=True), name="ui")

runtime = None
DB_PATH = str(REPO_ROOT / "cc_main.db")
LOG_PATH = str(REPO_ROOT / "cc_receipts.jsonl")

def _init_runtime() -> None:
    global runtime
    if runtime is not None:
        return

    from cc.runtime import AgentRuntime
    from cc.memory import SqliteMemoryStore
    from cc.identity import KeyManager, generate_keypair

    db_path = str(REPO_ROOT / "cc_main.db")
    log_path = str(REPO_ROOT / "cc_receipts.jsonl")
    mem = SqliteMemoryStore(db_path)

    # Load signing key if present; otherwise generate one (so export can sign).
    key_path = str(REPO_ROOT / "cc_identity.key")
    if not os.path.exists(key_path) or os.path.getsize(key_path) == 0:
        generate_keypair(key_file=key_path, pub_file=str(REPO_ROOT / "cc_identity.pub"))

    km = KeyManager.from_path(key_path)

    from cc.config import load_config
    cfg = load_config()
    allow = (cfg.get("security", {}) or {}).get("tool_allowlist", ["127.0.0.1", "localhost"])

    runtime = AgentRuntime(memory=mem, log_path=log_path, key_manager=km, tool_allowlist=allow)

def _tail_jsonl(path: str, limit: int = 20) -> List[Dict[str, Any]]:
    if limit < 1:
        return []
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    # simple tail: read all lines (OK for dev); upgrade to seek-based later if needed
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    for ln in lines[-limit:]:
        try:
            out.append(json.loads(ln))
        except Exception:
            out.append({"_error": "bad_jsonl_line", "raw": ln[:500]})
    return out

@app.get("/health")
async def health():
    _init_runtime()
    state_hash = None
    policy_mode = None
    policy_warning = None
    log_head = None
    if runtime is not None:
        try:
            state_hash = runtime.current_state_hash()
        except Exception:
            state_hash = getattr(runtime, "last_state_hash", None)

        policy_mode = getattr(runtime, "policy_mode", None)
        policy_warning = getattr(runtime, "policy_integrity_warning", None)
        log_head = getattr(runtime, "receipt_log_head", None)

    return {
        "ok": True,
        "state_hash": state_hash,
        "log_head": log_head,
        "policy_mode": policy_mode,
        "policy_integrity_warning": policy_warning,
        "ui_present": UI_DIST.is_dir(),
        "ui_path": str(UI_DIST),
        "db_path": DB_PATH,
        "log_path": LOG_PATH,
    }

@app.post("/api/ingest")
async def ingest(payload: Dict[str, Any]):
    _init_runtime()
    if runtime is None:
        return JSONResponse({"error": "runtime_not_initialized"}, status_code=500)

    text = (payload or {}).get("text", "")
    scope = (payload or {}).get("scope", "core")

    # Use the 2-unit chat turn
    rcpt = runtime.ingest_chat_turn(text, scope=scope)
    
    if rcpt.get("outcome") == "FAIL":
        raise HTTPException(
            status_code=502,
            detail={"error": "llm_failure", "reason": rcpt.get("error")}
        )

    return JSONResponse(rcpt)

# Back-compat with your existing UI button that calls /api/run_cycle
@app.post("/api/run_cycle")
async def run_cycle(payload: Dict[str, Any]):
    return await ingest(payload)

@app.get("/api/receipts/tail")
async def receipts_tail(limit: int = 20):
    return JSONResponse(_tail_jsonl(LOG_PATH, limit=limit))

@app.get("/api/llm/status")
async def llm_status():
    from cc.config import load_config
    cfg = load_config()
    llm = cfg.get("llm", {}) or {}
    return {
        "backend": llm.get("backend"),
        "model": llm.get("model"),
        "base_url": llm.get("base_url"),
    }

@app.post("/api/llm/config")
async def llm_config_update(payload: Dict[str, Any]):
    from cc.config import load_config, save_config
    
    backend  = str(payload.get("backend", "ollama")).lower().strip()
    model    = payload.get("model")
    base_url = payload.get("base_url")

    # Basic Validation
    if backend not in ("ollama", "none", "openai_compat", "openai", "anthropic"):
        return JSONResponse({"ok": False, "error": "invalid_backend"}, status_code=400)

    if not isinstance(model, str) or not model.strip():
        return JSONResponse({"ok": False, "error": "invalid_model"}, status_code=400)

    if base_url is not None:
        if not isinstance(base_url, str) or "://" not in base_url:
            return JSONResponse({"ok": False, "error": "invalid_base_url"}, status_code=400)

    cfg = load_config()
    if "llm" not in cfg:
        cfg["llm"] = {}
    
    cfg["llm"].update(payload)
    save_config(cfg)
    return {"ok": True, "llm": cfg["llm"]}

@app.get("/api/ollama/tags")
async def ollama_tags():
    from cc.config import load_config
    cfg = load_config()
    llm = (cfg.get("llm", {}) or {})
    base_url = (llm.get("base_url") or "http://127.0.0.1:11434").rstrip("/")
    url = base_url + "/api/tags"

    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as r:
            raw = r.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        models = []
        for m in (data.get("models") or []):
            name = m.get("name")
            if isinstance(name, str) and name.strip():
                models.append(name)
        models.sort()
        return {"ok": True, "base_url": base_url, "models": models}
    except urllib.error.URLError as e:
        return JSONResponse({"ok": False, "error": f"ollama_unreachable: {e}", "base_url": base_url, "models": []}, status_code=503)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"ollama_tags_error: {e}", "base_url": base_url, "models": []}, status_code=500)

@app.get("/", response_class=HTMLResponse)
async def root():
    if (REPO_ROOT / "ui" / "index.html").is_file():
        return RedirectResponse(url="/ui/")
    return HTMLResponse("<h1>Compatible Companion</h1><p>Open <a href='/ui/'>/ui/</a></p>")

@app.post("/api/capsule/export")
async def capsule_export(payload: Dict[str, Any]):
    """
    Exports a signed capsule to disk.
    Writes to ./exports/*.cc.json and returns the filepath + capsule_id.
    """
    _init_runtime()
    if runtime is None:
        return JSONResponse({"error": "runtime_not_initialized"}, status_code=500)

    from cc.capsule import CapsuleIO

    agent_id = (payload or {}).get("agent_id", "agent-x")
    profile  = (payload or {}).get("profile", {})  # optional metadata

    exports_dir = REPO_ROOT / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)

    # Freeze commits during export (uses your runtime's lock)
    lock = getattr(runtime, "_compact_lock", None)
    if lock is None:
        class _Noop:
            def __enter__(self): return None
            def __exit__(self, *a): return False
        lock = _Noop()

    with lock:
        io = CapsuleIO(runtime)
        capsule = io.export_capsule(agent_id=agent_id, profile=profile)

        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        capsule_id = capsule.get("capsule_id", "unknown")
        out_path = exports_dir / f"{ts}_{capsule_id}.cc.json"

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(capsule, f, indent=2)

    return {
        "ok": True,
        "path": str(out_path),
        "capsule_id": capsule_id,
        "signed": bool(capsule.get("signature")),
        "log_head": capsule.get("log_head") or capsule.get("log_chain_head"),
        "units": len(capsule.get("memory_units", [])),
    }

@app.post("/api/capsule/import")
async def capsule_import(payload: Dict[str, Any]):
    """
    Imports a capsule dict.
    payload = { "capsule": {...}, "override": false }
    """
    _init_runtime()
    if runtime is None:
        return JSONResponse({"error": "runtime_not_initialized"}, status_code=500)

    from cc.capsule import CapsuleIO

    capsule = (payload or {}).get("capsule")
    override = bool((payload or {}).get("override", False))
    if not isinstance(capsule, dict):
        return JSONResponse({"error": "missing_capsule_dict"}, status_code=400)

    io = CapsuleIO(runtime)
    report = io.import_capsule(capsule, override=override)
    return {"ok": True, "report": report}

