import asyncio
import json
import pathlib
import os
from typing import Any, List, Dict, Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from cc.runtime import AgentRuntime, SessionContext
from cc.capsule import export_capsule, CapsuleIO
from cc.identity import KeyManager

def _mem_store_act(plan: dict) -> dict:
    """Helper for mem_store tool to match run_cycle expectation."""
    return {
        'action': 'mem_store',
        'unit_id': plan.get('unit_id'),
        'scope': plan.get('scope'),
        'body': plan.get('body'),
        'tags': plan.get('tags', []),
        'ttl_expires_at': plan.get('ttl_expires_at') 
    }

def build_server(rt: AgentRuntime, key_manager: KeyManager) -> Server:
    server = Server("compatible-companion")

    @server.list_tools()
    async def list_tools():
        return [
            types.Tool(
                name="mem_find",
                description="Query memory units. READ ONLY.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scope": {"type": "string", "description": "Unit scope (e.g. core, style)."},
                        "tags": {"type": "array", "items": {"type": "string"}, "description": "List of tags to filter by."},
                        "limit": {"type": "integer", "description": "Max results.", "default": 10}
                    }
                }
            ),
            types.Tool(
                name="mem_store",
                description="Store a memory unit. MUTATION (Goes through run_cycle).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "unit_id": {"type": "string"},
                        "scope": {"type": "string"},
                        "body": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "ttl_seconds": {"type": "integer"}
                    },
                    "required": ["unit_id", "scope", "body"]
                }
            ),
            types.Tool(
                name="batch_store",
                description="Atomic store for multiple memory units. Goes through run_cycle.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "units": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "unit_id": {"type": "string"},
                                    "scope": {"type": "string"},
                                    "body": {"type": "object"},
                                    "tags": {"type": "array", "items": {"type": "string"}}
                                },
                                "required": ["unit_id", "scope", "body"]
                            }
                        }
                    },
                    "required": ["units"]
                }
            ),
            types.Tool(
                name="policy_status",
                description="Check if the verifier is in 'locked_down' mode and why. (P4 diagnostic)",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="capsule_export",
                description="Export companion state as a signed capsule. READ ONLY.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string", "default": "companion-v1"}
                    }
                }
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict, session_context: SessionContext = None):
        loop = asyncio.get_event_loop()
        try:
            if name == "mem_find":
                # Offload blocking SQLite call
                results = await loop.run_in_executor(
                    None,
                    lambda: rt.memory.mem_find(scope=arguments.get('scope'))
                )
                
                # Handle filtering and limiting locally 
                if arguments.get('tags'):
                    tags = set(arguments['tags'])
                    results = [u for u in results if any(t in tags for t in u.get('tags', []))]
                
                limit = arguments.get('limit', 10)
                results = results[:limit]
                
                return [types.TextContent(type='text', text=json.dumps(results))]
                
            elif name == "mem_store":
                # Must go through run_cycle — no direct writes to memory.py
                plan = {
                    'action': 'mem_store',
                    'unit_id': arguments['unit_id'],
                    'scope': arguments['scope'],
                    'body': arguments['body'],
                    'tags': arguments.get('tags', [])
                }
                if 'ttl_seconds' in arguments:
                    import time
                    plan['ttl_expires_at'] = int(time.time() + arguments['ttl_seconds'])
                
                # run_cycle is blocking — offload it
                result = await loop.run_in_executor(
                    None,
                    lambda: rt.run_cycle(plan=plan, act_fn=_mem_store_act, invariants=[], session_context=session_context)
                )
                return [types.TextContent(type='text', text=json.dumps({'outcome': result}))]
                
            elif name == "batch_store":
                # Implementation of P3: Semantic atomic ingestion
                units = arguments['units']
                plan = {
                    'action': 'batch_store',
                    'units': units
                }
                
                def _batch_act(p):
                    # Return list of units for the collector in run_cycle
                    return {'units': p['units']}
                
                result = await loop.run_in_executor(
                    None,
                    lambda: rt.run_cycle(plan=plan, act_fn=_batch_act, invariants=[], session_context=session_context)
                )
                return [types.TextContent(type='text', text=json.dumps({'outcome': result}))]
                
            elif name == "policy_status":
                return [types.TextContent(
                    type='text',
                    text=json.dumps({
                        'policy_mode': getattr(rt, 'policy_mode', 'unknown'),
                        'integrity_warning': getattr(rt, 'policy_integrity_warning', None)
                    })
                )]
            
            elif name == "capsule_export":
                # Export involves DB reads and signing — offload it
                io = CapsuleIO(rt)
                agent_id = arguments.get('agent_id', 'companion-v1')
                
                caps = await loop.run_in_executor(
                    None,
                    lambda: io.export_capsule(agent_id=agent_id, profile={})
                )
                return [types.TextContent(type='text', text=json.dumps(caps))]
                
            raise ValueError(f"Unknown tool: {name}")
            
        except Exception as e:
            return [types.TextContent(type='text', text=json.dumps({'error': str(e)}))]

    async def _dispatch(name: str, args: dict, session_context: SessionContext = None):
        return await call_tool(name, args, session_context=session_context)

    handlers = {
        "mem_find": _dispatch,
        "mem_store": _dispatch,
        "batch_store": _dispatch,
        "policy_status": _dispatch,
        "capsule_export": _dispatch,
        "list_tools": list_tools
    }

    return server, handlers

async def main():
    # ── PATH RESOLUTION (Boundary Layer) ───────────────────────────
    base_dir = pathlib.Path.home() / '.compatible'
    db_path = os.environ.get('CC_DB_PATH') or str(base_dir / 'companion.db')
    log_path = os.environ.get('CC_LOG_PATH') or str(base_dir / 'receipts.jsonl')
    key_path = os.environ.get('CC_KEY_PATH') or str(base_dir / 'identity.key')
    
    # ── DEPENDENCY INITIALIZATION ──────────────────────────────────
    import sqlite3
    from cc.memory import SqliteMemoryStore
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)

    memory = SqliteMemoryStore(db_path)
    
    km = None
    if os.path.exists(key_path):
        with open(key_path) as f:
            km = KeyManager.from_dict(json.load(f))
    
    rt = AgentRuntime(memory=memory, log_path=log_path, key_manager=km)
    
    server, handlers = build_server(rt, km)
    try:
        async with stdio_server() as (r, w):
            await server.run(r, w, server.create_initialization_options())
    finally:
        if km:
            km.close()
        rt.close()

if __name__ == '__main__':
    asyncio.run(main())
