import asyncio
import json
import pathlib
import os
from typing import Any, List, Dict, Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from cc.runtime import AgentRuntime
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
                name="run_cycle",
                description="Run a full PLAN→ACT→VERIFY→COMMIT cycle.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "plan": {"type": "object", "description": "The plan dict for the cycle."},
                        "invariants": {"type": "array", "items": {"type": "string"}, "description": "List of invariant names."}
                    },
                    "required": ["plan"]
                }
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
    async def call_tool(name: str, arguments: dict):
        try:
            if name == "mem_find":
                results = rt.memory.mem_find(scope=arguments.get('scope'))
                # Handle filtering and limiting locally if needed
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
                
                result = rt.run_cycle(plan=plan, act_fn=_mem_store_act, invariants=[])
                return [types.TextContent(type='text', text=json.dumps({'outcome': result}))]
                
            elif name == "run_cycle":
                # We need a dummy act_fn because we can't safely pass complex code via MCP yet
                # For Week 6, run_cycle tool assumes the plan itself describes the action
                # and acts like a pass-through if no explicit act_fn is provided.
                # Actually, the spec says "act_fn is not exposed — the adapter provides it internally"
                # For run_cycle we'll use a pass-through that returns the plan.
                def _adapter_act(p): return p
                result = rt.run_cycle(
                    plan=arguments['plan'],
                    act_fn=_adapter_act,
                    invariants=arguments.get('invariants', [])
                )
                return [types.TextContent(type='text', text=json.dumps({'outcome': result}))]
                
            elif name == "capsule_export":
                io = CapsuleIO(rt)
                agent_id = arguments.get('agent_id', 'companion-v1')
                caps = io.export_capsule(agent_id=agent_id, profile={})
                return [types.TextContent(type='text', text=json.dumps(caps))]
                
            raise ValueError(f"Unknown tool: {name}")
            
        except Exception as e:
            return [types.TextContent(type='text', text=json.dumps({'error': str(e)}))]

    return server, {"mem_find": call_tool, "mem_store": call_tool, "run_cycle": call_tool, "capsule_export": call_tool, "list_tools": list_tools}

async def main():
    base_dir = pathlib.Path.home() / '.compatible'
    rt = AgentRuntime() 
    
    key_path = os.environ.get('CC_KEY_PATH') or str(base_dir / 'identity.key')
    km = None
    if os.path.exists(key_path):
        km = KeyManager(key_path)
    
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
