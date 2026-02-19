"""
TCP Transport for Compatible Companion (Week 9).
Implements newline-delimited JSON protocol with shared-secret authentication
and per-session runtime isolation.
"""
import asyncio
import json
import uuid
import os
from cc.mcp_adapter import build_server
from cc.runtime import AgentRuntime

async def handle_client(shared_rt, reader, writer, token: str, key_manager):
    """
    Handles a single TCP connection.
    Spawns a per-session AgentRuntime on the same DB/Log to isolate staged state.
    """
    try:
        # 1. Handshake
        line = await reader.readline()
        if not line:
            writer.close()
            await writer.wait_closed()
            return

        try:
            req = json.loads(line.decode().strip())
        except Exception:
            writer.close()
            await writer.wait_closed()
            return

        if req.get('auth') != token:
            resp = json.dumps({'ok': False, 'error': 'unauthorized'}) + '\n'
            writer.write(resp.encode())
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        session_id = str(uuid.uuid4())
        resp = json.dumps({'ok': True, 'session_id': session_id}) + '\n'
        writer.write(resp.encode())
        await writer.drain()

        # 2. Per-Session Runtime Spawn (Isolation)
        # Shared DB/Log paths from shared_rt
        session_rt = AgentRuntime(
            db_path=shared_rt.db_path,
            log_path=shared_rt.log_path
        )
        _, session_handlers = build_server(session_rt, key_manager)

        # 3. Tool Loop
        while True:
            line = await reader.readline()
            if not line:
                break
            
            try:
                req = json.loads(line.decode().strip())
                tool = req.get('tool')
                args = req.get('args', {})
                
                # Support Week 8 'method'/'params' fallback
                if not tool and 'method' in req:
                    tool = req['method']
                    args = req.get('params', {})

                if tool not in session_handlers:
                    raise ValueError(f"Unknown tool: {tool}")
                
                result = await session_handlers[tool](tool, args)
                payload = json.dumps({
                    'ok': True,
                    'result': json.loads(result[0].text)
                }) + '\n'
            except Exception as e:
                payload = json.dumps({'ok': False, 'error': str(e)}) + '\n'
            
            writer.write(payload.encode())
            await writer.drain()

    except Exception as e:
        print(f"[TCP] Error handling client {session_id if 'session_id' in locals() else 'unknown'}: {e}")
    finally:
        if 'session_rt' in locals():
            session_rt.close()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

async def start_tcp_server(rt, key_manager, host='127.0.0.1', port=7700, token: str = None):
    """
    Starts the TCP server.
    """
    if token is None:
        raise ValueError("token is required. No unauthenticated servers.")
    
    server = await asyncio.start_server(
        lambda r, w: handle_client(rt, r, w, token, key_manager), host, port
    )
    addr = server.sockets[0].getsockname()
    print(f"[TCP] Server listening on {addr}")
    
    async with server:
        await server.serve_forever()
