import asyncio
import json
import uuid
import os
import ssl
import secrets
from cc.mcp_adapter import build_server
from cc.runtime import AgentRuntime, SessionContext
from cc.identity import verify_payload

async def handle_client(shared_rt, reader, writer, token: str, key_manager, shared_handlers, client_keys: dict = None):
    """
    Handles a single TCP connection.
    Spawns a per-session AgentRuntime on the same DB/Log to isolate staged state.
    """
    session_id = None
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

        # Legacy shared-secret path (backward compat)
        if 'auth' in req and client_keys is None:
            if req.get('auth') != token:
                writer.write((json.dumps({'ok': False, 'error': 'unauthorized'}) + '\n').encode())
                await writer.drain()
                writer.close(); await writer.wait_closed(); return
        
        # Per-client identity path
        elif 'hello' in req and client_keys is not None:
            client_id = req.get('hello')
            vk_b64    = req.get('vk')
            if client_id not in client_keys or client_keys[client_id] != vk_b64:
                writer.write((json.dumps({'ok': False, 'error': 'unauthorized'}) + '\n').encode())
                await writer.drain()
                writer.close(); await writer.wait_closed(); return
            # Issue challenge
            nonce = secrets.token_hex(32)
            writer.write((json.dumps({'challenge': nonce}) + '\n').encode())
            await writer.drain()
            # Await signature
            sig_line = await reader.readline()
            if not sig_line:
                writer.close(); await writer.wait_closed(); return
            try:
                sig_req  = json.loads(sig_line.decode().strip())
                sig_b64  = sig_req.get('signature')
                verify_payload(nonce.encode(), sig_b64, vk_b64)
            except Exception:
                writer.write((json.dumps({'ok': False, 'error': 'unauthorized'}) + '\n').encode())
                await writer.drain()
                writer.close(); await writer.wait_closed(); return
        else:
            # Fallback for mistyped or missing auth
            writer.write((json.dumps({'ok': False, 'error': 'unauthorized'}) + '\n').encode())
            await writer.drain()
            writer.close(); await writer.wait_closed(); return

        session_id = str(uuid.uuid4())
        resp = json.dumps({'ok': True, 'session_id': session_id}) + '\n'
        writer.write(resp.encode())
        await writer.drain()

        # 2. Session Context (Lightweight Bag)
        ctx = SessionContext(
            session_id=session_id,
            key_manager=key_manager
        )

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

                if tool not in shared_handlers:
                    raise ValueError(f"Unknown tool: {tool}")
                
                result = await shared_handlers[tool](tool, args, session_context=ctx)
                payload = json.dumps({
                    'ok': True,
                    'result': json.loads(result[0].text)
                }) + '\n'
            except Exception as e:
                payload = json.dumps({'ok': False, 'error': str(e)}) + '\n'
            
            writer.write(payload.encode())
            await writer.drain()

    except Exception as e:
        print(f"[TCP] Error handling client {session_id if session_id else 'unknown'}: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

async def start_tcp_server(rt, key_manager, host='127.0.0.1', port=7700, 
                            token: str = None, started_event: asyncio.Event = None,
                            ssl_context: ssl.SSLContext = None,
                            client_keys: dict = None):
    """
    Starts the TCP server.
    """
    if token is None and client_keys is None:
        raise ValueError("Either token or client_keys is required.")
    
    # ── SINGLETON SETUP ───────────────────────────────────────────
    # We build the server and handlers ONCE against the singleton RT
    _, handlers = build_server(rt, key_manager)
    
    server = await asyncio.start_server(
        lambda r, w: handle_client(rt, r, w, token, key_manager, handlers, client_keys=client_keys), 
        host, port,
        ssl=ssl_context
    )
    addr = server.sockets[0].getsockname()
    print(f"[TCP] Server listening on {addr}")
    
    if started_event:
        started_event.set()
    
    async with server:
        await server.serve_forever()

# Helper — generate a self-signed cert for testing
def make_dev_ssl_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """
    Creates a server-side SSLContext from a self-signed cert.
    Generate with: openssl req -x509 -newkey rsa:2048 -keyout key.pem
                           -out cert.pem -days 365 -nodes -subj '/CN=localhost'
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    return ctx
