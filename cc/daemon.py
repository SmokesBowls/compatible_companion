import asyncio
import os
import ssl
from cc.runtime import AgentRuntime
from cc.identity import KeyManager
from cc.server import start_tcp_server, make_dev_ssl_context
from cc.memory import SqliteMemoryStore

async def run_daemon(db_path: str, log_path: str, key_path: str, 
                     host='127.0.0.1', port=7700, 
                     tls_cert=None, tls_key=None, 
                     token=None, client_keys=None):
    """
    Main entry point for the long-running companion daemon.
    """
    print(f"Starting Compatible Companion Daemon on {host}:{port}...")
    
    km = KeyManager.from_path(key_path)
    rt = AgentRuntime(memory=SqliteMemoryStore(db_path), log_path=log_path, key_manager=km)
    
    ssl_ctx = None
    if tls_cert and tls_key:
        print("✓ Enabling TLS")
        ssl_ctx = make_dev_ssl_context(tls_cert, tls_key)
    
    await start_tcp_server(
        rt, km, host=host, port=port,
        token=token, client_keys=client_keys,
        ssl_context=ssl_ctx
    )

if __name__ == '__main__':
    # Default local dev run
    asyncio.run(run_daemon('cc_main.db', 'cc_receipts.jsonl', 'cc_identity.key', token='secret'))
