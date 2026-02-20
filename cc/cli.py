import sys
import argparse
import json
import os
import shutil
import asyncio
from cc.identity import generate_keypair, KeyManager
from cc.policy_store import seal_policy

def cmd_init(args):
    """companion init - setup keys and initial store."""
    print("Initializing Compatible Companion...")
    if os.path.exists('cc_identity.key'):
        print("Error: cc_identity.key already exists. Cleanup first.")
        sys.exit(1)
    
    generate_keypair()
    print("✓ Generated Ed25519 identity (cc_identity.key)")
    
    # Setup dummy policy if it doesn't exist
    db_path = args.db or 'cc_main.db'
    log_path = args.log or 'cc_receipts.jsonl'
    
    from cc.runtime import AgentRuntime
    from cc.memory import SqliteMemoryStore
    rt = AgentRuntime(memory=SqliteMemoryStore(db_path), log_path=log_path)
    seal_policy(rt.policy_store, log_path)
    print(f"✓ Initialized store at {db_path}")
    print(f"✓ Sealed initial policy in {log_path}")
    rt.close()
    
    # Save a default token
    token = args.token or secrets.token_hex(16)
    with open('cc_token.txt', 'w') as f: f.write(token)
    print(f"✓ Saved access token to cc_token.txt")
    print("\nOnboarding complete. Run 'companion start' to start the engine.")

import secrets
import asyncio

async def _client_call(host, port, token, req):
    try:
        r, w = await asyncio.open_connection(host, port)
        w.write((json.dumps({'auth': token}) + '\n').encode())
        await w.drain()
        auth_resp = json.loads((await r.readline()).decode())
        if not auth_resp.get('ok'):
            print(f"Error: Authentication failed: {auth_resp.get('error')}")
            return None
        
        w.write((json.dumps(req) + '\n').encode())
        await w.drain()
        line = await r.readline()
        if not line: return None
        resp = json.loads(line.decode())
        w.close(); await w.wait_closed()
        return resp
    except Exception as e:
        print(f"Error connecting to daemon: {e}")
        return None

def cmd_start(args):
    from cc.daemon import run_daemon
    token = None
    if os.path.exists('cc_token.txt'):
        token = open('cc_token.txt').read().strip()
    
    host = args.host or '127.0.0.1'
    port = args.port or 7700
    db = args.db or 'cc_main.db'
    log = args.log or 'cc_receipts.jsonl'
    key = args.key or 'cc_identity.key'

    try:
        asyncio.run(run_daemon(db, log, key, host=host, port=port, token=token))
    except KeyboardInterrupt:
        print("\nDaemon stopped.")

def cmd_status(args):
    token = open('cc_token.txt').read().strip() if os.path.exists('cc_token.txt') else None
    host = args.host or '127.0.0.1'
    port = args.port or 7700
    
    # Check policy_status
    resp = asyncio.run(_client_call(host, port, token, {'tool': 'policy_status', 'args': {}}))
    if resp and resp.get('ok'):
        status = resp['result']
        print(f"Companion Daemon: ONLINE")
        print(f"Policy Mode: {status['policy_mode']}")
        if status['integrity_warning']:
            print(f"WARNING: {status['integrity_warning']}")
        else:
            print(f"✓ Policy Integrity Verified")
    else:
        print("Companion Daemon: OFFLINE")

def cmd_ingest(args):
    token = open('cc_token.txt').read().strip() if os.path.exists('cc_token.txt') else None
    host = args.host or '127.0.0.1'
    port = args.port or 7700
    
    unit = {
        'action': 'mem_store',
        'unit_id': args.unit_id or secrets.token_hex(4),
        'scope': args.scope or 'core',
        'tags': args.tags.split(',') if args.tags else [],
        'body': {'summary': args.text}
    }
    
    req = {'tool': 'batch_store', 'args': {'units': [unit]}}
    resp = asyncio.run(_client_call(host, port, token, req))
    if resp and resp.get('ok'):
        print(f"✓ Ingested unit {unit['unit_id']} (Outcome: {resp['result']['outcome']})")
    else:
        print(f"Error: Ingest failed: {resp.get('error') if resp else 'No response'}")

def main():
    parser = argparse.ArgumentParser(prog='companion')
    subparsers = parser.add_subparsers(dest='command')
    
    # init
    p_init = subparsers.add_parser('init', help='Initialize keys and store')
    p_init.add_argument('--db', help='DB path')
    p_init.add_argument('--log', help='Log path')
    p_init.add_argument('--token', help='Custom token')

    # start
    p_start = subparsers.add_parser('start', help='Start the daemon')
    p_start.add_argument('--host', help='Host (default 127.0.0.1)')
    p_start.add_argument('--port', type=int, help='Port (default 7700)')
    p_start.add_argument('--db', help='DB path')
    p_start.add_argument('--log', help='Log path')
    p_start.add_argument('--key', help='Identity key path')

    # status
    p_status = subparsers.add_parser('status', help='Check engine status')
    p_status.add_argument('--host', help='Daemon host')
    p_status.add_argument('--port', type=int, help='Daemon port')

    # ingest
    p_ingest = subparsers.add_parser('ingest', help='Ingest a memory unit')
    p_ingest.add_argument('text', help='Summary text')
    p_ingest.add_argument('--scope', help='Unit scope')
    p_ingest.add_argument('--tags', help='Comma-sep tags')
    p_ingest.add_argument('--unit_id', help='Custom unit_id')
    p_ingest.add_argument('--host', help='Daemon host')
    p_ingest.add_argument('--port', type=int, help='Daemon port')
    
    args = parser.parse_args()
    if args.command == 'init':
        cmd_init(args)
    elif args.command == 'start':
        cmd_start(args)
    elif args.command == 'status':
        cmd_status(args)
    elif args.command == 'ingest':
        cmd_ingest(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
