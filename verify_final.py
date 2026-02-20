import subprocess
import time
import os
import secrets

def run():
    print("--- STARTING FINAL VERIFICATION ---")
    
    # 1. Cleanup
    for f in ['final.db', 'final.jsonl', 'cc_identity.key', 'cc_token.txt']:
        if os.path.exists(f): os.remove(f)
    
    # 2. Init
    print("\n[STEP 1] companion init")
    py = '/home/burdens/miniconda3/bin/python3'
    subprocess.run([py, 'cc/cli.py', 'init', '--token', 'secret', '--db', 'final.db', '--log', 'final.jsonl'], check=True, env={**os.environ, 'PYTHONPATH': '.'})
    
    # 3. Start Daemon
    print("\n[STEP 2] Launching daemon...")
    p = subprocess.Popen([py, 'cc/cli.py', 'start', '--db', 'final.db', '--log', 'final.jsonl', '--port', '9999'], env={**os.environ, 'PYTHONPATH': '.'})
    time.sleep(3)
    
    # 4. Check Status
    print("\n[STEP 3] companion status")
    subprocess.run([py, 'cc/cli.py', 'status', '--port', '9999'], env={**os.environ, 'PYTHONPATH': '.'})
    
    # 5. Ingest
    print("\n[STEP 4] companion ingest")
    subprocess.run([py, 'cc/cli.py', 'ingest', 'End-to-End Success', '--port', '9999'], env={**os.environ, 'PYTHONPATH': '.'})
    
    # 6. Check Status Again
    print("\n[STEP 5] Final status check")
    subprocess.run([py, 'cc/cli.py', 'status', '--port', '9999'], env={**os.environ, 'PYTHONPATH': '.'})
    
    # 7. Cleanup
    p.terminate()
    p.wait()
    print("\n--- VERIFICATION COMPLETE ---")

if __name__ == '__main__':
    run()
