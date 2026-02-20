import os
import shutil
import json
from cc.runtime import CompanionRuntime

def run_demo():
    log_path = "demo_receipts.jsonl"
    db_path = "demo_memory.db"

    # Cleanup previous runs
    if os.path.exists(log_path): os.remove(log_path)
    if os.path.exists(db_path): os.remove(db_path)

    print("=== SESSION 1: Initializing and Ingesting ===")
    from cc.memory import SqliteMemoryStore
    mem1 = SqliteMemoryStore(db_path)
    rt1 = CompanionRuntime(memory=mem1, log_path=log_path)
    rt1.ingest("User Name: Alice")
    rt1.ingest("User Role: Architect")
    final_hash1 = rt1.last_state_hash
    rt1.close()

    print(f"\nSession 1 finished. Final State Hash: {final_hash1}")
    print(f"Receipt log size: {os.path.getsize(log_path)} bytes")

    print("\n=== SESSION 2: Replaying log into a clean runtime ===")
    # Notice we don't use the DB from Session 1
    mem2 = SqliteMemoryStore(":memory:")
    rt2 = CompanionRuntime(memory=mem2, log_path=log_path) 
    rt2.replay_log(log_path)
    final_hash2 = rt2.last_state_hash
    rt2.close()

    print(f"\nSession 2 finished. Replayed State Hash: {final_hash2}")

    if final_hash1 == final_hash2:
        print("\nSUCCESS: State hashes match exactly! Deterministic replay confirmed.")
    else:
        print("\nFAILURE: State hashes do not match.")

    print("\n=== SESSION 3: Replaying corrupted log ===")
    # Manual corruption of the log file
    with open(log_path, "r") as f:
        lines = f.readlines()
    
    # Change a character in the first receipt's hash
    if lines:
        receipt = json.loads(lines[0])
        receipt["input_hash"] = "ffff" + receipt["input_hash"][4:]
        lines[0] = json.dumps(receipt, sort_keys=True) + "\n"
        
        corrupted_log = "corrupted_receipts.jsonl"
        with open(corrupted_log, "w") as f:
            f.writelines(lines)
            
        print(f"Corrupted log created at {corrupted_log}")
        
        mem3 = SqliteMemoryStore(":memory:")
        rt3 = CompanionRuntime(memory=mem3, log_path=corrupted_log)
        try:
            rt3.replay_log(corrupted_log)
            print("FAILURE: Replay should have failed!")
        except ValueError as e:
            print(f"SUCCESS: Replay blocked as expected: {e}")
        rt3.close()
        
        if os.path.exists(corrupted_log): os.remove(corrupted_log)

if __name__ == "__main__":
    run_demo()
