"""
Snapshot checkpointing for Compatible Companion.

compact_log(log_path, capsule_path, key_manager=None)
    Reads the current receipt log to find the tip. 
    Exports a capsule snapshot to capsule_path from the corresponding .db.
    The capsule becomes the official checkpoint.
"""
import json
import os
import hashlib
from cc.capsule import export_capsule, import_capsule

def compact_log(db_path: str, log_path: str,
                capsule_path: str,
                rt=None,
                key_manager=None) -> str:
    """
    Write a capsule snapshot.
    db_path and log_path are REQUIRED — no path inference.
    If rt is provided, acquires rt._compact_lock to freeze run_cycle
    during export. This closes the race window.
    Returns the log_head hash embedded in the capsule.
    """
    # Acquire freeze lock if runtime provided
    lock = getattr(rt, '_compact_lock', None) if rt else None

    if lock is not None:
        lock.acquire()
    try:
        # 1. Get Log Head (from the log we are compacting)
        head = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
            with open(log_path, "rb") as f:
                last_line = None
                for line in f:
                    if line.strip():
                        last_line = line
                if last_line:
                    head = hashlib.sha256(last_line.strip()).hexdigest()

        # 2. Export Capsule with deterministic log_head
        export_capsule(db_path, capsule_path, key_manager=key_manager, log_head=head)
    finally:
        if lock is not None:
            lock.release()

    with open(capsule_path) as f:
        caps = json.load(f)
    return caps.get('log_head', '')

def replay_from_snapshot(rt, capsule_path: str, log_path: str,
                          key_manager=None) -> None:
    """
    1. Import snapshot into rt (restores committed state).
    2. Read log_path. Skip all entries with hash matching the snapshot's log_head.
    3. Replay only the tail entries via rt.apply_receipt(receipt).
    """
    import_capsule(capsule_path, rt.memory.db_path, key_manager=key_manager)

    with open(capsule_path) as f:
        caps = json.load(f)
    checkpoint_head = caps.get('log_head', '')
    
    # Restore runtime state pointers
    rt.receipt_log_head = checkpoint_head
    rt.last_state_hash = rt.memory.derive_state_hash(checkpoint_head)

    with open(log_path) as f:
        entries = [json.loads(l) for l in f if l.strip()]

    # Find the first entry AFTER the checkpoint (by hash)
    past_checkpoint = False
    for entry in entries:
        receipt_bytes = json.dumps(entry, sort_keys=True, separators=(',', ':')).encode("utf-8")
        entry_hash = hashlib.sha256(receipt_bytes).hexdigest()

        if entry_hash == checkpoint_head:
            past_checkpoint = True
            continue
            
        if past_checkpoint:
            rt.receipt_log_head = entry_hash
            rt.apply_receipt(entry)   # replay tail only
