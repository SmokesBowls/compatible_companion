import os
import pytest
import hashlib
import json
from cc.zw_block import ZWBlock
from cc.memory import MemoryStore
from cc.runtime import CompanionRuntime
from cc.capsule import CapsuleIO

LOG_PATH = "test_receipts.jsonl"
DB_PATH = "test_memory.db"

@pytest.fixture
def clean_env():
    """Ensures a clean environment for each test."""
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    yield
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

def test_zw_block_canonicalization():
    """Acceptance: A ZW block can be ingested, canonicalized, and hashed."""
    content = "Hello ZW"
    block = ZWBlock(content)
    assert block.hash == hashlib.sha256(content.encode()).hexdigest()
    
    json_content = {"key": "value"}
    block_json = ZWBlock(json_content, content_type="json")
    # Deterministic keys sorting
    expected_bytes = b'{"key": "value"}'
    assert block_json.canonical_bytes == expected_bytes

def test_full_cycle_success(clean_env):
    """Acceptance: A full PLAN->ACT->VERIFY->COMMIT cycle completes and emits a chained receipt."""
    runtime = CompanionRuntime(DB_PATH, LOG_PATH)
    receipt = runtime.ingest("User preference: dark mode", scope="style")
    
    assert receipt["verdict"] == "PASS"
    assert receipt["phase"] == "COMMIT" # Receipt records the phase that produced it
    assert runtime.last_snapshot_id is not None
    assert runtime.last_state_hash is not None
    
    # Verify DB state
    cursor = runtime.memory.conn.cursor()
    cursor.execute("SELECT body FROM units WHERE scope='style'")
    row = cursor.fetchone()
    assert row["body"] == "User preference: dark mode"
    
    # Verify chained receipt
    assert os.path.exists(LOG_PATH)
    with open(LOG_PATH, "r") as f:
        log_line = json.loads(f.readline())
        assert log_line["receipt_id"] == receipt["receipt_id"]
        assert log_line["state_hash"] == runtime.last_state_hash
    runtime.close()

def test_verify_failure(clean_env):
    """Acceptance: A VERIFY failure discards staged writes and records a FAIL receipt."""
    runtime = CompanionRuntime(DB_PATH, LOG_PATH)
    # Add a policy rule that blocks specific keywords
    cursor = runtime.memory.conn.cursor()
    cursor.execute("INSERT INTO policy_rules (rule_id, scope, predicate, on_fail) VALUES (?, ?, ?, ?)",
                   ("rule1", "core", "'forbidden' not in body", "block"))
    runtime.memory.conn.commit()
    
    # This should fail due to the keyword 'forbidden'
    receipt = runtime.ingest("This has forbidden word", scope="core")
    
    assert receipt["verdict"] == "FAIL"
    
    # Verify DB state unchanged
    cursor.execute("SELECT COUNT(*) as count FROM units")
    assert cursor.fetchone()["count"] == 0
    
    # Verify FAIL receipt in log
    with open(LOG_PATH, "r") as f:
        # First line is for policy rule injection (if treated as event) - no, we inserted directly
        # So first line is the failed ingest
        log_line = json.loads(f.readline())
        assert log_line["verdict"] == "FAIL"
    runtime.close()

def test_deterministic_replay(clean_env):
    """Acceptance: Given the receipt log, a clean runtime replays it and arrives at the same state_hash."""
    # 1. First runtime session
    runtime1 = CompanionRuntime(DB_PATH, LOG_PATH)
    runtime1.ingest("Memory unit A")
    runtime1.ingest("Memory unit B")
    final_state_hash = runtime1.last_state_hash
    runtime1.close()
    
    # 2. Replay in a second clean runtime
    REPLAY_DB = "replay_memory.db"
    if os.path.exists(REPLAY_DB):
        os.remove(REPLAY_DB)
        
    runtime2 = CompanionRuntime(REPLAY_DB, LOG_PATH)
    # Replay from the existing LOG_PATH
    runtime2.replay_log(LOG_PATH)
    
    assert runtime2.last_state_hash == final_state_hash
    
    if os.path.exists(REPLAY_DB):
        os.remove(REPLAY_DB)
    runtime2.close()

def test_capsule_export(clean_env):
    """Verifies that capsule export contains the correct state anchors."""
    runtime = CompanionRuntime(DB_PATH, LOG_PATH)
    runtime.ingest("Core knowledge")
    
    io = CapsuleIO(runtime)
    capsule = io.export_capsule("companion-x", {"persona": "helpful"})
    
    assert capsule["spec_version"] == "cc/0.1"
    assert capsule["id"] == "companion-x"
    assert capsule["memory_snapshot"]["state_hash"] == runtime.last_state_hash
    assert capsule["memory_snapshot"]["unit_counts"]["core"] == 1
    runtime.close()
