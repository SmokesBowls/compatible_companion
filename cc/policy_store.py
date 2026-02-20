# cc/policy_store.py
"""
PolicyStore interface for Compatible Companion.

The Verifier interacts with policies through this interface only.
The concrete backend (SQLite today, Postgres tomorrow) is an implementation detail.
"""
import hashlib
import json
from abc import ABC, abstractmethod

class PolicyStore(ABC):

    @abstractmethod
    def get_active_rules(self) -> list[dict]:
        """Return all is_active=1 rules as list of dicts, sorted by rule_id."""
        ...

    @abstractmethod
    def add_rule(self, rule_id: str, description: str, predicate: str) -> None:
        """Insert a new active rule."""
        ...

    @abstractmethod
    def set_rule_active(self, rule_id: str, is_active: bool) -> None:
        """Enable or disable a rule."""
        ...

    def compute_hash(self) -> str:
        """
        Deterministic SHA-256 of the active policy set.
        Sorted by rule_id, stable JSON serialization.
        This method is NOT abstract — it is the same for all backends.
        """
        rules = self.get_active_rules()
        canonical = json.dumps(
            [{'rule_id': r['rule_id'],
              'description': r['description'],
              'predicate': r['predicate']}
             for r in sorted(rules, key=lambda r: r['rule_id'])],
            sort_keys=True, separators=(',', ':')
        )
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


class SQLitePolicyStore(PolicyStore):
    """Concrete SQLite backend. Wraps the existing policy_rules table."""

    def __init__(self, conn):
        self._conn = conn

    def get_active_rules(self) -> list[dict]:
        cur = self._conn.execute(
            'SELECT rule_id, description, predicate FROM policy_rules'
            ' WHERE is_active=1 ORDER BY rule_id'
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def add_rule(self, rule_id, description, predicate):
        from datetime import datetime, timezone
        self._conn.execute(
            'INSERT INTO policy_rules'
            ' (rule_id, description, predicate, is_active, created_at)'
            ' VALUES (?,?,?,1,?)',
            (rule_id, description, predicate,
             datetime.now(timezone.utc).isoformat())
        )
        self._conn.commit()

    def set_rule_active(self, rule_id, is_active):
        self._conn.execute(
            'UPDATE policy_rules SET is_active=? WHERE rule_id=?',
            (1 if is_active else 0, rule_id)
        )
        self._conn.commit()


def verify_policy_integrity(policy_store: PolicyStore,
                             receipts_path: str) -> tuple[bool, str]:
    """
    Compare the current active policy hash against the last
    POLICY_HASH receipt in the receipt log.

    Returns (True, '') if hashes match.
    Returns (False, reason) if tampered, unsealed, or log unreadable.
    """
    current_hash = policy_store.compute_hash()

    # Walk receipts log — find the LAST POLICY_HASH entry
    last_sealed = None
    try:
        with open(receipts_path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    entry = json.loads(line)
                    if entry.get('type') == 'POLICY_HASH':
                        last_sealed = entry.get('hash')
                except Exception:
                    continue
    except FileNotFoundError:
        return False, 'receipts log not found'

    if last_sealed is None:
        return False, 'policy set has never been sealed (run: companion policy:seal)'

    if current_hash != last_sealed:
        return False, (
            f'policy hash mismatch — expected {last_sealed[:16]}...'
            f' got {current_hash[:16]}...'
        )

    return True, ''


def seal_policy(policy_store: PolicyStore,
                receipts_path: str,
                key_manager=None) -> str:
    """
    Compute the current policy hash and append a POLICY_HASH receipt
    to the receipts log. This is the operator blessing step.
    Returns the hash that was sealed.
    """
    from datetime import datetime, timezone
    h = policy_store.compute_hash()
    receipt = {
        'type':      'POLICY_HASH',
        'hash':      h,
        'sealed_at': datetime.now(timezone.utc).isoformat(),
    }
    if key_manager is not None:
        import json as _json
        canonical = _json.dumps(receipt, sort_keys=True).encode()
        receipt['signature'] = key_manager.sign(canonical)
    with open(receipts_path, 'a') as f:
        f.write(json.dumps(receipt) + '\n')
    return h

def evaluate_rule(rule: dict, unit: dict) -> bool:
    """
    Pure Python rule evaluator. No eval. No exec. No string execution.
    Takes a structured rule dict and a unit dict.
    Returns True if the rule passes (unit is allowed).
    """
    op = rule.get('operator')

    # Compound operators
    if op is None and 'all' in rule:
        return all(evaluate_rule(r, unit) for r in rule['all'])
    if op is None and 'any' in rule:
        return any(evaluate_rule(r, unit) for r in rule['any'])

    field = rule.get('field')
    value = rule.get('value')

    # Resolve field from unit (support dot notation for body fields)
    def resolve(u, f):
        parts = f.split('.')
        cur = u
        for part in parts:
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
        return cur

    fval = resolve(unit, field) if field else None

    if op == 'eq':          return fval == value
    if op == 'neq':         return fval != value
    if op == 'exists':      return fval is not None
    if op == 'contains':    return value in fval if fval is not None else False
    if op == 'not_contains':return value not in fval if fval is not None else True
    if op == 'min_length':  return len(fval) >= value if fval is not None else False
    if op == 'max_length':  return len(fval) <= value if fval is not None else True
    if op == 'prefix':      return str(fval).startswith(value) if fval is not None else False

    raise ValueError(f'Unknown operator: {op}')
