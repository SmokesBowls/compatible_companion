import ast

class PolicyRuleError(Exception):
    """Raised when a policy predicate is malformed or violates security constraints."""
    pass

def eval_policy_predicate(predicate: str, context: dict) -> bool:
    """
    Safely evaluate a Python expression string as a policy predicate.
    Uses AST parsing and a strict whitelist of allowed node types and names.
    
    Allowed:
    - Comparison: ==, !=, <, <=, >, >=, in, not in
    - Boolean operators: and, or, not
    - Names: scope, tags, body_hash, content_type, entities
    - Constants: strings and integers
    - Calls: len() only
    
    Rejected:
    - Any node type not in whitelist
    - Attribute access (blocks __class__, etc.)
    - Subscripts (blocks dict/list access)
    - Imports, Lambdas, Comprehensions
    """
    try:
        tree = ast.parse(predicate, mode='eval')
    except SyntaxError as e:
        raise PolicyRuleError(f"Syntax error in predicate: {e}")

    # Whitelist of allowed AST node types
    ALLOWED_NODES = {
        ast.Expression,
        ast.Compare,
        ast.BoolOp,
        ast.UnaryOp,
        ast.Name,
        ast.Constant,
        ast.Call,
        ast.Load,
        # Ops
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
        ast.In, ast.NotIn,
        ast.And, ast.Or,
        ast.Not
    }

    ALLOWED_NAMES = {'scope', 'tags', 'body_hash', 'content_type', 'entities'}
    ALLOWED_CALLS = {'len'}

    def _check(node):
        if type(node) not in ALLOWED_NODES:
            raise PolicyRuleError(f"Disallowed operation: {type(node).__name__}")
        
        if isinstance(node, ast.Name):
            if node.id not in ALLOWED_NAMES and node.id not in ALLOWED_CALLS:
                raise PolicyRuleError(f"Disallowed name: {node.id}")
        
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in ALLOWED_CALLS:
                raise PolicyRuleError(f"Disallowed function call: {ast.dump(node.func)}")
        
        if isinstance(node, ast.Attribute):
            raise PolicyRuleError("Attribute access is disallowed (safety constraint)")
            
        if isinstance(node, ast.Subscript):
            raise PolicyRuleError("Subscript access is disallowed (safety constraint)")

        for child in ast.iter_child_nodes(node):
            _check(child)

    _check(tree)

    # If check passed, evaluate using a very restricted namespace
    # Note: We still use compile/eval for the final step, but ONLY after AST verification.
    # The namespace only contains the context and allowed functions.
    eval_globals = {"__builtins__": {}}
    eval_locals = {**context, "len": len}
    
    try:
        code = compile(tree, filename='<policy>', mode='eval')
        return bool(eval(code, eval_globals, eval_locals))
    except Exception as e:
        # Runtime errors (e.g. len() on non-iterable) should be caught
        raise PolicyRuleError(f"Error during predicate evaluation: {e}")
