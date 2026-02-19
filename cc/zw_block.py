import hashlib
import json
from typing import Any

def parse_zw_block(text: str) -> dict:
    """
    Parse a ZW block string. Format:
    
    ZW[type]
    @meta key: value
    ...
    body lines...

    Returns:
        {
            'block_type': str,           # e.g. 'profile'
            'meta': dict[str, str],      # @meta key/value pairs
            'body_lines': list[str],     # section body, verbatim
        }

    Raises:
        ValueError if the first line is not a valid ZW[...] header.
    """
    lines = text.splitlines()
    if not lines or not (lines[0].startswith('ZW[') and lines[0].endswith(']')):
        raise ValueError("Invalid ZW block: missing or malformed header line ZW[...] on line 1")
    
    block_type = lines[0][3:-1].strip()
    meta = {}
    body_start_idx = 1
    
    # Parse @meta lines
    for i in range(1, len(lines)):
        line = lines[i]
        if line.startswith('@meta '):
            content = line[6:].strip()
            if ':' in content:
                key, val = content.split(':', 1)
                meta[key.strip()] = val.strip()
            body_start_idx = i + 1
        else:
            # First non-@meta line marks start of body
            break
            
    body_lines = lines[body_start_idx:]
    
    return {
        'block_type': block_type,
        'meta': meta,
        'body_lines': body_lines
    }

def canonical_bytes(parsed: dict) -> tuple[bytes, str]:
    """
    Produce deterministic canonical bytes and SHA3-256 hash from a parsed block.
    
    Construction:
    1. Emit header: ZW[{type}]\n
    2. Sort @meta pairs alphabetically by key. Emit each as @meta {key}: {value}\n
    3. Emit section body lines, one per line, with \n. Strip trailing space from each.
    4. Encode as UTF-8.
    5. Strip trailing whitespace/newlines from final bytes.
    6. Hash result using SHA3-256.
    """
    lines = []
    
    # 1. Header
    lines.append(f"ZW[{parsed['block_type']}]")
    
    # 2. Sorted Meta
    sorted_keys = sorted(parsed['meta'].keys())
    for key in sorted_keys:
        lines.append(f"@meta {key}: {parsed['meta'][key]}")
        
    # 3. Body lines (strip trailing space)
    for line in parsed['body_lines']:
        lines.append(line.rstrip())
        
    # Combine with newline join
    content = "\n".join(lines)
    
    # 4 & 5. Encode and strip trailing whitespace/newlines from final byte sequence
    # Note: strip() on bytes works similarly.
    final_bytes = content.encode('utf-8').rstrip()
    
    # 6. Hash
    sha3_hash = hashlib.sha3_256(final_bytes).hexdigest()
    
    return final_bytes, sha3_hash

class ZWBlock:
    """Legacy Stage 1 Container for simple unit bodies."""
    def __init__(self, content: Any, content_type: str = "plain"):
        self.content = content
        self.content_type = content_type
        if content_type == "json":
            self.canonical_bytes = json.dumps(content, sort_keys=True).encode()
        else:
            self.canonical_bytes = content.encode() if isinstance(content, str) else str(content).encode()
        self.hash = hashlib.sha256(self.canonical_bytes).hexdigest()
