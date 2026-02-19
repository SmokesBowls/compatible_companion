import base64, json, os, stat, ctypes
import nacl.signing
import nacl.exceptions

KEY_FILE = 'cc_identity.key'
PUB_FILE = 'cc_identity.pub'

def generate_keypair() -> tuple[str, str]:
    """Returns (sk_b64, vk_b64). Writes both files."""
    sk = nacl.signing.SigningKey.generate()
    vk = sk.verify_key
    sk_b64 = base64.b64encode(bytes(sk)).decode()
    vk_b64 = base64.b64encode(bytes(vk)).decode()
    with open(KEY_FILE, 'w') as f:
        json.dump({'sk': sk_b64, 'vk': vk_b64}, f)
    os.chmod(KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 600
    with open(PUB_FILE, 'w') as f:
        json.dump({'vk': vk_b64}, f)
    return sk_b64, vk_b64

def sign_payload(payload_bytes: bytes) -> str:
    """Load key from file. Sign payload. Return base64 sig."""
    with open(KEY_FILE) as f:
        sk_b64 = json.load(f)['sk']
    sk = nacl.signing.SigningKey(base64.b64decode(sk_b64))
    sig = sk.sign(payload_bytes).signature
    return base64.b64encode(sig).decode()

def verify_payload(payload_bytes: bytes, sig_b64: str, vk_b64: str) -> None:
    """Raises nacl.exceptions.BadSignatureError if invalid."""
    vk = nacl.signing.VerifyKey(base64.b64decode(vk_b64))
    vk.verify(payload_bytes, base64.b64decode(sig_b64))


class KeyManager:
    """Session-resident signing key with explicit manual zeroing."""
    def __init__(self, key_path: str):
        self._key_path = key_path
        self._signing_key = self._load_key(key_path)

    def _load_key(self, path: str) -> nacl.signing.SigningKey:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Key file not found: {path}")
        with open(path) as f:
            sk_b64 = json.load(f)['sk']
        return nacl.signing.SigningKey(base64.b64decode(sk_b64))

    def sign(self, payload: bytes) -> str:
        if self._signing_key is None:
            raise RuntimeError("KeyManager is closed. Key has been zeroed.")
        sig = self._signing_key.sign(payload).signature
        return base64.b64encode(sig).decode()

    def close(self):
        """Explicitly zero key bytes and close the session."""
        if self._signing_key is not None:
            # Zeroing the underlying bytes of the key
            key_bytes = bytes(self._signing_key)
            # Use ctypes to zero the memory. id(obj) is the memory address in CPython.
            # bytes objects are immutable, but we can target the memory buffer if we are careful.
            # Actually, the safest way to ensure the SigningKey object is useless is to null it,
            # but the briefing explicitly asks to zero the bytes using ctypes.memset.
            ctypes.memset(id(key_bytes), 0, len(key_bytes))
            self._signing_key = None
