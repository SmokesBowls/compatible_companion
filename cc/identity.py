import base64, json, os, stat, ctypes
import nacl.signing
import nacl.exceptions
from typing import Union

KEY_FILE = 'cc_identity.key'
PUB_FILE = 'cc_identity.pub'

def generate_keypair(key_file: str = KEY_FILE, pub_file: str = PUB_FILE) -> tuple[str, str]:
    """Returns (sk_b64, vk_b64). Writes both files."""
    sk = nacl.signing.SigningKey.generate()
    vk = sk.verify_key
    sk_b64 = base64.b64encode(bytes(sk)).decode()
    vk_b64 = base64.b64encode(bytes(vk)).decode()
    with open(key_file, 'w') as f:
        json.dump({'sk': sk_b64, 'vk': vk_b64}, f)
    os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)  # 600
    with open(pub_file, 'w') as f:
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
    def __init__(self, sk_input: Union[bytes, str]):
        """
        initializes KeyManager with signing key bytes or base64 string.
        Use from_pem or from_dict for higher-level loading.
        """
        if isinstance(sk_input, str):
            # If it's a path, use from_path instead. 
            # If it looks like base64, decode it.
            try:
                sk_bytes = base64.b64decode(sk_input)
            except Exception:
                # If decode fails, it might be a raw string (not recommended) 
                # or we should have used from_path.
                sk_bytes = sk_input.encode('utf-8')
        else:
            sk_bytes = sk_input

        # Store key in a mutable bytearray to allow explicit zeroing
        self._signing_key_bytes = bytearray(sk_bytes)
        self._signing_key = nacl.signing.SigningKey(bytes(self._signing_key_bytes))

    @classmethod
    def from_pem(cls, pem_str: str) -> "KeyManager":
        """Accepts a JSON-based string with 'sk' as currently used in CC."""
        data = json.loads(pem_str)
        return cls(base64.b64decode(data['sk']))

    @classmethod
    def from_dict(cls, data: dict) -> "KeyManager":
        return cls(base64.b64decode(data['sk']))

    @classmethod
    def from_path(cls, path: str) -> "KeyManager":
        if not os.path.exists(path):
            raise FileNotFoundError(f"Key file not found: {path}")
        with open(path) as f:
            data = json.load(f)
        return cls.from_dict(data)

    def sign(self, payload: bytes) -> str:
        if self._signing_key is None:
            raise RuntimeError("KeyManager is closed. Key has been zeroed.")
        sig = self._signing_key.sign(payload).signature
        return base64.b64encode(sig).decode()

    def close(self):
        """Explicitly zero key bytes and close the session."""
        if self._signing_key_bytes is not None:
            # Zeroing the mutable bytearray buffer
            # This is more reliable than targeting an immutable 'bytes' object
            buf = self._signing_key_bytes
            ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
            self._signing_key_bytes = None
            self._signing_key = None
