"""Pure Python ECDSA wrapper using the 'ecdsa' package, compatible with OpenSSL 3.x."""
import hashlib
import ecdsa


class KEY:
    SECP256K1 = ecdsa.SECP256k1

    def __init__(self):
        self._sk = None
        self._vk = None
        self._compressed = False

    def generate(self, secret=None):
        if secret is None:
            self._sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        else:
            if isinstance(secret, str):
                secret = secret.encode()
            # Pad or truncate to exactly 32 bytes
            if len(secret) < 32:
                secret = secret.ljust(32, b'\x00')
            elif len(secret) > 32:
                secret = secret[:32]
            self._sk = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1)
        self._vk = self._sk.get_verifying_key()

    def set_compressed(self, compressed):
        self._compressed = compressed

    def get_secret(self):
        return self._sk.to_string()

    def get_privkey(self):
        return self._sk.to_pem()

    def get_pubkey(self):
        return self._vk.to_pem()

    def sign(self, hash_val):
        """Sign a pre-computed hash (raw bytes, up to 32 bytes)."""
        if isinstance(hash_val, str):
            hash_val = hash_val.encode()
        # SECP256k1 uses 32-byte digests
        if len(hash_val) < 32:
            hash_val = hash_val.ljust(32, b'\x00')
        elif len(hash_val) > 32:
            hash_val = hashlib.sha256(hash_val).digest()
        sig = self._sk.sign_digest(hash_val, sigencode=ecdsa.util.sigencode_string)
        return sig

    def verify(self, hash_val, sig):
        """Verify a signature against a pre-computed hash."""
        try:
            if isinstance(hash_val, str):
                hash_val = hash_val.encode()
            if len(hash_val) < 32:
                hash_val = hash_val.ljust(32, b'\x00')
            elif len(hash_val) > 32:
                hash_val = hashlib.sha256(hash_val).digest()
            return self._vk.verify_digest(sig, hash_val)
        except ecdsa.BadSignatureError:
            return False
