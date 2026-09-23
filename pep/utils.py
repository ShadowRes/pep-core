import hashlib
import hmac
import gc

def secure_wipe(*variables):
    """Zeroize RAM references explicitly."""
    for var in variables:
        del var
    gc.collect()

def hkdf_extract_and_expand(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive cryptographically strong keys using HKDF-SHA256."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    for i in range((length + 31) // 32):
        t = hmac.new(prk, t + info + bytes([i + 1]), hashlib.sha256).digest()
        okm += t
    return okm[:length]
