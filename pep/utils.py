import hashlib
import hmac
import os
import gc
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

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

def encrypt_chacha20(key: bytes, plaintext: bytes) -> dict:
    """ChaCha20-Poly1305 Authenticated Encryption."""
    chacha = ChaCha20Poly1305(key)
    # توليد 12 بايت عشوائية قياسية للـ nonce
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    return {"nonce": nonce, "ciphertext": ciphertext}

def decrypt_chacha20(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """ChaCha20-Poly1305 Authenticated Decryption."""
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None)
