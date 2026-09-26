import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def secure_wipe(*args):
    """تصفير ومسح المتغيرات من الذاكرة"""
    for arg in args:
        if isinstance(arg, bytearray):
            for i in range(len(arg)):
                arg[i] = 0

def hkdf_extract_and_expand(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)

def encrypt_chacha20(key: bytes, plaintext: bytes) -> dict:
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    return {"ciphertext": ciphertext, "nonce": nonce}

def decrypt_chacha20(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None)

def calculate_core_integrity_hash() -> str:
    """حساب البصمة الرقمية الحية لملفات الكود الأساسية للتحقق من عدم التلاعب"""
    hasher = hashlib.sha256()
    base_dir = os.path.dirname(__file__)
    
    # فحص الملفات الأساسية للمحرك
    for file_name in sorted(os.listdir(base_dir)):
        if file_name.endswith('.py'):
            file_path = os.path.join(base_dir, file_name)
            with open(file_path, 'rb') as f:
                hasher.update(f.read())
                
    return hasher.hexdigest()
