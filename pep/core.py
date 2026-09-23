import time
import hashlib
import secrets
from .utils import secure_wipe, hkdf_extract_and_expand, encrypt_chacha20, decrypt_chacha20

class PEPDevice:
    def __init__(self, handle: str):
        self.handle = handle
        self.__private_key = secrets.token_bytes(32)
        self.public_id = hashlib.sha256(self.__private_key).digest()

    def generate_physical_seed(self) -> bytes:
        """استخراج العشوائية الفيزيائية من المعالج"""
        entropy = []
        for _ in range(32):
            t1 = time.perf_counter_ns()
            _ = [x**2 for x in range(50)]
            t2 = time.perf_counter_ns()
            entropy.append((t2 - t1) % 256)
        return bytes(entropy)

    def encrypt_for_receiver(self, receiver_public_id: bytes, message_text: str) -> dict:
        """تشفير الرسالة باستخدام ChaCha20-Poly1305"""
        physical_seed = self.generate_physical_seed()
        salt = secrets.token_bytes(16)
        
        # اشتقاق مفتاح الجلسة مع HKDF
        session_key = hkdf_extract_and_expand(salt, physical_seed + receiver_public_id, b"PEP-v1.3-SessionKey")
        
        # تشفير الرسالة بالقفل الفولاذي ChaCha20
        msg_bytes = message_text.encode('utf-8')
        encrypted_data = encrypt_chacha20(session_key, msg_bytes)
        
        # حماية البذرة الفيزيائية
        wrapped_seed = bytes([b ^ receiver_public_id[i % len(receiver_public_id)] for i, b in enumerate(physical_seed)])
        
        # مسح المفاتيح من الذاكرة فوراً للأمان
        secure_wipe(session_key, physical_seed)
        
        return {
            "ciphertext": encrypted_data["ciphertext"],
            "nonce": encrypted_data["nonce"],
            "wrapped_seed": wrapped_seed,
            "salt": salt,
            "sender_handle": self.handle
        }

    def decrypt_incoming_package(self, package: dict) -> str:
        """فك تشفير الرسالة الواردة والتحقق من سلامتها"""
        wrapped_seed = package["wrapped_seed"]
        ciphertext = package["ciphertext"]
        nonce = package["nonce"]
        salt = package["salt"]
        
        # استرجاع البذرة الفيزيائية
        recovered_seed = bytes([b ^ self.public_id[i % len(self.public_id)] for i, b in enumerate(wrapped_seed)])
        
        # إعادة اشتقاق مفتاح الجلسة
        session_key = hkdf_extract_and_expand(salt, recovered_seed + self.public_id, b"PEP-v1.3-SessionKey")
        
        # فك التشفير والتحقق من عدم التلاعب بالرسالة
        decrypted_bytes = decrypt_chacha20(session_key, nonce, ciphertext)
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        # مسح المفاتيح من الذاكرة
        secure_wipe(session_key, recovered_seed)
        
        return decrypted_text
