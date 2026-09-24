import time
import hashlib
import secrets
from .utils import secure_wipe, hkdf_extract_and_expand, encrypt_chacha20, decrypt_chacha20

class PEPDevice:
    def __init__(self, handle: str):
        self.handle = handle
        self.__private_key = secrets.token_bytes(32)
        self.public_id = hashlib.sha256(self.__private_key).digest()

    def evaluate_entropy_health(self, seed: bytes) -> bool:
        """فحص لحظي لجودة العشوائية المجمعة من المعالج"""
        if len(seed) < 32:
            return False
        # حساب تنوع البايتات (Unique Byte Diversity)
        unique_bytes = len(set(seed))
        # يجب أن تحتوى البذرة على 18 بايت فريد على الأقل من أصل 32 بايت لضمان التنوع
        return unique_bytes >= 18

    def generate_physical_seed(self) -> bytes:
        """استخراج العشوائية الفيزيائية مع الفحص والتدقيق اللحظي"""
        attempts = 0
        while attempts < 5:
            entropy = []
            for _ in range(32):
                t1 = time.perf_counter_ns()
                _ = [x**2 for x in range(50)]
                t2 = time.perf_counter_ns()
                entropy.append((t2 - t1) % 256)
            
            candidate_seed = bytes(entropy)
            if self.evaluate_entropy_health(candidate_seed):
                return candidate_seed
            attempts += 1

        # في حالة انخفاض العشوائية الفيزيائية جداً، يتم خلطها بمولد أمني للطوارئ
        fallback = secrets.token_bytes(32)
        return bytes([b1 ^ b2 for b1, b2 in zip(candidate_seed, fallback)])

    def encrypt_for_receiver(self, receiver_public_id: bytes, message_text: str) -> dict:
        """تشفير الرسالة بـ ChaCha20-Poly1305 بعد التأكد من جودة العشوائية"""
        physical_seed = self.generate_physical_seed()
        salt = secrets.token_bytes(16)
        
        session_key = hkdf_extract_and_expand(salt, physical_seed + receiver_public_id, b"PEP-v1.3-SessionKey")
        
        msg_bytes = message_text.encode('utf-8')
        encrypted_data = encrypt_chacha20(session_key, msg_bytes)
        
        wrapped_seed = bytes([b ^ receiver_public_id[i % len(receiver_public_id)] for i, b in enumerate(physical_seed)])
        
        secure_wipe(session_key, physical_seed)
        
        return {
            "ciphertext": encrypted_data["ciphertext"],
            "nonce": encrypted_data["nonce"],
            "wrapped_seed": wrapped_seed,
            "salt": salt,
            "sender_handle": self.handle
        }

    def decrypt_incoming_package(self, package: dict) -> str:
        """فك التشفير والتحقق من سلامة البيانات"""
        wrapped_seed = package["wrapped_seed"]
        ciphertext = package["ciphertext"]
        nonce = package["nonce"]
        salt = package["salt"]
        
        recovered_seed = bytes([b ^ self.public_id[i % len(self.public_id)] for i, b in enumerate(wrapped_seed)])
        
        session_key = hkdf_extract_and_expand(salt, recovered_seed + self.public_id, b"PEP-v1.3-SessionKey")
        
        decrypted_bytes = decrypt_chacha20(session_key, nonce, ciphertext)
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        secure_wipe(session_key, recovered_seed)
        return decrypted_text
