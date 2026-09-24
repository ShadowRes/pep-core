import time
import hashlib
import secrets
import os
from .utils import secure_wipe, hkdf_extract_and_expand, encrypt_chacha20, decrypt_chacha20

CHUNK_SIZE = 64 * 1024

class PEPDevice:
    def __init__(self, handle: str):
        self.handle = handle
        self.__private_key = secrets.token_bytes(32)
        self.public_id = hashlib.sha256(self.__private_key).digest()
        self.failed_attempts = {}  # تتبع المحاولات الخاطئة لكل طرد/ملف

    def evaluate_entropy_health(self, seed: bytes) -> bool:
        if len(seed) < 32:
            return False
        return len(set(seed)) >= 18

    def generate_physical_seed(self) -> bytes:
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

        fallback = secrets.token_bytes(32)
        return bytes([b1 ^ b2 for b1, b2 in zip(candidate_seed, fallback)])

    def encrypt_with_passphrase(self, receiver_public_id: bytes, raw_data: bytes, passphrase: str) -> dict:
        """تشفير البيانات بدمج العشوائية الفيزيائية وكلمة سر المستخدم"""
        physical_seed = self.generate_physical_seed()
        salt = secrets.token_bytes(16)
        
        # خلط كلمة السر الخاصة بالمستخدم مع البذرة الفيزيائية
        passphrase_bytes = passphrase.encode('utf-8')
        combined_ikm = physical_seed + receiver_public_id + passphrase_bytes
        
        session_key = hkdf_extract_and_expand(salt, combined_ikm, b"PEP-v1.5-PassphraseKey")
        encrypted_data = encrypt_chacha20(session_key, raw_data)
        
        wrapped_seed = bytes([b ^ receiver_public_id[i % len(receiver_public_id)] for i, b in enumerate(physical_seed)])
        package_id = secrets.token_hex(8)
        
        secure_wipe(session_key, physical_seed, passphrase_bytes)
        
        return {
            "package_id": package_id,
            "ciphertext": encrypted_data["ciphertext"],
            "nonce": encrypted_data["nonce"],
            "wrapped_seed": wrapped_seed,
            "salt": salt,
            "sender_handle": self.handle
        }

    def decrypt_with_passphrase(self, package: dict, passphrase: str) -> bytes:
        """فك التشفير بكلمة السر مع نظام التدمير الذاتي بعد 3 محاولات خاطئة"""
        package_id = package.get("package_id", "default")
        current_failed = self.failed_attempts.get(package_id, 0)
        
        if current_failed >= 3:
            raise PermissionError("تم تجاوز الحد الأقصى للمحاولات الخاطئة (3 محاولات). تم تدمير وإتلاف الطرد أمنياً!")

        wrapped_seed = package["wrapped_seed"]
        ciphertext = package["ciphertext"]
        nonce = package["nonce"]
        salt = package["salt"]
        
        passphrase_bytes = passphrase.encode('utf-8')
        recovered_seed = bytes([b ^ self.public_id[i % len(self.public_id)] for i, b in enumerate(wrapped_seed)])
        combined_ikm = recovered_seed + self.public_id + passphrase_bytes
        
        session_key = hkdf_extract_and_expand(salt, combined_ikm, b"PEP-v1.5-PassphraseKey")
        
        try:
            decrypted_bytes = decrypt_chacha20(session_key, nonce, ciphertext)
            # عند النجاح يتم إعادة تصفير عداد الأخطاء
            self.failed_attempts[package_id] = 0
            secure_wipe(session_key, recovered_seed, passphrase_bytes)
            return decrypted_bytes
        except Exception as e:
            # زيادة عداد المحاولات الخاطئة
            self.failed_attempts[package_id] = current_failed + 1
            remaining = 3 - self.failed_attempts[package_id]
            secure_wipe(session_key, recovered_seed, passphrase_bytes)
            
            if remaining <= 0:
                # تدمير بيانات الطرد فوراً من القاموس
                package["ciphertext"] = b""
                package["wrapped_seed"] = b""
                raise PermissionError("كلمة السر خاطئة! تم استهلاك المحاولة الأخيرة وإتلاف البيانات نهائياً.")
            else:
                raise ValueError(f"كلمة السر خاطئة! متبقي لديك {remaining} محاولات قبل إتلاف البيانات.")
