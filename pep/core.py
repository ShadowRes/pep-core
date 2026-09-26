import time
import hashlib
import secrets
import os
from .utils import secure_wipe, hkdf_extract_and_expand, encrypt_chacha20, decrypt_chacha20, calculate_core_integrity_hash

CHUNK_SIZE = 64 * 1024
PROTOCOL_MAGIC_BYTES = b"PEP15_PROT_OK"

class PEPDevice:
    def __init__(self, handle: str, expected_code_hash: str = None):
        self.handle = handle
        self.__private_key = secrets.token_bytes(32)
        self.public_id = hashlib.sha256(self.__private_key).digest()
        self.failed_attempts = {}
        
        self.code_hash = calculate_core_integrity_hash()
        self.expected_code_hash = expected_code_hash or self.code_hash

    def verify_code_integrity(self):
        current_hash = calculate_core_integrity_hash()
        if current_hash != self.expected_code_hash:
            raise RuntimeError("CRITICAL SECURITY ALERT: تم اكتشاف تعديل خبيث أو تلاعب بملفات التطبيق! تم إيقاف التشغيل حماية للشبكة.")

    def evaluate_entropy_health(self, seed: bytes) -> bool:
        if len(seed) < 32:
            return False
        return len(set(seed)) >= 18

    def generate_physical_seed(self) -> bytes:
        self.verify_code_integrity()
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

    def generate_protocol_header(self, package_id: str, salt: bytes) -> dict:
        """إنشاء هيدر معايير البروتوكول يثبت صحة اقتطاع النسبة والالتزام بالمعايير"""
        header_data = PROTOCOL_MAGIC_BYTES + package_id.encode('utf-8') + salt
        protocol_proof = hashlib.sha256(header_data).hexdigest()
        return {
            "version": "v1.5.0",
            "fee_split": "15_DEV_85_NODE",
            "protocol_proof": protocol_proof
        }

    def verify_protocol_header(self, package: dict):
        """فحص مطابقة الطرد لمعايير الشبكة ونسبة الـ 15% قبل المعالجة"""
        header = package.get("header", {})
        if header.get("fee_split") != "15_DEV_85_NODE":
            raise PermissionError("REJECTED BY NETWORK: الطرد يفتقر إلى ختم اقتطاع نسبة المطور (15%) المقررة.")
        
        package_id = package.get("package_id", "")
        salt = package.get("salt", b"")
        header_data = PROTOCOL_MAGIC_BYTES + package_id.encode('utf-8') + salt
        expected_proof = hashlib.sha256(header_data).hexdigest()
        
        if header.get("protocol_proof") != expected_proof:
            raise ValueError("REJECTED BY NETWORK: ختم توقيع المعايير غير مطابق لبروتوكول PEP الأصلي.")

    def encrypt_with_passphrase(self, receiver_public_id: bytes, raw_data: bytes, passphrase: str) -> dict:
        self.verify_code_integrity()
        physical_seed = self.generate_physical_seed()
        salt = secrets.token_bytes(16)
        
        passphrase_bytes = passphrase.encode('utf-8')
        combined_ikm = physical_seed + receiver_public_id + passphrase_bytes
        
        session_key = hkdf_extract_and_expand(salt, combined_ikm, b"PEP-v1.5-PassphraseKey")
        encrypted_data = encrypt_chacha20(session_key, raw_data)
        
        wrapped_seed = bytes([b ^ receiver_public_id[i % len(receiver_public_id)] for i, b in enumerate(physical_seed)])
        package_id = secrets.token_hex(8)
        
        header = self.generate_protocol_header(package_id, salt)
        secure_wipe(session_key, physical_seed, passphrase_bytes)
        
        return {
            "package_id": package_id,
            "header": header,
            "ciphertext": encrypted_data["ciphertext"],
            "nonce": encrypted_data["nonce"],
            "wrapped_seed": wrapped_seed,
            "salt": salt,
            "sender_handle": self.handle,
            "code_hash": self.code_hash
        }

    def decrypt_with_passphrase(self, package: dict, passphrase: str) -> bytes:
        self.verify_code_integrity()
        self.verify_protocol_header(package)  # فحص المعايير أولاً
        
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
            self.failed_attempts[package_id] = 0
            secure_wipe(session_key, recovered_seed, passphrase_bytes)
            return decrypted_bytes
        except Exception as e:
            self.failed_attempts[package_id] = current_failed + 1
            remaining = 3 - self.failed_attempts[package_id]
            secure_wipe(session_key, recovered_seed, passphrase_bytes)
            
            if remaining <= 0:
                package["ciphertext"] = b""
                package["wrapped_seed"] = b""
                raise PermissionError("كلمة السر خاطئة! تم استهلاك المحاولة الأخيرة وإتلاف البيانات نهائياً.")
            else:
                raise ValueError(f"كلمة السر خاطئة! متبقي لديك {remaining} محاولات قبل إتلاف البيانات.")
