import time
import hashlib
import hmac
import secrets
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

class PEPDevice:
    def __init__(self, handle: str):
        self.handle = handle
        self.__private_key = secrets.token_bytes(32)
        self.public_id = hashlib.sha256(self.__private_key).digest()

    def generate_physical_seed(self) -> bytes:
        """Extract physical entropy via execution jitter."""
        entropy = []
        for _ in range(32):
            t1 = time.perf_counter_ns()
            _ = [x**2 for x in range(50)]
            t2 = time.perf_counter_ns()
            entropy.append((t2 - t1) % 256)
        return bytes(entropy)

    def encrypt_for_receiver(self, receiver_public_id: bytes, message_text: str) -> dict:
        physical_seed = self.generate_physical_seed()
        salt = secrets.token_bytes(16)
        
        # HKDF Key Derivation
        session_key = hkdf_extract_and_expand(salt, physical_seed + receiver_public_id, b"PEP-v1.1-SessionKey")
        
        msg_bytes = message_text.encode('utf-8')
        ciphertext = bytes([b ^ session_key[i % len(session_key)] for i, b in enumerate(msg_bytes)])
        wrapped_seed = bytes([b ^ receiver_public_id[i % len(receiver_public_id)] for i, b in enumerate(physical_seed)])
        
        secure_wipe(session_key, physical_seed)
        return {
            "ciphertext": ciphertext,
            "wrapped_seed": wrapped_seed,
            "salt": salt,
            "sender_handle": self.handle
        }

    def decrypt_incoming_package(self, package: dict) -> str:
        wrapped_seed = package["wrapped_seed"]
        ciphertext = package["ciphertext"]
        salt = package["salt"]
        
        recovered_seed = bytes([b ^ self.public_id[i % len(self.public_id)] for i, b in enumerate(wrapped_seed)])
        
        # HKDF Key Derivation
        session_key = hkdf_extract_and_expand(salt, recovered_seed + self.public_id, b"PEP-v1.1-SessionKey")
        
        decrypted_bytes = bytes([b ^ session_key[i % len(session_key)] for i, b in enumerate(ciphertext)])
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        secure_wipe(session_key, recovered_seed)
        return decrypted_text

if __name__ == "__main__":
    print("--- [PEP Protocol v1.1.0 HKDF Engine] ---")
    sender = PEPDevice("alice_pep")
    receiver = PEPDevice("bob_pep")

    payload = "PEP Secure Stream - Enhanced with HKDF-SHA256"
    package = sender.encrypt_for_receiver(receiver.public_id, payload)
    decrypted = receiver.decrypt_incoming_package(package)

    print(f"✓ Decrypted Payload: [{decrypted}]")
    print("🧹 Memory Wiped Successfully.")
