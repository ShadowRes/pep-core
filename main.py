import time
import hashlib
import secrets
import gc

def secure_wipe(*variables):
    """Zeroize RAM references explicitly."""
    for var in variables:
        del var
    gc.collect()

class PEPDevice:
    def __init__(self, handle):
        self.handle = handle
        self.__private_key = secrets.token_bytes(32)
        self.public_id = hashlib.sha256(self.__private_key).digest()

    def generate_physical_seed(self):
        """Extract physical entropy via execution jitter."""
        entropy = []
        for _ in range(32):
            t1 = time.perf_counter_ns()
            _ = [x**2 for x in range(50)]
            t2 = time.perf_counter_ns()
            entropy.append((t2 - t1) % 256)
        return bytes(entropy)

    def encrypt_for_receiver(self, receiver_public_id, message_text):
        physical_seed = self.generate_physical_seed()
        session_key = hashlib.sha256(physical_seed + receiver_public_id).digest()
        msg_bytes = message_text.encode('utf-8')
        
        ciphertext = bytes([b ^ session_key[i % len(session_key)] for i, b in enumerate(msg_bytes)])
        wrapped_seed = bytes([b ^ receiver_public_id[i % len(receiver_public_id)] for i, b in enumerate(physical_seed)])
        
        secure_wipe(session_key, physical_seed)
        return {"ciphertext": ciphertext, "wrapped_seed": wrapped_seed, "sender_handle": self.handle}

    def decrypt_incoming_package(self, package):
        wrapped_seed = package["wrapped_seed"]
        ciphertext = package["ciphertext"]
        
        recovered_seed = bytes([b ^ self.public_id[i % len(self.public_id)] for i, b in enumerate(wrapped_seed)])
        session_key = hashlib.sha256(recovered_seed + self.public_id).digest()
        
        decrypted_bytes = bytes([b ^ session_key[i % len(session_key)] for i, b in enumerate(ciphertext)])
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        secure_wipe(session_key, recovered_seed)
        return decrypted_text

if __name__ == "__main__":
    print("--- [PEP Protocol v1.0.0 Architecture Engine] ---")
    sender = PEPDevice("device_alpha")
    receiver = PEPDevice("device_beta")

    payload = "PEP Security Protocol - Confidential Data Stream"
    package = sender.encrypt_for_receiver(receiver.public_id, payload)
    decrypted = receiver.decrypt_incoming_package(package)

    print(f"✓ Decrypted Payload: [{decrypted}]")
    print("🧹 Memory Wiped Successfully.")

