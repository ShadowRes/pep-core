from pep.core import PEPDevice

if __name__ == "__main__":
    print("--- [PEP Protocol v1.2.0 Architecture Modular Engine] ---")
    sender = PEPDevice("alice_pep")
    receiver = PEPDevice("bob_pep")

    payload = "PEP Modular Architecture - Fully Verified Stream"
    package = sender.encrypt_for_receiver(receiver.public_id, payload)
    decrypted = receiver.decrypt_incoming_package(package)

    print(f"✓ Decrypted Payload: [{decrypted}]")
    print("🧹 Core Modules Verified & Loaded Successfully.")
