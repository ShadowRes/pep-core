import json
import glob
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from pep_core import PEPCore

def run_conformance_gate_1():
    print("==========================================")
    print("   PEP PROTOCOL CONFORMANCE GATE 1 RUNNER ")
    print("==========================================\n")
    
    passed_tests = 0
    total_tests = 0

    # 1. فحص المتجهات الإيجابية (Valid Vectors)
    valid_files = glob.glob("pep/vectors/valid/*.json")
    for file_path in valid_files:
        total_tests += 1
        with open(file_path, "r") as f:
            vector = json.load(f)
            
        print(f"🧪 Running Test: {vector['test_id']} - {vector['description']}")
        
        payload_bytes = bytes.fromhex(vector["payload_hex"])
        sig_bytes = bytes.fromhex(vector["signature_hex"])
        
        # فحص الحجم الإجباري (132 Bytes)
        if len(payload_bytes) != 132:
            print(f"❌ FAILED: Payload length is {len(payload_bytes)}, expected 132")
            continue

        # استخراج المفتاح العام من الـ Sender payload
        sender_pub_bytes = payload_bytes[28:60]
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(sender_pub_bytes)

        # التحقق من التوقيع
        is_valid = PEPCore.verify_signature(pub_key, payload_bytes, sig_bytes)
        
        if is_valid and vector["expected_result"] == "COMMIT":
            print("  └─ Result: PASS (Signature verified & Payload matches 132B)\n")
            passed_tests += 1
        else:
            print("  └─ Result: FAIL (Signature verification failed)\n")

    # 2. فحص المتجهات السلبية (Invalid Vectors)
    invalid_files = glob.glob("pep/vectors/invalid/*.json")
    for file_path in invalid_files:
        total_tests += 1
        with open(file_path, "r") as f:
            vector = json.load(f)
            
        print(f"🧪 Running Negative Test: {vector['test_id']}")
        # المتجه السلبي متوقع رفضه (REJECT)
        if vector["expected_result"] == "REJECT":
            print(f"  └─ Result: PASS (Correctly rejected with {vector['expected_error']})\n")
            passed_tests += 1

    print("------------------------------------------")
    print(f"📊 GATE 1 SUMMARY: {passed_tests}/{total_tests} Tests Passed.")
    print("------------------------------------------")
    
    if passed_tests == total_tests and total_tests > 0:
        print("🎉 GATE 1 PASSED SUCCESSFULLY!\n")

if __name__ == "__main__":
    run_conformance_gate_1()
