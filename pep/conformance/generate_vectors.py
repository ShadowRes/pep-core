import json
import os
from pep_core import PEPCore

def generate_reference_vectors():
    # مجلدات الحفظ
    valid_dir = "pep/vectors/valid"
    invalid_dir = "pep/vectors/invalid"
    os.makedirs(valid_dir, exist_ok=True)
    os.makedirs(invalid_dir, exist_ok=True)

    # 1. إنشاء اختبار إيجابي معتمد (Valid Vector)
    priv_key, pub_key = PEPCore.generate_keypair()
    pub_bytes = pub_key.public_bytes_raw()
    recipient = b"\x02" * 32
    nonce = b"\x00" * 16
    
    payload = PEPCore.encode_transaction(
        sender=pub_bytes,
        recipient=recipient,
        amount=1000,
        fee=100,
        sequence=1,
        nonce=nonce
    )
    sig = PEPCore.sign_transaction(priv_key, payload)

    valid_vector = {
        "test_id": "VEC_CORE_VALID_01",
        "description": "Valid transfer transaction on PEP-MAINNET-01",
        "payload_hex": payload.hex(),
        "signature_hex": sig.hex(),
        "expected_result": "COMMIT",
        "expected_error": None,
        "fee_split": {
            "dev_fee": 15,
            "node_fee": 85
        }
    }

    with open(f"{valid_dir}/valid_tx_01.json", "w") as f:
        json.dump(valid_vector, f, indent=2)

    # 2. إنشاء اختبار سلبي (Invalid Chain ID Vector)
    invalid_vector = {
        "test_id": "VEC_CORE_ERR_CHAIN_MISMATCH",
        "description": "Transaction targeted for unknown chain",
        "payload_hex": payload.hex(),
        "signature_hex": sig.hex(),
        "expected_result": "REJECT",
        "expected_error": "ERR_CHAIN_ID_MISMATCH"
    }

    with open(f"{invalid_dir}/invalid_chain_01.json", "w") as f:
        json.dump(invalid_vector, f, indent=2)

    print("✅ Reference Test Vectors Generated Successfully in pep/vectors/")

if __name__ == "__main__":
    generate_reference_vectors()
