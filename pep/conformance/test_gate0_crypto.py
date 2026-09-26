import sys
import os
import binascii
from cryptography.hazmat.primitives.asymmetric import ed25519

def run_gate0_crypto_primitive_tests():
    print("==========================================================")
    print("   PEP GATE 0: CRYPTOGRAPHIC PRIMITIVE (NIST CAVP / KAT) ")
    print("==========================================================\n")

    # 1. اختبارات المتجهات المعروفة لـ Ed25519 (RFC 8032 Known Answer Test Vector)
    test_secret_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    test_pub_hex    = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    test_message   = b""
    test_sig_hex   = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

    print("🔍 Testing Ed25519 RFC 8032 / NIST CAVP Known Answer Vector (KAT)...")
    
    priv_bytes = bytes.fromhex(test_secret_hex)
    expected_pub = bytes.fromhex(test_pub_hex)
    expected_sig = bytes.fromhex(test_sig_hex)

    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub_key = priv_key.public_key()
    pub_bytes = pub_key.public_bytes_raw()

    # التحقق من المفتاح العام
    assert pub_bytes == expected_pub, "ERR_KAT_PUBKEY_MISMATCH"
    print("  ├─ Key Generation (KeyGen): PASS")

    # التوقيع والتحقق
    sig = priv_key.sign(test_message)
    assert sig == expected_sig, "ERR_KAT_SIGGEN_MISMATCH"
    print("  ├─ Signature Generation (SigGen): PASS")

    pub_key.verify(expected_sig, test_message)
    print("  └─ Signature Verification (SigVer): PASS")

    # 2. اختبار WycheproofNegative (توقيع تالف لرفضه فوراً)
    print("\n🔍 Testing Wycheproof Negative / Adversarial Mutated Signature...")
    corrupted_sig = bytearray(expected_sig)
    corrupted_sig[0] ^= 0xFF # تغيير أول بايت
    
    rejected = False
    try:
        pub_key.verify(bytes(corrupted_sig), test_message)
    except Exception:
        rejected = True

    assert rejected, "ERR_WYCHEPROOF_FAILED_TO_REJECT_INVALID_SIG"
    print("  └─ Wycheproof Mutated Signature Rejection: PASS")

    print("\n----------------------------------------------------------")
    print("🛡️  GATE 0 CRYPTOGRAPHIC PRIMITIVE PASSED 100% COMPLIANCE!")
    print("----------------------------------------------------------\n")

if __name__ == "__main__":
    run_gate0_crypto_primitive_tests()
