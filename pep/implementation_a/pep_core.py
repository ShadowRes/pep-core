import struct
from cryptography.hazmat.primitives.asymmetric import ed25519

# الثوابت المعيارية للبروتوكول
DOMAIN_SEPARATOR = b"PEP-TX-V1\x00\x00\x00"  # 12 Bytes
NETWORK_CHAIN_ID = b"PEP-MAINNET-01\x00\x00" # 16 Bytes

class PEPCore:
    @staticmethod
    def calculate_fees(fee: int):
        """حساب العمولات بدقة حتمية بدون كسور"""
        dev_fee = (fee * 15) // 100
        node_fee = fee - dev_fee
        return dev_fee, node_fee

    @staticmethod
    def encode_transaction(sender: bytes, recipient: bytes, amount: int, fee: int, sequence: int, nonce: bytes) -> bytes:
        """تحويل المعاملة إلى 132 بايت بنظام Big-Endian الصارم"""
        if len(sender) != 32:
            raise ValueError("ERR_OUT_OF_BOUNDS: Sender address must be 32 bytes")
        if len(recipient) != 32:
            raise ValueError("ERR_OUT_OF_BOUNDS: Recipient address must be 32 bytes")
        if len(nonce) != 16:
            raise ValueError("ERR_OUT_OF_BOUNDS: Nonce must be 16 bytes")
        if amount < 0 or fee < 0 or sequence < 0:
            raise ValueError("ERR_OUT_OF_BOUNDS: Values cannot be negative")

        payload = struct.pack(
            ">12s16s32s32sQQQ16s",
            DOMAIN_SEPARATOR,
            NETWORK_CHAIN_ID,
            sender,
            recipient,
            amount,
            fee,
            sequence,
            nonce
        )
        return payload

    @staticmethod
    def generate_keypair():
        """توليد مفاتيح التشغير Ed25519 (Private & Public Keys)"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def sign_transaction(private_key, payload: bytes) -> bytes:
        """توقيع الـ 132 بايت باستخدام المفتاح الخاص (يُنتج 64 بايت)"""
        return private_key.sign(payload)

    @staticmethod
    def verify_signature(public_key, payload: bytes, signature: bytes) -> bool:
        """التحقق من صحة التوقيع المشفر"""
        try:
            public_key.verify(signature, payload)
            return True
        except Exception:
            return False

if __name__ == "__main__":
    # 1. توليد المفاتيح للراسل
    priv_key, pub_key = PEPCore.generate_keypair()
    pub_bytes = pub_key.public_bytes_raw() # 32 Bytes
    
    dummy_recipient = b"\x02" * 32
    dummy_nonce = b"\x00" * 16
    
    # 2. تحويل البيانات لـ 132 بايت
    payload = PEPCore.encode_transaction(
        sender=pub_bytes,
        recipient=dummy_recipient,
        amount=5000,
        fee=200,
        sequence=1,
        nonce=dummy_nonce
    )
    
    # 3. توقيع البيانات
    signature = PEPCore.sign_transaction(priv_key, payload)
    
    # 4. فحص التوقيع الاصلي
    is_valid = PEPCore.verify_signature(pub_key, payload, signature)
    
    # 5. تجربة هجوم لتعديل المبلغ (Tamper Attack Test)
    tampered_payload = PEPCore.encode_transaction(
        sender=pub_bytes,
        recipient=dummy_recipient,
        amount=999999, # تم تغيير المبلغ بعد التوقيع!
        fee=200,
        sequence=1,
        nonce=dummy_nonce
    )
    is_tampered_valid = PEPCore.verify_signature(pub_key, tampered_payload, signature)
    
    print(f"✅ Transaction Payload Length: {len(payload)} bytes")
    print(f"✅ Ed25519 Signature Length: {len(signature)} bytes")
    print(f"🔒 Original Signature Verification: {is_valid}")
    print(f"🛡️ Tampered Signature Verification: {is_tampered_valid} (Must be False!)")
