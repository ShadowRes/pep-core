import struct
from cryptography.hazmat.primitives.asymmetric import ed25519

# Constants derived strictly from PEP-Core-v1.0-RC1 Spec
EXPECTED_DOMAIN = b"PEP-TX-V1\x00\x00\x00"
EXPECTED_CHAIN = b"PEP-MAINNET-01\x00\x00"

class PEPCoreEngineB:
    """
    Independent Implementation B for PEP Protocol Core Spec v1.0-RC1.
    Designed with an independent validation pipeline architecture.
    """

    @classmethod
    def parse_and_validate_payload(cls, raw_bytes: bytes) -> dict:
        """فك تشفير الـ 132 بايت بشكل مستقل واختبار الحقول"""
        if len(raw_bytes) != 132:
            raise ValueError("ERR_MALFORMED_BINARY")

        # Unpack binary layout according to Spec Section 5
        domain, chain, sender, recipient, amount, fee, sequence, nonce = struct.unpack(
            ">12s16s32s32sQQQ16s", raw_bytes
        )

        if domain != EXPECTED_DOMAIN:
            raise ValueError("ERR_MALFORMED_BINARY")

        if chain != EXPECTED_CHAIN:
            raise ValueError("ERR_CHAIN_ID_MISMATCH")

        return {
            "domain": domain,
            "chain_id": chain,
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "fee": fee,
            "sequence": sequence,
            "nonce": nonce
        }

    @staticmethod
    def compute_fee_split(fee_value: int) -> tuple:
        """Deterministic fee division (15% Dev / 85% Node)"""
        dev_share = (fee_value * 15) // 100
        node_share = fee_value - dev_share
        return dev_share, node_share

    @staticmethod
    def verify_ed25519_sig(sender_pub_bytes: bytes, payload: bytes, signature: bytes) -> bool:
        """مكافئ مستقل للتحقق التشفيري"""
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(sender_pub_bytes)
            public_key.verify(signature, payload)
            return True
        except Exception:
            return False
