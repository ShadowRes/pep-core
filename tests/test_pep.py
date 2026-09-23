import unittest
from pep.core import PEPDevice
from pep.utils import hkdf_extract_and_expand

class TestPEPProtocol(unittest.TestCase):

    def setUp(self):
        self.sender = PEPDevice("alice")
        self.receiver = PEPDevice("bob")

    def test_encryption_decryption_cycle(self):
        """اختبار دورة التشفير وفك التشفير الناجحة"""
        message = "Confidential Data Stream Test"
        package = self.sender.encrypt_for_receiver(self.receiver.public_id, message)
        decrypted = self.receiver.decrypt_incoming_package(package)
        self.assertEqual(message, decrypted)

    def test_entropy_uniqueness(self):
        """اختبار عشوائية البذور الفيزيائية وعدم تكرارها"""
        seed1 = self.sender.generate_physical_seed()
        seed2 = self.sender.generate_physical_seed()
        self.assertNotEqual(seed1, seed2)
        self.assertEqual(len(seed1), 32)

    def test_hkdf_derivation_consistency(self):
        """اختبار استقرار اشتقاق المفاتيح HKDF"""
        salt = b"static_salt_1234"
        ikm = b"physical_entropy_seed"
        key1 = hkdf_extract_and_expand(salt, ikm, b"info")
        key2 = hkdf_extract_and_expand(salt, ikm, b"info")
        self.assertEqual(key1, key2)

if __name__ == "__main__":
    unittest.main()
