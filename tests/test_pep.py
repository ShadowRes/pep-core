import unittest
from pep.core import PEPDevice
from pep.utils import hkdf_extract_and_expand
from cryptography.exceptions import InvalidTag

class TestPEPProtocol(unittest.TestCase):

    def setUp(self):
        self.sender = PEPDevice("alice")
        self.receiver = PEPDevice("bob")

    def test_encryption_decryption_chacha20(self):
        """اختبار نجاح التشفير وفك التشفير بقفل ChaCha20-Poly1305"""
        message = "Confidential Data Stream Test with ChaCha20"
        package = self.sender.encrypt_for_receiver(self.receiver.public_id, message)
        decrypted = self.receiver.decrypt_incoming_package(package)
        self.assertEqual(message, decrypted)

    def test_tamper_detection(self):
        """اختبار كشف التلاعب بالرسالة المشفرة"""
        message = "Secret Message"
        package = self.sender.encrypt_for_receiver(self.receiver.public_id, message)
        
        # التلاعب بالبيانات المشفرة وتغيير أول بت فيها
        corrupted_ciphertext = bytearray(package["ciphertext"])
        corrupted_ciphertext[0] ^= 0xFF
        package["ciphertext"] = bytes(corrupted_ciphertext)
        
        # يجب أن يرفض النظام فك التشفير ويرفع خطأ InvalidTag
        with self.assertRaises(InvalidTag):
            self.receiver.decrypt_incoming_package(package)

    def test_entropy_uniqueness(self):
        """اختبار عشوائية البذور الفيزيائية وعدم تكرارها"""
        seed1 = self.sender.generate_physical_seed()
        seed2 = self.sender.generate_physical_seed()
        self.assertNotEqual(seed1, seed2)
        self.assertEqual(len(seed1), 32)

if __name__ == "__main__":
    unittest.main()
