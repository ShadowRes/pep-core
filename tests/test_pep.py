import unittest
from pep.core import PEPDevice
from cryptography.exceptions import InvalidTag

class TestPEPExtensiveSuite(unittest.TestCase):

    def setUp(self):
        self.sender = PEPDevice("alice")
        self.receiver = PEPDevice("bob")

    def test_encryption_decryption_loop(self):
        """اختبار مكثف: 50 دورة تشفير وفك تشفير متتالية"""
        for i in range(50):
            msg = f"Stress Test Message Iteration #{i}"
            pkg = self.sender.encrypt_for_receiver(self.receiver.public_id, msg)
            decrypted = self.receiver.decrypt_incoming_package(pkg)
            self.assertEqual(msg, decrypted)

    def test_realtime_entropy_health_and_uniqueness(self):
        """اختبار صحة الفحص اللحظي وجودة العشوائية الفيزيائية"""
        seeds = set()
        for _ in range(50):
            seed = self.sender.generate_physical_seed()
            # التأكد من نجاح الفحص اللحظي
            self.assertTrue(self.sender.evaluate_entropy_health(seed))
            seeds.add(seed)
        
        # التأكد من أن جميع البذور الـ 50 فريدة تماماً ولم تتكرر أي بذرة
        self.assertEqual(len(seeds), 50)

    def test_tamper_detection(self):
        """اختبار رفض التلاعب المباشر"""
        package = self.sender.encrypt_for_receiver(self.receiver.public_id, "Tamper Test")
        corrupted_ciphertext = bytearray(package["ciphertext"])
        corrupted_ciphertext[0] ^= 0xFF
        package["ciphertext"] = bytes(corrupted_ciphertext)
        
        with self.assertRaises(InvalidTag):
            self.receiver.decrypt_incoming_package(package)

if __name__ == "__main__":
    unittest.main()
