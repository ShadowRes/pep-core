import unittest
from pep.core import PEPDevice

class PEPPassphraseSelfDestructSuite(unittest.TestCase):

    def setUp(self):
        self.alice = PEPDevice("alice")
        self.bob = PEPDevice("bob")

    def test_successful_passphrase_decryption(self):
        """1. نجاح فك التشفير عند إدخال كلمة السر الصحيحة"""
        secret_msg = b"Confidential Financial Payload"
        passphrase = "MySecretPassphrase123"
        
        pkg = self.alice.encrypt_with_passphrase(self.bob.public_id, secret_msg, passphrase)
        decrypted = self.bob.decrypt_with_passphrase(pkg, passphrase)
        self.assertEqual(secret_msg, decrypted)

    def test_three_attempts_and_self_destruct(self):
        """2. اختبار الـ 3 محاولات الخاطئة وإتلاف البيانات نهائياً"""
        secret_msg = b"Top Secret Data"
        correct_passphrase = "CorrectPassphrase"
        wrong_passphrase = "WrongPassphrase"
        
        pkg = self.alice.encrypt_with_passphrase(self.bob.public_id, secret_msg, correct_passphrase)
        
        # المحاولة الخاطئة الأولى
        with self.assertRaises(ValueError) as ctx1:
            self.bob.decrypt_with_passphrase(pkg, wrong_passphrase)
        self.assertIn("متبقي لديك 2 محاولات", str(ctx1.exception))

        # المحاولة الخاطئة الثانية
        with self.assertRaises(ValueError) as ctx2:
            self.bob.decrypt_with_passphrase(pkg, wrong_passphrase)
        self.assertIn("متبقي لديك 1 محاولات", str(ctx2.exception))

        # المحاولة الخاطئة الثالثة -> التدمير الإجباري والإتلاف
        with self.assertRaises(PermissionError) as ctx3:
            self.bob.decrypt_with_passphrase(pkg, wrong_passphrase)
        self.assertIn("إتلاف البيانات نهائياً", str(ctx3.exception))

        # محاولة رابعة حتى لو أورد كلمة السر الصحيحة الآن -> يجب الرفض لأن البيانات أُتلفت
        with self.assertRaises(PermissionError):
            self.bob.decrypt_with_passphrase(pkg, correct_passphrase)

if __name__ == "__main__":
    unittest.main()
