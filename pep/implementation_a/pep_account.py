import time
from mnemonic import Mnemonic
from pep_core import PEPCore

class PEPAccount:
    def __init__(self, username: str, address: bytes):
        self.username = username
        self.address = address
        self.balance = 0
        self.subscription_expiry = 0  # Timestamp بالثواني
        self.is_custom_name = False

    @staticmethod
    def generate_mnemonic_24words() -> str:
        """توليد 24 كلمة مفتاحية معيارية للنسخ الاحتياطي (BIP-39)"""
        mnemo = Mnemonic("english")
        return mnemo.generate(strength=256) # 256-bit = 24 words

    def process_monthly_subscription(self, fee_amount: int):
        """
        معالجة اشتراك الـ 10 دولار شهرياً للرسائل
        تقسيم الـ 10$ (15% Dev / 85% Node Pool) والتمديد لـ 30 يوم
        """
        if self.balance < fee_amount:
            raise ValueError("ERR_INSUFFICIENT_FUNDS: Balance insufficient for $10 subscription")

        # 1. خصم قيمة الاشتراك من رصيد المستخدم
        self.balance -= fee_amount

        # 2. حساب وتقسيم العمولات (Dev vs Node Pool)
        dev_fee, node_fee = PEPCore.calculate_fees(fee_amount)

        # 3. تمديد اشتراك الرسائل غير المحدودة لمدة 30 يوم
        thirty_days_in_seconds = 30 * 24 * 60 * 60
        current_now = int(time.time())
        
        if self.subscription_expiry > current_now:
            self.subscription_expiry += thirty_days_in_seconds
        else:
            self.subscription_expiry = current_now + thirty_days_in_seconds

        return dev_fee, node_fee

    def can_send_message(self) -> bool:
        """التحقق هل المستخدم يملك اشتراك رسائل فعال حالياً"""
        return int(time.time()) <= self.subscription_expiry

if __name__ == "__main__":
    # توليد الكلمات المفتاحية
    mnemo_phrase = PEPAccount.generate_mnemonic_24words()
    print(f"🔑 Generated Mnemonic Phrase (24 Words):\n{mnemo_phrase}\n")

    # إنشاء حساب تجريبي
    user = PEPAccount(username="User_9841.pep", address=b"\x01"*32)
    user.balance = 5000  # شحن رصيد افتراضي

    # دفع اشتراك الـ 10$ (1000 وحدة)
    dev_share, node_share = user.process_monthly_subscription(fee_amount=1000)

    print("✅ Subscription Processed Successfully!")
    print(f" Dev Share (15%): {dev_share} units ($1.50)")
    print(f" Node Pool Share (85%): {node_share} units ($8.50)")
    print(f" User Remaining Balance: {user.balance} units")
    print(f" Subscription Valid Active: {user.can_send_message()}")
