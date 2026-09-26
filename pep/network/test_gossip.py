import subprocess
import time
import socket
import sys
import os

sys.path.append(os.path.abspath("pep/implementation_a"))
from pep_core import PEPCore

def test_p2p_gossip_propagation():
    print("==========================================================")
    print("   PEP P2P GOSSIP & MULTI-NODE RELAY TESTER               ")
    print("==========================================================\n")

    # 1. تشغيل العقدة الأولى (Node 9000) والعقدة الثانية (Node 9001)
    p1 = subprocess.Popen(["python3", "pep/network/gossip_relay.py", "9000"])
    p2 = subprocess.Popen(["python3", "pep/network/gossip_relay.py", "9001"])
    time.sleep(1.5)

    # 2. إنشاء معاملة معتمدة
    priv_key, pub_key = PEPCore.generate_keypair()
    payload = PEPCore.encode_transaction(
        sender=pub_key.public_bytes_raw(),
        recipient=b"\x05"*32,
        amount=250,
        fee=50,
        sequence=1,
        nonce=b"\x00"*16
    )

    # 3. إرسال المعاملة للعقدة الأولى (Node 9000) فقط
    print("🚀 Injecting Valid Transaction into Node 9000...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 9000))
    sock.sendall(payload)
    res = sock.recv(1024).decode()
    sock.close()
    print(f"  └─ Node 9000 Direct Response: {res}")

    time.sleep(1)

    # 4. التحقق لدى العقدة الثانية (Node 9001)
    print("\n🔍 Checking if Node 9001 Received Transaction via Gossip Relay...")
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.connect(("127.0.0.1", 9001))
    sock2.sendall(payload)
    res2 = sock2.recv(1024).decode()
    sock2.close()
    print(f"  └─ Node 9001 Response: {res2}")

    p1.terminate()
    p2.terminate()

    if res2 == "ALREADY_SEEN":
        print("\n🎉 SUCCESS! P2P GOSSIP PROPAGATED TRANSACTION TO ALL PEERS AUTOMATICALLY!\n")
    else:
        print("\n❌ GOSSIP PROPAGATION FAILED!\n")

if __name__ == "__main__":
    test_p2p_gossip_propagation()
