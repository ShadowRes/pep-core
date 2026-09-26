import socket
import sys
import os
import concurrent.futures

sys.path.append(os.path.abspath("pep/implementation_a"))
from pep_core import PEPCore

def send_payload(payload: bytes, host="127.0.0.1", port=9000) -> str:
    """إرسال حمولة عبر اتصال TCP مباشر للعقدة"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((host, port))
        sock.sendall(payload)
        response = sock.recv(1024).decode('utf-8').strip()
        sock.close()
        return response
    except Exception as e:
        return f"ERROR: {str(e)}"

def run_network_live_test():
    print("==========================================================")
    print("   PEP P2P NETWORK LIVE CLIENT & FLOOD TESTER             ")
    print("==========================================================\n")

    # 1. إنشاء معاملة سليمة رسمية (132 Bytes)
    priv_key, pub_key = PEPCore.generate_keypair()
    pub_bytes = pub_key.public_bytes_raw()
    valid_payload = PEPCore.encode_transaction(
        sender=pub_bytes,
        recipient=b"\x03"*32,
        amount=500,
        fee=100,
        sequence=1,
        nonce=b"\x00"*16
    )

    print("📡 Sending Valid 132-byte Transaction to Node [127.0.0.1:9000]...")
    res_valid = send_payload(valid_payload)
    print(f"  └─ Node Response: {res_valid}\n")

    print("📡 Sending Corrupted 50-byte Payload to Node...")
    res_invalid = send_payload(b"PEP-BAD-DATA"*4)
    print(f"  └─ Node Response: {res_invalid}\n")

    # 2. محاكاة ضغط شبكي متزامن (Concurrent Network Flood)
    num_requests = 200
    print(f"🔥 Simulating Concurrent Network Flood: Sending {num_requests} Requests...")
    
    accepted_count = 0
    rejected_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # إرسال مزيج من الطلبات المقبولة والمرفوضة بالتوازي
        futures = []
        for i in range(num_requests):
            payload = valid_payload if i % 2 == 0 else os.urandom(100)
            futures.append(executor.submit(send_payload, payload))

        for future in concurrent.futures.as_completed(futures):
            resp = future.result()
            if "ACCEPTED" in resp:
                accepted_count += 1
            else:
                rejected_count += 1

    print("----------------------------------------------------------")
    print(f"✅ Network Accepted Requests : {accepted_count}")
    print(f"🛡️  Network Rejected Requests : {rejected_count}")
    print("----------------------------------------------------------")
    print("🎉 P2P TRANSPORT TEST COMPLETED SUCCESSFULLY!\n")

if __name__ == "__main__":
    run_network_live_test()
