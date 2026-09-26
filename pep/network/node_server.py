import socket
import sys
import os
from concurrent.futures import ThreadPoolExecutor

sys.path.append(os.path.abspath("pep/implementation_a"))
from pep_core import PEPCore

class HighPerformancePEPNode:
    def __init__(self, host: str = "127.0.0.1", port: int = 9000, max_workers: int = 100):
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self.mempool = []
        # Thread Pool لمعالجة آلاف الطلبات المتزامنة بكفاءة عالية
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)

    def process_incoming_connection(self, client_socket, client_address):
        """معالجة آمنة فائقة السرعة للرسالة القادمة"""
        try:
            client_socket.settimeout(3.0) # منع هجمات التعليق (Slowloris Attacks)
            data = client_socket.recv(256)
            
            if not data or len(data) != 132:
                client_socket.sendall(b"REJECT: ERR_MALFORMED_BINARY\n")
            elif data[:12] != b"PEP-TX-V1\x00\x00\x00":
                client_socket.sendall(b"REJECT: ERR_DOMAIN_MISMATCH\n")
            elif data[12:28] != b"PEP-MAINNET-01\x00\x00":
                client_socket.sendall(b"REJECT: ERR_CHAIN_ID_MISMATCH\n")
            else:
                self.mempool.append(data)
                client_socket.sendall(b"ACCEPTED: COMMIT_TO_MEMPOOL\n")
        except Exception:
            pass
        finally:
            client_socket.close()

    def start_node(self):
        """تشغيل الخادم مع تحسين حواف النظام لحمل الضغط العالي"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(1000) # طابور استيعاب ضخم للمستخدمين المتزامنين
        print(f"⚡ HIGH-PERFORMANCE PEP NODE SERVER ONLINE [{self.host}:{self.port}]")
        print(f"🔥 Concurrency Worker Capacity: {self.max_workers} Concurrent Threads ThreadPool Enabled.\n")

        try:
            while True:
                client_sock, addr = server.accept()
                # توزيع الحمل فوراً على الـ ThreadPool لعدم تعطيل باقي المستخدمين
                self.executor.submit(self.process_incoming_connection, client_sock, addr)
        except KeyboardInterrupt:
            print("\n🛑 Gracefully Shutting Down High-Performance Node...")
            self.executor.shutdown(wait=False)
            server.close()

if __name__ == "__main__":
    node = HighPerformancePEPNode(port=9000)
    node.start_node()
