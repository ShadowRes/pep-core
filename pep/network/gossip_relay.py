import socket
import threading
import sys
import os
import time

sys.path.append(os.path.abspath("pep/implementation_a"))
from pep_core import PEPCore

class PEPGossipNode:
    def __init__(self, port: int, peers: list = None):
        self.host = "127.0.0.1"
        self.port = port
        self.peers = peers or []
        self.seen_transactions = set()
        self.mempool = []

    def broadcast_to_peers(self, payload: bytes):
        """إعادة بث المعاملة فوراً إلى باقي العقد المجاورة"""
        for peer_port in self.peers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                sock.connect((self.host, peer_port))
                sock.sendall(payload)
                sock.close()
            except Exception:
                pass

    def handle_peer(self, client_sock):
        try:
            data = client_sock.recv(256)
            if not data or len(data) != 132:
                client_sock.sendall(b"REJECT")
                return

            tx_hash = hash(data)
            # إذا كانت المعاملة قد وصلت مسبقاً عبر Gossip
            if tx_hash in self.seen_transactions:
                client_sock.sendall(b"ALREADY_SEEN")
                return

            self.seen_transactions.add(tx_hash)
            self.mempool.append(data)
            client_sock.sendall(b"ACCEPTED_AND_RELAYED")

            # بث عالي السرعة للعقد المجاورة
            threading.Thread(target=self.broadcast_to_peers, args=(data,)).start()

        except Exception:
            pass
        finally:
            client_sock.close()

    def start_listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(50)

        try:
            while True:
                sock, _ = server.accept()
                threading.Thread(target=self.handle_peer, args=(sock,)).start()
        except Exception:
            pass
        finally:
            server.close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    peer_port = 9001 if port == 9000 else 9000
    node = PEPGossipNode(port=port, peers=[peer_port])
    node.start_listen()
