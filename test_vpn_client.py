import socket
import struct
import json
import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.database import SessionLocal
from app.models.client import Client
from app.crypto.kem import KEMManager

HOST = "127.0.0.1"
PORT = 5151
CLIENT_IDENTIFIER = "test-client-1"

def send_length_prefixed(sock, data: bytes):
    sock.sendall(struct.pack('>I', len(data)))
    sock.sendall(data)

def read_length_prefixed(sock) -> bytes:
    length_bytes = sock.recv(4)
    if not length_bytes:
        return b""
    length = struct.unpack('>I', length_bytes)[0]
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            break
        data += packet
    return data

def main():
    print("[CLIENT] Fetching test-client-1 public key from database...")
    db = SessionLocal()
    try:
        client = db.query(Client).filter(Client.client_identifier == CLIENT_IDENTIFIER).first()
        if not client:
            print("❌ Client test-client-1 not found in database. Run create_mock_data.py first.")
            return
        
        public_key = client.public_key
        kem_algorithm = client.kem_algorithm
        print(f"[CLIENT] Found client public key ({len(public_key)} bytes) for {kem_algorithm}")
        
    finally:
        db.close()

    print("[CLIENT] Encapsulating shared secret using ML-KEM-768...")
    encap = KEMManager.encapsulate(kem_algorithm, public_key)
    ciphertext = encap["ciphertext"]
    shared_secret = encap["shared_secret"]
    print(f"[CLIENT] Encapsulated ciphertext length: {len(ciphertext)} bytes")
    
    # Derive AES-256 key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"qvpn-tunnel-key",
    )
    aes_key = hkdf.derive(shared_secret)
    cipher = AESGCM(aes_key)
    print(f"[CLIENT] AES Key derived successfully ({len(aes_key)} bytes)")

    print(f"[CLIENT] Connecting to socket server at {HOST}:{PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[CLIENT] Connected!")

        # 1. Send client identifier
        print(f"[CLIENT] Sending client identifier: {CLIENT_IDENTIFIER}")
        send_length_prefixed(s, CLIENT_IDENTIFIER.encode("utf-8"))

        # 2. Send ciphertext
        print("[CLIENT] Sending KEM ciphertext...")
        send_length_prefixed(s, ciphertext)

        # 3. Read Session ID
        print("[CLIENT] Waiting for handshake confirmation...")
        session_id_bytes = read_length_prefixed(s)
        if not session_id_bytes:
            print("❌ Did not receive session_id. Handshake failed.")
            return
        session_id = session_id_bytes.decode("utf-8")
        print(f"[CLIENT] Handshake success! Session ID: {session_id}")

        # 4. Encrypt and send target destination: example.com on port 80
        target = {"host": "example.com", "port": 80}
        target_json = json.dumps(target).encode("utf-8")
        
        nonce = os.urandom(12)
        encrypted_target = nonce + cipher.encrypt(nonce, target_json, None)
        print(f"[CLIENT] Sending encrypted target destination details...")
        send_length_prefixed(s, encrypted_target)

        # 4.5. Send a couple of encrypted heartbeat pings to test the health monitor
        for i in range(2):
            print(f"[CLIENT] Sending encrypted heartbeat ping #{i+1}...")
            ping_nonce = os.urandom(12)
            encrypted_ping = ping_nonce + cipher.encrypt(ping_nonce, b"ping", None)
            send_length_prefixed(s, encrypted_ping)
            time.sleep(2)

        # 5. Encrypt and send mock HTTP request
        http_request = (
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: QVPN-Client-Simulator\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("utf-8")
        
        request_nonce = os.urandom(12)
        encrypted_request = request_nonce + cipher.encrypt(request_nonce, http_request, None)
        print("[CLIENT] Sending encrypted HTTP request...")
        send_length_prefixed(s, encrypted_request)

        # 6. Read encrypted response packets
        print("[CLIENT] Waiting for response...")
        while True:
            response_len_bytes = s.recv(4)
            if not response_len_bytes:
                print("[CLIENT] Connection closed by server.")
                break
            
            response_len = struct.unpack('>I', response_len_bytes)[0]
            encrypted_payload = s.recv(response_len)
            if not encrypted_payload:
                break
            
            # Decrypt packet
            nonce = encrypted_payload[:12]
            ciphertext = encrypted_payload[12:]
            try:
                decrypted_payload = cipher.decrypt(nonce, ciphertext, None)
                print("\n=== DECRYPTED RESPONSE PACKET ===")
                print(decrypted_payload.decode("utf-8", errors="replace"))
                print("=================================\n")
            except Exception as decrypt_err:
                print(f"❌ Failed to decrypt response packet: {decrypt_err}")

if __name__ == "__main__":
    main()
