import asyncio
import oqs

async def handle_client(reader, writer):
    print("\n[Gateway] Client connection established.")
    kem_alg = "ML-KEM-768"

    try:
        # 1. Generate Server Keypair
        with oqs.KeyEncapsulation(kem_alg) as server_kem:
            public_key = server_kem.generate_keypair()
            
            # 2. Send Public Key to Client
            print(f"[Gateway] Sending ML-KEM-768 public key ({len(public_key)} bytes)...")
            writer.write(public_key)
            await writer.drain()

            # 3. Receive Ciphertext from Client
            ciphertext = await reader.readexactly(server_kem.details['length_ciphertext'])
            print(f"[Gateway] Received ciphertext ({len(ciphertext)} bytes). Decapsulating...")
            
            # 4. Decapsulate to get the shared secret
            shared_secret = server_kem.decap_secret(ciphertext)
            print("[Gateway] Shared secret established successfully! Tunnel is UP.")

        # 5. Handle the Heartbeat loop
        while True:
            data = await reader.read(1024)
            if not data:
                break
            if data == b"PING":
                print("[Gateway] Received PING. Sending PONG...")
                writer.write(b"PONG")
                await writer.drain()

    except Exception as e:
        print(f"[Gateway] Connection error: {e}")
    finally:
        print("[Gateway] Client disconnected.")
        writer.close()
        await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle_client, '127.0.0.1', 8443)
    addr = server.sockets[0].getsockname()
    print(f"[*] Mock QVPN Gateway listening on {addr[0]}:{addr[1]}")
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())