import asyncio
import os
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"qvpn-session-key-derivation",
    )
    return hkdf.derive(shared_secret)


def encrypt_packet(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_packet(key: bytes, data: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], None)


async def _do_handshake(reader, writer):
    """Run ML-KEM handshake and return the derived session key."""
    kem_alg = "ML-KEM-768"
    with oqs.KeyEncapsulation(kem_alg) as server_kem:
        public_key = server_kem.generate_keypair()
        print(f"[Gateway] Sending public key ({len(public_key)} bytes)...")
        writer.write(public_key)
        await writer.drain()

        ciphertext = await reader.readexactly(server_kem.details['length_ciphertext'])
        shared_secret = server_kem.decap_secret(ciphertext)

    session_key = derive_key(shared_secret)
    print("[Gateway] AES-256 session key derived. Tunnel UP.")
    return session_key


async def handle_client(reader, writer):
    print("\n[Gateway] New connection.")
    try:
        session_key = await _do_handshake(reader, writer)

        # Read the first encrypted message to decide what this connection is for
        data = await reader.read(4096)
        if not data:
            return

        first_msg = decrypt_packet(session_key, data).strip()

        if first_msg.startswith(b"CONNECT "):
            # ── Proxy tunnel mode ─────────────────────────────────────────
            dest = first_msg[8:].decode()
            host, port = dest.rsplit(":", 1)
            print(f"[Gateway] CONNECT → {host}:{port}")

            try:
                inet_reader, inet_writer = await asyncio.open_connection(host, int(port))
            except Exception as e:
                writer.write(encrypt_packet(session_key, b"ERR"))
                await writer.drain()
                print(f"[Gateway] Could not reach {dest}: {e}")
                return

            writer.write(encrypt_packet(session_key, b"OK"))
            await writer.drain()

            async def client_to_inet():
                try:
                    while True:
                        raw = await reader.read(4096)
                        if not raw:
                            break
                        inet_writer.write(decrypt_packet(session_key, raw))
                        await inet_writer.drain()
                except Exception:
                    pass
                finally:
                    inet_writer.close()

            async def inet_to_client():
                try:
                    while True:
                        raw = await inet_reader.read(4096)
                        if not raw:
                            break
                        writer.write(encrypt_packet(session_key, raw))
                        await writer.drain()
                except Exception:
                    pass
                finally:
                    writer.close()

            await asyncio.gather(client_to_inet(), inet_to_client())

        else:
            # ── Heartbeat / control mode ──────────────────────────────────
            print("[Gateway] Control tunnel established.")
            if first_msg == b"PING":
                writer.write(encrypt_packet(session_key, b"PONG"))
                await writer.drain()

            while True:
                data = await reader.read(4096)
                if not data:
                    break
                try:
                    msg = decrypt_packet(session_key, data)
                    if msg == b"PING":
                        print("[Gateway] PING → PONG")
                        writer.write(encrypt_packet(session_key, b"PONG"))
                        await writer.drain()
                except Exception:
                    pass

    except Exception as e:
        print(f"[Gateway] Error: {e}")
    finally:
        print("[Gateway] Connection closed.")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle_client, '127.0.0.1', 8443)
    addr = server.sockets[0].getsockname()
    print(f"[*] Mock QVPN Gateway listening on {addr[0]}:{addr[1]}")
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
