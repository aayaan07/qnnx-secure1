import os
import asyncio
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.database import SessionLocal
from app.services.gateway_service import establish_session, HandshakeError

logger = logging.getLogger("qvpn.gateway")

HOST = "0.0.0.0"
PORT = 5151  # the raw VPN tunnel port -- separate from the FastAPI HTTP port


async def _read_length_prefixed(reader: asyncio.StreamReader) -> bytes:
    """
    Reads one length-prefixed field from the stream:
    first 4 bytes = big-endian length, then that many bytes of payload.
    """
    length_bytes = await reader.readexactly(4)
    length = int.from_bytes(length_bytes, byteorder="big")
    payload = await reader.readexactly(length)
    return payload


async def pipe_client_to_remote(client_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter, cipher: AESGCM, session_id: str):
    """Reads encrypted VPN traffic from the client, decrypts it, and forwards it to the internet."""
    accumulated_bytes = 0
    accumulated_packets = 0
    try:
        while True:
            # 1. Read the length prefix (4 bytes)
            length_bytes = await client_reader.readexactly(4)
            length = int.from_bytes(length_bytes, byteorder="big")
            
            # 2. Read the full encrypted payload
            encrypted_payload = await client_reader.readexactly(length)
            
            # 3. Extract the 12-byte nonce and the actual ciphertext
            nonce = encrypted_payload[:12]
            ciphertext = encrypted_payload[12:]
            
            # 4. Decrypt the raw traffic
            raw_traffic = cipher.decrypt(nonce, ciphertext, None)
            
            # Check for heartbeat ping control packet
            if raw_traffic == b"ping":
                logger.info(f"[GATEWAY] Received heartbeat (ping) for session {session_id}")
                await _record_heartbeat(session_id)
                continue
            
            # 5. Forward the decrypted traffic out to the internet
            remote_writer.write(raw_traffic)
            await remote_writer.drain()
            
            # Accumulate stats
            accumulated_bytes += len(raw_traffic)
            accumulated_packets += 1
            
            # Flush stats periodically to avoid DB traffic overload
            if accumulated_packets % 10 == 0:
                await _flush_traffic_stats(session_id, bytes_sent=accumulated_bytes, packets_sent=accumulated_packets)
                accumulated_bytes = 0
                accumulated_packets = 0
            
    except (asyncio.IncompleteReadError, ConnectionError):
        logger.info("[TUNNEL] Client disconnected upstream.")
    except Exception as e:
        logger.error(f"[TUNNEL] Upstream decryption error: {e}")
    finally:
        remote_writer.close()
        if accumulated_packets > 0 or accumulated_bytes > 0:
            try:
                await _flush_traffic_stats(session_id, bytes_sent=accumulated_bytes, packets_sent=accumulated_packets)
            except Exception:
                pass


async def pipe_remote_to_client(remote_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, cipher: AESGCM, session_id: str):
    """Reads raw internet traffic, encrypts it, and forwards it down the VPN tunnel."""
    accumulated_bytes = 0
    accumulated_packets = 0
    try:
        while True:
            # 1. Read raw response from the internet (up to 4KB at a time)
            raw_traffic = await remote_reader.read(4096)
            if not raw_traffic:
                break # Connection closed by remote server
                
            # 2. Generate a secure 12-byte nonce for this specific packet
            nonce = os.urandom(12)
            
            # 3. Encrypt the data
            ciphertext = cipher.encrypt(nonce, raw_traffic, None)
            
            # 4. Package it: Nonce + Ciphertext
            encrypted_payload = nonce + ciphertext
            
            # 5. Send length prefix, then the payload back to the client
            client_writer.write(len(encrypted_payload).to_bytes(4, byteorder="big"))
            client_writer.write(encrypted_payload)
            await client_writer.drain()
            
            # Accumulate stats
            accumulated_bytes += len(raw_traffic)
            accumulated_packets += 1
            
            # Flush stats periodically
            if accumulated_packets % 10 == 0:
                await _flush_traffic_stats(session_id, bytes_received=accumulated_bytes, packets_received=accumulated_packets)
                accumulated_bytes = 0
                accumulated_packets = 0
            
    except ConnectionError:
        logger.info("[TUNNEL] Remote server closed downstream.")
    except Exception as e:
        logger.error(f"[TUNNEL] Downstream encryption error: {e}")
    finally:
        client_writer.close()
        if accumulated_packets > 0 or accumulated_bytes > 0:
            try:
                await _flush_traffic_stats(session_id, bytes_received=accumulated_bytes, packets_received=accumulated_packets)
            except Exception:
                pass


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Called automatically by asyncio for each new raw TCP connection.
    Runs the ML-KEM handshake, derives the AES-256 key, and prepares the tunnel.
    """
    peer_addr = writer.get_extra_info("peername")
    logger.info(f"[GATEWAY] New connection from {peer_addr}")

    db = SessionLocal()
    try:
        # Step 1: read the client's identifier and ciphertext off the wire.
        client_identifier_bytes = await _read_length_prefixed(reader)
        kem_ciphertext = await _read_length_prefixed(reader)

        client_identifier = client_identifier_bytes.decode("utf-8")
        logger.info(f"[GATEWAY] Handshake attempt from client_identifier={client_identifier}")

        remote_ip, remote_port = peer_addr[0], peer_addr[1]

        # Step 2: hand off to the service layer for decapsulation
        handshake_data = await asyncio.to_thread(
            establish_session,
            db=db,
            client_identifier=client_identifier,
            kem_ciphertext=kem_ciphertext,
            remote_ip=remote_ip,
            remote_port=remote_port,
        )

        session_id = handshake_data["session_id"]
        shared_secret = handshake_data["shared_secret"]

        logger.info(f"[GATEWAY] Session established: {session_id}")
        logger.info(f"[GATEWAY] 🔐 Socket holds a {len(shared_secret)}-byte shared secret in memory!")

        # --- PHASE 2: INITIALIZE THE AES CIPHER ---
        # Derive a perfect 32-byte AES-256 key using HKDF to stretch the KEM secret safely
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"qvpn-tunnel-key",
        )
        aes_key = hkdf.derive(shared_secret)
        
        # Create the AES-GCM cipher object for this specific client connection
        cipher = AESGCM(aes_key)
        logger.info("[GATEWAY] 🛡️ AES-256-GCM cipher initialized and ready for traffic!")

        # Step 3: tell the client the handshake succeeded.
        session_id_bytes = session_id.encode("utf-8")
        writer.write(len(session_id_bytes).to_bytes(4, byteorder="big"))
        writer.write(session_id_bytes)
        await writer.drain()

        # --- PHASE 3: THE TRAFFIC FORWARDING LOOP ---
        logger.info("[GATEWAY] Waiting for client to send target destination...")
        
        # Read the encrypted target details (host & port)
        target_len_bytes = await reader.readexactly(4)
        target_len = int.from_bytes(target_len_bytes, byteorder="big")
        encrypted_target = await reader.readexactly(target_len)
        
        # Decrypt target details
        target_nonce = encrypted_target[:12]
        target_ciphertext = encrypted_target[12:]
        decrypted_target = cipher.decrypt(target_nonce, target_ciphertext, None).decode("utf-8")
        
        import json
        target_data = json.loads(decrypted_target)
        target_host = target_data["host"]
        target_port = target_data["port"]
        logger.info(f"[GATEWAY] 🌍 Connecting to target destination: {target_host}:{target_port}...")
        
        # Connect to target
        remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
        logger.info(f"[GATEWAY] ✅ Connected to {target_host}:{target_port}")
        
        # Pipe traffic bi-directionally
        client_to_remote = asyncio.create_task(
            pipe_client_to_remote(reader, remote_writer, cipher, session_id)
        )
        remote_to_client = asyncio.create_task(
            pipe_remote_to_client(remote_reader, writer, cipher, session_id)
        )
        
        await asyncio.gather(client_to_remote, remote_to_client)
        
    except HandshakeError as e:
        logger.error(f"[GATEWAY] Handshake failed: {e}")
        try:
            error_msg = f"Handshake failed: {e}".encode("utf-8")
            writer.write(len(error_msg).to_bytes(4, byteorder="big"))
            writer.write(error_msg)
            await writer.drain()
        except Exception:
            pass
    except Exception as e:
        logger.error(f"[GATEWAY] Exception in client session: {e}")
    finally:
        logger.info(f"[GATEWAY] Cleaning up connection for session: {session_id if 'session_id' in locals() else 'unknown'}")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
            
        if "remote_writer" in locals():
            remote_writer.close()
            try:
                await remote_writer.wait_closed()
            except Exception:
                pass
                
        if "session_id" in locals() and "db" in locals():
            try:
                from app.repositories.tunnel_state_repo import TunnelStateRepository
                ts_repo = TunnelStateRepository()
                ts = ts_repo.get_by_session_id(db, session_id)
                if ts:
                    ts_repo.update(db, ts.id, {"status": "DISCONNECTED"})
                    logger.info(f"[GATEWAY] Tunnel state marked DISCONNECTED for session {session_id}")
            except Exception as db_err:
                logger.error(f"[GATEWAY] Failed to update tunnel status on disconnect: {db_err}")
            finally:
                db.close()
        else:
            if "db" in locals():
                db.close()


async def _flush_traffic_stats(session_id: str, bytes_sent: int = 0, bytes_received: int = 0, packets_sent: int = 0, packets_received: int = 0):
    """Flushes traffic statistics to the database in a non-blocking thread pool task."""
    def db_update():
        db = SessionLocal()
        try:
            from app.repositories.traffic_stat_repo import TrafficStatRepository
            ts_repo = TrafficStatRepository()
            ts_repo.increment(
                db=db,
                session_id=session_id,
                bytes_sent=bytes_sent,
                bytes_received=bytes_received,
                packets_sent=packets_sent,
                packets_received=packets_received
            )
        except Exception as e:
            logger.error(f"[GATEWAY] Failed to increment traffic stats: {e}")
        finally:
            db.close()
    await asyncio.to_thread(db_update)


async def _record_heartbeat(session_id: str):
    """Updates the last heartbeat timestamp for a session in the database."""
    def db_update():
        db = SessionLocal()
        try:
            from app.repositories.tunnel_state_repo import TunnelStateRepository
            ts_repo = TunnelStateRepository()
            ts_repo.record_heartbeat(db, session_id)
        except Exception as e:
            logger.error(f"[GATEWAY] Failed to record heartbeat for session {session_id}: {e}")
        finally:
            db.close()
    await asyncio.to_thread(db_update)


async def monitor_tunnel_health():
    """Background task to periodically clean up timed-out tunnels."""
    while True:
        try:
            await asyncio.sleep(30)
            logger.info("[HEALTH_CHECK] Scanning for timed-out tunnels...")
            
            def db_cleanup():
                db = SessionLocal()
                try:
                    from app.repositories.tunnel_state_repo import TunnelStateRepository
                    from datetime import datetime, timezone, timedelta
                    ts_repo = TunnelStateRepository()
                    tunnels = ts_repo.get_all(db)
                    now = datetime.now(timezone.utc)
                    for ts in tunnels:
                        if ts.status == "ACTIVE" and ts.last_heartbeat:
                            # If last heartbeat is older than 60 seconds, mark as disconnected
                            if now - ts.last_heartbeat > timedelta(seconds=60):
                                ts_repo.update(db, ts.id, {"status": "DISCONNECTED"})
                                logger.info(f"[HEALTH_CHECK] Marked timed-out session {ts.session_id} as DISCONNECTED")
                except Exception as cleanup_err:
                    logger.error(f"[HEALTH_CHECK] Error during health cleanup: {cleanup_err}")
                finally:
                    db.close()
            
            await asyncio.to_thread(db_cleanup)
            
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"[HEALTH_CHECK] Health monitor encountered error: {e}")


async def start_gateway_server():
    """Starts the raw TCP socket VPN gateway listener and background health monitor."""
    server = await asyncio.start_server(handle_client, HOST, PORT)
    logger.info(f"[GATEWAY] Raw TCP VPN socket server started on {HOST}:{PORT}")
    
    # Start the background health monitor task
    asyncio.create_task(monitor_tunnel_health())
    
    return server