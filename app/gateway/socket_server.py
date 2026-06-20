"""
socket_server.py — Raw TCP VPN tunnel gateway.

This module runs a persistent TCP socket server on VPN_PORT (default 5151).
Each connection follows this protocol:

  Wire protocol — Handshake phase:
    CLIENT → GATEWAY:  [4-byte length][client_identifier UTF-8 bytes]
    CLIENT → GATEWAY:  [4-byte length][kem_ciphertext bytes]
    GATEWAY → CLIENT:  [4-byte length][session_id UTF-8 bytes]

  Wire protocol — Traffic phase:
    CLIENT → GATEWAY:  [4-byte length][nonce(12) + encrypted(target_json)]
    CLIENT → GATEWAY:  [4-byte length][nonce(12) + encrypted(raw_traffic)]  (repeated)
    GATEWAY → CLIENT:  [4-byte length][nonce(12) + encrypted(raw_traffic)]  (repeated)

  Heartbeat (client → gateway):
    CLIENT → GATEWAY:  [4-byte length][nonce(12) + encrypted(b"ping")]

AES key lifecycle:
  - Derived from KEM shared_secret via HKDF in complete_handshake().
  - Stored only in session_store (in-memory TTL cache).
  - NEVER written to any database or log file.
  - Evicted from session_store on disconnect, timeout, or server shutdown.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.exceptions import HandshakeError, AEADError
from app.gateway.session_store import session_store
from app.services.handshake_service import complete_handshake
from app.services.session_service import close_session, expire_stale_sessions

logger = logging.getLogger("qvpn.gateway")

HOST = "0.0.0.0"
VPN_PORT = 5151  # Raw TCP VPN tunnel port — separate from the FastAPI HTTP port


# ---------------------------------------------------------------------------
# Wire protocol helpers
# ---------------------------------------------------------------------------


async def _read_framed(reader: asyncio.StreamReader) -> bytes:
    """Read one length-prefixed frame: 4-byte big-endian length + payload."""
    length_bytes = await reader.readexactly(4)
    length = int.from_bytes(length_bytes, byteorder="big")
    return await reader.readexactly(length)


def _write_framed(writer: asyncio.StreamWriter, data: bytes) -> None:
    """Write one length-prefixed frame."""
    writer.write(len(data).to_bytes(4, byteorder="big"))
    writer.write(data)


# ---------------------------------------------------------------------------
# Traffic forwarding — client → remote (decrypt then forward)
# ---------------------------------------------------------------------------


async def _pipe_client_to_remote(
    client_reader: asyncio.StreamReader,
    remote_writer: asyncio.StreamWriter,
    cipher: AESGCM,
    session_id: str,
) -> None:
    """Decrypt client-side encrypted traffic and forward it to the remote server."""
    accumulated_bytes = 0
    accumulated_packets = 0

    try:
        while True:
            # Read length-framed encrypted payload
            length_bytes = await client_reader.readexactly(4)
            length = int.from_bytes(length_bytes, byteorder="big")
            encrypted_payload = await client_reader.readexactly(length)

            # AES-GCM decrypt: nonce is first 12 bytes
            nonce = encrypted_payload[:12]
            ciphertext = encrypted_payload[12:]
            raw_traffic = cipher.decrypt(nonce, ciphertext, None)

            # Heartbeat control packet
            if raw_traffic == b"ping":
                logger.debug("[TUNNEL] Heartbeat (ping) for session=%s", session_id)
                await _record_heartbeat(session_id)
                continue

            # Forward decrypted traffic upstream
            remote_writer.write(raw_traffic)
            await remote_writer.drain()

            # Batch stats
            accumulated_bytes += len(raw_traffic)
            accumulated_packets += 1
            if accumulated_packets % 10 == 0:
                await _flush_stats(session_id, bytes_sent=accumulated_bytes, packets_sent=accumulated_packets)
                accumulated_bytes = accumulated_packets = 0

    except (asyncio.IncompleteReadError, ConnectionError):
        logger.info("[TUNNEL] Client disconnected upstream (session=%s)", session_id)
    except Exception as exc:
        logger.error("[TUNNEL] Upstream error for session=%s: %s", session_id, exc)
    finally:
        remote_writer.close()
        if accumulated_packets > 0 or accumulated_bytes > 0:
            try:
                await _flush_stats(session_id, bytes_sent=accumulated_bytes, packets_sent=accumulated_packets)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Traffic forwarding — remote → client (encrypt then forward)
# ---------------------------------------------------------------------------


async def _pipe_remote_to_client(
    remote_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    cipher: AESGCM,
    session_id: str,
) -> None:
    """Read raw internet traffic, encrypt it, and forward it to the VPN client."""
    accumulated_bytes = 0
    accumulated_packets = 0

    try:
        while True:
            raw_traffic = await remote_reader.read(4096)
            if not raw_traffic:
                break  # Remote closed connection

            nonce = os.urandom(12)
            ciphertext = cipher.encrypt(nonce, raw_traffic, None)
            encrypted_payload = nonce + ciphertext

            _write_framed(client_writer, encrypted_payload)
            await client_writer.drain()

            accumulated_bytes += len(raw_traffic)
            accumulated_packets += 1
            if accumulated_packets % 10 == 0:
                await _flush_stats(session_id, bytes_received=accumulated_bytes, packets_received=accumulated_packets)
                accumulated_bytes = accumulated_packets = 0

    except ConnectionError:
        logger.info("[TUNNEL] Remote disconnected downstream (session=%s)", session_id)
    except Exception as exc:
        logger.error("[TUNNEL] Downstream error for session=%s: %s", session_id, exc)
    finally:
        client_writer.close()
        if accumulated_packets > 0 or accumulated_bytes > 0:
            try:
                await _flush_stats(session_id, bytes_received=accumulated_bytes, packets_received=accumulated_packets)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Main connection handler
# ---------------------------------------------------------------------------


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Handle one incoming VPN client TCP connection.

    Runs the KEM handshake, reads the target destination (host:port),
    opens a connection to that target, and bi-directionally pipes
    encrypted traffic between the client and the remote server.
    """
    peer_addr = writer.get_extra_info("peername")
    logger.info("[GATEWAY] New connection from %s", peer_addr)

    remote_ip = peer_addr[0] if peer_addr else "unknown"
    remote_port = peer_addr[1] if peer_addr else 0

    session_id: str | None = None
    remote_writer: asyncio.StreamWriter | None = None
    db = None

    try:
        # --- HANDSHAKE ---
        # Read client_identifier and ciphertext off the wire
        client_identifier_bytes = await _read_framed(reader)
        kem_ciphertext = await _read_framed(reader)
        client_identifier = client_identifier_bytes.decode("utf-8")

        logger.info("[GATEWAY] Handshake from client_identifier=%s", client_identifier)

        # complete_handshake is async; pass the session_id from the client
        # In the socket protocol the client sends session_id as the identifier
        # so the gateway can correlate with the REST /handshake/init call.
        # Here session_id == client_identifier (the socket client sends the
        # session_id it received from /handshake/init as its "identifier").
        db = SessionLocal()

        handshake_data = await complete_handshake(
            db=db,
            session_id=client_identifier,  # client sends session_id as identifier
            kem_ciphertext=kem_ciphertext,
            remote_ip=remote_ip,
            remote_port=remote_port,
        )

        session_id = handshake_data["session_id"]
        aes_key: bytes = handshake_data["aes_key"]  # in memory only

        logger.info("[GATEWAY] Session established: %s (AES key = %d bytes)", session_id, len(aes_key))

        # Build the cipher once for the session lifetime
        cipher = AESGCM(aes_key)

        # Tell the client the handshake succeeded
        _write_framed(writer, session_id.encode("utf-8"))
        await writer.drain()

        # --- TRAFFIC PHASE ---
        # Read encrypted target destination (host + port)
        encrypted_target = await _read_framed(reader)
        target_nonce = encrypted_target[:12]
        target_ciphertext = encrypted_target[12:]
        target_json = cipher.decrypt(target_nonce, target_ciphertext, None).decode("utf-8")
        target_data = json.loads(target_json)
        target_host = target_data["host"]
        target_port = int(target_data["port"])

        logger.info("[GATEWAY] Connecting to target %s:%d for session=%s", target_host, target_port, session_id)

        remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
        logger.info("[GATEWAY] Connected to %s:%d", target_host, target_port)

        # Bi-directional traffic forwarding
        upstream = asyncio.create_task(_pipe_client_to_remote(reader, remote_writer, cipher, session_id))
        downstream = asyncio.create_task(_pipe_remote_to_client(remote_reader, writer, cipher, session_id))

        await asyncio.gather(upstream, downstream)

    except HandshakeError as exc:
        logger.error("[GATEWAY] Handshake failed: %s", exc)
        try:
            _write_framed(writer, f"HANDSHAKE_FAILED: {exc}".encode("utf-8"))
            await writer.drain()
        except Exception:
            pass

    except AEADError as exc:
        logger.error("[GATEWAY] AEAD error for session=%s: %s", session_id, exc)

    except Exception as exc:
        logger.error("[GATEWAY] Unhandled exception for session=%s: %s", session_id, exc, exc_info=True)

    finally:
        # Always close writer
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        if remote_writer:
            try:
                remote_writer.close()
                await remote_writer.wait_closed()
            except Exception:
                pass

        # Update session status in DB
        if session_id and db:
            try:
                def _close_db():
                    close_session(db, session_id, reason="CLIENT_DISCONNECT")
                await asyncio.to_thread(_close_db)
            except Exception as exc:
                logger.error("[GATEWAY] Failed to close session %s in DB: %s", session_id, exc)

        if db:
            db.close()


# ---------------------------------------------------------------------------
# DB helpers (run in thread pool — sync SQLAlchemy)
# ---------------------------------------------------------------------------


async def _flush_stats(
    session_id: str,
    bytes_sent: int = 0,
    bytes_received: int = 0,
    packets_sent: int = 0,
    packets_received: int = 0,
) -> None:
    def _db_work():
        db = SessionLocal()
        try:
            from app.services.stats_service import increment_stats
            increment_stats(
                db=db,
                session_id=session_id,
                bytes_sent=bytes_sent,
                bytes_received=bytes_received,
                packets_sent=packets_sent,
                packets_received=packets_received,
            )
        except Exception as exc:
            logger.error("[GATEWAY] Failed to flush stats for session=%s: %s", session_id, exc)
        finally:
            db.close()

    await asyncio.to_thread(_db_work)


async def _record_heartbeat(session_id: str) -> None:
    def _db_work():
        db = SessionLocal()
        try:
            from app.repositories.tunnel_state_repo import TunnelStateRepository
            ts_repo = TunnelStateRepository()
            ts_repo.record_heartbeat(db, session_id)
        except Exception as exc:
            logger.error("[GATEWAY] Failed to record heartbeat for session=%s: %s", session_id, exc)
        finally:
            db.close()

    await asyncio.to_thread(_db_work)


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------


async def start_gateway_server():
    """
    Start the raw TCP VPN socket server and the background session expiry task.

    Returns the asyncio.Server object so the caller can manage its lifecycle.
    """
    server = await asyncio.start_server(handle_client, HOST, VPN_PORT)
    logger.info("[GATEWAY] TCP VPN server listening on %s:%d", HOST, VPN_PORT)

    # Start background session expiry
    asyncio.create_task(expire_stale_sessions())
    logger.info("[GATEWAY] Session expiry monitor started (interval=%ds)", settings.HEARTBEAT_TIMEOUT_SECONDS)

    return server