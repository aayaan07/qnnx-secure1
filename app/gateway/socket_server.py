"""
socket_server.py — Raw TCP VPN tunnel gateway.

This module runs a persistent TCP socket server on VPN_PORT (default 5151).
Each connection follows this protocol:

  Wire protocol — Session resumption:
    CLIENT → GATEWAY:  [4-byte length][session_id UTF-8 bytes]
    GATEWAY → CLIENT:  [4-byte length][session_id UTF-8 bytes]

  Wire protocol — Traffic phase:
    CLIENT → GATEWAY:  [4-byte length][nonce(12) + encrypted(target_json)]
    CLIENT → GATEWAY:  [4-byte length][nonce(12) + encrypted(raw_traffic)]  (repeated)
    GATEWAY → CLIENT:  [4-byte length][nonce(12) + encrypted(raw_traffic)]  (repeated)

  Heartbeat (client → gateway):
    CLIENT → GATEWAY:  [4-byte length][nonce(12) + encrypted(b"ping")]

AES key lifecycle:
  Normal mode:
    - Derived from KEM shared_secret via HKDF in complete_handshake().
    - Stored only in session_store (in-memory TTL cache).
    - NEVER written to any database or log file.
    - Evicted from session_store on disconnect, timeout, or server shutdown.
  Debug mode (DEBUG_MODE_PQC=true):
    - MASTER_KEY bytes are used directly as the AES-256 key.
    - session_store and database session validation are bypassed entirely.
    - Only for local testing — never use in production.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.exceptions import HandshakeError, AEADError, SessionNotEstablished
from app.gateway.session_store import session_store
from app.repositories.session_repo import SessionRepository
from app.services.handshake_service import complete_handshake
from app.services.session_service import close_session, expire_stale_sessions, is_session_resumable

logger = logging.getLogger("qvpn.gateway")

_session_repo = SessionRepository()

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


async def _safe_close(writer: asyncio.StreamWriter, label: str) -> None:
    """Close a StreamWriter and wait for it to drain — never raises."""
    try:
        writer.close()
        await writer.wait_closed()
    except Exception as exc:
        logger.debug("[GATEWAY] Close failed (%s): %s", label, exc)


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
            # Read length-framed payload
            length_bytes = await client_reader.readexactly(4)
            length = int.from_bytes(length_bytes, byteorder="big")
            encrypted_payload = await client_reader.readexactly(length)

            if settings.DEBUG_AES:
                raw_traffic = encrypted_payload
            else:
                # AES-GCM decrypt: nonce is first 12 bytes
                nonce = encrypted_payload[:12]
                ciphertext = encrypted_payload[12:]
                try:
                    raw_traffic = cipher.decrypt(nonce, ciphertext, None)
                except InvalidTag:
                    logger.error(
                        "[TUNNEL] AES-GCM auth failure (upstream session=%s) — "
                        "dropping connection (possible key mismatch or replay attack).",
                        session_id,
                    )
                    break

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

    except asyncio.CancelledError:
        logger.debug("[TUNNEL] Upstream pipe cancelled (session=%s)", session_id)
        raise  # allow gather/task cancellation to propagate
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        logger.info("[TUNNEL] Client disconnected upstream (session=%s)", session_id)
    except Exception as exc:
        logger.error("[TUNNEL] Upstream error for session=%s: %s", session_id, exc)
    finally:
        await _safe_close(remote_writer, f"remote_writer[{session_id}]")
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
            raw_traffic = await remote_reader.read(65536)
            if not raw_traffic:
                break  # Remote closed connection

            if settings.DEBUG_AES:
                encrypted_payload = raw_traffic
            else:
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

    except asyncio.CancelledError:
        logger.debug("[TUNNEL] Downstream pipe cancelled (session=%s)", session_id)
        raise  # allow gather/task cancellation to propagate
    except (ConnectionError, OSError):
        logger.info("[TUNNEL] Remote disconnected downstream (session=%s)", session_id)
    except Exception as exc:
        logger.error("[TUNNEL] Downstream error for session=%s: %s", session_id, exc)
    finally:
        await _safe_close(client_writer, f"client_writer[{session_id}]")
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

    Session resumption flow:
      1. Read session_id from wire.
      2a. [Normal] Verify session in session_store + DB; reject if not established.
      2b. [Debug]  Skip store/DB; use MASTER_KEY directly.
      3. Echo session_id back to signal readiness.
      4. Read encrypted target destination.
      5. Open TCP connection to target.
      6. Bi-directionally pipe encrypted traffic.

    All cleanup (close writers, cancel pipe tasks, close DB session) executes
    in the finally block regardless of which exception fires. Each cleanup step
    is individually guarded so a failure in one does not skip the rest.
    """
    peer_addr = writer.get_extra_info("peername")
    logger.info("[GATEWAY] New connection from %s", peer_addr)

    remote_ip = peer_addr[0] if peer_addr else "unknown"
    remote_port = peer_addr[1] if peer_addr else 0

    session_id: str | None = None
    remote_writer: asyncio.StreamWriter | None = None
    upstream: asyncio.Task | None = None
    downstream: asyncio.Task | None = None
    db = None

    try:
        # ── SESSION RESUMPTION ────────────────────────────────────────────────

        session_id_bytes = await _read_framed(reader)
        session_id = session_id_bytes.decode("utf-8")
        logger.info("[GATEWAY] Session resumption request: session_id=%s from %s", session_id, peer_addr)

        if settings.DEBUG_MODE_PQC:
            # ── DEBUG MODE ────────────────────────────────────────────────────
            # Skip session_store and DB entirely. Use MASTER_KEY as the AES key.
            # Accept any session_id without validation.
            aes_key = settings.master_key_bytes
            logger.warning(
                "[GATEWAY][DEBUG] PQC debug mode: accepting session=%s without store/DB validation.",
                session_id,
            )
            # Echo session_id back so the client proceeds to the traffic phase
            _write_framed(writer, session_id.encode("utf-8"))
            await writer.drain()

        else:
            # ── NORMAL MODE ───────────────────────────────────────────────────
            # Look up the session AES key in the in-memory store
            aes_key = session_store.get(session_id)

            # Query database to verify session exists and is in established state
            db = SessionLocal()
            try:
                session_uuid = uuid.UUID(session_id)
            except ValueError:
                raise SessionNotEstablished(f"Invalid session UUID format: '{session_id}'")

            session = await asyncio.to_thread(lambda: _session_repo.get_by_id(db, session_uuid))

            if not aes_key or not session or not is_session_resumable(session):
                logger.warning(
                    "[GATEWAY] Session resumption rejected: session=%s "
                    "(key_found=%s, session_found=%s)",
                    session_id,
                    bool(aes_key),
                    bool(session),
                )
                try:
                    _write_framed(writer, b"SESSION_NOT_ESTABLISHED")
                    await writer.drain()
                except Exception:
                    pass
                raise SessionNotEstablished(f"Session '{session_id}' is not in an established/active state")

            logger.info(
                "[GATEWAY] Session established: session_id=%s (AES key=%d bytes)",
                session_id,
                len(aes_key),
            )

            # Echo session_id to signal the client the session is ready
            _write_framed(writer, session_id.encode("utf-8"))
            await writer.drain()

        # ── TRAFFIC PHASE ─────────────────────────────────────────────────────

        # Build the cipher once for this connection's lifetime
        cipher = AESGCM(aes_key)

        # Read target destination (host + port)
        encrypted_target = await _read_framed(reader)
        if settings.DEBUG_AES:
            target_json = encrypted_target.decode("utf-8")
        else:
            target_nonce = encrypted_target[:12]
            target_ciphertext = encrypted_target[12:]
            try:
                target_json = cipher.decrypt(target_nonce, target_ciphertext, None).decode("utf-8")
            except InvalidTag:
                raise AEADError(
                    f"AES-GCM auth failure decrypting target for session={session_id}. "
                    "Key mismatch between client and gateway?"
                )

        target_data = json.loads(target_json)
        target_host = target_data["host"]
        target_port = int(target_data["port"])

        logger.info(
            "[GATEWAY] Connecting to target %s:%d for session=%s",
            target_host, target_port, session_id,
        )

        remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
        logger.info("[GATEWAY] Connected to %s:%d (session=%s)", target_host, target_port, session_id)

        # Bi-directional traffic forwarding — both pipes run concurrently.
        # Tasks are tracked so we can cancel them if the handler exits unexpectedly.
        upstream = asyncio.create_task(
            _pipe_client_to_remote(reader, remote_writer, cipher, session_id),
            name=f"upstream-{session_id}",
        )
        downstream = asyncio.create_task(
            _pipe_remote_to_client(remote_reader, writer, cipher, session_id),
            name=f"downstream-{session_id}",
        )

        logger.info("[GATEWAY] Bidirectional pipe active: session=%s → %s:%d", session_id, target_host, target_port)
        await asyncio.gather(upstream, downstream)
        logger.info("[GATEWAY] Bidirectional pipe closed: session=%s", session_id)

    # ── Exception handlers ────────────────────────────────────────────────────

    except asyncio.CancelledError:
        logger.info("[GATEWAY] Handler cancelled: session=%s", session_id)
        raise  # propagate so the server can shut down cleanly

    except SessionNotEstablished as exc:
        logger.warning("[GATEWAY] Session resumption failed: %s", exc)

    except HandshakeError as exc:
        logger.error("[GATEWAY] Handshake failed (session=%s): %s", session_id, exc)
        try:
            _write_framed(writer, f"HANDSHAKE_FAILED: {exc}".encode("utf-8"))
            await writer.drain()
        except Exception:
            pass

    except AEADError as exc:
        logger.error("[GATEWAY] AEAD error (session=%s): %s", session_id, exc)

    except (ConnectionResetError, ConnectionError, OSError) as exc:
        # Normal disconnects: browser/client closed the connection, or the
        # remote site dropped it. This happens constantly during real
        # browsing — log quietly, not as an error.
        logger.info("[GATEWAY] Connection closed (session=%s): %s", session_id, exc)

    except Exception as exc:
        logger.error(
            "[GATEWAY] Unhandled exception (session=%s): %s",
            session_id, exc, exc_info=True,
        )

    # ── Cleanup — always runs, each step independently guarded ────────────────

    finally:
        logger.debug("[GATEWAY] Cleanup started: session=%s", session_id)

        # Cancel any still-running pipe tasks first
        for task, name in ((upstream, "upstream"), (downstream, "downstream")):
            if task and not task.done():
                try:
                    task.cancel()
                    await asyncio.wait([task], timeout=2.0)
                except Exception as exc:
                    logger.debug("[GATEWAY] Could not cancel %s task (session=%s): %s", name, session_id, exc)

        # Close the client writer
        await _safe_close(writer, f"client_writer[{session_id}]")

        # Close the remote writer (if the connection to the target was opened)
        if remote_writer:
            await _safe_close(remote_writer, f"remote_writer[{session_id}]")

        # Close the database session
        if db:
            try:
                db.close()
            except Exception as exc:
                logger.debug("[GATEWAY] DB close failed (session=%s): %s", session_id, exc)

        logger.debug("[GATEWAY] Cleanup complete: session=%s", session_id)


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

    if settings.DEBUG_MODE_PQC:
        logger.warning("[GATEWAY] DEBUG MODE: session_store and DB validation are DISABLED.")
        logger.warning("[GATEWAY] DEBUG MODE: MASTER_KEY (%d bytes) in use.", len(settings.master_key_bytes))

    # Start background session expiry
    asyncio.create_task(expire_stale_sessions())
    logger.info("[GATEWAY] Session expiry monitor started (interval=%ds)", settings.HEARTBEAT_TIMEOUT_SECONDS)

    return server