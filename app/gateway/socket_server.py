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

Session resumption (data-plane hot path — normal mode):
  session_store is the sole source of truth for whether a session may resume
  a tunnel connection. The DB is NOT consulted per-connection. A key present
  in session_store implies the session was validly established (complete_handshake
  placed it there) and has not yet been deactivated (close_session /
  expire_stale_sessions / TTL evict it). A periodic reconciliation task
  cross-checks memory state against the DB and logs any drift it finds.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.exceptions import HandshakeError, AEADError, SessionNotEstablished
from app.gateway.session_store import session_store
from app.repositories.session_repo import SessionRepository
from app.services.handshake_service import complete_handshake
from app.services.session_service import close_session, expire_stale_sessions
from app.core.logger import get_logger

logger = get_logger(
    "gateway",
    "logs/gateway.log"
)

# Reconciliation uses the session repo to cross-check DB state against memory.
# It is NOT used on the per-connection hot path.
_session_repo = SessionRepository()

HOST = "0.0.0.0"
VPN_PORT = 5151  # Raw TCP VPN tunnel port — separate from the FastAPI HTTP port

_active_tasks = set()
_expiry_task = None


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

            # AES-GCM decrypt: nonce is first 12 bytes
            nonce = encrypted_payload[:12]
            ciphertext = encrypted_payload[12:]
            try:
                raw_traffic = cipher.decrypt(nonce, ciphertext, None)
            except InvalidTag:
                logger.error(
                    "[CRYPTO_FAIL] AES_GCM_AUTH_FAILED | session=%s | reason=key_mismatch_or_replay",
                    session_id,
                )
                break

            # Heartbeat control packet — fire-and-forget DB write, don't stall pipe
            if raw_traffic == b"ping":
                logger.debug("[HEARTBEAT] PING_RECEIVED | session=%s", session_id)
                asyncio.create_task(_record_heartbeat(session_id))
                continue

            # Forward decrypted traffic upstream
            remote_writer.write(raw_traffic)
            if remote_writer.transport.get_write_buffer_size() > 262144:
                await remote_writer.drain()

            # Batch stats — fire-and-forget every 100 packets, never stall the pipe
            accumulated_bytes += len(raw_traffic)
            accumulated_packets += 1
            if accumulated_packets % 100 == 0:
                asyncio.create_task(_flush_stats(
                    session_id,
                    bytes_sent=accumulated_bytes,
                    packets_sent=accumulated_packets,
                ))
                accumulated_bytes = accumulated_packets = 0

    except asyncio.CancelledError:
        logger.debug("[TUNNEL] Upstream pipe cancelled (session=%s)", session_id)
        raise
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        logger.info("[LIFECYCLE] CLIENT_DISCONNECT | session=%s", session_id)
    except Exception as exc:
        logger.error("[TUNNEL] Upstream error for session=%s: %s", session_id, exc)
    finally:
        await _safe_close(remote_writer, f"remote_writer[{session_id}]")
        if accumulated_packets > 0 or accumulated_bytes > 0:
            try:
                asyncio.create_task(_flush_stats(
                    session_id,
                    bytes_sent=accumulated_bytes,
                    packets_sent=accumulated_packets,
                ))
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

    # Pre-generate a pool of nonces to avoid a syscall on every single packet.
    # Refilled when empty. os.urandom is the bottleneck on high-packet paths.
    _NONCE_POOL_SIZE = 64
    nonce_pool: list[bytes] = []

    def _refill_nonces() -> None:
        blob = os.urandom(12 * _NONCE_POOL_SIZE)
        nonce_pool.extend(blob[i * 12:(i + 1) * 12] for i in range(_NONCE_POOL_SIZE))

    _refill_nonces()

    try:
        while True:
            raw_traffic = await remote_reader.read(131072)
            if not raw_traffic:
                break  # Remote closed connection

            if not nonce_pool:
                _refill_nonces()
            nonce = nonce_pool.pop()

            ciphertext = cipher.encrypt(nonce, raw_traffic, None)
            encrypted_payload = nonce + ciphertext

            _write_framed(client_writer, encrypted_payload)
            if client_writer.transport.get_write_buffer_size() > 262144:
                await client_writer.drain()

            accumulated_bytes += len(raw_traffic)
            accumulated_packets += 1
            if accumulated_packets % 100 == 0:
                asyncio.create_task(_flush_stats(
                    session_id,
                    bytes_received=accumulated_bytes,
                    packets_received=accumulated_packets,
                ))
                accumulated_bytes = accumulated_packets = 0

    except asyncio.CancelledError:
        logger.debug("[TUNNEL] Downstream pipe cancelled (session=%s)", session_id)
        raise
    except (ConnectionError, OSError):
        logger.info("[LIFECYCLE] REMOTE_DISCONNECT | session=%s", session_id)
    except Exception as exc:
        logger.error("[TUNNEL] Downstream error for session=%s: %s", session_id, exc)
    finally:
        await _safe_close(client_writer, f"client_writer[{session_id}]")
        if accumulated_packets > 0 or accumulated_bytes > 0:
            try:
                asyncio.create_task(_flush_stats(
                    session_id,
                    bytes_received=accumulated_bytes,
                    packets_received=accumulated_packets,
                ))
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
      2a. [Normal] Validate UUID format (cheap, local). Look up AES key in
          session_store (in-memory, zero network I/O). Reject if missing.
      2b. [Debug]  Skip store entirely; use MASTER_KEY directly.
      3. Echo session_id back to signal readiness.
      4. Read encrypted target destination.
      5. Open TCP connection to target.
      6. Bi-directionally pipe encrypted traffic.

    The DB is NOT consulted per-connection in normal mode. session_store is the
    sole gatekeeper — see module docstring for the invariant that makes this safe.

    All cleanup (close writers, cancel pipe tasks) executes in the finally block
    regardless of which exception fires. Each cleanup step is individually guarded
    so a failure in one does not skip the rest.
    """
    peer_addr = writer.get_extra_info("peername")
    logger.info("[LIFECYCLE] CONNECTION_NEW | peer=%s", peer_addr)

    remote_ip = peer_addr[0] if peer_addr else "unknown"
    remote_port = peer_addr[1] if peer_addr else 0

    session_id: str | None = None
    remote_writer: asyncio.StreamWriter | None = None
    upstream: asyncio.Task | None = None
    downstream: asyncio.Task | None = None

    current_task = asyncio.current_task()
    _active_tasks.add(current_task)

    try:
        # ── SESSION RESUMPTION ────────────────────────────────────────────────

        session_id_bytes = await _read_framed(reader)
        session_id = session_id_bytes.decode("utf-8")
        logger.info("[LIFECYCLE] SESSION_RESUME | session_id=%s | peer=%s", session_id, peer_addr)

        # Step 1: Validate UUID format — cheap local check, no network I/O.
        try:
            uuid.UUID(session_id)
        except ValueError:
            logger.warning(
                "[GATEWAY] Session resumption rejected: malformed UUID session_id=%r from %s",
                session_id,
                peer_addr,
            )
            try:
                _write_framed(writer, b"SESSION_NOT_ESTABLISHED")
                await writer.drain()
            except Exception:
                pass
            raise SessionNotEstablished(f"Invalid session_id format: {session_id!r}")

        # Step 2: session_store is the sole gatekeeper for hot-path resumption.
        # Keys are placed here only by complete_handshake() (post-ESTABLISHED)
        # and are evicted by close_session(), expire_stale_sessions(), or TTL.
        # No DB round-trip needed — see module docstring for the full invariant.
        aes_key = session_store.get(session_id)

        if not aes_key:
            logger.warning(
                "[GATEWAY] Session resumption rejected: no active key in session_store "
                "(session=%s from %s) — session may be expired, closed, or not yet established.",
                session_id,
                peer_addr,
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
        logger.info("[LIFECYCLE] PIPE_START | session=%s | target=%s:%d", session_id, target_host, target_port)

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

        logger.info("[GATEWAY] Bidirectional pipe active: session=%s -> %s:%d", session_id, target_host, target_port)
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
        _active_tasks.discard(current_task)

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
    session_store.last_seen[session_id] = time.time()
    logger.debug("[HEARTBEAT] RECEIVED | session=%s", session_id)
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
# Periodic reconciliation — session_store vs DB (off hot path)
# ---------------------------------------------------------------------------


async def _reconcile_session_store() -> None:
    """
    Cross-check session_store's live keys against the DB's session states.

    For each session ID currently held in memory, query the DB (off-thread).
    Log a WARNING if the DB shows the session as CLOSED, EXPIRED, or FAILED
    while a key is still alive in memory — this indicates drift that should
    not occur under normal operation.

    If drift is found, also proactively evict the stale key to self-heal.
    This does NOT block or affect the data-plane hot path.
    """
    live_ids = session_store.active_session_ids()
    if not live_ids:
        logger.debug("[RECONCILE] session_store is empty - nothing to reconcile.")
        return

    logger.debug("[RECONCILE] Checking %d live session(s) against DB.", len(live_ids))

    INACTIVE_STATES = {"CLOSED", "EXPIRED", "FAILED"}

    def _db_check():
        db = SessionLocal()
        mismatches = []
        try:
            for sid in live_ids:
                try:
                    session = _session_repo.get_by_id(db, sid)
                    if session is None:
                        mismatches.append((sid, "NOT_FOUND"))
                    elif session.tunnel_status in INACTIVE_STATES or session.kem_state in INACTIVE_STATES:
                        mismatches.append((sid, f"tunnel_status={session.tunnel_status} kem_state={session.kem_state}"))
                except Exception as exc:
                    logger.debug("[RECONCILE] Could not query session %s: %s", sid, exc)
        finally:
            db.close()
        return mismatches

    try:
        mismatches = await asyncio.to_thread(_db_check)
    except Exception as exc:
        logger.error("[RECONCILE] DB check failed: %s", exc)
        return

    for sid, reason in mismatches:
        logger.warning(
            "[RECONCILE] Drift detected: session_store holds a live key for session=%s "
            "but DB reports %s — evicting now.",
            sid, reason,
        )
        session_store.evict(sid)

    if not mismatches:
        logger.debug("[RECONCILE] All %d live session(s) match DB state - no drift.", len(live_ids))


async def _reconcile_loop() -> None:
    """
    Background loop that periodically calls _reconcile_session_store().

    Interval: 5 × HEARTBEAT_TIMEOUT_SECONDS (or at least 60s).
    This is intentionally slower than the expiry scan — it's a safety net,
    not a critical path.
    """
    interval = max(60, settings.HEARTBEAT_TIMEOUT_SECONDS * 5)
    logger.info("[RECONCILE] Reconciliation monitor started (interval=%ds)", interval)
    while True:
        try:
            await asyncio.sleep(interval)
            await _reconcile_session_store()
        except asyncio.CancelledError:
            logger.info("[RECONCILE] Reconciliation task cancelled")
            break
        except Exception as exc:
            logger.error("[RECONCILE] Unexpected error in reconciliation loop: %s", exc)


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------


_reconcile_task = None


async def start_gateway_server():
    """
    Start the raw TCP VPN socket server and background maintenance tasks.

    Background tasks started:
      - expire_stale_sessions(): marks timed-out sessions EXPIRED, evicts keys.
      - _reconcile_loop(): periodically cross-checks session_store vs DB for drift.

    Returns the asyncio.Server object so the caller can manage its lifecycle.
    """
    global _expiry_task, _reconcile_task
    server = await asyncio.start_server(
        handle_client,
        HOST,
        VPN_PORT,
        limit=262144,  # 256 KB stream reader buffer (default 64 KB is too small for VPN throughput)
    )
    logger.info("[GATEWAY] TCP VPN server listening on %s:%d", HOST, VPN_PORT)

    # Start background session expiry
    _expiry_task = asyncio.create_task(expire_stale_sessions())
    logger.info("[GATEWAY] Session expiry monitor started (interval=%ds)", settings.HEARTBEAT_TIMEOUT_SECONDS)

    # Start background reconciliation (session_store vs DB drift detection)
    _reconcile_task = asyncio.create_task(_reconcile_loop())

    return server