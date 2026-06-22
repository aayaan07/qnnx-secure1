"""
handshake_service.py — Async VPN handshake orchestration.

Two-phase flow:

  Phase 1: init_handshake(client_identifier)
    - Look up client in DB
    - Call PQC API to generate a fresh KEM keypair
    - Create Session row in PENDING state
    - Return the public_key to the caller so it can be sent to the VPN client

  Phase 2: complete_handshake(session_id, kem_ciphertext)
    - Load the session and client from DB
    - Call PQC API to decapsulate the ciphertext using the stored private_key
    - Derive a 32-byte AES-256 session key via HKDF
    - Store the AES key in the in-memory session_store (never in DB)
    - Update session to ESTABLISHED + tunnel_status to CONNECTING
    - Initialize TunnelState and TrafficStat rows
    - Return session_id and the raw AES key to the socket layer

This service is async because every PQC API call is made via httpx.AsyncClient.
DB calls use asyncio.to_thread() via the sync SQLAlchemy pattern.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session as DBSession
from app.models.session import KEMState, TunnelStatus

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.exceptions import (
    ClientNotRegistered,
    DuplicateHandshake,
    HandshakeError,
    PQCDecapsulationError,
    PQCKeygenError,
    PQCServiceUnavailable,
    SessionNotFound,
)
from app.crypto import pqc_client
from app.crypto.session_key import derive_session_key
from app.gateway.session_store import session_store
from app.repositories.client_repo import ClientRepository
from app.repositories.session_repo import SessionRepository
from app.repositories.traffic_stat_repo import TrafficStatRepository
from app.repositories.tunnel_event_repo import TunnelEventRepository
from app.repositories.tunnel_state_repo import TunnelStateRepository

logger = logging.getLogger("qvpn.handshake")

_client_repo = ClientRepository()
_session_repo = SessionRepository()
_tunnel_state_repo = TunnelStateRepository()
_traffic_stat_repo = TrafficStatRepository()
_event_repo = TunnelEventRepository()


# ---------------------------------------------------------------------------
# Phase 1: Init
# ---------------------------------------------------------------------------


async def init_handshake(db: DBSession | None = None, client_identifier: str = "") -> dict:
    """
    Phase 1 of the VPN handshake.

    1. Verify the client is registered and active.
    2. Generate a fresh KEM keypair via PQC API.
    3. Create a new Session row in state PENDING.
    4. Record HANDSHAKE_INIT event.
    5. Return { session_id, algorithm, public_key (bytes) }.

    The returned public_key should be forwarded to the VPN client so it can
    encapsulate (encrypt) the shared secret.
    """
    # Step 1 — client lookup (sync DB → thread)
    def _lookup_client():
        _db = db or SessionLocal()
        try:
            client = _client_repo.get_by_identifier(_db, client_identifier)
            if not client:
                return None, None, None
            return client.id, client.is_active, client.kem_algorithm
        finally:
            if not db:
                _db.close()

    client_id, is_active, algorithm = await asyncio.to_thread(_lookup_client)

    if not client_id:
        raise ClientNotRegistered(f"client_identifier '{client_identifier}' not registered")
    if not is_active:
        raise ClientNotRegistered(f"client_identifier '{client_identifier}' is disabled")

    # Step 2 — keygen via PQC API (fully async)
    try:
        keygen_resp = await pqc_client.keygen(algorithm)
    except PQCServiceUnavailable:
        raise
    except Exception as exc:
        raise PQCKeygenError(f"Keygen failed for {algorithm}: {exc}") from exc

    import base64
    public_key_bytes = base64.b64decode(keygen_resp.public_key)
    private_key_bytes = b""  # Keygen response no longer contains raw private key

    # Step 3 — create session row in PENDING state (sync DB → thread)
    session_id = uuid.uuid4()

    def _create_session():
        _db = db or SessionLocal()
        try:
            _session_repo.create(_db, {
                "id": session_id,
                "client_id": client_id,
                "kem_algorithm": algorithm,
                "pqc_key_id": keygen_resp.key_id,
                "kem_state": KEMState.PENDING,
                "tunnel_status": TunnelStatus.CONNECTING,
            })
            # Store freshly generated public_key and key_id reference.
            # Since private key is not returned by the API, private_key is stored as empty bytes.
            _client_repo.update(_db, client_id, {
                "public_key": public_key_bytes,
                "private_key": private_key_bytes,
                "pqc_key_id": keygen_resp.key_id,
            })
            if not db:
                _db.commit()
        except Exception:
            if not db:
                _db.rollback()
            raise
        finally:
            if not db:
                _db.close()

    await asyncio.to_thread(_create_session)

    # Step 4 — audit event
    def _record_init_event():
        _db = db or SessionLocal()
        try:
            _event_repo.record(
                db=_db,
                session_id=session_id,
                event_type="HANDSHAKE_INIT",
                details={"client_identifier": client_identifier, "algorithm": algorithm},
            )
            if not db:
                _db.commit()
        except Exception:
            if not db:
                _db.rollback()
            raise
        finally:
            if not db:
                _db.close()

    await asyncio.to_thread(_record_init_event)

    logger.info(
        "[HANDSHAKE] Init: client=%s session=%s algorithm=%s",
        client_identifier, session_id, algorithm,
    )

    return {
        "session_id": str(session_id),
        "algorithm": algorithm,
        "public_key": public_key_bytes,
    }


# ---------------------------------------------------------------------------
# Phase 2: Complete
# ---------------------------------------------------------------------------


async def complete_handshake(
    db: DBSession | None = None,
    session_id: str = "",
    kem_ciphertext: bytes = b"",
    remote_ip: str = "127.0.0.1",
    remote_port: int = 0,
) -> dict:
    """
    Phase 2 of the VPN handshake.

    1. Load session + client from DB.
    2. Decapsulate the ciphertext via PQC API.
    3. Derive AES-256 key from shared_secret via HKDF.
    4. Store AES key in in-memory session_store.
    5. Update session to ESTABLISHED; create TunnelState + TrafficStat rows.
    6. Record HANDSHAKE_COMPLETE event.
    7. Return { session_id, aes_key (bytes) }.

    The aes_key is returned to the socket layer for use in the tunnel.
    It is NEVER persisted.
    """
    session_uuid = uuid.UUID(session_id) if isinstance(session_id, str) else session_id

    # Step 1 — load session
    def _load():
        _db = db or SessionLocal()
        try:
            session = _session_repo.get_by_id(_db, session_uuid)
            if not session:
                return None
            return {
                "client_id": session.client_id,
                "kem_algorithm": session.kem_algorithm,
                "pqc_key_id": session.pqc_key_id,
                "kem_state": session.kem_state,
                "kem_ciphertext": session.kem_ciphertext,
            }
        finally:
            if not db:
                _db.close()

    session_data = await asyncio.to_thread(_load)

    if not session_data:
        raise SessionNotFound(f"session_id '{session_id}' not found")
    if session_data["kem_state"] not in (KEMState.PENDING,):
        if session_data["kem_state"] == KEMState.ESTABLISHED:
            aes_key = session_store.get(str(session_uuid))
            if aes_key and session_data["kem_ciphertext"] == kem_ciphertext:
                logger.info(
                    "[HANDSHAKE] Duplicate handshake for established session=%s, returning cached AES key",
                    session_id,
                )
                return {
                    "session_id": str(session_uuid),
                    "aes_key": aes_key,
                }
        raise DuplicateHandshake(
            f"session '{session_id}' is already in state '{session_data['kem_state']}'"
        )

    # Load client for key_id reference
    def _load_client():
        _db = db or SessionLocal()
        try:
            client = _client_repo.get_by_id(_db, session_data["client_id"])
            if not client:
                return None
            return client.pqc_key_id
        finally:
            if not db:
                _db.close()

    client_pqc_key_id = await asyncio.to_thread(_load_client)
    if client_pqc_key_id is None and session_data["client_id"] is not None:
        def _check_client_exists():
            _db = db or SessionLocal()
            try:
                return _client_repo.get_by_id(_db, session_data["client_id"]) is not None
            finally:
                if not db:
                    _db.close()
        exists = await asyncio.to_thread(_check_client_exists)
        if not exists:
            raise ClientNotRegistered(f"Client for session '{session_id}' not found")

    key_id = session_data["pqc_key_id"] or client_pqc_key_id
    if not key_id:
        raise HandshakeError(f"No key_id reference found for session '{session_id}'")

    # Step 2 — decapsulate via PQC API
    try:
        shared_secret = await pqc_client.decapsulate(
            session_data["kem_algorithm"],
            kem_ciphertext,
            key_id,
        )
    except (PQCServiceUnavailable, PQCDecapsulationError):
        def _mark_failed():
            _db = db or SessionLocal()
            try:
                _session_repo.update(_db, session_uuid, {"kem_state": KEMState.FAILED, "tunnel_status": TunnelStatus.FAILED})
                if not db:
                    _db.commit()
            except Exception:
                if not db:
                    _db.rollback()
            finally:
                if not db:
                    _db.close()
        await asyncio.to_thread(_mark_failed)
        raise
    except Exception as exc:
        def _mark_failed():
            _db = db or SessionLocal()
            try:
                _session_repo.update(_db, session_uuid, {"kem_state": KEMState.FAILED, "tunnel_status": TunnelStatus.FAILED})
                if not db:
                    _db.commit()
            except Exception:
                if not db:
                    _db.rollback()
            finally:
                if not db:
                    _db.close()
        await asyncio.to_thread(_mark_failed)
        raise HandshakeError(f"Decapsulation error: {exc}") from exc

    # Step 3 — derive AES-256 key
    aes_key = derive_session_key(shared_secret)

    # Step 4 — store in memory (never DB)
    session_store.put(session_id, aes_key)

    # Step 5 — update session + create related rows
    now = datetime.now(timezone.utc)

    def _finalize():
        _db = db or SessionLocal()
        try:
            # Update session ciphertext + state
            _session_repo.update(_db, session_uuid, {
                "kem_ciphertext": kem_ciphertext,
                "kem_state": KEMState.ESTABLISHED,
                "tunnel_status": TunnelStatus.CONNECTING,
                "established_at": now,
            })

            # Create TunnelState
            _tunnel_state_repo.create(_db, {
                "id": uuid.uuid4(),
                "session_id": session_uuid,
                "status": TunnelStatus.CONNECTING,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "last_heartbeat": now,
            })

            # Create TrafficStat row
            _traffic_stat_repo.create(_db, {
                "id": uuid.uuid4(),
                "session_id": session_uuid,
                "bytes_sent": 0,
                "bytes_received": 0,
                "packets_sent": 0,
                "packets_received": 0,
            })

            # Update client last_seen
            _client_repo.update(_db, session_data["client_id"], {"last_seen": now})
            if not db:
                _db.commit()
        except Exception:
            if not db:
                _db.rollback()
            raise
        finally:
            if not db:
                _db.close()

    await asyncio.to_thread(_finalize)

    # Step 6 — audit event
    def _record_complete_event():
        _db = db or SessionLocal()
        try:
            _event_repo.record(
                db=_db,
                session_id=session_uuid,
                event_type="HANDSHAKE_COMPLETE",
                details={
                    "algorithm": session_data["kem_algorithm"],
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                },
            )
            if not db:
                _db.commit()
        except Exception:
            if not db:
                _db.rollback()
            raise
        finally:
            if not db:
                _db.close()

    await asyncio.to_thread(_record_complete_event)

    logger.info(
        "[HANDSHAKE] Complete: session=%s algorithm=%s remote=%s:%d aes_key_len=%d",
        session_id, session_data["kem_algorithm"], remote_ip, remote_port, len(aes_key),
    )

    return {
        "session_id": session_id,
        "aes_key": aes_key,  # 32 bytes; live only in memory
    }
