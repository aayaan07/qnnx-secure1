"""
session_service.py — Session lifecycle management.

Handles queries, status transitions, and the background expiry cleanup task.
"""
from __future__ import annotations
from app.core import database

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List

from sqlalchemy.orm import Session as DBSession

from app.core.config import settings
from app.core.database import SessionLocal
from app.gateway.session_store import session_store
from app.models.session import Session as SessionModel, KEMState, TunnelStatus
from app.repositories.session_repo import SessionRepository
from app.repositories.tunnel_state_repo import TunnelStateRepository
from app.repositories.tunnel_event_repo import TunnelEventRepository

logger = logging.getLogger("qvpn.session_service")

_session_repo = SessionRepository()
_tunnel_state_repo = TunnelStateRepository()
_event_repo = TunnelEventRepository()


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def get_session(db: DBSession, session_id: str) -> SessionModel | None:
    return _session_repo.get_by_id(db, session_id)


def list_sessions(db: DBSession, tunnel_status: str | None = None) -> List[SessionModel]:
    if tunnel_status:
        return _session_repo.list_by_status(db, tunnel_status)
    return _session_repo.get_all(db)


def is_session_resumable(session: SessionModel) -> bool:
    """Determine if a session is in a valid state to resume the VPN tunnel connection."""
    return (
        session.kem_state == KEMState.ESTABLISHED
        and session.tunnel_status in (TunnelStatus.CONNECTING, TunnelStatus.ACTIVE)
    )


# ---------------------------------------------------------------------------
# Lifecycle transitions
# ---------------------------------------------------------------------------


def activate_session(db: DBSession, session_id: str) -> None:
    """Called when the first data packet arrives — transitions CONNECTING → ACTIVE."""
    _session_repo.update(db, session_id, {"tunnel_status": TunnelStatus.ACTIVE})
    ts = _tunnel_state_repo.get_by_session_id(db, session_id)
    if ts:
        _tunnel_state_repo.update(db, str(ts.id), {"status": "ACTIVE"})


def close_session(db: DBSession, session_id: str, reason: str = "CLIENT_DISCONNECT") -> None:
    """
    Close a session cleanly.

    Each cleanup step runs in its own try/except so that a failure in one step
    (e.g. a DB error) does not prevent later steps — in particular, the
    session_store.evict() call that frees the in-memory AES key must always run.

    Steps:
      1. Update Session row → CLOSED / kem_state=CLOSED
      2. Update TunnelState row → DISCONNECTED
      3. Evict AES key from in-memory session_store  ← CRITICAL, always runs
      4. Record CLIENT_DISCONNECT audit event
    """
    now = datetime.now(timezone.utc)
    cleanup_errors: list[str] = []

    # Step 1 — mark session as closed in DB
    try:
        _session_repo.update(db, session_id, {
            "tunnel_status": TunnelStatus.CLOSED,
            "kem_state": KEMState.CLOSED,
            "closed_at": now,
        })
    except Exception as exc:
        cleanup_errors.append(f"session_repo.update: {exc}")
        logger.error("[SESSION] close_session: failed to update session row (session=%s): %s", session_id, exc)

    # Step 2 — mark tunnel state as disconnected
    try:
        ts = _tunnel_state_repo.get_by_session_id(db, session_id)
        if ts:
            _tunnel_state_repo.update(db, str(ts.id), {"status": "DISCONNECTED"})
    except Exception as exc:
        cleanup_errors.append(f"tunnel_state_repo.update: {exc}")
        logger.error("[SESSION] close_session: failed to update tunnel_state (session=%s): %s", session_id, exc)

    # Step 3 — evict AES key from in-memory store (CRITICAL — must always run)
    try:
        session_store.evict(session_id)
    except Exception as exc:
        cleanup_errors.append(f"session_store.evict: {exc}")
        logger.error("[SESSION] close_session: CRITICAL — failed to evict AES key (session=%s): %s", session_id, exc)

    # Step 4 — record audit event
    try:
        _event_repo.record(
            db=db,
            session_id=session_id,
            event_type="CLIENT_DISCONNECT",
            details={"reason": reason},
        )
    except Exception as exc:
        cleanup_errors.append(f"event_repo.record: {exc}")
        logger.error("[SESSION] close_session: failed to record disconnect event (session=%s): %s", session_id, exc)

    if cleanup_errors:
        logger.warning(
            "[SESSION] close_session completed with %d error(s) for session=%s: %s",
            len(cleanup_errors),
            session_id,
            "; ".join(cleanup_errors),
        )
    else:
        logger.info("[SESSION] Closed session=%s reason=%s", session_id, reason)


# ---------------------------------------------------------------------------
# Background expiry cleanup
# ---------------------------------------------------------------------------


async def expire_stale_sessions() -> None:
    """
    Background coroutine that periodically marks timed-out sessions as EXPIRED.

    Runs every HEARTBEAT_TIMEOUT_SECONDS and closes any tunnel that has not
    had a heartbeat within that window.
    """
    timeout = settings.HEARTBEAT_TIMEOUT_SECONDS

    while True:
        try:
            await asyncio.sleep(timeout)
            logger.debug("[SESSION] Running stale-session expiry scan...")

            cutoff = datetime.now(timezone.utc) - timedelta(seconds=timeout)

            def _cleanup():
                db = SessionLocal()
                try:
                    # Find ACTIVE tunnel states with stale heartbeats
                    all_tunnels = _tunnel_state_repo.get_all(db)
                    closed_count = 0
                    for ts in all_tunnels:
                        if ts.status not in ("ACTIVE", "CONNECTING"):
                            continue
                        if ts.last_heartbeat:
                            last_hb = ts.last_heartbeat
                            if last_hb.tzinfo is None:
                                last_hb = last_hb.replace(tzinfo=timezone.utc)
                            if last_hb < cutoff:
                                _tunnel_state_repo.update(db, str(ts.id), {"status": "TIMED_OUT"})
                                _session_repo.update(db, str(ts.session_id), {
                                    "tunnel_status": TunnelStatus.EXPIRED,
                                    "kem_state": KEMState.EXPIRED,
                                    "closed_at": datetime.now(timezone.utc),
                                })
                                session_store.evict(str(ts.session_id))
                                _event_repo.record(
                                    db=db,
                                    session_id=str(ts.session_id),
                                    event_type="GATEWAY_TIMEOUT",
                                    details={"last_heartbeat": ts.last_heartbeat.isoformat() if ts.last_heartbeat else None},
                                )
                                closed_count += 1
                    if closed_count:
                        logger.info("[SESSION] Expired %d stale session(s)", closed_count)
                except Exception as exc:
                    logger.error("[SESSION] Expiry scan error: %s", exc)
                finally:
                    db.close()

            await asyncio.to_thread(_cleanup)

        except asyncio.CancelledError:
            logger.info("[SESSION] Expiry task cancelled")
            break
        except Exception as exc:
            logger.error("[SESSION] Unexpected error in expiry task: %s", exc)
