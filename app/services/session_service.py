"""
session_service.py — Session lifecycle management.

Handles queries, status transitions, and the background expiry cleanup task.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List

from sqlalchemy.orm import Session as DBSession

from app.core.config import settings
from app.core.database import SessionLocal
from app.gateway.session_store import session_store
from app.models.session import Session as SessionModel
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


# ---------------------------------------------------------------------------
# Lifecycle transitions
# ---------------------------------------------------------------------------


def activate_session(db: DBSession, session_id: str) -> None:
    """Called when the first data packet arrives — transitions CONNECTING → ACTIVE."""
    _session_repo.update(db, session_id, {"tunnel_status": "ACTIVE"})
    ts = _tunnel_state_repo.get_by_session_id(db, session_id)
    if ts:
        _tunnel_state_repo.update(db, str(ts.id), {"status": "ACTIVE"})


def close_session(db: DBSession, session_id: str, reason: str = "CLIENT_DISCONNECT") -> None:
    """
    Close a session cleanly.

    Updates tunnel_status → CLOSED, records closed_at timestamp,
    removes the AES key from the in-memory store, and logs an audit event.
    """
    now = datetime.now(timezone.utc)
    _session_repo.update(db, session_id, {
        "tunnel_status": "CLOSED",
        "kem_state": "CLOSED",
        "closed_at": now,
    })
    ts = _tunnel_state_repo.get_by_session_id(db, session_id)
    if ts:
        _tunnel_state_repo.update(db, str(ts.id), {"status": "DISCONNECTED"})

    # Evict the AES key from memory
    session_store.evict(session_id)

    # Audit
    _event_repo.record(
        db=db,
        session_id=session_id,
        event_type="CLIENT_DISCONNECT",
        details={"reason": reason},
    )

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
                        if ts.last_heartbeat and ts.last_heartbeat < cutoff:
                            _tunnel_state_repo.update(db, str(ts.id), {"status": "TIMED_OUT"})
                            _session_repo.update(db, str(ts.session_id), {
                                "tunnel_status": "EXPIRED",
                                "kem_state": "EXPIRED",
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
