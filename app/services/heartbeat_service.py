"""
services/heartbeat_service.py — Heartbeat recording service.

Handles the dual-write on each heartbeat:
  1. Appends a row to the heartbeats table (audit log)
  2. Updates tunnel_states.last_heartbeat + status (live health)
  3. Updates sessions.tunnel_status → ACTIVE if not already

This keeps the routes thin and the business logic here.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session as DBSession

from app.models.heartbeat import Heartbeat
from app.repositories.heartbeat_repo import HeartbeatRepository
from app.repositories.tunnel_state_repo import TunnelStateRepository
from app.repositories.session_repo import SessionRepository
from app.models.session import TunnelStatus

logger = logging.getLogger("qvpn.heartbeat_service")

_heartbeat_repo = HeartbeatRepository()
_tunnel_state_repo = TunnelStateRepository()
_session_repo = SessionRepository()


def record_heartbeat(
    db: DBSession,
    session_id: str,
    sequence_number: int = 0,
    packets_sent: int = 0,
    packets_received: int = 0,
) -> Heartbeat:
    """
    Record a client heartbeat ping.

    Steps:
      1. Insert a new Heartbeat row (append-only audit log).
      2. Update the TunnelState row: last_heartbeat = now, missed_heartbeats = 0,
         status = ACTIVE.
      3. If the session's tunnel_status is not already ACTIVE, set it to ACTIVE.

    Args:
        db:               Active SQLAlchemy session.
        session_id:       UUID string of the VPN session.
        sequence_number:  Monotonic client-side counter (0 if not provided by client).
        packets_sent:     Cumulative client-side packets sent.
        packets_received: Cumulative client-side packets received.

    Returns:
        The newly created Heartbeat ORM row.
    """
    # 1. Append heartbeat record
    hb = _heartbeat_repo.create(
        db=db,
        session_id=session_id,
        sequence_number=sequence_number,
        packets_sent=packets_sent,
        packets_received=packets_received,
    )
    logger.debug(
        "[HEARTBEAT] session=%s seq=%d packets_sent=%d packets_received=%d",
        session_id, sequence_number, packets_sent, packets_received,
    )

    # 2. Update live tunnel state
    _tunnel_state_repo.record_heartbeat(db, session_id)

    # 3. Mark session tunnel_status ACTIVE if needed
    session = _session_repo.get_by_id(db, session_id)
    if session and session.tunnel_status not in (TunnelStatus.ACTIVE,):
        _session_repo.update(db, session_id, {"tunnel_status": TunnelStatus.ACTIVE})

    return hb
