"""
stats_service.py — Traffic statistics service.

Wraps TrafficStatRepository to provide a clean service-layer interface for
reading and updating session traffic counters.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session as DBSession

from app.models.traffic_stat import TrafficStat
from app.repositories.traffic_stat_repo import TrafficStatRepository

logger = logging.getLogger("qvpn.stats_service")

_stat_repo = TrafficStatRepository()


def get_session_stats(db: DBSession, session_id: str) -> TrafficStat | None:
    """
    Return the TrafficStat row for a session, or None if not found.
    """
    return _stat_repo.get_by_session_id(db, session_id)


def increment_stats(
    db: DBSession,
    session_id: str,
    bytes_sent: int = 0,
    bytes_received: int = 0,
    packets_sent: int = 0,
    packets_received: int = 0,
) -> TrafficStat | None:
    """
    Increment the cumulative traffic counters for a session.

    Called in batches from the socket server's pipe_* helpers to minimize
    DB write frequency. Returns None if no TrafficStat row exists for the
    session (which would indicate a logic error in the handshake flow).
    """
    return _stat_repo.increment(
        db=db,
        session_id=session_id,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        packets_sent=packets_sent,
        packets_received=packets_received,
    )
