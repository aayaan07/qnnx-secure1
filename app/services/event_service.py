"""
event_service.py — Tunnel event recording and querying.

Wraps TunnelEventRepository to provide a clean service-layer interface.
"""
from __future__ import annotations

import logging
from typing import List

from sqlalchemy.orm import Session as DBSession

from app.models.tunnel_event import TunnelEvent
from app.repositories.tunnel_event_repo import TunnelEventRepository

logger = logging.getLogger("qvpn.event_service")

_event_repo = TunnelEventRepository()


def record_event(
    db: DBSession,
    session_id: str,
    event_type: str,
    details: dict | None = None,
) -> TunnelEvent:
    """
    Append a new tunnel event to the audit log.

    Args:
        db:          Active SQLAlchemy session.
        session_id:  UUID string of the associated session.
        event_type:  Short uppercase string, e.g. "HEARTBEAT", "ERROR".
        details:     Optional structured data (stored as JSONB).

    Returns:
        The created TunnelEvent ORM object.
    """
    event = _event_repo.record(db=db, session_id=session_id, event_type=event_type, details=details)
    logger.debug("[EVENT] session=%s type=%s", session_id, event_type)
    return event


def list_events(
    db: DBSession,
    session_id: str,
    limit: int = 100,
) -> List[TunnelEvent]:
    """
    Retrieve the most recent tunnel events for a session.

    Args:
        db:          Active SQLAlchemy session.
        session_id:  UUID string of the associated session.
        limit:       Maximum number of events to return (default 100).

    Returns:
        List of TunnelEvent objects ordered newest-first.
    """
    return _event_repo.list_by_session(db=db, session_id=session_id, limit=limit)
