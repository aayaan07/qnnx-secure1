"""
repositories/heartbeat_repo.py — Data access for the heartbeats table.

Heartbeats are append-only; no update or delete operations are exposed.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session as DBSession

from app.models.heartbeat import Heartbeat


def _to_uuid(value) -> uuid.UUID:
    """Coerce str/UUID → uuid.UUID for SQLite-compatible UUID column filters."""
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))

class HeartbeatRepository:

    def create(
        self,
        db: DBSession,
        session_id: str,
        sequence_number: int = 0,
        packets_sent: int = 0,
        packets_received: int = 0,
    ) -> Heartbeat:
        """
        Append a new heartbeat record.

        Args:
            db:               Active SQLAlchemy session.
            session_id:       UUID string of the associated VPN session.
            sequence_number:  Monotonic counter from the client (0 if not provided).
            packets_sent:     Cumulative sent packet count from client.
            packets_received: Cumulative received packet count from client.

        Returns:
            The newly created Heartbeat row.
        """
        hb = Heartbeat(
            id=uuid.uuid4(),
            session_id=_to_uuid(session_id),
            timestamp=datetime.now(timezone.utc),
            sequence_number=sequence_number,
            packets_sent=packets_sent,
            packets_received=packets_received,
        )
        db.add(hb)
        db.commit()
        db.refresh(hb)
        return hb

    def list_by_session(
        self,
        db: DBSession,
        session_id: str,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Heartbeat]:
        """
        Return heartbeats for a session, newest first.

        Args:
            since: If provided, only return heartbeats after this timestamp.
            limit: Maximum rows to return (default 100, max 1000).
        """
        q = db.query(Heartbeat).filter(Heartbeat.session_id == _to_uuid(session_id))
        if since:
            q = q.filter(Heartbeat.timestamp >= since)
        return q.order_by(Heartbeat.timestamp.desc()).limit(limit).all()

    def count_by_session(self, db: DBSession, session_id: str) -> int:
        """Return the total number of heartbeats recorded for a session."""
        return db.query(Heartbeat).filter(Heartbeat.session_id == _to_uuid(session_id)).count()
