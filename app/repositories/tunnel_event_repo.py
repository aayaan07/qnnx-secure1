from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List

from sqlalchemy.orm import Session as DBSession

from app.models.tunnel_event import TunnelEvent


class TunnelEventRepository:

    def get_by_id(self, db: DBSession, event_id: str) -> TunnelEvent | None:
        return db.query(TunnelEvent).filter(TunnelEvent.id == event_id).first()

    def list_by_session(self, db: DBSession, session_id: str, limit: int = 100) -> List[TunnelEvent]:
        """Return events for a session, newest first."""
        return (
            db.query(TunnelEvent)
            .filter(TunnelEvent.session_id == session_id)
            .order_by(TunnelEvent.occurred_at.desc())
            .limit(limit)
            .all()
        )

    def record(
        self,
        db: DBSession,
        session_id: str,
        event_type: str,
        details: dict | None = None,
    ) -> TunnelEvent:
        """
        Append a new event to the audit log.

        Args:
            db:          Active SQLAlchemy session.
            session_id:  UUID string of the associated session.
            event_type:  Short string identifier, e.g. "HANDSHAKE_COMPLETE".
            details:     Optional dict of structured event data (stored as JSONB).

        Returns:
            The newly created TunnelEvent row.
        """
        event = TunnelEvent(
            id=uuid.uuid4(),
            session_id=session_id,
            event_type=event_type,
            details=details or {},
            occurred_at=datetime.now(timezone.utc),
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event
