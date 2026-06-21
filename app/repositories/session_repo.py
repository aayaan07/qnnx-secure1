from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List

from sqlalchemy.orm import Session as DBSession

from app.models.session import Session as SessionModel


def _to_uuid(value) -> uuid.UUID:
    """Coerce str/UUID → uuid.UUID for SQLite-compatible UUID column filters."""
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))


class SessionRepository:

    def get_all(self, db: DBSession) -> List[SessionModel]:
        return db.query(SessionModel).all()

    def get_by_id(self, db: DBSession, session_id: str) -> SessionModel | None:
        return db.query(SessionModel).filter(
            SessionModel.id == _to_uuid(session_id)
        ).first()

    def list_by_status(self, db: DBSession, tunnel_status: str) -> List[SessionModel]:
        """Return all sessions with the given tunnel_status."""
        return db.query(SessionModel).filter(
            SessionModel.tunnel_status == tunnel_status
        ).all()

    def list_by_kem_state(self, db: DBSession, kem_state: str) -> List[SessionModel]:
        """Return all sessions with the given kem_state."""
        return db.query(SessionModel).filter(
            SessionModel.kem_state == kem_state
        ).all()

    def create(self, db: DBSession, session_data: dict) -> SessionModel:
        session_row = SessionModel(**session_data)
        db.add(session_row)
        db.commit()
        db.refresh(session_row)
        return session_row

    def update(self, db: DBSession, session_id: str, update_data: dict) -> SessionModel | None:
        session_row = self.get_by_id(db, session_id)
        if not session_row:
            return None
        for key, value in update_data.items():
            setattr(session_row, key, value)
        db.commit()
        db.refresh(session_row)
        return session_row

    def mark_expired(self, db: DBSession, before: datetime) -> int:
        """
        Mark all ACTIVE/ESTABLISHED sessions that were created before `before`
        (and have no recent heartbeat) as EXPIRED.

        Returns the number of rows updated.
        """
        rows = (
            db.query(SessionModel)
            .filter(
                SessionModel.tunnel_status.in_(["CONNECTING", "ACTIVE"]),
                SessionModel.created_at < before,
            )
            .all()
        )
        count = 0
        for row in rows:
            row.tunnel_status = "EXPIRED"
            row.kem_state = "EXPIRED"
            row.closed_at = datetime.now(timezone.utc)
            count += 1
        if count:
            db.commit()
        return count

    def delete(self, db: DBSession, session_id: str) -> SessionModel | None:
        session_row = self.get_by_id(db, session_id)
        if not session_row:
            return None
        db.delete(session_row)
        db.commit()
        return session_row