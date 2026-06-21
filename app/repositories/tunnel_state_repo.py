import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.tunnel_state import TunnelState


def _to_uuid(value) -> uuid.UUID:
    """Coerce str/UUID → uuid.UUID for SQLite-compatible UUID column filters."""
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))

class TunnelStateRepository:

    def get_all(self, db: Session):
        return db.query(TunnelState).all()

    def get_by_id(self, db: Session, tunnel_state_id: str):
        return db.query(TunnelState).filter(
            TunnelState.id == _to_uuid(tunnel_state_id)
        ).first()

    def get_by_session_id(self, db: Session, session_id: str):
        return db.query(TunnelState).filter(
            TunnelState.session_id == _to_uuid(session_id)
        ).first()

    def create(self, db: Session, tunnel_state_data: dict):
        tunnel_state = TunnelState(**tunnel_state_data)

        db.add(tunnel_state)
        db.commit()
        db.refresh(tunnel_state)

        return tunnel_state

    def update(self, db: Session, tunnel_state_id: str, update_data: dict):
        tunnel_state = self.get_by_id(db, tunnel_state_id)

        if not tunnel_state:
            return None

        for key, value in update_data.items():
            setattr(tunnel_state, key, value)

        db.commit()
        db.refresh(tunnel_state)

        return tunnel_state

    def record_heartbeat(self, db: Session, session_id: str):
        tunnel_state = self.get_by_session_id(db, session_id)

        if not tunnel_state:
            return None

        tunnel_state.last_heartbeat = datetime.now(timezone.utc)
        tunnel_state.missed_heartbeats = 0
        tunnel_state.status = "ACTIVE"

        db.commit()
        db.refresh(tunnel_state)

        return tunnel_state

    def delete(self, db: Session, tunnel_state_id: str):
        tunnel_state = self.get_by_id(db, tunnel_state_id)

        if not tunnel_state:
            return None

        db.delete(tunnel_state)
        db.commit()

        return tunnel_state