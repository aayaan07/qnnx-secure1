from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.tunnel_state import TunnelState

class TunnelStateRepository:

    def get_all(self, db: Session):
        return db.query(TunnelState).all()

    def get_by_id(self, db: Session, tunnel_state_id: str):
        return db.query(TunnelState).filter(
            TunnelState.id == tunnel_state_id
        ).first()

    def get_by_session_id(self, db: Session, session_id: str):
        return db.query(TunnelState).filter(
            TunnelState.session_id == session_id
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
        # Called every time a heartbeat packet arrives from a client.
        # Resets missed_heartbeats and marks the tunnel ACTIVE again
        # if it had previously been marked DEGRADED.
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