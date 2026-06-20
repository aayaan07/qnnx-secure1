from sqlalchemy.orm import Session
from app.models.ip_history import IPHistory

class IPHistoryRepository:

    def create(self, db: Session, history_data: dict) -> IPHistory:
        history = IPHistory(**history_data)
        db.add(history)
        db.commit()
        db.refresh(history)
        return history

    def get_latest_for_client(self, db: Session, client_identifier: str) -> IPHistory | None:
        """Returns the most recent IP address recorded for a client device."""
        return db.query(IPHistory).filter(
            IPHistory.client_identifier == client_identifier
        ).order_by(IPHistory.recorded_at.desc()).first()

    def get_all(self, db: Session) -> list[IPHistory]:
        return db.query(IPHistory).order_by(IPHistory.recorded_at.desc()).all()
