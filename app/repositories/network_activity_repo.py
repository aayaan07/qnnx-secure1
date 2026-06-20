from sqlalchemy.orm import Session
from app.models.network_activity import NetworkActivity

class NetworkActivityRepository:

    def create(self, db: Session, activity_data: dict) -> NetworkActivity:
        activity = NetworkActivity(**activity_data)
        db.add(activity)
        db.commit()
        db.refresh(activity)
        return activity

    def get_all(self, db: Session) -> list[NetworkActivity]:
        return db.query(NetworkActivity).order_by(NetworkActivity.recorded_at.desc()).all()

    def get_latest_for_client(self, db: Session, client_identifier: str, limit: int = 5) -> list[NetworkActivity]:
        return db.query(NetworkActivity).filter(
            NetworkActivity.client_identifier == client_identifier
        ).order_by(NetworkActivity.recorded_at.desc()).limit(limit).all()

    def delete_all_for_client(self, db: Session, client_identifier: str):
        """Clears old connections to prevent database bloat before logging fresh snapshots."""
        db.query(NetworkActivity).filter(
            NetworkActivity.client_identifier == client_identifier
        ).delete()
        db.commit()
