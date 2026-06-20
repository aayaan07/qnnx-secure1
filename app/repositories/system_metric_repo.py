from sqlalchemy.orm import Session
from app.models.system_metric import SystemMetric

class SystemMetricRepository:

    def create(self, db: Session, metric_data: dict) -> SystemMetric:
        metric = SystemMetric(**metric_data)
        db.add(metric)
        db.commit()
        db.refresh(metric)
        return metric

    def get_latest_for_client(self, db: Session, client_identifier: str) -> SystemMetric | None:
        """Returns the most recent metric report for a specific client identifier."""
        return db.query(SystemMetric).filter(
            SystemMetric.client_identifier == client_identifier
        ).order_by(SystemMetric.recorded_at.desc()).first()

    def get_all(self, db: Session) -> list[SystemMetric]:
        return db.query(SystemMetric).all()
