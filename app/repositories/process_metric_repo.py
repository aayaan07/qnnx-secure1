from sqlalchemy.orm import Session
from app.models.process_metric import ProcessMetric

class ProcessMetricRepository:

    def create(self, db: Session, metric_data: dict) -> ProcessMetric:
        metric = ProcessMetric(**metric_data)
        db.add(metric)
        db.commit()
        db.refresh(metric)
        return metric

    def get_all(self, db: Session) -> list[ProcessMetric]:
        return db.query(ProcessMetric).order_by(ProcessMetric.recorded_at.desc()).all()

    def get_latest_for_client(self, db: Session, client_identifier: str, limit: int = 5) -> list[ProcessMetric]:
        return db.query(ProcessMetric).filter(
            ProcessMetric.client_identifier == client_identifier
        ).order_by(ProcessMetric.recorded_at.desc()).limit(limit).all()

    def delete_all_for_client(self, db: Session, client_identifier: str):
        """Clears old process listings before logging fresh snapshots."""
        db.query(ProcessMetric).filter(
            ProcessMetric.client_identifier == client_identifier
        ).delete()
        db.commit()
