from sqlalchemy.orm import Session
from app.models.security_alert import SecurityAlert

class SecurityAlertRepository:

    def create(self, db: Session, alert_data: dict) -> SecurityAlert:
        alert = SecurityAlert(**alert_data)
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert

    def get_open_alerts(self, db: Session) -> list[SecurityAlert]:
        """Returns all unresolved/open security alerts."""
        return db.query(SecurityAlert).filter(
            SecurityAlert.status == "OPEN"
        ).order_by(SecurityAlert.timestamp.desc()).all()

    def get_all(self, db: Session) -> list[SecurityAlert]:
        return db.query(SecurityAlert).order_by(SecurityAlert.timestamp.desc()).all()

    def resolve_alert(self, db: Session, alert_id: str) -> SecurityAlert | None:
        """Marks a security alert as RESOLVED."""
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if alert:
            alert.status = "RESOLVED"
            db.commit()
            db.refresh(alert)
        return alert
