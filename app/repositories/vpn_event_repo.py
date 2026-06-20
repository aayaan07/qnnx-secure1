from sqlalchemy.orm import Session
from app.models.vpn_event import VPNEvent

class VPNEventRepository:

    def create(self, db: Session, event_data: dict) -> VPNEvent:
        event = VPNEvent(**event_data)
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    def get_all(self, db: Session) -> list[VPNEvent]:
        return db.query(VPNEvent).order_by(VPNEvent.recorded_at.desc()).all()
