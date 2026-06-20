from sqlalchemy.orm import Session
from app.models.traffic_stat import TrafficStat

class TrafficStatRepository:

    def get_all(self, db: Session):
        return db.query(TrafficStat).all()

    def get_by_id(self, db: Session, traffic_stat_id: str):
        return db.query(TrafficStat).filter(
            TrafficStat.id == traffic_stat_id
        ).first()

    def get_by_session_id(self, db: Session, session_id: str):
        return db.query(TrafficStat).filter(
            TrafficStat.session_id == session_id
        ).first()

    def create(self, db: Session, traffic_stat_data: dict):
        traffic_stat = TrafficStat(**traffic_stat_data)

        db.add(traffic_stat)
        db.commit()
        db.refresh(traffic_stat)

        return traffic_stat

    def increment(self, db: Session, session_id: str, bytes_sent: int = 0, bytes_received: int = 0,
                  packets_sent: int = 0, packets_received: int = 0):
        # Called continuously as the tunnel forwards traffic, instead of
        # overwriting counters, this adds to whatever is already there.
        traffic_stat = self.get_by_session_id(db, session_id)

        if not traffic_stat:
            return None

        traffic_stat.bytes_sent += bytes_sent
        traffic_stat.bytes_received += bytes_received
        traffic_stat.packets_sent += packets_sent
        traffic_stat.packets_received += packets_received

        db.commit()
        db.refresh(traffic_stat)

        return traffic_stat

    def delete(self, db: Session, traffic_stat_id: str):
        traffic_stat = self.get_by_id(db, traffic_stat_id)

        if not traffic_stat:
            return None

        db.delete(traffic_stat)
        db.commit()

        return traffic_stat