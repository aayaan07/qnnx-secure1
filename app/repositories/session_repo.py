from sqlalchemy.orm import Session
from app.models.session import Session as SessionModel

class SessionRepository:

    def get_all(self, db: Session):
        return db.query(SessionModel).all()

    def get_by_id(self, db: Session, session_id: str):
        return db.query(SessionModel).filter(
            SessionModel.id == session_id
        ).first()

    def create(self, db: Session, session_data: dict):
        session_row = SessionModel(**session_data)

        db.add(session_row)
        db.commit()
        db.refresh(session_row)

        return session_row

    def update(self, db: Session, session_id: str, update_data: dict):
        session_row = self.get_by_id(db, session_id)

        if not session_row:
            return None

        for key, value in update_data.items():
            setattr(session_row, key, value)

        db.commit()
        db.refresh(session_row)

        return session_row

    def delete(self, db: Session, session_id: str):
        session_row = self.get_by_id(db, session_id)

        if not session_row:
            return None

        db.delete(session_row)
        db.commit()

        return session_row