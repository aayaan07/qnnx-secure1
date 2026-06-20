from sqlalchemy.orm import Session
from app.models.user_activity import UserActivity

class UserActivityRepository:

    def create(self, db: Session, activity_data: dict) -> UserActivity:
        activity = UserActivity(**activity_data)
        db.add(activity)
        db.commit()
        db.refresh(activity)
        return activity

    def get_all(self, db: Session) -> list[UserActivity]:
        return db.query(UserActivity).order_by(UserActivity.recorded_at.desc()).all()
