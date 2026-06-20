from sqlalchemy import Column, Text, Integer, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class UserActivity(Base):
    """
    Windows login and logout event logs forwarded by the Monitoring Agent.
    Event ID 4624 = Successful Login
    Event ID 4634 = Successful Logout
    """
    __tablename__ = "user_activities"

    id = Column(UUID(as_uuid=True), primary_key=True)
    client_identifier = Column(Text, nullable=False)

    event_id = Column(Integer, nullable=False)
    time_generated = Column(Text, nullable=False)
    record_number = Column(Integer, nullable=False)

    recorded_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
