from sqlalchemy import Column, Text, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class IPHistory(Base):
    """
    Historical log of public IP addresses seen on client devices.
    Used to track IP change events.
    """
    __tablename__ = "ip_history"

    id = Column(UUID(as_uuid=True), primary_key=True)
    client_identifier = Column(Text, nullable=False)

    ip_address = Column(Text, nullable=False)

    recorded_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
