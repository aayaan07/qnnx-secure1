from sqlalchemy import Column, Text, Integer, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class NetworkActivity(Base):
    """
    Active internet connections currently established on the client machine.
    """
    __tablename__ = "network_activities"

    id = Column(UUID(as_uuid=True), primary_key=True)
    client_identifier = Column(Text, nullable=False)

    pid = Column(Integer, nullable=False)
    local_port = Column(Integer, nullable=False)
    remote_ip = Column(Text, nullable=False)
    remote_port = Column(Integer, nullable=False)

    recorded_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
