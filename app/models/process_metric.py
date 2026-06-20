from sqlalchemy import Column, Text, Integer, Float, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class ProcessMetric(Base):
    """
    Active processes running on the client machine, sorted by CPU usage.
    """
    __tablename__ = "process_metrics"

    id = Column(UUID(as_uuid=True), primary_key=True)
    client_identifier = Column(Text, nullable=False)

    pid = Column(Integer, nullable=False)
    name = Column(Text, nullable=False)
    cpu_percent = Column(Float, nullable=False)

    recorded_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
