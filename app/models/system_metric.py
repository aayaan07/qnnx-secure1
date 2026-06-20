from sqlalchemy import Column, Text, Float, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class SystemMetric(Base):
    """
    Client resource statistics (CPU, RAM, Disk) sent by the Monitoring Agent.
    """
    __tablename__ = "system_metrics"

    id = Column(UUID(as_uuid=True), primary_key=True)
    
    # Identifier of the reporting client device
    client_identifier = Column(Text, nullable=False)

    cpu_usage = Column(Float, nullable=False)
    ram_usage = Column(Float, nullable=False)
    disk_usage = Column(Float, nullable=False)

    recorded_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
