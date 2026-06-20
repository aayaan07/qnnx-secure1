from sqlalchemy import Column, BigInteger, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class TrafficStat(Base):
    """
    Traffic counters for a session. One row per session, incremented as
    data flows through the tunnel.
    """
    __tablename__ = "traffic_stats"

    id = Column(UUID(as_uuid=True), primary_key=True)

    session_id = Column(UUID(as_uuid=True), ForeignKey("sessions.id"), nullable=False)

    bytes_sent = Column(BigInteger, nullable=False, server_default="0")
    bytes_received = Column(BigInteger, nullable=False, server_default="0")
    packets_sent = Column(BigInteger, nullable=False, server_default="0")
    packets_received = Column(BigInteger, nullable=False, server_default="0")

    recorded_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )