from sqlalchemy import Column, BigInteger, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class TrafficStat(Base):
    """
    Cumulative traffic counters for a session.

    One row per session, incremented atomically as data flows through the
    tunnel. Queries use session_id to fetch stats for a specific session.

    Counters are incremented in batches (every 10 packets) from the socket
    server's pipe_* helpers to reduce DB write load.
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


# Indexes
_idx_traffic_session_id = Index("ix_traffic_stats_session_id", TrafficStat.session_id)
_idx_traffic_recorded_at = Index("ix_traffic_stats_recorded_at", TrafficStat.recorded_at)