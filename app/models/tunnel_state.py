from sqlalchemy import Column, Text, Integer, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class TunnelState(Base):
    """
    Live health/status of a tunnel tied to one session. Updated continuously
    while the tunnel is active (e.g. on every heartbeat packet).
    """
    __tablename__ = "tunnel_states"

    id = Column(UUID(as_uuid=True), primary_key=True)

    session_id = Column(UUID(as_uuid=True), ForeignKey("sessions.id"), nullable=False, unique=True)

    # status values: "CONNECTING", "ACTIVE", "DEGRADED", "DISCONNECTED"
    status = Column(Text, nullable=False, server_default="CONNECTING")

    remote_ip = Column(Text)
    remote_port = Column(Integer)
    assigned_virtual_ip = Column(Text)

    last_heartbeat = Column(DateTime(timezone=True))
    missed_heartbeats = Column(Integer, nullable=False, server_default="0")

    established_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )