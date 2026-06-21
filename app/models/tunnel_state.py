import uuid as _uuid
from sqlalchemy import Column, Text, Integer, DateTime, ForeignKey, Index
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class TunnelState(Base):
    """
    Live health/status of a tunnel tied to one session.

    Updated continuously while the tunnel is active (e.g. on every heartbeat
    packet from the client). The gateway socket server queries this table to
    decide whether to keep forwarding traffic or to close the connection.

    Status values:
      CONNECTING    → session established, waiting for first traffic packet
      ACTIVE        → traffic flowing normally
      DEGRADED      → missed heartbeats but not yet expired
      DISCONNECTED  → client cleanly disconnected
      TIMED_OUT     → no heartbeat within HEARTBEAT_TIMEOUT_SECONDS

    The health monitor task in socket_server.py transitions ACTIVE → TIMED_OUT
    when last_heartbeat is older than the configured threshold.
    """
    __tablename__ = "tunnel_states"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)

    # The associated session
    session_id = Column(UUID(as_uuid=True), ForeignKey("sessions.id"), nullable=False, unique=True)

    # Status values: "CONNECTING", "ACTIVE", "DEGRADED", "DISCONNECTED", "TIMED_OUT"
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


# Indexes for monitoring queries
_idx_tunnel_status = Index("ix_tunnel_states_status", TunnelState.status)
_idx_tunnel_session_id = Index("ix_tunnel_states_session_id", TunnelState.session_id)
_idx_tunnel_last_heartbeat = Index("ix_tunnel_states_last_heartbeat", TunnelState.last_heartbeat)