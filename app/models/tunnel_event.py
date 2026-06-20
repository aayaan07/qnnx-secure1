from sqlalchemy import Column, Text, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func

from app.core.database import Base


class TunnelEvent(Base):
    """
    An immutable audit-log entry for a single notable event in a tunnel session.

    Events are append-only; never update or delete rows in this table.

    Example event_type values:
      "HANDSHAKE_INIT"       → client opened TCP connection and sent ciphertext
      "HANDSHAKE_COMPLETE"   → decapsulation succeeded; AES key live
      "HEARTBEAT"            → client sent a ping control packet
      "TARGET_CONNECTED"     → gateway opened TCP to the destination host
      "TRAFFIC_STARTED"      → first data packet forwarded
      "CLIENT_DISCONNECT"    → client closed the connection
      "GATEWAY_TIMEOUT"      → missed heartbeat threshold exceeded
      "ERROR"                → unexpected exception in the tunnel

    The `details` JSONB field holds event-specific structured data (e.g.
    target host/port for TARGET_CONNECTED, error message for ERROR, etc.).
    """
    __tablename__ = "tunnel_events"

    id = Column(UUID(as_uuid=True), primary_key=True)

    session_id = Column(UUID(as_uuid=True), ForeignKey("sessions.id"), nullable=False)

    event_type = Column(Text, nullable=False)

    # Optional free-form JSON payload
    details = Column(JSONB, nullable=True)

    occurred_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


# Indexes
_idx_event_session_id = Index("ix_tunnel_events_session_id", TunnelEvent.session_id)
_idx_event_type = Index("ix_tunnel_events_event_type", TunnelEvent.event_type)
_idx_event_occurred_at = Index("ix_tunnel_events_occurred_at", TunnelEvent.occurred_at)
