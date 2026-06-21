"""
models/network_activity.py — Network connection and IP-change events from the Monitoring Agent.

Covers two sub-types from the agent:
  NETWORK_ACTIVITY — active TCP connection enumerated by poll_network_connections()
  IP_CHANGE        — public IP address change detected by poll_public_ip()

Both are stored in this table, differentiated by event_type.
"""
import uuid as _uuid
from sqlalchemy import Column, Text, DateTime, ForeignKey, Index, JSON
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class NetworkActivity(Base):
    """
    Network-layer event observed by the Monitoring Agent.

    event_type values:
      "new_connection" — a new established TCP connection (from poll_network_connections)
      "ip_change"      — the client's public IP changed (from poll_public_ip)

    The `details` JSON field carries event-specific data:
      new_connection: { pid, local_port, remote_ip, remote_port }
      ip_change:      { old_ip, new_ip }
    """
    __tablename__ = "network_activities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)

    client_id = Column(
        UUID(as_uuid=True),
        ForeignKey("clients.id", ondelete="CASCADE"),
        nullable=False,
    )

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # "new_connection" or "ip_change"
    event_type = Column(Text, nullable=False)

    # Structured event payload
    details = Column(JSON, nullable=True)


# Indexes
_idx_netact_client_ts = Index(
    "ix_network_activities_client_id_timestamp",
    NetworkActivity.client_id,
    NetworkActivity.timestamp,
)
_idx_netact_client_id = Index("ix_network_activities_client_id", NetworkActivity.client_id)
_idx_netact_event_type = Index("ix_network_activities_event_type", NetworkActivity.event_type)
