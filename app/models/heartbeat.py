"""
models/heartbeat.py — Append-only heartbeat log per session.

One row is inserted per heartbeat packet received from the VPN client.
The live tunnel health status is tracked separately in tunnel_states.
"""
import uuid as _uuid
from sqlalchemy import Column, Integer, BigInteger, DateTime, ForeignKey, Index
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class Heartbeat(Base):
    """
    Immutable heartbeat record.

    Each row represents one heartbeat ping received from the client.
    Do NOT update or delete rows — this is an append-only audit log.

    Fields:
      sequence_number  — monotonically increasing counter from the client
      packets_sent     — cumulative packets sent by client at time of ping
      packets_received — cumulative packets received by client at time of ping
    """
    __tablename__ = "heartbeats"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)

    session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
    )

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    sequence_number = Column(Integer, nullable=False, server_default="0")
    packets_sent = Column(BigInteger, nullable=False, server_default="0")
    packets_received = Column(BigInteger, nullable=False, server_default="0")


# Indexes — queried by session_id + time range constantly
_idx_heartbeat_session_ts = Index(
    "ix_heartbeats_session_id_timestamp",
    Heartbeat.session_id,
    Heartbeat.timestamp,
)
_idx_heartbeat_session_id = Index("ix_heartbeats_session_id", Heartbeat.session_id)
