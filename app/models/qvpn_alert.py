"""
models/qvpn_alert.py — Security alerts from the embedded client agent.

Maps to the existing public.qvpn_alerts table:
  alert_id  uuid  PK
  client_id uuid  FK → clients(id)
  timestamp timestamptz
  severity  varchar
  description varchar
  status    varchar  (nullable)
"""
import uuid as _uuid
from sqlalchemy import Column, Text, DateTime, ForeignKey, Index
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class QVPNAlert(Base):
    __tablename__ = "qvpn_alerts"

    alert_id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)

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

    severity    = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    status      = Column(Text, nullable=True, default="open")


_idx_alert_client_ts = Index(
    "ix_qvpn_alerts_client_id_timestamp",
    QVPNAlert.client_id,
    QVPNAlert.timestamp,
)
