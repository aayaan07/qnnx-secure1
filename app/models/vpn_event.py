from sqlalchemy import Column, Text, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class VPNEvent(Base):
    """
    QVPN Client state transition events (e.g. TUNNEL_UP, TUNNEL_DOWN, HEARTBEAT_LOSS).
    """
    __tablename__ = "vpn_events"

    id = Column(UUID(as_uuid=True), primary_key=True)
    client_identifier = Column(Text, nullable=False)

    event_type = Column(Text, nullable=False) # e.g. "TUNNEL_UP", "TUNNEL_DOWN", "HEARTBEAT_LOSS"
    ip_address = Column(Text, nullable=True)
    details = Column(Text, nullable=True)     # JSON string of extra details

    recorded_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
