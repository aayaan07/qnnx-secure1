from sqlalchemy import Column, Text, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class SecurityAlert(Base):
    """
    Threat detection alerts (e.g. Failed Logins, Heartbeat Loss, USB Inserted)
    stored in the database for dashboard query.
    """
    __tablename__ = "security_alerts"

    id = Column(UUID(as_uuid=True), primary_key=True)

    # e.g., "FAILED_LOGIN", "TUNNEL_FAILURE", "HEARTBEAT_LOSS", "USB_INSERTION"
    alert_type = Column(Text, nullable=False)

    # e.g., "LOW", "MEDIUM", "HIGH"
    severity = Column(Text, nullable=False)

    description = Column(Text, nullable=False)

    # e.g., "OPEN", "RESOLVED"
    status = Column(Text, nullable=False, server_default="OPEN")

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
