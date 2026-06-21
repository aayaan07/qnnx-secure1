"""
models/user_activity.py — Login / logout / failed-login events from the Monitoring Agent.

The agent sources these from the Windows Security Event Log (event IDs 4624, 4625,
4634, 4647). The gateway route maps those IDs to structured event_type values.
"""
import uuid as _uuid
from sqlalchemy import Column, Text, DateTime, ForeignKey, Index, JSON
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class UserActivity(Base):
    """
    Windows Security Event Log entry, normalized.

    event_type values:
      "login"        — Event ID 4624 (successful logon)
      "failed_login" — Event ID 4625 (failed logon)
      "logout"       — Event ID 4634 or 4647 (logoff)
      "unknown"      — any other event ID captured for forward-compat

    username is extracted from the event details when available;
    raw Windows event data is preserved in the `details` JSON field.
    """
    __tablename__ = "user_activities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)

    client_id = Column(
        UUID(as_uuid=True),
        ForeignKey("clients.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Normalized event type: login / logout / failed_login / unknown
    event_type = Column(Text, nullable=False)

    # Username extracted from the event (may be None if not available)
    username = Column(Text, nullable=True)

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Raw event details preserved (Windows event_id, time_generated, etc.)
    details = Column(JSON, nullable=True)


# Indexes
_idx_useract_client_ts = Index(
    "ix_user_activities_client_id_timestamp",
    UserActivity.client_id,
    UserActivity.timestamp,
)
_idx_useract_client_id = Index("ix_user_activities_client_id", UserActivity.client_id)
_idx_useract_event_type = Index("ix_user_activities_event_type", UserActivity.event_type)
