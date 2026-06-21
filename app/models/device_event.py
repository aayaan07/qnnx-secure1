"""
models/device_event.py — USB device insertion/removal events from the Monitoring Agent.

Sourced from the WMI Win32_DeviceChangeEvent watcher in windows_agent._wmi_usb_watcher().
EventType 2 = Arrival (inserted), EventType 3 = Removal (removed).
"""
import uuid as _uuid
from sqlalchemy import Column, Text, DateTime, ForeignKey, Index, JSON
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class DeviceEvent(Base):
    """
    USB device lifecycle event.

    action values:
      "inserted" — device connected (WMI EventType 2)
      "removed"  — device disconnected (WMI EventType 3)

    device_info JSON preserves the raw hardware identifier supplied by the agent
    (e.g. hardware_id, device name). Schema is flexible to accommodate different
    WMI event payloads across Windows versions.
    """
    __tablename__ = "device_events"

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

    # "inserted" or "removed"
    action = Column(Text, nullable=False)

    # Free-form device descriptor JSON (hardware_id, etc.)
    device_info = Column(JSON, nullable=True)


# Indexes
_idx_devevt_client_ts = Index(
    "ix_device_events_client_id_timestamp",
    DeviceEvent.client_id,
    DeviceEvent.timestamp,
)
_idx_devevt_client_id = Index("ix_device_events_client_id", DeviceEvent.client_id)
_idx_devevt_action = Index("ix_device_events_action", DeviceEvent.action)
