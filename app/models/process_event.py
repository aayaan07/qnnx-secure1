"""
models/process_event.py — Process launch/terminate events from the Monitoring Agent.

Sourced from the WMI Win32_Process watcher in windows_agent._wmi_process_watcher().
Currently the agent captures process creation only (action=launched). The schema
supports termination events for future WMI termination watch support.
"""
import uuid as _uuid
from sqlalchemy import Column, Text, Integer, DateTime, ForeignKey, Index
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class ProcessEvent(Base):
    """
    OS process lifecycle event.

    action values:
      "launched"   — process was created (WMI creation event)
      "terminated" — process exited (reserved for future WMI deletion watch)

    process_name and pid match the fields provided by the agent.
    """
    __tablename__ = "process_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)

    client_id = Column(
        UUID(as_uuid=True),
        ForeignKey("clients.id", ondelete="CASCADE"),
        nullable=False,
    )

    process_name = Column(Text, nullable=False)
    pid = Column(Integer, nullable=True)

    # "launched" or "terminated"
    action = Column(Text, nullable=False)

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


# Indexes
_idx_procevt_client_ts = Index(
    "ix_process_events_client_id_timestamp",
    ProcessEvent.client_id,
    ProcessEvent.timestamp,
)
_idx_procevt_client_id = Index("ix_process_events_client_id", ProcessEvent.client_id)
_idx_procevt_process_name = Index("ix_process_events_process_name", ProcessEvent.process_name)
