"""
models/system_metric.py — System resource utilization metrics from the Monitoring Agent.

One row per metric reading (CPU / RAM / disk). The agent batch-inserts multiple
readings per HTTP call; each reading becomes its own row.
"""
import uuid as _uuid
from sqlalchemy import Column, Float, DateTime, ForeignKey, Index
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class SystemMetric(Base):
    """
    Point-in-time snapshot of client system resource usage.

    Sourced from the Windows Monitoring Agent's poll_system_metrics().
    The agent sends: cpu_usage, ram_usage, disk_usage (float %).
    These are stored as cpu_percent, ram_percent, disk_percent for clarity.
    """
    __tablename__ = "system_metrics"

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

    cpu_percent = Column(Float, nullable=False)
    ram_percent = Column(Float, nullable=False)
    disk_percent = Column(Float, nullable=False)


# Compound index for time-range queries per client
_idx_sysmetric_client_ts = Index(
    "ix_system_metrics_client_id_timestamp",
    SystemMetric.client_id,
    SystemMetric.timestamp,
)
_idx_sysmetric_client_id = Index("ix_system_metrics_client_id", SystemMetric.client_id)
