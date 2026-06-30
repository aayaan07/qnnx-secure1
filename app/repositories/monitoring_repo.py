"""
repositories/monitoring_repo.py — Data access for all 5 monitoring tables.

All repositories follow the same pattern:
  - bulk_insert(): accepts a list of pre-built model instances, inserts atomically
  - list_by_client(): time-range query for the given client_id

Bulk inserts are all-or-nothing within a single DB transaction.
If any row fails validation at the DB level, the whole batch is rolled back.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session as DBSession

from app.models.system_metric import SystemMetric
from app.models.network_activity import NetworkActivity
from app.models.process_event import ProcessEvent
from app.models.device_event import DeviceEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bulk_insert(db: DBSession, instances: list) -> list:
    """
    Insert a list of ORM instances atomically.

    Raises on DB-level constraint violations (the caller is responsible for
    Pydantic-level validation before calling this).
    """
    db.add_all(instances)
    db.commit()
    for obj in instances:
        db.refresh(obj)
    return instances


def _to_uuid(value) -> uuid.UUID:
    """
    Coerce a string or UUID to a uuid.UUID object.

    Required because SQLAlchemy's UUID(as_uuid=True) column type expects
    uuid.UUID objects for equality filters — passing a plain string works on
    PostgreSQL (which has a native UUID type) but fails on SQLite where the
    column stores the value as TEXT and the processor calls .hex on the value.
    By coercing to uuid.UUID here we stay compatible with both backends.
    """
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))


# ---------------------------------------------------------------------------
# SystemMetric
# ---------------------------------------------------------------------------

class SystemMetricRepository:

    def bulk_insert(self, db: DBSession, records: List[dict]) -> List[SystemMetric]:
        """
        Insert a batch of system metric readings.

        Each dict in records must contain: client_id, timestamp, cpu_percent,
        ram_percent, disk_percent.
        """
        instances = [
            SystemMetric(id=uuid.uuid4(), **r)
            for r in records
        ]
        return _bulk_insert(db, instances)

    def list_by_client(
        self,
        db: DBSession,
        client_id: str,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[SystemMetric]:
        q = (
            db.query(SystemMetric)
            .filter(SystemMetric.client_id == _to_uuid(client_id))
        )
        if since:
            q = q.filter(SystemMetric.timestamp >= since)
        return q.order_by(SystemMetric.timestamp.desc()).limit(limit).all()


# ---------------------------------------------------------------------------
# NetworkActivity
# ---------------------------------------------------------------------------

class NetworkActivityRepository:

    def bulk_insert(self, db: DBSession, records: List[dict]) -> List[NetworkActivity]:
        """
        Insert a batch of network activity events.

        Each dict must contain: client_id, event_type, timestamp.
        Optional: details (JSON).
        """
        instances = [
            NetworkActivity(id=uuid.uuid4(), **r)
            for r in records
        ]
        return _bulk_insert(db, instances)

    def list_by_client(
        self,
        db: DBSession,
        client_id: str,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[NetworkActivity]:
        q = (
            db.query(NetworkActivity)
            .filter(NetworkActivity.client_id == _to_uuid(client_id))
        )
        if since:
            q = q.filter(NetworkActivity.timestamp >= since)
        return q.order_by(NetworkActivity.timestamp.desc()).limit(limit).all()


# ---------------------------------------------------------------------------
# ProcessEvent
# ---------------------------------------------------------------------------

class ProcessEventRepository:

    def bulk_insert(self, db: DBSession, records: List[dict]) -> List[ProcessEvent]:
        """
        Insert a batch of process events.

        Each dict must contain: client_id, process_name, action, timestamp.
        Optional: pid.
        """
        instances = [
            ProcessEvent(id=uuid.uuid4(), **r)
            for r in records
        ]
        return _bulk_insert(db, instances)

    def list_by_client(
        self,
        db: DBSession,
        client_id: str,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[ProcessEvent]:
        q = (
            db.query(ProcessEvent)
            .filter(ProcessEvent.client_id == _to_uuid(client_id))
        )
        if since:
            q = q.filter(ProcessEvent.timestamp >= since)
        return q.order_by(ProcessEvent.timestamp.desc()).limit(limit).all()


# ---------------------------------------------------------------------------
# DeviceEvent
# ---------------------------------------------------------------------------

class DeviceEventRepository:

    def bulk_insert(self, db: DBSession, records: List[dict]) -> List[DeviceEvent]:
        """
        Insert a batch of USB device events.

        Each dict must contain: client_id, action, timestamp.
        Optional: device_info (JSON).
        """
        instances = [
            DeviceEvent(id=uuid.uuid4(), **r)
            for r in records
        ]
        return _bulk_insert(db, instances)

    def list_by_client(
        self,
        db: DBSession,
        client_id: str,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[DeviceEvent]:
        q = (
            db.query(DeviceEvent)
            .filter(DeviceEvent.client_id == _to_uuid(client_id))
        )
        if since:
            q = q.filter(DeviceEvent.timestamp >= since)
        return q.order_by(DeviceEvent.timestamp.desc()).limit(limit).all()
