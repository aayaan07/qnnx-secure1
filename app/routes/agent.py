"""
routes/agent.py — Monitoring agent data ingestion and query endpoints.

Ingestion (POST):
  POST /api/v1/agent/metrics   — Batch CPU/RAM/disk readings
  POST /api/v1/agent/activity  — Batch login/logout/failed-login events
  POST /api/v1/agent/network   — Batch network connection / IP-change events
  POST /api/v1/agent/process   — Batch process launch/terminate events
  POST /api/v1/agent/device    — Batch USB device events

Query (GET):
  GET /api/v1/clients/{client_id}/metrics
  GET /api/v1/clients/{client_id}/activity
  GET /api/v1/clients/{client_id}/network
  GET /api/v1/clients/{client_id}/process
  GET /api/v1/clients/{client_id}/device

Security alerts are handled separately in routes/alerts.py.

All routes require the standard X-API-Key authentication applied at the router
level in main.py. Batch rejection policy: entire batch rejected (422) on any
invalid record — no partial inserts.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DBSession

from app.core.database import get_db
from app.repositories.monitoring_repo import (
    SystemMetricRepository,
    UserActivityRepository,
    NetworkActivityRepository,
    ProcessEventRepository,
    DeviceEventRepository,
)
from app.services import monitoring_service

logger = logging.getLogger("qvpn.routes.agent")

router = APIRouter(tags=["Monitoring Agent"])

_metric_repo   = SystemMetricRepository()
_activity_repo = UserActivityRepository()
_network_repo  = NetworkActivityRepository()
_process_repo  = ProcessEventRepository()
_device_repo   = DeviceEventRepository()


# ---------------------------------------------------------------------------
# Pydantic schemas — ingestion
# ---------------------------------------------------------------------------

class SystemMetricItem(BaseModel):
    cpu_usage:   float = Field(..., ge=0, le=100)
    ram_usage:   float = Field(..., ge=0, le=100)
    disk_usage:  float = Field(..., ge=0, le=100)
    recorded_at: Optional[str] = None


class MetricsBatchRequest(BaseModel):
    client_identifier: str
    readings: Union[SystemMetricItem, List[SystemMetricItem]]


class UserActivityItem(BaseModel):
    event_id:       int
    time_generated: Optional[str] = None
    record_number:  Optional[int] = None
    username:       Optional[str] = None


class ActivityBatchRequest(BaseModel):
    client_identifier: str
    events: Union[UserActivityItem, List[UserActivityItem]]


class NetworkActivityItem(BaseModel):
    event_type:  str = "NETWORK_ACTIVITY"
    pid:         Optional[int] = None
    local_port:  Optional[int] = None
    remote_ip:   Optional[str] = None
    remote_port: Optional[int] = None
    details:     Optional[dict] = None
    recorded_at: Optional[str] = None
    timestamp:   Optional[str] = None


class NetworkBatchRequest(BaseModel):
    client_identifier: str
    events: Union[NetworkActivityItem, List[NetworkActivityItem]]


class ProcessEventItem(BaseModel):
    process_name: str
    pid:          Optional[int] = None
    action:       Optional[str] = None
    event_type:   Optional[str] = None
    timestamp:    Optional[str] = None


class ProcessBatchRequest(BaseModel):
    client_identifier: str
    events: Union[ProcessEventItem, List[ProcessEventItem]]


class DeviceEventItem(BaseModel):
    action:      Optional[str] = None
    event_type:  Optional[str] = None
    hardware_id: Optional[str] = None
    device_info: Optional[dict] = None
    timestamp:   Optional[str] = None


class DeviceBatchRequest(BaseModel):
    client_identifier: str
    events: Union[DeviceEventItem, List[DeviceEventItem]]


# ---------------------------------------------------------------------------
# Pydantic schemas — query responses
# ---------------------------------------------------------------------------

class SystemMetricOut(BaseModel):
    id:           str
    client_id:    str
    timestamp:    datetime
    cpu_percent:  float
    ram_percent:  float
    disk_percent: float
    model_config = {"from_attributes": True}


class UserActivityOut(BaseModel):
    id:         str
    client_id:  str
    event_type: str
    username:   Optional[str]
    timestamp:  datetime
    details:    Optional[dict]
    model_config = {"from_attributes": True}


class NetworkActivityOut(BaseModel):
    id:         str
    client_id:  str
    timestamp:  datetime
    event_type: str
    details:    Optional[dict]
    model_config = {"from_attributes": True}


class ProcessEventOut(BaseModel):
    id:           str
    client_id:    str
    process_name: str
    pid:          Optional[int]
    action:       str
    timestamp:    datetime
    model_config = {"from_attributes": True}


class DeviceEventOut(BaseModel):
    id:          str
    client_id:   str
    timestamp:   datetime
    action:      str
    device_info: Optional[dict]
    model_config = {"from_attributes": True}


class IngestResponse(BaseModel):
    inserted: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_list(value):
    if isinstance(value, list):
        return [item.model_dump() for item in value]
    return [value.model_dump()]


def _handle_ingest_error(exc: Exception):
    msg = str(exc)
    if "not found" in msg.lower() or "not registered" in msg.lower():
        raise HTTPException(status_code=401, detail=msg)
    if "inactive" in msg.lower():
        raise HTTPException(status_code=403, detail=msg)
    raise HTTPException(status_code=422, detail=msg)


# ---------------------------------------------------------------------------
# POST — ingestion endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/agent/metrics",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest system metrics batch",
)
def ingest_metrics(payload: MetricsBatchRequest, db: DBSession = Depends(get_db)):
    readings = _normalize_list(payload.readings)
    try:
        created = monitoring_service.ingest_metrics(
            db=db, client_identifier=payload.client_identifier, readings=readings,
        )
    except ValueError as exc:
        _handle_ingest_error(exc)
    return IngestResponse(inserted=len(created))


@router.post(
    "/agent/activity",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest user activity events batch",
)
def ingest_activity(payload: ActivityBatchRequest, db: DBSession = Depends(get_db)):
    events = _normalize_list(payload.events)
    try:
        created = monitoring_service.ingest_activity(
            db=db, client_identifier=payload.client_identifier, events=events,
        )
    except ValueError as exc:
        _handle_ingest_error(exc)
    return IngestResponse(inserted=len(created))


@router.post(
    "/agent/network",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest network activity events batch",
)
def ingest_network(payload: NetworkBatchRequest, db: DBSession = Depends(get_db)):
    events = _normalize_list(payload.events)
    try:
        created = monitoring_service.ingest_network(
            db=db, client_identifier=payload.client_identifier, events=events,
        )
    except ValueError as exc:
        _handle_ingest_error(exc)
    return IngestResponse(inserted=len(created))


@router.post(
    "/agent/process",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest process events batch",
)
def ingest_process(payload: ProcessBatchRequest, db: DBSession = Depends(get_db)):
    events = _normalize_list(payload.events)
    try:
        created = monitoring_service.ingest_process(
            db=db, client_identifier=payload.client_identifier, events=events,
        )
    except ValueError as exc:
        _handle_ingest_error(exc)
    return IngestResponse(inserted=len(created))


@router.post(
    "/agent/device",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest USB device events batch",
)
def ingest_device(payload: DeviceBatchRequest, db: DBSession = Depends(get_db)):
    events = _normalize_list(payload.events)
    try:
        created = monitoring_service.ingest_device(
            db=db, client_identifier=payload.client_identifier, events=events,
        )
    except ValueError as exc:
        _handle_ingest_error(exc)
    return IngestResponse(inserted=len(created))


# ---------------------------------------------------------------------------
# GET — per-client query endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/clients/{client_id}/metrics",
    response_model=List[SystemMetricOut],
    summary="Query system metrics for a client",
)
def get_client_metrics(
    client_id: str,
    since: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db: DBSession = Depends(get_db),
):
    rows = _metric_repo.list_by_client(db, client_id, since=since, limit=limit)
    return [
        SystemMetricOut(
            id=str(r.id), client_id=str(r.client_id), timestamp=r.timestamp,
            cpu_percent=r.cpu_percent, ram_percent=r.ram_percent, disk_percent=r.disk_percent,
        ) for r in rows
    ]


@router.get(
    "/clients/{client_id}/activity",
    response_model=List[UserActivityOut],
    summary="Query user activity events for a client",
)
def get_client_activity(
    client_id: str,
    since: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db: DBSession = Depends(get_db),
):
    rows = _activity_repo.list_by_client(db, client_id, since=since, limit=limit)
    return [
        UserActivityOut(
            id=str(r.id), client_id=str(r.client_id), event_type=r.event_type,
            username=r.username, timestamp=r.timestamp, details=r.details,
        ) for r in rows
    ]


@router.get(
    "/clients/{client_id}/network",
    response_model=List[NetworkActivityOut],
    summary="Query network activity events for a client",
)
def get_client_network(
    client_id: str,
    since: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db: DBSession = Depends(get_db),
):
    rows = _network_repo.list_by_client(db, client_id, since=since, limit=limit)
    return [
        NetworkActivityOut(
            id=str(r.id), client_id=str(r.client_id), timestamp=r.timestamp,
            event_type=r.event_type, details=r.details,
        ) for r in rows
    ]


@router.get(
    "/clients/{client_id}/process",
    response_model=List[ProcessEventOut],
    summary="Query process events for a client",
)
def get_client_process(
    client_id: str,
    since: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db: DBSession = Depends(get_db),
):
    rows = _process_repo.list_by_client(db, client_id, since=since, limit=limit)
    return [
        ProcessEventOut(
            id=str(r.id), client_id=str(r.client_id), process_name=r.process_name,
            pid=r.pid, action=r.action, timestamp=r.timestamp,
        ) for r in rows
    ]


@router.get(
    "/clients/{client_id}/device",
    response_model=List[DeviceEventOut],
    summary="Query USB device events for a client",
)
def get_client_device(
    client_id: str,
    since: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db: DBSession = Depends(get_db),
):
    rows = _device_repo.list_by_client(db, client_id, since=since, limit=limit)
    return [
        DeviceEventOut(
            id=str(r.id), client_id=str(r.client_id), timestamp=r.timestamp,
            action=r.action, device_info=r.device_info,
        ) for r in rows
    ]
