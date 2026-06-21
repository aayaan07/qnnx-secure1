"""
routes/agent.py — Monitoring Agent data ingestion and query endpoints.

Ingestion endpoints (POST):
  POST /agent/metrics   — Batch of system metric readings
  POST /agent/activity  — Batch of login/logout/failed-login events
  POST /agent/network   — Batch of network connection / IP-change events
  POST /agent/process   — Batch of process launch/terminate events
  POST /agent/device    — Batch of USB device events

Query endpoints (GET) — round-trip verification:
  GET /clients/{client_id}/metrics?since=&limit=
  GET /clients/{client_id}/activity?since=&limit=
  GET /clients/{client_id}/network?since=&limit=
  GET /clients/{client_id}/process?since=&limit=
  GET /clients/{client_id}/device?since=&limit=

All routes require the standard X-API-Key authentication dependency applied
at the router level in main.py — no per-route auth decoration needed.

Batch rejection policy: entire batch is rejected (422) if any single record
is invalid. No partial inserts occur.
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

_metric_repo = SystemMetricRepository()
_activity_repo = UserActivityRepository()
_network_repo = NetworkActivityRepository()
_process_repo = ProcessEventRepository()
_device_repo = DeviceEventRepository()


# ---------------------------------------------------------------------------
# Pydantic schemas — ingestion (match the agent's details dict keys exactly)
# ---------------------------------------------------------------------------

class SystemMetricItem(BaseModel):
    """One system metrics reading from the agent's poll_system_metrics()."""
    cpu_usage: float = Field(..., ge=0, le=100)
    ram_usage: float = Field(..., ge=0, le=100)
    disk_usage: float = Field(..., ge=0, le=100)
    recorded_at: Optional[str] = None  # ISO 8601 string; defaults to now()


class MetricsBatchRequest(BaseModel):
    """
    Batch of system metrics from one client.
    Accepts either a single item or a list.
    """
    client_identifier: str
    readings: Union[SystemMetricItem, List[SystemMetricItem]]


class UserActivityItem(BaseModel):
    """One Windows Security Event log entry."""
    event_id: int  # Windows event ID: 4624, 4625, 4634, 4647
    time_generated: Optional[str] = None
    record_number: Optional[int] = None
    username: Optional[str] = None


class ActivityBatchRequest(BaseModel):
    client_identifier: str
    events: Union[UserActivityItem, List[UserActivityItem]]


class NetworkActivityItem(BaseModel):
    """One network event — connection or IP change."""
    event_type: str = "NETWORK_ACTIVITY"  # NETWORK_ACTIVITY or IP_CHANGE
    # Connection fields (new_connection events)
    pid: Optional[int] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    # IP change fields
    details: Optional[dict] = None
    recorded_at: Optional[str] = None
    timestamp: Optional[str] = None


class NetworkBatchRequest(BaseModel):
    client_identifier: str
    events: Union[NetworkActivityItem, List[NetworkActivityItem]]


class ProcessEventItem(BaseModel):
    """One process launch or terminate event."""
    process_name: str
    pid: Optional[int] = None
    action: Optional[str] = None  # "launched" or "terminated"; inferred if absent
    event_type: Optional[str] = None  # Raw agent event_type for action inference
    timestamp: Optional[str] = None


class ProcessBatchRequest(BaseModel):
    client_identifier: str
    events: Union[ProcessEventItem, List[ProcessEventItem]]


class DeviceEventItem(BaseModel):
    """One USB device event."""
    action: Optional[str] = None  # "inserted" or "removed"
    event_type: Optional[str] = None  # "USB_INSERTION" or "USB_REMOVAL" (agent raw)
    hardware_id: Optional[str] = None
    device_info: Optional[dict] = None
    timestamp: Optional[str] = None


class DeviceBatchRequest(BaseModel):
    client_identifier: str
    events: Union[DeviceEventItem, List[DeviceEventItem]]


# ---------------------------------------------------------------------------
# Pydantic schemas — query responses
# ---------------------------------------------------------------------------

class SystemMetricOut(BaseModel):
    id: str
    client_id: str
    timestamp: datetime
    cpu_percent: float
    ram_percent: float
    disk_percent: float

    model_config = {"from_attributes": True}


class UserActivityOut(BaseModel):
    id: str
    client_id: str
    event_type: str
    username: Optional[str]
    timestamp: datetime
    details: Optional[dict]

    model_config = {"from_attributes": True}


class NetworkActivityOut(BaseModel):
    id: str
    client_id: str
    timestamp: datetime
    event_type: str
    details: Optional[dict]

    model_config = {"from_attributes": True}


class ProcessEventOut(BaseModel):
    id: str
    client_id: str
    process_name: str
    pid: Optional[int]
    action: str
    timestamp: datetime

    model_config = {"from_attributes": True}


class DeviceEventOut(BaseModel):
    id: str
    client_id: str
    timestamp: datetime
    action: str
    device_info: Optional[dict]

    model_config = {"from_attributes": True}


class IngestResponse(BaseModel):
    inserted: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_list(value):
    """Accept a single item or a list; always return a list of dicts."""
    if isinstance(value, list):
        return [item.model_dump() for item in value]
    return [value.model_dump()]


def _handle_ingest_error(exc: Exception):
    """Convert service-layer errors to appropriate HTTP responses."""
    msg = str(exc)
    if "not found" in msg.lower() or "not registered" in msg.lower():
        raise HTTPException(status_code=401, detail=msg)
    if "inactive" in msg.lower():
        raise HTTPException(status_code=403, detail=msg)
    raise HTTPException(status_code=422, detail=msg)


# ---------------------------------------------------------------------------
# POST Ingestion endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/agent/metrics",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest system metrics batch",
    description=(
        "Accept a batch of CPU/RAM/disk readings from the Monitoring Agent. "
        "The entire batch is rejected (422) if any single reading is invalid. "
        "Requires X-API-Key authentication."
    ),
)
def ingest_metrics(
    payload: MetricsBatchRequest,
    db: DBSession = Depends(get_db),
):
    readings = _normalize_list(payload.readings)
    try:
        created = monitoring_service.ingest_metrics(
            db=db,
            client_identifier=payload.client_identifier,
            readings=readings,
        )
    except ValueError as exc:
        _handle_ingest_error(exc)
    return IngestResponse(inserted=len(created))


@router.post(
    "/agent/activity",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest user activity events batch",
    description=(
        "Accept login/logout/failed-login events from the Monitoring Agent. "
        "Windows event IDs are normalized to event_type strings. "
        "Entire batch rejected on any invalid record."
    ),
)
def ingest_activity(
    payload: ActivityBatchRequest,
    db: DBSession = Depends(get_db),
):
    events = _normalize_list(payload.events)
    try:
        created = monitoring_service.ingest_activity(
            db=db,
            client_identifier=payload.client_identifier,
            events=events,
        )
    except ValueError as exc:
        _handle_ingest_error(exc)
    return IngestResponse(inserted=len(created))


@router.post(
    "/agent/network",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest network activity events batch",
    description=(
        "Accept network connection and IP-change events from the Monitoring Agent. "
        "Supports both NETWORK_ACTIVITY (TCP connections) and IP_CHANGE sub-types."
    ),
)
def ingest_network(
    payload: NetworkBatchRequest,
    db: DBSession = Depends(get_db),
):
    events = _normalize_list(payload.events)
    try:
        created = monitoring_service.ingest_network(
            db=db,
            client_identifier=payload.client_identifier,
            events=events,
        )
    except ValueError as exc:
        _handle_ingest_error(exc)
    return IngestResponse(inserted=len(created))


@router.post(
    "/agent/process",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest process events batch",
    description=(
        "Accept process launch/terminate events from the WMI watcher. "
        "action field is inferred from event_type if not explicitly provided."
    ),
)
def ingest_process(
    payload: ProcessBatchRequest,
    db: DBSession = Depends(get_db),
):
    events = _normalize_list(payload.events)
    try:
        created = monitoring_service.ingest_process(
            db=db,
            client_identifier=payload.client_identifier,
            events=events,
        )
    except ValueError as exc:
        _handle_ingest_error(exc)
    return IngestResponse(inserted=len(created))


@router.post(
    "/agent/device",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest USB device events batch",
    description=(
        "Accept USB insertion/removal events from the WMI device watcher. "
        "action is inferred from event_type (USB_INSERTION/USB_REMOVAL) if not explicit."
    ),
)
def ingest_device(
    payload: DeviceBatchRequest,
    db: DBSession = Depends(get_db),
):
    events = _normalize_list(payload.events)
    try:
        created = monitoring_service.ingest_device(
            db=db,
            client_identifier=payload.client_identifier,
            events=events,
        )
    except ValueError as exc:
        _handle_ingest_error(exc)
    return IngestResponse(inserted=len(created))


# ---------------------------------------------------------------------------
# GET Query endpoints (round-trip verification)
# ---------------------------------------------------------------------------

@router.get(
    "/clients/{client_id}/metrics",
    response_model=List[SystemMetricOut],
    summary="Query system metrics for a client",
)
def get_client_metrics(
    client_id: str,
    since: Optional[datetime] = Query(None, description="Return records after this ISO timestamp"),
    limit: int = Query(100, ge=1, le=1000),
    db: DBSession = Depends(get_db),
):
    rows = _metric_repo.list_by_client(db, client_id, since=since, limit=limit)
    return [
        SystemMetricOut(
            id=str(r.id),
            client_id=str(r.client_id),
            timestamp=r.timestamp,
            cpu_percent=r.cpu_percent,
            ram_percent=r.ram_percent,
            disk_percent=r.disk_percent,
        )
        for r in rows
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
            id=str(r.id),
            client_id=str(r.client_id),
            event_type=r.event_type,
            username=r.username,
            timestamp=r.timestamp,
            details=r.details,
        )
        for r in rows
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
            id=str(r.id),
            client_id=str(r.client_id),
            timestamp=r.timestamp,
            event_type=r.event_type,
            details=r.details,
        )
        for r in rows
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
            id=str(r.id),
            client_id=str(r.client_id),
            process_name=r.process_name,
            pid=r.pid,
            action=r.action,
            timestamp=r.timestamp,
        )
        for r in rows
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
            id=str(r.id),
            client_id=str(r.client_id),
            timestamp=r.timestamp,
            action=r.action,
            device_info=r.device_info,
        )
        for r in rows
    ]
