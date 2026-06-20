"""
routes/sessions.py — REST API for session lifecycle management.

Endpoints:
  GET    /api/v1/sessions                    — List sessions (filterable by status)
  GET    /api/v1/sessions/{session_id}       — Get a single session
  DELETE /api/v1/sessions/{session_id}       — Close a session
  POST   /api/v1/sessions/{session_id}/heartbeat  — Record a heartbeat for a session
  GET    /api/v1/sessions/{session_id}/events     — List audit events for a session
  POST   /api/v1/sessions/{session_id}/events     — Append a custom event
  GET    /api/v1/sessions/{session_id}/stats      — Get traffic statistics
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, UUID4
from sqlalchemy.orm import Session as DBSession

from app.core.database import get_db
from app.core.exceptions import SessionNotFound
from app.gateway.session_store import session_store
from app.repositories.tunnel_state_repo import TunnelStateRepository
from app.services import event_service, session_service, stats_service

logger = logging.getLogger("qvpn.routes.sessions")

router = APIRouter(prefix="/sessions", tags=["Sessions"])

_tunnel_state_repo = TunnelStateRepository()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class SessionOut(BaseModel):
    session_id: str
    client_id: str
    kem_algorithm: str
    kem_state: str
    tunnel_status: str
    pqc_key_id: Optional[str]
    created_at: Optional[datetime]
    established_at: Optional[datetime]
    closed_at: Optional[datetime]
    aes_key_active: bool  # True if AES key is live in session_store

    model_config = {"from_attributes": True}


class TunnelStateOut(BaseModel):
    status: str
    remote_ip: Optional[str]
    remote_port: Optional[int]
    assigned_virtual_ip: Optional[str]
    last_heartbeat: Optional[datetime]
    missed_heartbeats: int
    established_at: Optional[datetime]

    model_config = {"from_attributes": True}


class SessionDetailOut(SessionOut):
    tunnel_state: Optional[TunnelStateOut]


class EventOut(BaseModel):
    event_id: str
    session_id: str
    event_type: str
    details: Optional[dict]
    occurred_at: datetime

    model_config = {"from_attributes": True}


class EventCreateRequest(BaseModel):
    event_type: str
    details: Optional[dict] = None


class TrafficStatsOut(BaseModel):
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    recorded_at: Optional[datetime]

    model_config = {"from_attributes": True}


class HeartbeatResponse(BaseModel):
    session_id: str
    status: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _session_or_404(db: DBSession, session_id: str):
    session = session_service.get_session(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return session


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=List[SessionOut],
    summary="List VPN sessions",
    description="Return all sessions, optionally filtered by tunnel_status.",
)
def list_sessions(
    tunnel_status: Optional[str] = Query(None, description="Filter by tunnel_status, e.g. ACTIVE, CLOSED"),
    db: DBSession = Depends(get_db),
):
    sessions = session_service.list_sessions(db, tunnel_status=tunnel_status)
    result = []
    for s in sessions:
        result.append(SessionOut(
            session_id=str(s.id),
            client_id=str(s.client_id),
            kem_algorithm=s.kem_algorithm,
            kem_state=s.kem_state,
            tunnel_status=s.tunnel_status,
            pqc_key_id=s.pqc_key_id,
            created_at=s.created_at,
            established_at=s.established_at,
            closed_at=s.closed_at,
            aes_key_active=str(s.id) in session_store,
        ))
    return result


@router.get(
    "/{session_id}",
    response_model=SessionDetailOut,
    summary="Get session details",
)
def get_session(session_id: str, db: DBSession = Depends(get_db)):
    s = _session_or_404(db, session_id)
    ts = _tunnel_state_repo.get_by_session_id(db, session_id)

    tunnel_state_out = None
    if ts:
        tunnel_state_out = TunnelStateOut(
            status=ts.status,
            remote_ip=ts.remote_ip,
            remote_port=ts.remote_port,
            assigned_virtual_ip=ts.assigned_virtual_ip,
            last_heartbeat=ts.last_heartbeat,
            missed_heartbeats=ts.missed_heartbeats or 0,
            established_at=ts.established_at,
        )

    return SessionDetailOut(
        session_id=str(s.id),
        client_id=str(s.client_id),
        kem_algorithm=s.kem_algorithm,
        kem_state=s.kem_state,
        tunnel_status=s.tunnel_status,
        pqc_key_id=s.pqc_key_id,
        created_at=s.created_at,
        established_at=s.established_at,
        closed_at=s.closed_at,
        aes_key_active=session_id in session_store,
        tunnel_state=tunnel_state_out,
    )


@router.delete(
    "/{session_id}",
    status_code=204,
    summary="Close a session",
    description="Closes the session, evicts the AES key from memory, and records a CLOSED event.",
)
def close_session(session_id: str, db: DBSession = Depends(get_db)):
    s = _session_or_404(db, session_id)
    session_service.close_session(db, session_id, reason="ADMIN_CLOSE")


@router.post(
    "/{session_id}/heartbeat",
    response_model=HeartbeatResponse,
    summary="Record a session heartbeat",
    description="Updates the last_heartbeat timestamp and resets missed_heartbeats to 0.",
)
def record_heartbeat(session_id: str, db: DBSession = Depends(get_db)):
    _session_or_404(db, session_id)
    ts = _tunnel_state_repo.get_by_session_id(db, session_id)
    if not ts:
        raise HTTPException(status_code=404, detail=f"No tunnel state for session '{session_id}'")
    _tunnel_state_repo.record_heartbeat(db, session_id)
    return HeartbeatResponse(session_id=session_id, status="ok")


@router.get(
    "/{session_id}/events",
    response_model=List[EventOut],
    summary="List tunnel events for a session",
)
def list_events(
    session_id: str,
    limit: int = Query(100, ge=1, le=1000),
    db: DBSession = Depends(get_db),
):
    _session_or_404(db, session_id)
    events = event_service.list_events(db, session_id, limit=limit)
    return [
        EventOut(
            event_id=str(e.id),
            session_id=str(e.session_id),
            event_type=e.event_type,
            details=e.details,
            occurred_at=e.occurred_at,
        )
        for e in events
    ]


@router.post(
    "/{session_id}/events",
    response_model=EventOut,
    status_code=201,
    summary="Append a custom tunnel event",
)
def create_event(
    session_id: str,
    payload: EventCreateRequest,
    db: DBSession = Depends(get_db),
):
    _session_or_404(db, session_id)
    e = event_service.record_event(
        db=db,
        session_id=session_id,
        event_type=payload.event_type,
        details=payload.details,
    )
    return EventOut(
        event_id=str(e.id),
        session_id=str(e.session_id),
        event_type=e.event_type,
        details=e.details,
        occurred_at=e.occurred_at,
    )


@router.get(
    "/{session_id}/stats",
    response_model=TrafficStatsOut,
    summary="Get traffic statistics for a session",
)
def get_stats(session_id: str, db: DBSession = Depends(get_db)):
    _session_or_404(db, session_id)
    stat = stats_service.get_session_stats(db, session_id)
    if not stat:
        raise HTTPException(status_code=404, detail=f"No traffic stats for session '{session_id}'")
    return TrafficStatsOut(
        bytes_sent=stat.bytes_sent,
        bytes_received=stat.bytes_received,
        packets_sent=stat.packets_sent,
        packets_received=stat.packets_received,
        recorded_at=stat.recorded_at,
    )
