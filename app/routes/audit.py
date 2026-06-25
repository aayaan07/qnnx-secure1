"""
routes/audit.py — Audit log query endpoints.

  GET /api/v1/audit                            — List recent audit log entries
  GET /api/v1/audit/clients/{client_id}        — Audit entries for one client
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session as DBSession

from app.core.database import get_db
from app.repositories.audit_log_repo import AuditLogRepository

logger = logging.getLogger("qvpn.routes.audit")

router = APIRouter(tags=["Audit Logs"])

_repo = AuditLogRepository()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class AuditLogOut(BaseModel):
    id:          str
    client_id:   Optional[str]
    method:      str
    path:        str
    status_code: int
    duration_ms: Optional[int]
    ip_address:  Optional[str]
    user_agent:  Optional[str]
    created_at:  datetime

    model_config = {"from_attributes": True}


def _to_out(row) -> AuditLogOut:
    return AuditLogOut(
        id          = str(row.id),
        client_id   = str(row.client_id) if row.client_id else None,
        method      = row.method,
        path        = row.path,
        status_code = row.status_code,
        duration_ms = row.duration_ms,
        ip_address  = row.ip_address,
        user_agent  = row.user_agent,
        created_at  = row.created_at,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/audit",
    response_model=List[AuditLogOut],
    summary="List audit log entries",
    description=(
        "Returns recent gateway request audit records. "
        "Filterable by path prefix, HTTP status code, and time range."
    ),
)
def list_audit_logs(
    path_prefix:  Optional[str] = Query(None, description="Filter by path prefix, e.g. /api/v1/agent"),
    status_code:  Optional[int] = Query(None, description="Filter by HTTP status code, e.g. 401"),
    since:        Optional[datetime] = Query(None, description="Return entries after this ISO timestamp"),
    limit:        int = Query(100, ge=1, le=1000),
    db:           DBSession = Depends(get_db),
):
    rows = _repo.list(
        db,
        path_prefix=path_prefix,
        status_code=status_code,
        since=since,
        limit=limit,
    )
    return [_to_out(r) for r in rows]


@router.get(
    "/audit/clients/{client_id}",
    response_model=List[AuditLogOut],
    summary="List audit log entries for a specific client",
)
def list_client_audit_logs(
    client_id:   str,
    path_prefix: Optional[str] = Query(None),
    status_code: Optional[int] = Query(None),
    since:       Optional[datetime] = Query(None),
    limit:       int = Query(100, ge=1, le=1000),
    db:          DBSession = Depends(get_db),
):
    rows = _repo.list(
        db,
        client_id=client_id,
        path_prefix=path_prefix,
        status_code=status_code,
        since=since,
        limit=limit,
    )
    return [_to_out(r) for r in rows]
