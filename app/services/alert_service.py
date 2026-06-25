"""
services/alert_service.py — Business logic for security alert ingestion and querying.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session as DBSession

from app.models.qvpn_alert import QVPNAlert
from app.repositories.client_repo import ClientRepository

logger = logging.getLogger("qvpn.alert_service")

_client_repo = ClientRepository()

_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_VALID_STATUSES   = {"open", "acknowledged", "resolved", "suppressed"}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value) -> datetime:
    if not value:
        return _now_utc()
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return _now_utc()


def resolve_client(db: DBSession, client_id_str: str):
    """
    Resolve a client_identifier string or raw UUID string → Client ORM row.
    Raises ValueError if not found or inactive.
    """
    client = _client_repo.get_by_identifier(db, client_id_str)
    if not client:
        try:
            client = _client_repo.get_by_id(db, client_id_str)
        except (ValueError, Exception):
            client = None
    if not client:
        raise ValueError(f"Client not found: {client_id_str!r}")
    if not client.is_active:
        raise ValueError(f"Client is inactive: {client_id_str!r}")
    return client


def ingest_alert(db: DBSession, payload: dict) -> QVPNAlert:
    """
    Validate and persist one security alert from the client agent.

    payload keys: alert_id, client_id, timestamp, severity, description, status
    """
    client = resolve_client(db, payload["client_id"])

    severity = (payload.get("severity") or "").upper()
    if severity not in _VALID_SEVERITIES:
        raise ValueError(f"Invalid severity {severity!r}. Must be one of {sorted(_VALID_SEVERITIES)}")

    status = (payload.get("status") or "open").lower()
    if status not in _VALID_STATUSES:
        status = "open"

    try:
        alert_uuid = uuid.UUID(str(payload["alert_id"]))
    except (ValueError, KeyError):
        alert_uuid = uuid.uuid4()

    # Idempotent insert: if the alert_id already exists (client retry after
    # a lost response), return the existing row without error.
    existing = db.query(QVPNAlert).filter(QVPNAlert.alert_id == alert_uuid).first()
    if existing:
        logger.debug(
            "[ALERT] Duplicate alert_id=%s - returning existing row (client retry).",
            alert_uuid,
        )
        return existing

    row = QVPNAlert(
        alert_id    = alert_uuid,
        client_id   = client.id,
        timestamp   = _parse_ts(payload.get("timestamp")),
        severity    = severity,
        description = str(payload.get("description") or ""),
        status      = status,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    logger.info(
        "[ALERT] Inserted alert_id=%s severity=%s client=%s",
        row.alert_id, row.severity, payload["client_id"],
    )
    return row


def list_alerts(
    db: DBSession,
    *,
    client_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = 100,
) -> List[QVPNAlert]:
    q = db.query(QVPNAlert)

    if client_id:
        try:
            q = q.filter(QVPNAlert.client_id == uuid.UUID(client_id))
        except ValueError:
            return []

    if severity:
        q = q.filter(QVPNAlert.severity == severity.upper())

    if status:
        q = q.filter(QVPNAlert.status == status.lower())

    if since:
        q = q.filter(QVPNAlert.timestamp >= since)

    return q.order_by(QVPNAlert.timestamp.desc()).limit(limit).all()


def update_alert_status(db: DBSession, alert_id: str, new_status: str) -> QVPNAlert:
    """Update the status of an existing alert (acknowledge / resolve / suppress)."""
    new_status = new_status.lower()
    if new_status not in _VALID_STATUSES:
        raise ValueError(f"Invalid status {new_status!r}. Must be one of {sorted(_VALID_STATUSES)}")

    try:
        alert_uuid = uuid.UUID(alert_id)
    except ValueError:
        raise ValueError(f"Invalid alert_id UUID: {alert_id!r}")

    row = db.query(QVPNAlert).filter(QVPNAlert.alert_id == alert_uuid).first()
    if not row:
        return None

    row.status = new_status
    db.commit()
    db.refresh(row)
    return row
