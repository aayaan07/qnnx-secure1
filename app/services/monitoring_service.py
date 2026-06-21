"""
services/monitoring_service.py — Monitoring Agent data ingestion service.

Each ingest_* function:
  1. Resolves client_identifier → client_id (UUID FK) via the client repo.
  2. Validates the resolved client exists and is active.
  3. Transforms the incoming payload dicts into DB-ready dicts.
  4. Delegates to the corresponding repository for atomic bulk insert.

Batch rejection policy: ALL-OR-NOTHING.
If any record in a batch is invalid (missing fields, bad types), the entire
batch is rejected before any DB write is attempted. Partial inserts do not occur.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List

from sqlalchemy.orm import Session as DBSession

from app.repositories.client_repo import ClientRepository
from app.repositories.monitoring_repo import (
    SystemMetricRepository,
    UserActivityRepository,
    NetworkActivityRepository,
    ProcessEventRepository,
    DeviceEventRepository,
)

logger = logging.getLogger("qvpn.monitoring_service")

_client_repo = ClientRepository()
_metric_repo = SystemMetricRepository()
_activity_repo = UserActivityRepository()
_network_repo = NetworkActivityRepository()
_process_repo = ProcessEventRepository()
_device_repo = DeviceEventRepository()

# Map Windows Security event IDs to normalized event_type strings
_WIN_EVENT_ID_MAP = {
    4624: "login",
    4625: "failed_login",
    4634: "logout",
    4647: "logout",
}


def _resolve_client(db: DBSession, client_identifier: str):
    """
    Look up the Client row by identifier string.

    Raises ValueError if the client is not found or is inactive.
    Returns the Client ORM object on success.
    """
    client = _client_repo.get_by_identifier(db, client_identifier)
    if not client:
        raise ValueError(f"Client not found: {client_identifier!r}")
    if not client.is_active:
        raise ValueError(f"Client is inactive: {client_identifier!r}")
    return client


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# System Metrics
# ---------------------------------------------------------------------------

def ingest_metrics(
    db: DBSession,
    client_identifier: str,
    readings: List[dict],
):
    """
    Ingest a batch of system metric readings.

    Each reading dict (from the agent's details payload) must contain:
      cpu_usage, ram_usage, disk_usage  — floats (0-100)
    Optional: recorded_at (ISO string) — defaults to now() if absent.

    Returns the list of created SystemMetric rows.
    """
    client = _resolve_client(db, client_identifier)

    records = []
    for i, r in enumerate(readings):
        try:
            ts = _parse_ts(r.get("recorded_at")) or _now_utc()
            records.append({
                "client_id": client.id,
                "timestamp": ts,
                "cpu_percent": float(r["cpu_usage"]),
                "ram_percent": float(r["ram_usage"]),
                "disk_percent": float(r["disk_usage"]),
            })
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid metric reading at index {i}: {exc}") from exc

    result = _metric_repo.bulk_insert(db, records)
    logger.info("[MONITORING] metrics client=%s count=%d", client_identifier, len(result))
    return result


# ---------------------------------------------------------------------------
# User Activity
# ---------------------------------------------------------------------------

def ingest_activity(
    db: DBSession,
    client_identifier: str,
    events: List[dict],
):
    """
    Ingest a batch of user activity (login/logout/failed_login) events.

    Each event dict from the agent details must contain:
      event_id   — Windows Security Event ID (int: 4624, 4625, 4634, 4647)
    Optional:
      time_generated — ISO string timestamp
      record_number  — Windows event record number
      username       — extracted username if available

    Returns the list of created UserActivity rows.
    """
    client = _resolve_client(db, client_identifier)

    records = []
    for i, ev in enumerate(events):
        try:
            raw_event_id = ev.get("event_id")
            if raw_event_id is None:
                raise KeyError("event_id")
            win_event_id = int(raw_event_id)
            event_type = _WIN_EVENT_ID_MAP.get(win_event_id, "unknown")

            ts = _parse_ts(ev.get("time_generated")) or _now_utc()
            records.append({
                "client_id": client.id,
                "event_type": event_type,
                "username": ev.get("username"),
                "timestamp": ts,
                "details": {
                    "windows_event_id": win_event_id,
                    "record_number": ev.get("record_number"),
                    "raw": ev,
                },
            })
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid activity event at index {i}: {exc}") from exc

    result = _activity_repo.bulk_insert(db, records)
    logger.info("[MONITORING] activity client=%s count=%d", client_identifier, len(result))
    return result


# ---------------------------------------------------------------------------
# Network Activity
# ---------------------------------------------------------------------------

def ingest_network(
    db: DBSession,
    client_identifier: str,
    events: List[dict],
):
    """
    Ingest a batch of network activity events.

    Two sub-types are handled:
      NETWORK_ACTIVITY (from poll_network_connections): details has pid, local_port,
        remote_ip, remote_port → stored as event_type="new_connection"
      IP_CHANGE (from poll_public_ip): details has old_ip, new_ip →
        stored as event_type="ip_change"

    Each event dict must contain an 'event_type' field (NETWORK_ACTIVITY or IP_CHANGE)
    or a 'details' dict that can be used to infer it.

    Returns the list of created NetworkActivity rows.
    """
    client = _resolve_client(db, client_identifier)

    records = []
    for i, ev in enumerate(events):
        try:
            raw_type = ev.get("event_type", "NETWORK_ACTIVITY")
            if raw_type == "IP_CHANGE":
                normalized_type = "ip_change"
            else:
                normalized_type = "new_connection"

            ts = _parse_ts(ev.get("recorded_at") or ev.get("timestamp")) or _now_utc()
            records.append({
                "client_id": client.id,
                "timestamp": ts,
                "event_type": normalized_type,
                "details": ev.get("details") or {k: v for k, v in ev.items()
                                                   if k not in ("event_type", "client_identifier",
                                                                "recorded_at", "timestamp")},
            })
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid network event at index {i}: {exc}") from exc

    result = _network_repo.bulk_insert(db, records)
    logger.info("[MONITORING] network client=%s count=%d", client_identifier, len(result))
    return result


# ---------------------------------------------------------------------------
# Process Events
# ---------------------------------------------------------------------------

def ingest_process(
    db: DBSession,
    client_identifier: str,
    events: List[dict],
):
    """
    Ingest a batch of process launch/terminate events.

    Each event dict must contain: process_name
    Optional: pid (int), action ("launched"/"terminated"), timestamp

    The agent currently emits "UNKNOWN_PROCESS_LAUNCH" event_type — this is
    normalized to action="launched". If action is explicitly provided, it is
    used directly (supports future termination events).

    Returns the list of created ProcessEvent rows.
    """
    client = _resolve_client(db, client_identifier)

    records = []
    for i, ev in enumerate(events):
        try:
            process_name = ev.get("process_name")
            if not process_name:
                raise KeyError("process_name")

            # Normalize action: explicit field takes precedence; event_type fallback
            raw_action = ev.get("action", "")
            raw_event_type = ev.get("event_type", "")
            if raw_action in ("launched", "terminated"):
                action = raw_action
            elif "LAUNCH" in raw_event_type.upper() or "CREATE" in raw_event_type.upper():
                action = "launched"
            elif "TERMINAT" in raw_event_type.upper():
                action = "terminated"
            else:
                action = "launched"  # default to launched for forward-compat

            ts = _parse_ts(ev.get("timestamp")) or _now_utc()
            records.append({
                "client_id": client.id,
                "process_name": process_name,
                "pid": int(ev["pid"]) if ev.get("pid") is not None else None,
                "action": action,
                "timestamp": ts,
            })
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid process event at index {i}: {exc}") from exc

    result = _process_repo.bulk_insert(db, records)
    logger.info("[MONITORING] process client=%s count=%d", client_identifier, len(result))
    return result


# ---------------------------------------------------------------------------
# Device Events (USB)
# ---------------------------------------------------------------------------

def ingest_device(
    db: DBSession,
    client_identifier: str,
    events: List[dict],
):
    """
    Ingest a batch of USB device events.

    Each event dict must contain an 'action' field ("inserted" / "removed")
    OR the raw agent event_type ("USB_INSERTION" / "USB_REMOVAL").
    Optional: device_info (dict), timestamp.

    Returns the list of created DeviceEvent rows.
    """
    client = _resolve_client(db, client_identifier)

    records = []
    for i, ev in enumerate(events):
        try:
            raw_action = ev.get("action", "")
            raw_event_type = ev.get("event_type", "")

            if raw_action in ("inserted", "removed"):
                action = raw_action
            elif "INSERTION" in raw_event_type.upper() or "ARRIVAL" in raw_event_type.upper():
                action = "inserted"
            elif "REMOVAL" in raw_event_type.upper():
                action = "removed"
            else:
                raise ValueError(
                    f"Cannot determine action from event_type={raw_event_type!r} action={raw_action!r}"
                )

            ts = _parse_ts(ev.get("timestamp")) or _now_utc()
            device_info = ev.get("device_info") or {
                k: v for k, v in ev.items()
                if k not in ("action", "event_type", "client_identifier", "timestamp")
            }
            records.append({
                "client_id": client.id,
                "timestamp": ts,
                "action": action,
                "device_info": device_info,
            })
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid device event at index {i}: {exc}") from exc

    result = _device_repo.bulk_insert(db, records)
    logger.info("[MONITORING] device client=%s count=%d", client_identifier, len(result))
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_ts(value) -> datetime | None:
    """Parse an ISO 8601 string to a timezone-aware datetime, or return None."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None
