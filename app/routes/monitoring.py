import uuid
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.repositories.system_metric_repo import SystemMetricRepository
from app.repositories.security_alert_repo import SecurityAlertRepository
from app.repositories.user_activity_repo import UserActivityRepository
from app.repositories.network_activity_repo import NetworkActivityRepository
from app.repositories.process_metric_repo import ProcessMetricRepository
from app.repositories.ip_history_repo import IPHistoryRepository
from app.repositories.vpn_event_repo import VPNEventRepository
from app.services.monitoring_service import MonitoringService

# Import SQLAlchemy models directly for unified transactional execution
from app.models.system_metric import SystemMetric
from app.models.security_alert import SecurityAlert
from app.models.user_activity import UserActivity
from app.models.network_activity import NetworkActivity
from app.models.process_metric import ProcessMetric
from app.models.ip_history import IPHistory

router = APIRouter()

# Dependency to get db session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Pydantic validation schemas for agent reports
class ProcessMetricSchema(BaseModel):
    pid: int
    name: str
    cpu_percent: float

class NetworkConnectionSchema(BaseModel):
    pid: int
    local_port: int
    remote_ip: str
    remote_port: int

class EventLogRecordSchema(BaseModel):
    event_id: int | None = None
    time_generated: str | None = None
    record_number: int | None = None
    error: str | None = None

class AuthenticationEventsSchema(BaseModel):
    successful_logins_and_logouts: list[EventLogRecordSchema] = []
    failed_login_attempts: list[EventLogRecordSchema] = []

class HardwareEventsSchema(BaseModel):
    usb_pnp_activity: list[EventLogRecordSchema] = []

class AgentMetadataSchema(BaseModel):
    hostname: str
    current_user: str
    public_ip: str
    scan_time_utc: str

class SystemHealthSchema(BaseModel):
    cpu_percent: float
    ram_used_percent: float
    disk_c_percent: float

class FullAgentReportSchema(BaseModel):
    agent_metadata: AgentMetadataSchema
    system_health: SystemHealthSchema
    top_active_processes: list[ProcessMetricSchema] = []
    active_network_connections: list[NetworkConnectionSchema] = []
    authentication_events: AuthenticationEventsSchema
    hardware_events: HardwareEventsSchema


# Pydantic schema for VPN client tunnel events
class VPNEventIngestRequest(BaseModel):
    client_identifier: str = Field(..., description="Client identifier reporting this event")
    event_type: str = Field(..., description="Event type: TUNNEL_UP, TUNNEL_DOWN, or HEARTBEAT_LOSS")
    ip_address: str = Field(None, description="IP address of the tunnel gateway")
    details: dict = Field(None, description="Additional context or failure reasons")


# Repositories & Services instances
metric_repo = SystemMetricRepository()
alert_repo = SecurityAlertRepository()
user_act_repo = UserActivityRepository()
net_act_repo = NetworkActivityRepository()
process_repo = ProcessMetricRepository()
ip_repo = IPHistoryRepository()
vpn_evt_repo = VPNEventRepository()
monitoring_service = MonitoringService()


@router.post(
    "/monitoring/metrics",
    status_code=201,
    summary="Ingest Agent Telemetry Report",
    description="Endpoint for Windows Monitoring Agent to submit full CPU/RAM, processes, sockets, and Windows event logs."
)
def ingest_agent_metrics(payload: FullAgentReportSchema, db: Session = Depends(get_db)):
    try:
        client_id = payload.agent_metadata.hostname
        current_ip = payload.agent_metadata.public_ip
        
        # 1. Store System CPU/RAM/Disk metrics
        metric = SystemMetric(
            id=uuid.uuid4(),
            client_identifier=client_id,
            cpu_usage=payload.system_health.cpu_percent,
            ram_usage=payload.system_health.ram_used_percent,
            disk_usage=payload.system_health.disk_c_percent
        )
        db.add(metric)

        # 2. Store active processes (delete older snapshot first to prevent bloat)
        db.query(ProcessMetric).filter(ProcessMetric.client_identifier == client_id).delete()
        for proc in payload.top_active_processes:
            db.add(ProcessMetric(
                id=uuid.uuid4(),
                client_identifier=client_id,
                pid=proc.pid,
                name=proc.name,
                cpu_percent=proc.cpu_percent
            ))
            
            # Check for suspicious process name (Phase 4 test case)
            if proc.name.lower() in ["miner.exe", "malware.exe", "hack.exe"]:
                db.add(SecurityAlert(
                    id=uuid.uuid4(),
                    alert_type="SUSPICIOUS_PROCESS",
                    severity="HIGH",
                    description=f"Suspicious running process detected: '{proc.name}' (PID: {proc.pid}) on host '{client_id}'",
                    status="OPEN"
                ))

        # 3. Store active network connections (delete older snapshot first)
        db.query(NetworkActivity).filter(NetworkActivity.client_identifier == client_id).delete()
        for conn in payload.active_network_connections:
            db.add(NetworkActivity(
                id=uuid.uuid4(),
                client_identifier=client_id,
                pid=conn.pid,
                local_port=conn.local_port,
                remote_ip=conn.remote_ip,
                remote_port=conn.remote_port
            ))

        # 4. Store successful login/logout events (avoid logging duplicates based on record number)
        existing_activities = db.query(UserActivity.record_number).filter(
            UserActivity.client_identifier == client_id
        ).all()
        logged_records = {r[0] for r in existing_activities}
        
        for event in payload.authentication_events.successful_logins_and_logouts:
            if event.error or event.event_id is None:
                continue
            if event.record_number not in logged_records:
                db.add(UserActivity(
                    id=uuid.uuid4(),
                    client_identifier=client_id,
                    event_id=event.event_id,
                    time_generated=event.time_generated,
                    record_number=event.record_number
                ))

        # 5. IP Change Detection (Phase 3)
        last_ip_record = ip_repo.get_latest_for_client(db, client_id)
        if not last_ip_record:
            # First time seeing this client, log initial IP
            db.add(IPHistory(
                id=uuid.uuid4(),
                client_identifier=client_id,
                ip_address=current_ip
            ))
        elif last_ip_record.ip_address != current_ip:
            # IP changed! Log it and trigger alert
            old_ip = last_ip_record.ip_address
            db.add(IPHistory(
                id=uuid.uuid4(),
                client_identifier=client_id,
                ip_address=current_ip
            ))
            db.add(SecurityAlert(
                id=uuid.uuid4(),
                alert_type="IP_CHANGE",
                severity="MEDIUM",
                description=f"Public IP address changed from '{old_ip}' to '{current_ip}' on client '{client_id}'",
                status="OPEN"
            ))

        # 6. Ingest Security Alerts from logs (Phase 4)
        # Check for failed logins
        for failed in payload.authentication_events.failed_login_attempts:
            if failed.error or failed.event_id is None:
                continue
            db.add(SecurityAlert(
                id=uuid.uuid4(),
                alert_type="FAILED_LOGIN",
                severity="MEDIUM",
                description=f"Failed Windows login attempt (Event 4625) recorded on client '{client_id}' at {failed.time_generated}",
                status="OPEN"
            ))

        # Check for USB insertion events
        for usb in payload.hardware_events.usb_pnp_activity:
            if usb.error or usb.event_id is None:
                continue
            db.add(SecurityAlert(
                id=uuid.uuid4(),
                alert_type="USB_INSERTION",
                severity="HIGH",
                description=f"Unauthorized USB mass storage insertion (Event 20001) detected on client '{client_id}' at {usb.time_generated}",
                status="OPEN"
            ))

        # Perform a single commit at the end of the transaction!
        db.commit()
        return {"success": True, "message": "Telemetry report ingested successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to ingest agent telemetry: {e}")


@router.post(
    "/monitoring/vpn_events",
    status_code=201,
    summary="Ingest VPN Tunnel Event",
    description="Endpoint for VPN Client to log tunnel state changes (Up/Down/Heartbeat loss)."
)
def ingest_vpn_event(payload: VPNEventIngestRequest, db: Session = Depends(get_db)):
    try:
        # Create the event log
        event_data = {
            "id": uuid.uuid4(),
            "client_identifier": payload.client_identifier,
            "event_type": payload.event_type,
            "ip_address": payload.ip_address,
            "details": json.dumps(payload.details or {})
        }
        vpn_evt_repo.create(db, event_data)

        # Trigger alerts based on event type (Phase 4)
        if payload.event_type == "HEARTBEAT_LOSS":
            alert_repo.create(db, {
                "id": uuid.uuid4(),
                "alert_type": "HEARTBEAT_LOSS",
                "severity": "HIGH",
                "description": f"VPN Tunnel lost heartbeat connection on client '{payload.client_identifier}'",
                "status": "OPEN"
            })
        elif payload.event_type == "TUNNEL_DOWN":
            reason = (payload.details or {}).get("reason", "Unknown reason")
            # Only alert if it wasn't a clean disconnect initiated by the client
            if "Client initiated disconnect" not in reason:
                alert_repo.create(db, {
                    "id": uuid.uuid4(),
                    "alert_type": "TUNNEL_FAILURE",
                    "severity": "HIGH",
                    "description": f"VPN Tunnel disconnected unexpectedly on client '{payload.client_identifier}'. Reason: {reason}",
                    "status": "OPEN"
                })

        return {"success": True, "message": "VPN event logged successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log VPN event: {e}")


@router.get(
    "/monitoring/state",
    summary="Get Real-Time Monitoring State",
    description="Aggregated real-time system state (sessions, health, alerts, traffic)."
)
def get_monitoring_state(db: Session = Depends(get_db)):
    try:
        state = monitoring_service.get_realtime_state(db)
        return state
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to aggregate state: {e}")


@router.post(
    "/monitoring/alerts/{alert_id}/resolve",
    summary="Resolve Threat Alert",
    description="Mark a threat alert as resolved."
)
def resolve_alert(alert_id: str, db: Session = Depends(get_db)):
    record = alert_repo.resolve_alert(db, uuid.UUID(alert_id))
    if not record:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"success": True, "status": record.status}
