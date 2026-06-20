import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.repositories.system_metric_repo import SystemMetricRepository
from app.repositories.security_alert_repo import SecurityAlertRepository
from app.services.monitoring_service import MonitoringService

router = APIRouter()

# Dependency to get db session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic Schemas for Ingestion Request validation
class MetricIngestRequest(BaseModel):
    client_identifier: str = Field(..., description="Unique client hardware/system identifier")
    cpu_usage: float = Field(..., ge=0.0, le=100.0, description="CPU usage in percentage")
    ram_usage: float = Field(..., ge=0.0, le=100.0, description="RAM usage in percentage")
    disk_usage: float = Field(..., ge=0.0, le=100.0, description="Disk usage in percentage")

class AlertIngestRequest(BaseModel):
    alert_type: str = Field(..., description="Type of threat alert, e.g. USB_INSERTION, FAILED_LOGIN")
    severity: str = Field(..., pattern="^(LOW|MEDIUM|HIGH)$", description="Alert severity level")
    description: str = Field(..., description="Detailed description of the warning/alert")

# Services and Repositories instances
metric_repo = SystemMetricRepository()
alert_repo = SecurityAlertRepository()
monitoring_service = MonitoringService()


@router.post(
    "/monitoring/metrics",
    status_code=201,
    summary="Ingest Client Metrics",
    description="Endpoint for Windows Monitoring Agent to report CPU, RAM, and Disk metrics."
)
def ingest_metrics(payload: MetricIngestRequest, db: Session = Depends(get_db)):
    try:
        metric_data = {
            "id": uuid.uuid4(),
            "client_identifier": payload.client_identifier,
            "cpu_usage": payload.cpu_usage,
            "ram_usage": payload.ram_usage,
            "disk_usage": payload.disk_usage
        }
        record = metric_repo.create(db, metric_data)
        return {"success": True, "id": str(record.id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest metrics: {e}")


@router.post(
    "/monitoring/alerts",
    status_code=201,
    summary="Ingest Threat Alert",
    description="Endpoint for Threat Detection Engine to log security alerts."
)
def ingest_alert(payload: AlertIngestRequest, db: Session = Depends(get_db)):
    try:
        alert_data = {
            "id": uuid.uuid4(),
            "alert_type": payload.alert_type,
            "severity": payload.severity,
            "description": payload.description,
            "status": "OPEN"
        }
        record = alert_repo.create(db, alert_data)
        return {"success": True, "id": str(record.id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest alert: {e}")


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
