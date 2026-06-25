import uuid as _uuid
from sqlalchemy import Column, Text, Integer, DateTime, Index
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class AuditLog(Base):
    """
    audit_logs — Immutable record of every HTTP request received by the gateway.

    One row per request. Written by AuditLogMiddleware after the response is sent
    so it never blocks the response path.

    Columns:
      id           — surrogate PK (uuid)
      client_id    — resolved from X-API-Key → api_keys.id (nullable: unauthenticated requests)
      method       — HTTP verb (GET, POST, …)
      path         — raw request path (e.g. /api/v1/agent/alerts)
      status_code  — HTTP response status
      duration_ms  — wall-clock time from first byte in to last byte out
      ip_address   — client remote IP (proxy-aware: X-Forwarded-For preferred)
      user_agent   — User-Agent header (truncated to 512 chars)
      created_at   — UTC timestamp of the request
    """
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)

    # Nullable — unauthenticated / pre-auth requests are still logged
    client_id = Column(UUID(as_uuid=True), nullable=True)

    method      = Column(Text, nullable=False)
    path        = Column(Text, nullable=False)
    status_code = Column(Integer, nullable=False)
    duration_ms = Column(Integer, nullable=True)
    ip_address  = Column(Text, nullable=True)
    user_agent  = Column(Text, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


_idx_audit_client     = Index("ix_audit_logs_client_id",   AuditLog.client_id)
_idx_audit_created    = Index("ix_audit_logs_created_at",  AuditLog.created_at)
_idx_audit_path       = Index("ix_audit_logs_path",        AuditLog.path)
_idx_audit_status     = Index("ix_audit_logs_status_code", AuditLog.status_code)
