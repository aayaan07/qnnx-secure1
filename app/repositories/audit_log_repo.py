from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.models.audit_log import AuditLog


class AuditLogRepository:

    def create(self, db: DBSession, record: dict) -> AuditLog:
        row = AuditLog(id=uuid.uuid4(), **record)
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    def list(
        self,
        db: DBSession,
        *,
        client_id: Optional[str] = None,
        path_prefix: Optional[str] = None,
        status_code: Optional[int] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[AuditLog]:
        q = db.query(AuditLog)

        if client_id:
            try:
                q = q.filter(AuditLog.client_id == uuid.UUID(client_id))
            except ValueError:
                pass

        if path_prefix:
            q = q.filter(AuditLog.path.like(f"{path_prefix}%"))

        if status_code is not None:
            q = q.filter(AuditLog.status_code == status_code)

        if since:
            q = q.filter(AuditLog.created_at >= since)

        return q.order_by(AuditLog.created_at.desc()).limit(limit).all()
