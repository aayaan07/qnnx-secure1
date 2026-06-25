"""
middleware.py — Request-level middleware for the QVPN Gateway.

AuditLogMiddleware:
  - Runs on every HTTP request (including unauthenticated ones that fail auth)
  - Records: method, path, status_code, duration_ms, ip_address, user_agent, client_id
  - client_id is the api_keys.id UUID resolved from the X-API-Key header after auth
  - The resolved ApiKey object is attached to request.state.api_key by the
    get_api_key dependency; the middleware reads it from there post-handler
  - Writes are fire-and-forget on a background thread to avoid blocking responses
  - Skips /health and /docs/* to avoid audit noise
"""
from __future__ import annotations

import hashlib
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.database import SessionLocal

logger = logging.getLogger("qvpn.middleware.audit")

from app.core.config import settings as _settings

_SKIP_PATHS = frozenset(p.strip() for p in _settings.AUDIT_SKIP_PATHS.split(",") if p.strip())
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="audit-writer")


def _resolve_client_id(request: Request) -> uuid.UUID | None:
    """
    Extract the api_key id from request.state.api_key_id (a plain string set by
    get_api_key dependency before the DB session closes).
    Returns None for unauthenticated / failed requests.
    """
    raw = getattr(request.state, "api_key_id", None)
    if raw is not None:
        try:
            return uuid.UUID(raw)
        except (ValueError, AttributeError):
            pass
    return None


def _get_client_ip(request: Request) -> str:
    """Prefer X-Forwarded-For (set by reverse proxy) over direct remote address."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _write_audit(record: dict) -> None:
    """Synchronously write one audit row. Runs in background thread."""
    try:
        from app.models.audit_log import AuditLog  # local import to avoid circular
        db = SessionLocal()
        try:
            row = AuditLog(id=uuid.uuid4(), **record)
            db.add(row)
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        logger.error("[AUDIT] Failed to write audit log: %s", exc)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that writes one audit_logs row per request.

    Timing:
      - Starts a wall-clock timer before passing to the next handler.
      - Records the response status after the handler returns.
      - Submits the DB write to a background thread pool so the response
        is never delayed by the audit write.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if not _settings.AUDIT_LOG_ENABLED:
            return await call_next(request)

        # Skip noise paths
        if request.url.path in _SKIP_PATHS or request.url.path.startswith("/docs"):
            return await call_next(request)

        t0 = time.monotonic()
        response: Response = await call_next(request)
        duration_ms = int((time.monotonic() - t0) * 1000)

        client_id = _resolve_client_id(request)

        record = {
            "client_id":   client_id,
            "method":      request.method,
            "path":        request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "ip_address":  _get_client_ip(request),
            "user_agent":  (request.headers.get("User-Agent") or "")[:512],
        }

        _executor.submit(_write_audit, record)

        return response
