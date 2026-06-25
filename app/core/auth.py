from fastapi import Header, Depends, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.exceptions import InvalidApiKey
from app.services.api_key_service import verify_api_key, _CachedKey


def get_api_key(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key", description="Gateway access API key"),
    db: Session = Depends(get_db),
) -> _CachedKey:
    """
    FastAPI dependency that verifies the X-API-Key header.

    Returns a _CachedKey dataclass (plain data, no ORM session lifetime issues).
    Stores api_key_id as a plain string in request.state so AuditLogMiddleware
    can read it after the DB session closes.
    """
    if not x_api_key:
        raise InvalidApiKey("X-API-Key header is missing")
    api_key = verify_api_key(db, x_api_key)
    request.state.api_key = api_key
    request.state.api_key_id = api_key.api_key_id
    return api_key
