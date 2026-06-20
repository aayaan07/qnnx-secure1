from fastapi import Header, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.exceptions import InvalidApiKey
from app.services.api_key_service import verify_api_key
from app.models.api_key import ApiKey


def get_api_key(
    x_api_key: str | None = Header(None, alias="X-API-Key", description="Gateway access API key"),
    db: Session = Depends(get_db),
) -> ApiKey:
    """
    FastAPI dependency to extract and verify the API key from the X-API-Key header.
    Returns the validated ApiKey ORM object on success.
    """
    if not x_api_key:
        raise InvalidApiKey("X-API-Key header is missing")
    return verify_api_key(db, x_api_key)
