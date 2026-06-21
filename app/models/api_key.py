import uuid as _uuid
from sqlalchemy import Column, Text, DateTime, Index, JSON
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class ApiKey(Base):
    """
    ApiKey — Database storage for API Key authentication on the gateway.

    Storage + Verification only. Keys are generated out-of-band and stored hashed.
    """
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    key_id = Column(Text, nullable=False, unique=True, index=True)
    hashed_key = Column(Text, nullable=False)
    name = Column(Text, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    # JSON works for both SQLite (as TEXT) and PostgreSQL (as JSONB)
    scopes = Column(JSON, nullable=False, default=list)


# Index for lookup query
_idx_api_keys_lookup = Index("ix_api_keys_lookup", ApiKey.key_id, ApiKey.revoked_at, ApiKey.expires_at)

