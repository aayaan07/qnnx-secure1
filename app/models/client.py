import uuid as _uuid
from sqlalchemy import Column, Text, Boolean, DateTime, LargeBinary, Index
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class Client(Base):
    """
    A registered VPN client/device.

    Key storage pattern:
      - public_key is handed to the client during provisioning so it can
        encapsulate (encrypt) the session shared secret.
      - private_key is held server-side ONLY. It is never sent to the client
        and is used only during decapsulation via the PQC API.
      - pqc_key_id is the reference returned by the PQC service's /keygen
        endpoint. It can be used for service-managed key storage in the future.

    All three fields are populated by the /provisioning/register endpoint when
    a new client is registered.
    """
    __tablename__ = "clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)

    # Human/device-supplied identifier, e.g. hostname or provisioning token
    client_identifier = Column(Text, nullable=False, unique=True)

    kem_algorithm = Column(Text, nullable=False)  # e.g. "ML-KEM-768"

    # Reference to the keypair in the PQC service (customer_managed mode)
    pqc_key_id = Column(Text, nullable=True)

    # Public key is distributed to the client during provisioning
    public_key = Column(LargeBinary, nullable=False)

    # Private key is held server-side; used only for decapsulation via PQC API
    # Never log, serialize to JSON, or send this field to any client
    private_key = Column(LargeBinary, nullable=False)

    is_active = Column(Boolean, nullable=False, server_default="true")

    last_seen = Column(DateTime(timezone=True))

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


# Indexes for fast lookups
_idx_client_identifier = Index("ix_clients_client_identifier", Client.client_identifier)
_idx_client_is_active = Index("ix_clients_is_active", Client.is_active)