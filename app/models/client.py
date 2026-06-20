from sqlalchemy import Column, Text, Boolean, DateTime, LargeBinary
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class Client(Base):
    """
    A registered VPN client/device. Holds the client's own unique ML-KEM
    keypair: the gateway generated this pair (via /keygen) and keeps the
    private key here so it can later DEcapsulate ciphertexts this specific
    client sends during a handshake.
    """
    __tablename__ = "clients"

    id = Column(UUID(as_uuid=True), primary_key=True)

    # Human/device-supplied identifier, e.g. hostname or provisioning token
    client_identifier = Column(Text, nullable=False, unique=True)

    kem_algorithm = Column(Text, nullable=False)  # e.g. "ML-KEM-768"

    # Public key is handed out to the client; private key NEVER leaves the gateway.
    public_key = Column(LargeBinary, nullable=False)
    private_key = Column(LargeBinary, nullable=False)

    is_active = Column(Boolean, nullable=False, server_default="true")

    last_seen = Column(DateTime(timezone=True))

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )