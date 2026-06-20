from sqlalchemy import Column, Text, DateTime, LargeBinary, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class Session(Base):
    """
    One handshake/tunnel instance for a client. A new row is created every
    time a client opens a fresh connection to the gateway.
    """
    __tablename__ = "sessions"

    id = Column(UUID(as_uuid=True), primary_key=True)

    client_id = Column(UUID(as_uuid=True), ForeignKey("clients.id"), nullable=False)

    kem_algorithm = Column(Text, nullable=False)

    # kem_state values: "PENDING", "DECAPSULATED", "ESTABLISHED", "FAILED"
    kem_state = Column(Text, nullable=False, server_default="PENDING")

    # Ciphertext the CLIENT sent (it encapsulated using the client's own public key)
    kem_ciphertext = Column(LargeBinary)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    expires_at = Column(DateTime(timezone=True))