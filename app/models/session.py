import uuid as _uuid
from sqlalchemy import Column, Text, DateTime, ForeignKey, Enum, LargeBinary, Index
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class Session(Base):
    """
    One handshake/tunnel instance for a client.

    Lifecycle:
      PENDING       → handshake initiated; decapsulation in progress
      ESTABLISHED   → shared_secret decapsulated; AES key live in session_store
      ACTIVE        → traffic flowing (tunnel confirmed by first heartbeat)
      EXPIRED       → TTL elapsed with no heartbeat
      CLOSED        → client or gateway explicitly closed the tunnel
      FAILED        → handshake failed (PQC API error, unknown client, etc.)

    Security notes:
      - kem_ciphertext is stored for audit only; it cannot be used to re-derive
        the shared_secret without the private_key.
      - pqc_key_id links back to the keypair on the PQC service.
      - AES session keys are NEVER written to the DB; they live only in
        gateway/session_store.py (in-memory TTL cache).
    """
    __tablename__ = "sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    # Foreign key to clients
    client_id = Column(UUID(as_uuid=True), ForeignKey("clients.id"), nullable=False)

    kem_algorithm = Column(Text, nullable=False)

    # Reference to the PQC keypair used in this session
    pqc_key_id = Column(Text, nullable=True)

    # KEM handshake state
    # Values: "PENDING", "ESTABLISHED", "ACTIVE", "EXPIRED", "CLOSED", "FAILED"
    kem_state = Column(Text, nullable=False, server_default="PENDING")

    # Tunnel lifecycle status (separate from KEM state — a session can be
    # "ESTABLISHED" cryptographically but "ACTIVE"/"CLOSED" at tunnel level)
    # Values: "CONNECTING", "ACTIVE", "EXPIRED", "CLOSED", "FAILED"
    tunnel_status = Column(Text, nullable=False, server_default="CONNECTING")

    # Ciphertext the CLIENT sent (stored for audit; not used for re-decapsulation)
    kem_ciphertext = Column(LargeBinary)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    established_at = Column(DateTime(timezone=True))  # set when kem_state → ESTABLISHED
    closed_at = Column(DateTime(timezone=True))         # set when tunnel_status → CLOSED/EXPIRED
    expires_at = Column(DateTime(timezone=True))        # optional hard expiry timestamp


# Indexes
_idx_session_client_id = Index("ix_sessions_client_id", Session.client_id)
_idx_session_kem_state = Index("ix_sessions_kem_state", Session.kem_state)
_idx_session_tunnel_status = Index("ix_sessions_tunnel_status", Session.tunnel_status)
_idx_session_created_at = Index("ix_sessions_created_at", Session.created_at)